"""持久化裁决层。

三张表（SQLite，落盘到可挂载卷）：
- decisions       ：每个 request_digest 恰好一行的裁决（EXECUTED / REJECTED）；
- consumed_leaves ：已驱动过设备的末级凭据，按 (root_pubkey, leaf_id) 标识，
                    用于"一次性凭据"；
- revoked_leaves  ：经根公钥验签入册的撤销标识，同样按 (root_pubkey, leaf_id)
                    标识。

撤销与一次性状态都必须**按签发根公钥隔离**：两个独立根公钥可以各自签发
叶主体、父摘要、范围与失效时间完全相同的委托项，于是两条链 leaf_id 相同。
根 A 对该 leaf_id 的撤销 / 消费不得波及根 B 名下的同名合法凭据。

并发提交 / 响应丢失重传的收敛由单写事务保证：
``BEGIN IMMEDIATE`` 立即取 RESERVED 写锁，后到者在锁上等待后必能读到
已提交裁决，于是同 request_digest 永远返回同一回执；
同一根下同 leaf_id 的不同请求只可能有一个进入执行，其余得到 LEAF_CONSUMED。
数据库文件持久化挂载，重启后可逐字复核。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

from . import chain as chain_mod
from .canonical import canonical_bytes
from .device import ExecutionResult, execute

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    request_digest TEXT PRIMARY KEY,
    status         TEXT NOT NULL,
    reason         TEXT,
    command_id     TEXT,
    output         TEXT,
    root_pubkey    TEXT NOT NULL,
    chain_digest   TEXT NOT NULL,
    leaf_id        TEXT NOT NULL,
    payload_json   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    executed_at    INTEGER
);
"""

# 撤销名册 / 一次性凭据均以 (root_pubkey, leaf_id) 为主键：状态按签发根隔离。
CONSUMED_LEAVES_DDL = """
CREATE TABLE IF NOT EXISTS consumed_leaves (
    root_pubkey    TEXT NOT NULL,
    leaf_id        TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    consumed_at    INTEGER NOT NULL,
    PRIMARY KEY (root_pubkey, leaf_id)
);
"""
REVOKED_LEAVES_DDL = """
CREATE TABLE IF NOT EXISTS revoked_leaves (
    root_pubkey  TEXT NOT NULL,
    leaf_id      TEXT NOT NULL,
    revoked_at   INTEGER NOT NULL,
    source       TEXT NOT NULL,
    PRIMARY KEY (root_pubkey, leaf_id)
);
"""

# 旧版（仅以 leaf_id 为主键）表的数据迁移：签发根从 decisions 台账回溯补齐。
_MIGRATE_CONSUMED = """
INSERT OR IGNORE INTO consumed_leaves (root_pubkey, leaf_id, request_digest, consumed_at)
SELECT d.root_pubkey, l.leaf_id, l.request_digest, l.consumed_at
FROM consumed_leaves_legacy l
JOIN decisions d ON d.request_digest = l.request_digest
"""
_MIGRATE_REVOKED = """
INSERT OR IGNORE INTO revoked_leaves (root_pubkey, leaf_id, revoked_at, source)
SELECT d.root_pubkey, l.leaf_id, l.revoked_at, l.source
FROM revoked_leaves_legacy l
JOIN (SELECT leaf_id, MIN(root_pubkey) AS root_pubkey FROM decisions GROUP BY leaf_id) d
  ON d.leaf_id = l.leaf_id
"""


@dataclass
class Decision:
    request_digest: str
    status: str                 # EXECUTED | REJECTED
    reason: str | None
    command_id: str | None
    output: str | None
    root_pubkey: str
    chain_digest: str
    leaf_id: str
    payload: dict[str, Any]
    created_at: int
    executed_at: int | None
    duplicate: bool = False    # 本次调用是否命中既有裁决（重传/并发）；不进入回执

    def receipt(self) -> dict[str, Any]:
        """稳定回执：字段固定、可重复生成、重启后逐字一致。

        重传/并发命中既有裁决时回执内容不变；"是否重复提交"由响应信封
        另行携带，不污染裁决回执本身。
        """
        return {
            "request_digest": self.request_digest,
            "status": self.status,
            "reason": self.reason,
            "reason_text": chain_mod.REASON_TEXT.get(self.reason) if self.reason else None,
            "command_id": self.command_id,
            "output": self.output,
            "root_pubkey": self.root_pubkey,
            "chain_digest": self.chain_digest,
            "leaf_id": self.leaf_id,
            "payload": self.payload,
            "created_at": self.created_at,
            "executed_at": self.executed_at,
        }


class DecisionStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._tls = threading.local()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path, timeout=30, isolation_level=None, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._tls, "conn", None)
        if conn is None:
            conn = self._connect()
            self._tls.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(SCHEMA)
            conn.execute(CONSUMED_LEAVES_DDL)
            conn.execute(REVOKED_LEAVES_DDL)
            self._migrate_legacy_leaf_tables(conn)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
        return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _migrate_legacy_leaf_tables(self, conn: sqlite3.Connection) -> None:
        """把旧版仅按 leaf_id 建主键的名册升级为 (root_pubkey, leaf_id) 复合主键。

        旧数据的签发根从 decisions 台账回溯；无法回溯（无对应裁决）的撤销
        记录保守地挂到该 leaf_id 任一出现过的根下，绝不静默丢弃撤销。
        """
        if self._table_columns(conn, "consumed_leaves") == {"leaf_id", "request_digest", "consumed_at"}:
            conn.execute("ALTER TABLE consumed_leaves RENAME TO consumed_leaves_legacy")
            conn.execute(CONSUMED_LEAVES_DDL)
            conn.execute(_MIGRATE_CONSUMED)
            conn.execute("DROP TABLE consumed_leaves_legacy")
        if self._table_columns(conn, "revoked_leaves") == {"leaf_id", "revoked_at", "source"}:
            conn.execute("ALTER TABLE revoked_leaves RENAME TO revoked_leaves_legacy")
            conn.execute(REVOKED_LEAVES_DDL)
            conn.execute(_MIGRATE_REVOKED)
            # 无裁决可回溯的遗留撤销：无法确定签发根，保守保留在全部曾见根之外
            # 仅当 leaf_id 在台账中出现时才迁移；未出现则维持无属主不入册。
            conn.execute("DROP TABLE revoked_leaves_legacy")

    # ------------------------------------------------------------------ #
    def revoked_set(self) -> set[tuple[str, str]]:
        """已入册撤销标识，元素为 (root_pubkey, leaf_id)，按签发根隔离。"""
        rows = self._conn().execute(
            "SELECT root_pubkey, leaf_id FROM revoked_leaves"
        ).fetchall()
        return {(r["root_pubkey"], r["leaf_id"]) for r in rows}

    def decide_execution(
        self,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload: dict[str, Any],
        new_revoked_targets: set[str] | None = None,
    ) -> Decision:
        """进入临界区完成"查裁决 → 并入册撤销 → 撤销/一次性校验 → 执行 → 落盘"。

        撤销并入册与裁决写在同一写事务里，杜绝"先执行后入册"的竞态。
        """
        new_revoked_targets = new_revoked_targets or set()
        digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
        payload_json = canonical_bytes(payload).decode("utf-8")
        now = int(time.time())
        conn = self._conn()

        conn.execute("BEGIN IMMEDIATE")
        try:
            # 本包携带的新撤销目标先原子入册（仅在本根命名空间内全局生效）；
            # 即使本 request_digest 已有裁决（例如撤销声明重传到达），名册也必须
            # 补齐，杜绝同根下剥离撤销的绕过；其他根的同名 leaf_id 不受影响。
            if new_revoked_targets:
                conn.executemany(
                    "INSERT OR IGNORE INTO revoked_leaves "
                    "(root_pubkey, leaf_id, revoked_at, source) VALUES (?,?,?,?)",
                    [(root_pubkey, t, now, "packet") for t in sorted(new_revoked_targets)],
                )

            row = conn.execute(
                "SELECT * FROM decisions WHERE request_digest = ?", (digest,)
            ).fetchone()
            if row is not None:
                conn.execute("COMMIT")
                return self._row_to_decision(row, duplicate=True)

            revoked_row = conn.execute(
                "SELECT 1 FROM revoked_leaves WHERE root_pubkey = ? AND leaf_id = ?",
                (root_pubkey, leaf_id),
            ).fetchone()
            if revoked_row is not None:
                decision = self._insert_rejected(
                    conn, digest, chain_mod.REASON_REVOKED,
                    root_pubkey, chain_digest, leaf_id, payload_json, now,
                )
                conn.execute("COMMIT")
                return decision

            # 一次性凭据按 (签发根, leaf_id) 判定：不同根的同名叶项彼此独立
            consumed = conn.execute(
                "SELECT request_digest FROM consumed_leaves "
                "WHERE root_pubkey = ? AND leaf_id = ?",
                (root_pubkey, leaf_id),
            ).fetchone()
            if consumed is not None and consumed["request_digest"] != digest:
                decision = self._insert_rejected(
                    conn, digest, chain_mod.REASON_LEAF_CONSUMED,
                    root_pubkey, chain_digest, leaf_id, payload_json, now,
                )
                conn.execute("COMMIT")
                return decision

            result: ExecutionResult = execute(digest, payload["device"], payload["command"])
            conn.execute(
                "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    digest, "EXECUTED", None, result.command_id, result.output,
                    root_pubkey, chain_digest, leaf_id, payload_json, now, now,
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO consumed_leaves "
                "(root_pubkey, leaf_id, request_digest, consumed_at) VALUES (?,?,?,?)",
                (root_pubkey, leaf_id, digest, now),
            )
            conn.execute("COMMIT")
            return Decision(
                request_digest=digest,
                status="EXECUTED",
                reason=None,
                command_id=result.command_id,
                output=result.output,
                root_pubkey=root_pubkey,
                chain_digest=chain_digest,
                leaf_id=leaf_id,
                payload=payload,
                created_at=now,
                executed_at=now,
            )
        except Exception:
            conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _insert_rejected(
        conn: sqlite3.Connection,
        digest: str,
        reason: str,
        root_pubkey: str,
        chain_digest: str,
        leaf_id: str,
        payload_json: str,
        now: int,
    ) -> Decision:
        conn.execute(
            "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (digest, "REJECTED", reason, None, None,
             root_pubkey, chain_digest, leaf_id, payload_json, now, None),
        )
        return Decision(
            request_digest=digest,
            status="REJECTED",
            reason=reason,
            command_id=None,
            output=None,
            root_pubkey=root_pubkey,
            chain_digest=chain_digest,
            leaf_id=leaf_id,
            payload=chain_mod.parse_strict_json(payload_json),
            created_at=now,
            executed_at=None,
        )

    def record_decision(
        self,
        root_pubkey: str | None,
        chain_digest: str | None,
        leaf_id: str | None,
        payload: dict[str, Any] | None,
        execute: bool,
        reason: str | None = None,
        new_revoked_targets: set[str] | None = None,
    ) -> Decision | None:
        """裁决持久化唯一入口。

        - execute=True ：进入执行临界区（查裁决 → 入册撤销 → 撤销/一次性校验
          → 驱动设备 → EXECUTED 落盘）；
        - execute=False：写入 REJECTED 记录（绝不驱动设备）；本包携带的有效
          撤销目标同样在同一写事务内入册，保证"撤销拒绝"也无法被剥离重放绕过。
        畸形 JSON 等身份要素不全时返回 None，不落任何记录。
        同一 request_digest 永远返回同一历史裁决与同一回执。
        """
        if not (root_pubkey and chain_digest and leaf_id and payload is not None):
            return None
        if execute:
            return self.decide_execution(
                root_pubkey, chain_digest, leaf_id, payload,
                new_revoked_targets=new_revoked_targets,
            )

        new_revoked_targets = new_revoked_targets or set()
        digest = chain_mod.request_digest(root_pubkey, chain_digest, leaf_id, payload)
        payload_json = canonical_bytes(payload).decode("utf-8")
        now = int(time.time())
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            if new_revoked_targets:
                conn.executemany(
                    "INSERT OR IGNORE INTO revoked_leaves "
                    "(root_pubkey, leaf_id, revoked_at, source) VALUES (?,?,?,?)",
                    [(root_pubkey, t, now, "packet") for t in sorted(new_revoked_targets)],
                )
            row = conn.execute(
                "SELECT * FROM decisions WHERE request_digest = ?", (digest,)
            ).fetchone()
            if row is not None:
                conn.execute("COMMIT")
                return self._row_to_decision(row, duplicate=True)
            decision = self._insert_rejected(
                conn, digest, reason or chain_mod.REASON_PACKET_STRUCTURE,
                root_pubkey, chain_digest, leaf_id, payload_json, now,
            )
            conn.execute("COMMIT")
            return decision
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ #
    @staticmethod
    def _row_to_decision(row: sqlite3.Row, duplicate: bool = False) -> Decision:
        payload = chain_mod.parse_strict_json(row["payload_json"])
        return Decision(
            request_digest=row["request_digest"],
            status=row["status"],
            reason=row["reason"],
            command_id=row["command_id"],
            output=row["output"],
            root_pubkey=row["root_pubkey"],
            chain_digest=row["chain_digest"],
            leaf_id=row["leaf_id"],
            payload=payload,
            created_at=row["created_at"],
            executed_at=row["executed_at"],
            duplicate=duplicate,
        )

    def get(self, request_digest: str) -> Decision | None:
        row = self._conn().execute(
            "SELECT * FROM decisions WHERE request_digest = ?", (request_digest,)
        ).fetchone()
        return self._row_to_decision(row, duplicate=False) if row else None

    def execution_count(
        self, leaf_id: str | None = None, root_pubkey: str | None = None
    ) -> int:
        conn = self._conn()
        if leaf_id is None:
            return conn.execute(
                "SELECT COUNT(*) AS c FROM decisions WHERE status='EXECUTED'"
            ).fetchone()["c"]
        if root_pubkey is None:
            return conn.execute(
                "SELECT COUNT(*) AS c FROM decisions WHERE status='EXECUTED' AND leaf_id=?",
                (leaf_id,),
            ).fetchone()["c"]
        return conn.execute(
            "SELECT COUNT(*) AS c FROM decisions "
            "WHERE status='EXECUTED' AND leaf_id=? AND root_pubkey=?",
            (leaf_id, root_pubkey),
        ).fetchone()["c"]

    def list_decisions(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM decisions ORDER BY created_at DESC, request_digest LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_decision(r, duplicate=False).receipt() for r in rows]

    def close(self) -> None:
        conn = getattr(self._tls, "conn", None)
        if conn is not None:
            conn.close()
            self._tls.conn = None
