"""持久化裁决层。

三张表（SQLite，落盘到可挂载卷）：
- decisions       ：每个 request_digest 恰好一行的裁决（EXECUTED / REJECTED）；
- consumed_leaves ：已驱动过设备的末级凭据，用于"一次性凭据"；
- revoked_leaves  ：经根公钥验签入册的撤销名册。

撤销名册与一次性消耗均按 **(签发根 root_pubkey, leaf_id)** 定位：两个独立
根公钥可以签发内容完全相同的叶项 header（leaf_id 相同而签名与签发根不同），
根 A 的撤销或消耗不得影响根 B 的合法凭据。

并发提交 / 响应丢失重传的收敛由单写事务保证：
``BEGIN IMMEDIATE`` 立即取 RESERVED 写锁，后到者在锁上等待后必能读到
已提交裁决，于是同 request_digest 永远返回同一回执；
同一签发根下同 leaf_id 的不同请求只可能有一个进入执行，其余得到
LEAF_CONSUMED。数据库文件持久化挂载，重启后可逐字复核。
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
CREATE TABLE IF NOT EXISTS consumed_leaves (
    root_pubkey    TEXT NOT NULL,
    leaf_id        TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    consumed_at    INTEGER NOT NULL,
    PRIMARY KEY (root_pubkey, leaf_id)
);
CREATE TABLE IF NOT EXISTS revoked_leaves (
    root_pubkey TEXT NOT NULL,
    leaf_id     TEXT NOT NULL,
    revoked_at  INTEGER NOT NULL,
    source      TEXT NOT NULL,
    PRIMARY KEY (root_pubkey, leaf_id)
);
"""

# 旧库迁移占位：升级前无法归属单一签发根的撤销条目保留为通配根域，
# 命中任一根的裁决仍视为已撤销（fail-closed，宁可误拒不可放行）。
# 真实根公钥是 32 字节 Ed25519 公钥的 base64，不会与该哨兵冲突。
LEGACY_GLOBAL_ROOT = "*"


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
            for stmt in (s.strip() for s in SCHEMA.split(";") if s.strip()):
                conn.execute(stmt)
            self._migrate_root_scoping(conn)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _migrate_root_scoping(conn: sqlite3.Connection) -> None:
        """旧库迁移：撤销名册 / 一次性消耗从仅按 leaf_id 升级为按
        (root_pubkey, leaf_id) 定位。

        - consumed_leaves 的既有行经 decisions.request_digest 找回签发根，平移保留；
        - revoked_leaves 的既有行无法归属单一签发根，保留为通配根域
          （LEGACY_GLOBAL_ROOT），对任一根的裁决依旧生效（fail-closed）。
        """
        consumed_cols = {
            r["name"] for r in conn.execute("PRAGMA table_info(consumed_leaves)")
        }
        if consumed_cols and "root_pubkey" not in consumed_cols:
            conn.execute("ALTER TABLE consumed_leaves RENAME TO consumed_leaves_legacy")
            conn.execute(
                "CREATE TABLE consumed_leaves ("
                " root_pubkey TEXT NOT NULL, leaf_id TEXT NOT NULL,"
                " request_digest TEXT NOT NULL, consumed_at INTEGER NOT NULL,"
                " PRIMARY KEY (root_pubkey, leaf_id))"
            )
            conn.execute(
                "INSERT OR IGNORE INTO consumed_leaves "
                "SELECT d.root_pubkey, c.leaf_id, c.request_digest, c.consumed_at "
                "FROM consumed_leaves_legacy c "
                "JOIN decisions d ON d.request_digest = c.request_digest"
            )
            conn.execute("DROP TABLE consumed_leaves_legacy")

        revoked_cols = {
            r["name"] for r in conn.execute("PRAGMA table_info(revoked_leaves)")
        }
        if revoked_cols and "root_pubkey" not in revoked_cols:
            conn.execute("ALTER TABLE revoked_leaves RENAME TO revoked_leaves_legacy")
            conn.execute(
                "CREATE TABLE revoked_leaves ("
                " root_pubkey TEXT NOT NULL, leaf_id TEXT NOT NULL,"
                " revoked_at INTEGER NOT NULL, source TEXT NOT NULL,"
                " PRIMARY KEY (root_pubkey, leaf_id))"
            )
            conn.execute(
                "INSERT OR IGNORE INTO revoked_leaves "
                "SELECT ?, leaf_id, revoked_at, source FROM revoked_leaves_legacy",
                (LEGACY_GLOBAL_ROOT,),
            )
            conn.execute("DROP TABLE revoked_leaves_legacy")

    # ------------------------------------------------------------------ #
    def revoked_set(self, root_pubkey: str | None = None) -> set[str]:
        """站内已入册的撤销叶项标识。

        指定 root_pubkey 时只返回该签发根域内（含历史通配条目）的撤销；
        不传则返回全部名册（台账断言等用途）。
        """
        if root_pubkey is None:
            rows = self._conn().execute("SELECT leaf_id FROM revoked_leaves").fetchall()
        else:
            rows = self._conn().execute(
                "SELECT leaf_id FROM revoked_leaves WHERE root_pubkey IN (?, ?)",
                (root_pubkey, LEGACY_GLOBAL_ROOT),
            ).fetchall()
        return {r["leaf_id"] for r in rows}

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
            # 本包携带的新撤销目标先原子入册（按签发根生效）；即使本
            # request_digest 已有裁决（例如撤销声明重传到达），名册也必须
            # 补齐，杜绝绕过。
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
                "SELECT 1 FROM revoked_leaves "
                "WHERE leaf_id = ? AND root_pubkey IN (?, ?)",
                (leaf_id, root_pubkey, LEGACY_GLOBAL_ROOT),
            ).fetchone()
            if revoked_row is not None:
                decision = self._insert_rejected(
                    conn, digest, chain_mod.REASON_REVOKED,
                    root_pubkey, chain_digest, leaf_id, payload_json, now,
                )
                conn.execute("COMMIT")
                return decision

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

    def execution_count(self, leaf_id: str | None = None) -> int:
        conn = self._conn()
        if leaf_id is None:
            return conn.execute(
                "SELECT COUNT(*) AS c FROM decisions WHERE status='EXECUTED'"
            ).fetchone()["c"]
        return conn.execute(
            "SELECT COUNT(*) AS c FROM decisions WHERE status='EXECUTED' AND leaf_id=?",
            (leaf_id,),
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
