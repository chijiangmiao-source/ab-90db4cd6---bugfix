"""跨根隔离回归：独立签发根不得共享叶项的撤销或一次性消耗状态。

两个独立根公钥可以分别签发内容完全相同的单级委托 header（同叶主体、
同父摘要锚点、同设备/命令范围、同失效时间），于是两条链 leaf_id 相同，
而签名与签发根不同。撤销名册与一次性消耗登记均按 (root_pubkey, leaf_id)
定位：根 A 的撤销或消耗不得影响根 B 的合法凭据，根 B 的首次请求应能
独立执行；同时一次性约束与撤销名册在各自根域内依然成立。
"""
import sqlite3

import httpx
import pytest

from app import chain as C
from app import testkit
from app.canonical import canonicalize
from app.cryptohelp import public_b64, sign_payload
from app.store import LEGACY_GLOBAL_ROOT, DecisionStore
from conftest import FAR_FUTURE

# 两个彼此独立的签发根 + 共享的叶主体（确定性种子，跨重启稳定）
ROOT_A = testkit.seeded_key("iso-root-a")
ROOT_B = testkit.seeded_key("iso-root-b")
LEAF = testkit.seeded_key("iso-leaf")
ROOT_A_PUB = public_b64(ROOT_A)
ROOT_B_PUB = public_b64(ROOT_B)

DEVICES = ["dev-a", "dev-b"]
COMMANDS = ["reboot", "status"]
NOW = FAR_FUTURE - 10**8


def _twin_chains():
    """两个独立根签发内容相同的单级委托 header → 相同 leaf_id、不同签名。"""
    leaf_pub = public_b64(LEAF)

    def one(root):
        return [testkit.make_item(
            root, leaf_pub, C.ROOT_ANCHOR_DIGEST, DEVICES, COMMANDS, FAR_FUTURE,
        )]

    chain_a, chain_b = one(ROOT_A), one(ROOT_B)
    # 构造前提：叶主体、父摘要、设备/命令范围、失效时间一致 → leaf_id 相同
    assert chain_a[0]["header"] == chain_b[0]["header"]
    assert C.item_id_of(chain_a[0]["header"]) == C.item_id_of(chain_b[0]["header"])
    assert chain_a[0]["signature"] != chain_b[0]["signature"]
    assert ROOT_A_PUB != ROOT_B_PUB
    return chain_a, chain_b


def _evaluate(packet, payload, store=None, root_pub=None):
    return C.evaluate_packet(
        packet, NOW, payload=payload,
        payload_signature=sign_payload(LEAF, payload),
        persisted_revoked=(store.revoked_set(root_pub) if store is not None else set()),
    )


@pytest.fixture
def store(tmp_path):
    return DecisionStore(str(tmp_path / "mdms.db"))


# ------------------------------------------------------------------ #
# 场景一：根 A 已撤销该 leaf_id 后，根 B 的干净链不得被判 REVOKED
# ------------------------------------------------------------------ #
def test_revocation_is_scoped_to_issuing_root(store):
    chain_a, chain_b = _twin_chains()
    leaf_id = C.item_id_of(chain_a[0]["header"])

    # 根 A 对该叶项提交有效撤销并完成裁决（拒绝 + 撤销入册）
    payload_a = {"device": "dev-a", "command": "status", "nonce": "a-rev"}
    packet_a_rev = testkit.make_packet(
        ROOT_A, chain_a,
        revocations=[testkit.make_revocation(ROOT_A, [leaf_id], FAR_FUTURE)],
    )
    ev = _evaluate(packet_a_rev, payload_a, store, ROOT_A_PUB)
    assert ev.first_reason == C.REASON_REVOKED
    d = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload_a,
        execute=False, reason=ev.first_reason,
        new_revoked_targets=set(ev.valid_revoked_targets),
    )
    assert d.status == "REJECTED" and d.reason == C.REASON_REVOKED
    assert leaf_id in store.revoked_set(ROOT_A_PUB)
    assert leaf_id in store.revoked_set()            # 全量名册可见
    assert leaf_id not in store.revoked_set(ROOT_B_PUB)  # 但不属于根 B 根域

    # 根 B 的干净链：同一 leaf_id，核验不得被判 REVOKED
    payload_b = {"device": "dev-b", "command": "reboot", "nonce": "b-first"}
    ev_b = _evaluate(testkit.make_packet(ROOT_B, chain_b), payload_b, store, ROOT_B_PUB)
    assert ev_b.ok, ev_b.first_reason
    # 根 B 的首次请求独立执行成功
    d_b = store.record_decision(
        ev_b.root_pubkey, ev_b.chain_digest, ev_b.leaf_id, payload_b, execute=True,
    )
    assert d_b.status == "EXECUTED"

    # 根 A 自己的干净链（剥离撤销声明重传）仍被名册拒绝：撤销在签发根域内持续生效
    payload_a2 = {"device": "dev-a", "command": "status", "nonce": "a-stripped"}
    ev_a2 = _evaluate(testkit.make_packet(ROOT_A, chain_a), payload_a2, store, ROOT_A_PUB)
    assert ev_a2.first_reason == C.REASON_REVOKED
    assert ev_a2.revoked_by_persisted is True
    # 即便绕过核验层直接请求执行裁决，临界区内的复查同样拒绝
    d_a2 = store.record_decision(
        ev_a2.root_pubkey, ev_a2.chain_digest, ev_a2.leaf_id, payload_a2, execute=True,
    )
    assert d_a2.status == "REJECTED" and d_a2.reason == C.REASON_REVOKED
    assert store.execution_count() == 1  # 只有根 B 的一次执行


# ------------------------------------------------------------------ #
# 场景二：根 A 已完成一次执行后，根 B 不同载荷的首次执行不得被判 LEAF_CONSUMED
# ------------------------------------------------------------------ #
def test_consumption_is_scoped_to_issuing_root(store):
    chain_a, chain_b = _twin_chains()

    # 根 A 的链完成一次执行
    payload_a = {"device": "dev-a", "command": "status", "nonce": "a-exec"}
    ev_a = _evaluate(testkit.make_packet(ROOT_A, chain_a), payload_a)
    assert ev_a.ok
    d_a = store.record_decision(
        ev_a.root_pubkey, ev_a.chain_digest, ev_a.leaf_id, payload_a, execute=True,
    )
    assert d_a.status == "EXECUTED"

    # 根 B：同一 leaf_id、不同请求载荷的首次执行 —— 不得被判 LEAF_CONSUMED
    payload_b = {"device": "dev-b", "command": "reboot", "nonce": "b-first"}
    ev_b = _evaluate(testkit.make_packet(ROOT_B, chain_b), payload_b)
    assert ev_b.ok
    d_b = store.record_decision(
        ev_b.root_pubkey, ev_b.chain_digest, ev_b.leaf_id, payload_b, execute=True,
    )
    assert d_b.status == "EXECUTED"
    assert d_b.command_id and d_b.command_id != d_a.command_id

    # 一次性约束在各自根域内依然成立：同根同叶项的第二次不同载荷请求被拒
    payload_a2 = {"device": "dev-a", "command": "reboot", "nonce": "a-second"}
    ev_a2 = _evaluate(testkit.make_packet(ROOT_A, chain_a), payload_a2)
    d_a2 = store.record_decision(
        ev_a2.root_pubkey, ev_a2.chain_digest, ev_a2.leaf_id, payload_a2, execute=True,
    )
    assert d_a2.status == "REJECTED" and d_a2.reason == C.REASON_LEAF_CONSUMED

    payload_b2 = {"device": "dev-b", "command": "status", "nonce": "b-second"}
    ev_b2 = _evaluate(testkit.make_packet(ROOT_B, chain_b), payload_b2)
    d_b2 = store.record_decision(
        ev_b2.root_pubkey, ev_b2.chain_digest, ev_b2.leaf_id, payload_b2, execute=True,
    )
    assert d_b2.status == "REJECTED" and d_b2.reason == C.REASON_LEAF_CONSUMED

    assert store.execution_count() == 2  # 两个根各执行一次


# ------------------------------------------------------------------ #
# HTTP 边界：与值班员提交路径完全一致的隔离验收
# ------------------------------------------------------------------ #
def _body(chain, root, payload, revocations=None):
    packet = testkit.make_packet(root, chain, revocations=revocations)
    return {
        "packet_text": canonicalize(packet),
        "request_text": canonicalize(
            {"payload": payload, "payload_signature": sign_payload(LEAF, payload)}
        ),
    }


def test_http_cross_root_revocation_isolation(server):
    chain_a, chain_b = _twin_chains()
    leaf_id = C.item_id_of(chain_a[0]["header"])
    url = server.base_url + "/api/execute"

    # 根 A 提交有效撤销并完成裁决
    payload_a = {"device": "dev-a", "command": "status", "nonce": "ha-rev"}
    body_rev = _body(chain_a, ROOT_A, payload_a,
                     revocations=[testkit.make_revocation(ROOT_A, [leaf_id], FAR_FUTURE)])
    r = httpx.post(url, json=body_rev, timeout=10).json()
    assert r["accepted"] is False
    assert r["evaluation"]["first_reason"] == C.REASON_REVOKED

    # 根 B 的干净链：同一 leaf_id 首执行成功，不因根 A 的撤销被判 REVOKED
    payload_b = {"device": "dev-b", "command": "reboot", "nonce": "hb-first"}
    r2 = httpx.post(url, json=_body(chain_b, ROOT_B, payload_b), timeout=10).json()
    assert r2["accepted"] is True, r2["evaluation"]["first_reason"]
    assert r2["receipt"]["status"] == "EXECUTED"
    assert r2["receipt"]["leaf_id"] == leaf_id

    # 根 A 剥离撤销声明重传仍被名册拒绝
    r3 = httpx.post(url, json=_body(
        chain_a, ROOT_A, {"device": "dev-a", "command": "status", "nonce": "ha-strip"},
    ), timeout=10).json()
    assert r3["accepted"] is False
    assert r3["evaluation"]["first_reason"] == C.REASON_REVOKED


def test_http_cross_root_consumption_isolation(server):
    chain_a, chain_b = _twin_chains()
    url = server.base_url + "/api/execute"

    # 根 A 的链完成一次执行
    payload_a = {"device": "dev-a", "command": "status", "nonce": "ha-exec"}
    r1 = httpx.post(url, json=_body(chain_a, ROOT_A, payload_a), timeout=10).json()
    assert r1["accepted"] is True and r1["receipt"]["status"] == "EXECUTED"

    # 根 B 不同请求载荷的首次执行不因根 A 的记录被判 LEAF_CONSUMED
    payload_b = {"device": "dev-b", "command": "reboot", "nonce": "hb-first"}
    r2 = httpx.post(url, json=_body(chain_b, ROOT_B, payload_b), timeout=10).json()
    assert r2["accepted"] is True, r2["evaluation"]["first_reason"]
    assert r2["receipt"]["status"] == "EXECUTED"

    # 根 A 的第二份不同载荷请求仍被一次性约束拒绝
    r3 = httpx.post(url, json=_body(
        chain_a, ROOT_A, {"device": "dev-a", "command": "reboot", "nonce": "ha-second"},
    ), timeout=10).json()
    assert r3["accepted"] is False
    assert r3["evaluation"]["first_reason"] == C.REASON_LEAF_CONSUMED


# ------------------------------------------------------------------ #
# 旧库迁移：仅按 leaf_id 的历史表升级为按 (root_pubkey, leaf_id) 定位
# ------------------------------------------------------------------ #
def test_legacy_db_migrates_to_root_scoped(tmp_path):
    db = str(tmp_path / "mdms.db")
    chain_a, _ = _twin_chains()
    leaf_id = C.item_id_of(chain_a[0]["header"])

    # 先以新库产生一条执行 + 一条撤销，再把两张表改回旧结构模拟历史库
    s = DecisionStore(db)
    payload = {"device": "dev-a", "command": "status", "nonce": "legacy"}
    ev = _evaluate(testkit.make_packet(ROOT_A, chain_a), payload)
    d = s.record_decision(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload,
                          execute=True, new_revoked_targets={"f" * 64})
    assert d.status == "EXECUTED"
    s.close()

    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE consumed_leaves RENAME TO consumed_leaves_new")
    conn.execute(
        "CREATE TABLE consumed_leaves ("
        " leaf_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL,"
        " consumed_at INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO consumed_leaves SELECT leaf_id, request_digest, consumed_at "
        "FROM consumed_leaves_new"
    )
    conn.execute("DROP TABLE consumed_leaves_new")
    conn.execute("ALTER TABLE revoked_leaves RENAME TO revoked_leaves_new")
    conn.execute(
        "CREATE TABLE revoked_leaves ("
        " leaf_id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL, source TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO revoked_leaves SELECT leaf_id, revoked_at, source "
        "FROM revoked_leaves_new"
    )
    conn.execute("DROP TABLE revoked_leaves_new")
    conn.commit()
    conn.close()

    # 重新打开：结构升级，历史行不丢失
    s2 = DecisionStore(db)
    cols = {r[1] for r in s2._conn().execute("PRAGMA table_info(revoked_leaves)")}
    assert "root_pubkey" in cols
    # 历史消耗行经 decisions 找回签发根：同根同叶项仍不得二次执行
    payload2 = {"device": "dev-a", "command": "reboot", "nonce": "legacy-2"}
    ev2 = _evaluate(testkit.make_packet(ROOT_A, chain_a), payload2)
    d2 = s2.record_decision(ev2.root_pubkey, ev2.chain_digest, ev2.leaf_id, payload2,
                            execute=True)
    assert d2.status == "REJECTED" and d2.reason == C.REASON_LEAF_CONSUMED
    # 无法归属单一根的历史撤销条目保留为通配根域（fail-closed）
    assert "f" * 64 in s2.revoked_set(ROOT_A_PUB)
    assert "f" * 64 in s2.revoked_set(ROOT_B_PUB)
    conn = s2._conn()
    row = conn.execute(
        "SELECT root_pubkey FROM revoked_leaves WHERE leaf_id = ?", ("f" * 64,)
    ).fetchone()
    assert row[0] == LEGACY_GLOBAL_ROOT
