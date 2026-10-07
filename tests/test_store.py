"""持久化裁决层测试：幂等、并发收敛、重启复核、一次性凭据、拒绝不落执行记录。"""
import json
import threading
from pathlib import Path

import pytest

from app import chain as C
from app import testkit
from app.cryptohelp import sign_payload
from app.store import DecisionStore
from conftest import FAR_FUTURE


@pytest.fixture
def store_factory(tmp_path):
    def _make():
        return DecisionStore(str(tmp_path / "mdms.db"))
    return _make


@pytest.fixture
def scenario(keys, levels, valid_payload):
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8,
        payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
    )
    assert ev.ok
    return ev, valid_payload


def test_successful_execution_persisted(store_factory, scenario):
    store = store_factory()
    ev, payload = scenario
    d = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload, execute=True
    )
    assert d.status == "EXECUTED"
    assert d.command_id and d.command_id.startswith("cmd-")
    assert store.execution_count() == 1
    again = store.get(d.request_digest)
    assert again.status == "EXECUTED"
    assert again.command_id == d.command_id


def test_retry_returns_same_receipt_and_single_execution(store_factory, scenario):
    store = store_factory()
    ev, payload = scenario
    d1 = store.record_decision(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload, execute=True)
    d2 = store.record_decision(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload, execute=True)
    assert d1.receipt() == d2.receipt()
    assert d2.duplicate is True
    assert store.execution_count() == 1


def test_concurrent_same_request_converges_to_one(store_factory, scenario):
    store = store_factory()
    ev, payload = scenario
    results: list = []
    errors: list = []

    def worker():
        try:
            results.append(
                store.record_decision(
                    ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload, execute=True
                )
            )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(results) == 16
    receipts = {json.dumps(r.receipt(), sort_keys=True) for r in results}
    assert len(receipts) == 1            # 同一回执
    assert store.execution_count() == 1  # 恰好一次执行
    assert sum(1 for r in results if not r.duplicate) == 1


def test_reopen_db_receipt_verifiable(store_factory, scenario, tmp_path):
    db = str(tmp_path / "mdms.db")
    s1 = DecisionStore(db)
    ev, payload = scenario
    d1 = s1.record_decision(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload, execute=True)
    s1.close()

    s2 = DecisionStore(db)  # 模拟重启
    d2 = s2.get(d1.request_digest)
    assert d2 is not None
    assert d2.receipt() == d1.receipt()
    assert s2.execution_count() == 1
    # 重启后重传仍是同一回执，不会二次执行
    d3 = s2.record_decision(ev.root_pubkey, ev.chain_digest, ev.leaf_id, payload, execute=True)
    assert d3.receipt() == d1.receipt()
    assert d3.duplicate is True
    assert s2.execution_count() == 1


def test_consumed_leaf_cannot_drive_again(store_factory, keys, levels, valid_payload):
    store = store_factory()
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)

    p1 = {**valid_payload, "nonce": "first"}
    ev1 = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=p1,
        payload_signature=sign_payload(keys["leaf"], p1),
    )
    d1 = store.record_decision(ev1.root_pubkey, ev1.chain_digest, ev1.leaf_id, p1, execute=True)
    assert d1.status == "EXECUTED"

    p2 = {**valid_payload, "nonce": "second"}
    ev2 = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=p2,
        payload_signature=sign_payload(keys["leaf"], p2),
    )
    d2 = store.record_decision(ev2.root_pubkey, ev2.chain_digest, ev2.leaf_id, p2, execute=True)
    assert d2.status == "REJECTED"
    assert d2.reason == C.REASON_LEAF_CONSUMED
    assert d2.command_id is None
    assert store.execution_count(ev2.leaf_id) == 1
    assert store.execution_count() == 1


def test_rejected_records_are_never_executions(store_factory, keys, levels):
    store = store_factory()
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    leaf_id = C.item_id_of(chain[-1]["header"])

    # 越权命令
    bad = {"device": "dev-a", "command": "diagnose", "nonce": "z"}
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=bad,
        payload_signature=sign_payload(keys["leaf"], bad),
    )
    assert not ev.ok
    d = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, bad,
        execute=False, reason=ev.first_reason,
    )
    assert d.status == "REJECTED"
    assert d.reason == C.REASON_COMMAND_OUT_OF_SCOPE
    assert store.execution_count() == 0
    assert store.get(d.request_digest).status == "REJECTED"
    # 同一被拒请求重传 → 同一拒绝回执
    d2 = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, bad,
        execute=False, reason=ev.first_reason,
    )
    assert d2.duplicate is True
    assert d2.receipt() == d.receipt()
    assert store.execution_count() == 0


def test_revocation_registered_blocks_stripped_replay(store_factory, keys, levels, valid_payload):
    store = store_factory()
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    leaf_id = C.item_id_of(chain[-1]["header"])
    revocation = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_rev = testkit.make_packet(keys["root"], chain, revocations=[revocation])

    ev = C.evaluate_packet(
        packet_rev, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
    )
    assert ev.first_reason == C.REASON_REVOKED
    # 撤销随拒绝裁决原子入册
    d = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, valid_payload,
        execute=False, reason=ev.first_reason,
        new_revoked_targets=set(ev.valid_revoked_targets),
    )
    assert d.status == "REJECTED"
    assert store.execution_count() == 0
    assert (ev.root_pubkey, leaf_id) in store.revoked_set()

    # 攻击者剥离撤销声明重传：持久化名册仍然拒绝
    packet_clean = testkit.make_packet(keys["root"], chain)
    ev2 = C.evaluate_packet(
        packet_clean, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
        persisted_revoked=store.revoked_set(),
    )
    assert ev2.first_reason == C.REASON_REVOKED
    d2 = store.record_decision(
        ev2.root_pubkey, ev2.chain_digest, ev2.leaf_id, valid_payload, execute=True,
    )
    assert d2.status == "REJECTED"
    assert d2.reason == C.REASON_REVOKED
    assert store.execution_count() == 0


def test_revocation_vs_execution_race(store_factory, keys, levels, valid_payload):
    """并发：一个携带撤销，一个正常执行——任意顺序下设备最多执行一次且撤销最终生效。"""
    store = store_factory()
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    leaf_id = C.item_id_of(chain[-1]["header"])
    revocation = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_rev = testkit.make_packet(keys["root"], chain, revocations=[revocation])
    packet_clean = testkit.make_packet(keys["root"], chain)

    outcomes: list = []

    def run_revoked():
        ev = C.evaluate_packet(
            packet_rev, FAR_FUTURE - 10**8, payload=valid_payload,
            payload_signature=sign_payload(keys["leaf"], valid_payload),
            persisted_revoked=store.revoked_set(),
        )
        outcomes.append(store.record_decision(
            ev.root_pubkey, ev.chain_digest, ev.leaf_id, valid_payload,
            execute=False, reason=ev.first_reason,
            new_revoked_targets=set(ev.valid_revoked_targets),
        ))

    def run_execute():
        ev = C.evaluate_packet(
            packet_clean, FAR_FUTURE - 10**8, payload=valid_payload,
            payload_signature=sign_payload(keys["leaf"], valid_payload),
            persisted_revoked=store.revoked_set(),
        )
        if ev.ok:
            outcomes.append(store.record_decision(
                ev.root_pubkey, ev.chain_digest, ev.leaf_id, valid_payload, execute=True,
            ))

    t1 = threading.Thread(target=run_revoked)
    t2 = threading.Thread(target=run_execute)
    t1.start(); t2.start(); t1.join(); t2.join()

    assert store.execution_count() <= 1
    # 撤销名册最终必然包含该叶项（本根命名空间内）
    assert (packet_rev["root_pubkey"], leaf_id) in store.revoked_set()
    # 设备最多执行一次：若执行先于撤销到达，撤销方只会拿到同一历史回执（幂等），
    # 不可能产生第二次执行；若撤销先到，执行必被 REVOKED 拒绝。
    executed = [o for o in outcomes if o.status == "EXECUTED"]
    if executed:
        assert len({o.request_digest for o in executed}) == 1
    assert store.execution_count() == (1 if executed else 0)


# ---------------------------------------------------------------------------
# 回归：独立签发根之间，撤销 / 一次性消耗状态必须按 (root_pubkey, leaf_id) 隔离
# ---------------------------------------------------------------------------

def _two_root_chains_same_leaf(keys, levels):
    """两个独立根各自签发内容相同的单级（两级链）委托：header 全同 → leaf_id 相同。

    根项由不同根私钥签名（签名不同），叶主体、父摘要、范围、失效时间一致，
    于是两条链 leaf_id 相同、chain_digest 不同、签发根不同。
    """
    chain_a = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    chain_b = testkit.make_chain(keys["other"], levels, FAR_FUTURE)
    leaf_a = C.item_id_of(chain_a[-1]["header"])
    leaf_b = C.item_id_of(chain_b[-1]["header"])
    assert leaf_a == leaf_b  # 前置条件：叶项 header 逐字一致
    assert C.chain_digest_of(chain_a) != C.chain_digest_of(chain_b)
    return chain_a, chain_b, leaf_a


def test_revocation_by_root_a_does_not_revoke_root_b(store_factory, keys, levels, valid_payload):
    """根 A 已撤销该 leaf_id 后，根 B 的干净合法链不得被判 REVOKED。"""
    store = store_factory()
    now = FAR_FUTURE - 10**8
    chain_a, chain_b, leaf_id = _two_root_chains_same_leaf(keys, levels)
    packet_a = testkit.make_packet(keys["root"], chain_a)
    packet_b = testkit.make_packet(keys["other"], chain_b)

    # 根 A 对该叶项提交有效撤销并完成裁决（撤销原子入册）
    crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_a_rev = testkit.make_packet(keys["root"], chain_a, revocations=[crl])
    ev_rev = C.evaluate_packet(
        packet_a_rev, now, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
        persisted_revoked=store.revoked_set(),
    )
    assert ev_rev.first_reason == C.REASON_REVOKED
    d_rev = store.record_decision(
        ev_rev.root_pubkey, ev_rev.chain_digest, ev_rev.leaf_id, valid_payload,
        execute=False, reason=ev_rev.first_reason,
        new_revoked_targets=set(ev_rev.valid_revoked_targets),
    )
    assert d_rev.status == "REJECTED"
    assert (packet_a["root_pubkey"], leaf_id) in store.revoked_set()

    # 根 B 的干净合法链：不命中根 A 名下的撤销，正常裁决并执行
    ev_b = C.evaluate_packet(
        packet_b, now, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
        persisted_revoked=store.revoked_set(),
    )
    assert ev_b.ok is True
    assert ev_b.first_reason is None
    d_b = store.record_decision(
        ev_b.root_pubkey, ev_b.chain_digest, ev_b.leaf_id, valid_payload, execute=True,
    )
    assert d_b.status == "EXECUTED"
    # 根 A 名下仍无执行记录；根 B 名下恰有一条
    assert store.execution_count(leaf_id, packet_a["root_pubkey"]) == 0
    assert store.execution_count(leaf_id, packet_b["root_pubkey"]) == 1
    assert store.execution_count() == 1


def test_consumption_by_root_a_does_not_consume_root_b(store_factory, keys, levels):
    """根 A 链执行一次后，根 B 以不同请求载荷的首次执行不得被判 LEAF_CONSUMED。"""
    store = store_factory()
    now = FAR_FUTURE - 10**8
    chain_a, chain_b, leaf_id = _two_root_chains_same_leaf(keys, levels)
    packet_a = testkit.make_packet(keys["root"], chain_a)
    packet_b = testkit.make_packet(keys["other"], chain_b)

    payload_a = {"device": "dev-a", "command": "status", "nonce": "root-a-once"}
    payload_b = {"device": "dev-b", "command": "reboot", "nonce": "root-b-once"}

    ev_a = C.evaluate_packet(
        packet_a, now, payload=payload_a,
        payload_signature=sign_payload(keys["leaf"], payload_a),
        persisted_revoked=store.revoked_set(),
    )
    d_a = store.record_decision(
        ev_a.root_pubkey, ev_a.chain_digest, ev_a.leaf_id, payload_a, execute=True,
    )
    assert d_a.status == "EXECUTED"

    # 根 B 的首次执行（不同请求载荷）必须独立放行
    ev_b = C.evaluate_packet(
        packet_b, now, payload=payload_b,
        payload_signature=sign_payload(keys["leaf"], payload_b),
        persisted_revoked=store.revoked_set(),
    )
    assert ev_b.ok is True
    d_b = store.record_decision(
        ev_b.root_pubkey, ev_b.chain_digest, ev_b.leaf_id, payload_b, execute=True,
    )
    assert d_b.status == "EXECUTED"
    assert d_b.reason is None
    assert store.execution_count(leaf_id) == 2
    assert store.execution_count(leaf_id, packet_a["root_pubkey"]) == 1
    assert store.execution_count(leaf_id, packet_b["root_pubkey"]) == 1

    # 隔离不等于放开一次性约束：根 A 再换载荷仍被 LEAF_CONSUMED 拒绝
    payload_a2 = {"device": "dev-a", "command": "reboot", "nonce": "root-a-again"}
    ev_a2 = C.evaluate_packet(
        packet_a, now, payload=payload_a2,
        payload_signature=sign_payload(keys["leaf"], payload_a2),
        persisted_revoked=store.revoked_set(),
    )
    assert ev_a2.ok is True
    d_a2 = store.record_decision(
        ev_a2.root_pubkey, ev_a2.chain_digest, ev_a2.leaf_id, payload_a2, execute=True,
    )
    assert d_a2.status == "REJECTED"
    assert d_a2.reason == C.REASON_LEAF_CONSUMED
    assert store.execution_count(leaf_id) == 2


def test_legacy_leaf_id_only_schema_migrates_scoped(tmp_path, keys):
    """旧版仅以 leaf_id 建主键的名册在重启打开时升级为按根隔离，并从台账回溯签发根。"""
    import sqlite3

    from app.canonical import canonical_bytes

    db = str(tmp_path / "legacy.db")
    root_a = testkit.public_b64(keys["root"])
    root_b = testkit.public_b64(keys["other"])
    leaf_consumed = "a" * 64
    leaf_revoked = "b" * 64
    now = FAR_FUTURE - 10**8
    payload = {"device": "dev-a", "command": "status", "nonce": "legacy"}
    digest_exec = C.request_digest(root_a, "c" * 64, leaf_consumed, payload)
    digest_rej = C.request_digest(root_a, "d" * 64, leaf_revoked, payload)
    payload_json = canonical_bytes(payload).decode()

    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE decisions (
            request_digest TEXT PRIMARY KEY, status TEXT NOT NULL, reason TEXT,
            command_id TEXT, output TEXT, root_pubkey TEXT NOT NULL,
            chain_digest TEXT NOT NULL, leaf_id TEXT NOT NULL, payload_json TEXT NOT NULL,
            created_at INTEGER NOT NULL, executed_at INTEGER
        );
        CREATE TABLE consumed_leaves (
            leaf_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, consumed_at INTEGER NOT NULL
        );
        CREATE TABLE revoked_leaves (
            leaf_id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL, source TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (digest_exec, "EXECUTED", None, "cmd-x", "out", root_a,
         "c" * 64, leaf_consumed, payload_json, now, now),
    )
    conn.execute(
        "INSERT INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (digest_rej, "REJECTED", "REVOKED", None, None, root_a,
         "d" * 64, leaf_revoked, payload_json, now, None),
    )
    conn.execute("INSERT INTO consumed_leaves VALUES (?,?,?)",
                 (leaf_consumed, digest_exec, now))
    conn.execute("INSERT INTO revoked_leaves VALUES (?,?,?)",
                 (leaf_revoked, now, "packet"))
    conn.commit()
    conn.close()

    store = DecisionStore(db)
    # 旧记录按台账中的签发根归属，不凭空波及其他根
    assert store.revoked_set() == {(root_a, leaf_revoked)}
    row = store._conn().execute(
        "SELECT request_digest FROM consumed_leaves WHERE root_pubkey=? AND leaf_id=?",
        (root_a, leaf_consumed),
    ).fetchone()
    assert row is not None and row["request_digest"] == digest_exec
    assert store._conn().execute(
        "SELECT 1 FROM consumed_leaves WHERE root_pubkey=? AND leaf_id=?",
        (root_b, leaf_consumed),
    ).fetchone() is None
    store.close()
