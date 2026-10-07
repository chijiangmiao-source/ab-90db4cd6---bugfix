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
    assert leaf_id in store.revoked_set()

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
    # 撤销名册最终必然包含该叶项
    assert leaf_id in store.revoked_set()
    # 设备最多执行一次：若执行先于撤销到达，撤销方只会拿到同一历史回执（幂等），
    # 不可能产生第二次执行；若撤销先到，执行必被 REVOKED 拒绝。
    executed = [o for o in outcomes if o.status == "EXECUTED"]
    if executed:
        assert len({o.request_digest for o in executed}) == 1
    assert store.execution_count() == (1 if executed else 0)
