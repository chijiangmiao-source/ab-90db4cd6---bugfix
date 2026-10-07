"""HTTP/API 测试：真实接口上的有效执行、并发重传、篡改拒绝、重启复核、健康检查。"""
import concurrent.futures
import json

import httpx
import pytest

from app import chain as C
from app import testkit
from app.canonical import canonicalize
from app.cryptohelp import sign_payload
from conftest import FAR_FUTURE


def _envelope(keys, levels, *, packet_mut=None, payload=None, revoked=False):
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    if revoked:
        leaf_id = C.item_id_of(chain[-1]["header"])
        crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
        packet = testkit.make_packet(keys["root"], chain, revocations=[crl])
    else:
        packet = testkit.make_packet(keys["root"], chain)
    if packet_mut:
        packet_mut(packet, chain)
    payload = payload or {"device": "dev-a", "command": "status", "nonce": "api-1"}
    sig = sign_payload(keys["leaf"], payload)
    return {
        "packet_text": canonicalize(packet),
        "request_text": canonicalize({"payload": payload, "payload_signature": sig}),
        "_payload": payload,
        "_leaf_id": C.item_id_of(chain[-1]["header"]),
    }


def test_healthz(server):
    r = httpx.get(server.base_url + "/healthz", timeout=5)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_index_served(server):
    r = httpx.get(server.base_url + "/", timeout=5)
    assert r.status_code == 200
    assert "委托链" in r.text


def test_drill_bundle(server):
    j = httpx.get(server.base_url + "/api/drill", timeout=5).json()
    assert "packet_text" in j["valid"] and "request_text" in j["valid"]
    # 演练包是合法 JSON
    json.loads(j["valid"]["packet_text"])
    json.loads(j["valid"]["request_text"])


def test_inspect_accepts_valid_and_persists_nothing(server, keys, levels):
    body = _envelope(keys, levels)
    r = httpx.post(server.base_url + "/api/inspect", json=body, timeout=10)
    j = r.json()
    assert j["accepted"] is True
    assert j["evaluation"]["first_reason"] is None
    assert len(j["evaluation"]["items"]) == 2
    dec = httpx.get(server.base_url + "/api/decisions", timeout=5).json()
    assert dec["decisions"] == []  # 核验不落盘


def test_execute_valid_and_stable_receipt(server, keys, levels):
    body = _envelope(keys, levels)
    r1 = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert r1["accepted"] is True
    assert r1["receipt"]["status"] == "EXECUTED"
    assert r1["duplicate"] is False
    cmd_id = r1["receipt"]["command_id"]
    digest = r1["receipt"]["request_digest"]

    # 重传：同一回执，duplicate=True
    r2 = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert r2["receipt"] == r1["receipt"]
    assert r2["duplicate"] is True

    # 回执查询接口逐字一致
    r3 = httpx.get(server.base_url + f"/api/receipt/{digest}", timeout=5).json()
    assert r3["receipt"] == r1["receipt"]
    assert r3["receipt"]["command_id"] == cmd_id


def test_concurrent_submissions_converge(server, keys, levels):
    body = _envelope(keys, levels)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(
            lambda _: httpx.post(server.base_url + "/api/execute", json=body, timeout=20),
            range(12),
        ))
    js = [r.json() for r in responses]
    assert all(j["accepted"] for j in js)
    receipts = {json.dumps(j["receipt"], sort_keys=True) for j in js}
    assert len(receipts) == 1
    assert sum(1 for j in js if not j["duplicate"]) == 1
    # 设备执行记录恰好一条
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    executed = [d for d in ledger if d["status"] == "EXECUTED"]
    assert len(executed) == 1


def test_consumed_leaf_rejected_on_second_command(server, keys, levels):
    b1 = _envelope(keys, levels, payload={"device": "dev-a", "command": "status", "nonce": "c1"})
    r1 = httpx.post(server.base_url + "/api/execute", json=b1, timeout=10).json()
    assert r1["accepted"] is True
    b2 = _envelope(keys, levels, payload={"device": "dev-a", "command": "reboot", "nonce": "c2"})
    r2 = httpx.post(server.base_url + "/api/execute", json=b2, timeout=10).json()
    assert r2["accepted"] is False
    assert r2["evaluation"]["first_reason"] == C.REASON_LEAF_CONSUMED
    assert r2["receipt"]["status"] == "REJECTED"
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert [d for d in ledger if d["status"] == "EXECUTED"] and len(
        [d for d in ledger if d["status"] == "EXECUTED"]
    ) == 1


def test_tampered_command_out_of_scope_no_execution(server, keys, levels):
    body = _envelope(
        keys, levels,
        payload={"device": "dev-a", "command": "firmware-update", "nonce": "bad"},
    )
    r = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert r["accepted"] is False
    assert r["evaluation"]["first_reason"] == C.REASON_COMMAND_OUT_OF_SCOPE
    assert r["receipt"]["status"] == "REJECTED"
    assert r["receipt"]["command_id"] is None
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert all(d["status"] == "REJECTED" for d in ledger)


def test_tampered_signature_rejected(server, keys, levels):
    def mut(packet, chain):
        packet["chain"][-1]["header"]["devices"] = ["dev-a", "dev-x"]
    body = _envelope(keys, levels, packet_mut=mut)
    r = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert r["accepted"] is False
    assert r["evaluation"]["first_reason"] == C.REASON_SIGNATURE_INVALID
    assert r["receipt"] is None  # 身份要素不完整（chain_digest 基于畸形链仍可算？见下）


def test_tampered_chain_no_execution_record(server, keys, levels):
    # 改已签字段：签名失效在链级即拒，不应出现任何 EXECUTED
    def mut(packet, chain):
        packet["chain"][0]["header"]["commands"] = ["reboot"]
    body = _envelope(keys, levels, packet_mut=mut)
    r = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert not r["accepted"]
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert not any(d["status"] == "EXECUTED" for d in ledger)


def test_revoked_packet_rejected_and_persists(server, keys, levels):
    body = _envelope(keys, levels, revoked=True)
    r = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert r["accepted"] is False
    assert r["evaluation"]["first_reason"] == C.REASON_REVOKED
    # 剥离撤销声明后重传：仍被全局名册拒绝
    clean = dict(body)
    packet = json.loads(body["packet_text"])
    packet.pop("revocations", None)
    clean["packet_text"] = canonicalize(packet)
    r2 = httpx.post(server.base_url + "/api/execute", json=clean, timeout=10).json()
    assert r2["accepted"] is False
    assert r2["evaluation"]["first_reason"] == C.REASON_REVOKED
    assert r2["evaluation"]["revoked_by_persisted"] is True
    ledger = httpx.get(server.base_url + "/api/decisions?limit=100", timeout=5).json()["decisions"]
    assert not any(d["status"] == "EXECUTED" for d in ledger)


def test_expired_chain_rejected(server, keys, levels):
    chain = testkit.make_chain(keys["root"], levels, 100)
    packet = testkit.make_packet(keys["root"], chain)
    payload = {"device": "dev-a", "command": "status", "nonce": "ex"}
    body = {
        "packet_text": canonicalize(packet),
        "request_text": canonicalize(
            {"payload": payload, "payload_signature": sign_payload(keys["leaf"], payload)}
        ),
    }
    r = httpx.post(server.base_url + "/api/execute", json=body, timeout=10).json()
    assert r["evaluation"]["first_reason"] == C.REASON_EXPIRED


def test_malformed_json_returns_400(server, keys, levels):
    r = httpx.post(
        server.base_url + "/api/execute",
        json={"packet_text": "{not json", "request_text": ""}, timeout=10,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == C.REASON_MALFORMED_JSON


def test_receipt_survives_restart(server_factory, keys, levels):
    srv1 = server_factory()
    body = _envelope(keys, levels, payload={"device": "dev-b", "command": "reboot", "nonce": "rr"})
    r1 = httpx.post(srv1.base_url + "/api/execute", json=body, timeout=10).json()
    digest = r1["receipt"]["request_digest"]
    srv1.stop()

    srv2 = server_factory()  # 同一 db 文件，全新进程
    r2 = httpx.get(srv2.base_url + f"/api/receipt/{digest}", timeout=10).json()
    assert r2["receipt"] == r1["receipt"]
    # 重启后重传收敛
    r3 = httpx.post(srv2.base_url + "/api/execute", json=body, timeout=10).json()
    assert r3["receipt"] == r1["receipt"]
    assert r3["duplicate"] is True
    srv2.stop()
