#!/usr/bin/env python3
"""verify 容器入口：单元/集成测试 + 对运行中的 app 服务做 API/HTTP 验收。

场景（全部基于真实 HTTP 接口）：
  1. 有效执行：加载/构造合法委托链 → EXECUTED，回执可按 request_digest 复核；
  2. 并发重传：同叶项同载荷并发 12 次 → 恰好一次执行、回执逐字相同；
  3. 篡改拒绝：改已签字段 / 越权命令 / 过期 / 撤销 / 剥离撤销重放 / 二次使用；
  4. 根隔离：两个独立根签发同 leaf_id 链时，撤销 / 一次性消耗按 (根, leaf_id) 隔离；
  5. 冒烟：healthz、静态页面、内置演练包、畸形 JSON 400。

先运行 pytest 全量测试，再做在线 HTTP 场景；任一步失败即以非零状态码退出。
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

# 容器内为 /srv；容器外（本地直接运行）回退到仓库根目录
SRV_DIR = Path("/srv") if Path("/srv/app").is_dir() else Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SRV_DIR))

from app import chain as C  # noqa: E402
from app import testkit  # noqa: E402
from app.canonical import canonicalize  # noqa: E402
from app.cryptohelp import sign_payload  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://app:8000")
TIMEOUT = 15
FAR_FUTURE = 4070908800

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def wait_for_app() -> bool:
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            r = httpx.get(BASE_URL + "/healthz", timeout=3)
            if r.status_code == 200 and r.json().get("status") == "ok":
                print(f"[INFO] app 已就绪：{r.json()}")
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    return False


def fresh_keys_and_levels():
    keys = {
        "root": testkit.generate_private_key(),
        "org": testkit.generate_private_key(),
        "leaf": testkit.generate_private_key(),
    }
    levels = [
        (keys["org"], ["dev-a", "dev-b", "dev-c"], ["reboot", "status", "diagnose"]),
        (keys["leaf"], ["dev-a", "dev-b"], ["reboot", "status"]),
    ]
    return keys, levels


def envelope(keys, levels, payload, *, chain_kw=None, packet_mut=None):
    chain_kw = chain_kw or {}
    chain = testkit.make_chain(keys["root"], levels, chain_kw.get("expires_at", FAR_FUTURE))
    packet = testkit.make_packet(keys["root"], chain)
    if packet_mut:
        packet_mut(packet, chain, keys)
    return {
        "packet_text": canonicalize(packet),
        "request_text": canonicalize(
            {"payload": payload, "payload_signature": sign_payload(keys["leaf"], payload)}
        ),
    }


def post_execute(body: dict) -> tuple[int, dict]:
    r = httpx.post(BASE_URL + "/api/execute", json=body, timeout=30)
    try:
        return r.status_code, r.json()
    except Exception:  # noqa: BLE001
        return r.status_code, {}


def executed_leaf_ids() -> set[str]:
    j = httpx.get(BASE_URL + "/api/decisions?limit=200", timeout=TIMEOUT).json()
    return {d["leaf_id"] for d in j["decisions"] if d["status"] == "EXECUTED"}


def scenario_valid_execution_and_retry() -> None:
    print("\n=== 场景 1：有效执行 + 稳定回执 ===")
    keys, levels = fresh_keys_and_levels()
    payload = {"device": "dev-a", "command": "status", "nonce": os.urandom(8).hex()}
    body = envelope(keys, levels, payload)

    code, j = post_execute(body)
    check("有效执行 HTTP 200", code == 200, f"code={code}")
    check("裁决接受", j.get("accepted") is True, str(j.get("evaluation", {}).get("first_reason")))
    receipt = j.get("receipt") or {}
    check("回执状态 EXECUTED", receipt.get("status") == "EXECUTED", str(receipt.get("reason")))
    check("回执含 command_id", bool(receipt.get("command_id")))
    digest = receipt.get("request_digest")

    got = httpx.get(BASE_URL + f"/api/receipt/{digest}", timeout=TIMEOUT).json()["receipt"]
    check("按 request_digest 复核回执逐字一致", got == receipt)

    code2, j2 = post_execute(body)
    check("重传得到同一回执", j2.get("receipt") == receipt)
    check("重传标记 duplicate", j2.get("duplicate") is True)


def scenario_concurrent_retransmit() -> None:
    print("\n=== 场景 2：相同叶项并发提交收敛为一次执行 ===")
    keys, levels = fresh_keys_and_levels()
    payload = {"device": "dev-b", "command": "reboot", "nonce": os.urandom(8).hex()}
    body = envelope(keys, levels, payload)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(lambda _: post_execute(body), range(12)))

    codes = {c for c, _ in responses}
    jsons = [j for _, j in responses]
    check("并发请求全部 200", codes == {200}, str(codes))
    receipts = {json.dumps(j.get("receipt"), sort_keys=True) for j in jsons}
    check("12 个并发响应回执完全相同", len(receipts) == 1)
    firsts = [j for j in jsons if j.get("duplicate") is False]
    check("恰好一次首执行", len(firsts) == 1, f"firsts={len(firsts)}")

    leaf_id = jsons[0]["receipt"]["leaf_id"]
    ledger = httpx.get(BASE_URL + "/api/decisions?limit=200", timeout=TIMEOUT).json()["decisions"]
    n_exec = [d for d in ledger if d["status"] == "EXECUTED" and d["leaf_id"] == leaf_id]
    check("该叶项执行记录恰好一条", len(n_exec) == 1, f"n={len(n_exec)}")

    # 同叶项不同命令 → 一次性凭据拒绝
    payload2 = {"device": "dev-a", "command": "status", "nonce": os.urandom(8).hex()}
    body2 = envelope(keys, levels, payload2)
    _, j2 = post_execute(body2)
    check("已使用末级凭据拒绝二次驱动",
          j2.get("accepted") is False and j2["evaluation"]["first_reason"] == C.REASON_LEAF_CONSUMED,
          str(j2.get("evaluation", {}).get("first_reason")))


def scenario_tamper_rejections() -> None:
    print("\n=== 场景 3：篡改 / 越权 / 过期 / 撤销拒绝 ===")
    # 3.1 改动已签字段
    keys, levels = fresh_keys_and_levels()
    payload = {"device": "dev-a", "command": "status", "nonce": os.urandom(8).hex()}

    def tamper_signed(packet, chain, ks):
        packet["chain"][-1]["header"]["devices"].append("dev-z")

    _, j = post_execute(envelope(keys, levels, payload, packet_mut=tamper_signed))
    check("改动已签字段 → SIGNATURE_INVALID",
          j.get("evaluation", {}).get("first_reason") == C.REASON_SIGNATURE_INVALID,
          str(j.get("evaluation", {}).get("first_reason")))

    # 3.2 越权命令（叶项命令集合已收窄，不含 diagnose）
    keys, levels = fresh_keys_and_levels()
    bad_payload = {"device": "dev-a", "command": "diagnose", "nonce": os.urandom(8).hex()}
    _, j = post_execute(envelope(keys, levels, bad_payload))
    check("越权命令 → COMMAND_OUT_OF_SCOPE 且 REJECTED",
          j.get("evaluation", {}).get("first_reason") == C.REASON_COMMAND_OUT_OF_SCOPE
          and (j.get("receipt") or {}).get("status") == "REJECTED"
          and (j.get("receipt") or {}).get("command_id") is None)

    # 3.3 过期链
    keys, levels = fresh_keys_and_levels()
    _, j = post_execute(envelope(
        keys, levels, payload, chain_kw={"expires_at": 100}))
    check("过期委托 → EXPIRED",
          j.get("evaluation", {}).get("first_reason") == C.REASON_EXPIRED)

    # 3.4 有效撤销声明 + 剥离撤销重放
    keys, levels = fresh_keys_and_levels()
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    leaf_id = C.item_id_of(chain[-1]["header"])
    crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_rev = testkit.make_packet(keys["root"], chain, revocations=[crl])
    body_rev = {
        "packet_text": canonicalize(packet_rev),
        "request_text": canonicalize(
            {"payload": payload, "payload_signature": sign_payload(keys["leaf"], payload)}
        ),
    }
    _, j = post_execute(body_rev)
    check("携带有效撤销声明 → REVOKED",
          j.get("evaluation", {}).get("first_reason") == C.REASON_REVOKED)
    packet_rev.pop("revocations")
    body_stripped = {**body_rev, "packet_text": canonicalize(packet_rev)}
    _, j2 = post_execute(body_stripped)
    check("剥离撤销声明重放仍 → REVOKED（全局持久名册）",
          j2.get("evaluation", {}).get("first_reason") == C.REASON_REVOKED
          and j2.get("evaluation", {}).get("revoked_by_persisted") is True)
    check("被拒叶项无任何执行记录", leaf_id not in executed_leaf_ids())

    # 3.5 畸形 JSON
    r = httpx.post(BASE_URL + "/api/execute",
                   json={"packet_text": "{oops", "request_text": ""}, timeout=TIMEOUT)
    check("畸形 JSON → 400 + MALFORMED_JSON",
          r.status_code == 400 and r.json().get("detail", {}).get("code") == C.REASON_MALFORMED_JSON)


def scenario_root_isolation() -> None:
    """两个独立签发根、同一叶主体与相同范围/失效时间：撤销与一次性状态按根隔离。"""
    print("\n=== 场景 4：独立签发根不共享撤销 / 一次性消耗状态 ===")
    keys, levels = fresh_keys_and_levels()
    root_b = testkit.generate_private_key()  # 第二个独立根

    chain_a = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    chain_b = testkit.make_chain(root_b, levels, FAR_FUTURE)
    leaf_id = C.item_id_of(chain_a[-1]["header"])
    check("两条链 leaf_id 相同（仅签发根/签名不同）",
          leaf_id == C.item_id_of(chain_b[-1]["header"]),
          f"{leaf_id} vs {C.item_id_of(chain_b[-1]['header'])}")

    # ---- 隔离 A：根 A 撤销后，根 B 的干净链不被误判 REVOKED ----
    crl = testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)
    packet_a_rev = testkit.make_packet(keys["root"], chain_a, revocations=[crl])
    payload_rev = {"device": "dev-a", "command": "status", "nonce": os.urandom(8).hex()}
    body_a_rev = {
        "packet_text": canonicalize(packet_a_rev),
        "request_text": canonicalize(
            {"payload": payload_rev,
             "payload_signature": sign_payload(keys["leaf"], payload_rev)}
        ),
    }
    _, j_rev = post_execute(body_a_rev)
    check("根 A 携带有效撤销 → REVOKED",
          j_rev.get("evaluation", {}).get("first_reason") == C.REASON_REVOKED,
          str(j_rev.get("evaluation", {}).get("first_reason")))

    payload_b = {"device": "dev-a", "command": "status", "nonce": os.urandom(8).hex()}
    packet_b_clean = testkit.make_packet(root_b, chain_b)
    body_b = {
        "packet_text": canonicalize(packet_b_clean),
        "request_text": canonicalize(
            {"payload": payload_b,
             "payload_signature": sign_payload(keys["leaf"], payload_b)}
        ),
    }
    code_b, j_b = post_execute(body_b)
    check("根 A 已撤销，根 B 干净链仍正常 EXECUTED（非 REVOKED）",
          code_b == 200 and j_b.get("accepted") is True
          and (j_b.get("receipt") or {}).get("status") == "EXECUTED",
          str(j_b.get("evaluation", {}).get("first_reason")))

    # ---- 隔离 B：根 A 已消费后，根 B 不同载荷的首次执行不被误判 LEAF_CONSUMED ----
    keys2, levels2 = fresh_keys_and_levels()
    root2_b = testkit.generate_private_key()
    chain2_a = testkit.make_chain(keys2["root"], levels2, FAR_FUTURE)
    chain2_b = testkit.make_chain(root2_b, levels2, FAR_FUTURE)
    leaf2 = C.item_id_of(chain2_a[-1]["header"])
    assert leaf2 == C.item_id_of(chain2_b[-1]["header"])

    payload2_a = {"device": "dev-a", "command": "status", "nonce": os.urandom(8).hex()}
    body2_a = {
        "packet_text": canonicalize(testkit.make_packet(keys2["root"], chain2_a)),
        "request_text": canonicalize(
            {"payload": payload2_a,
             "payload_signature": sign_payload(keys2["leaf"], payload2_a)}
        ),
    }
    _, j2_a = post_execute(body2_a)
    check("根 A 链完成一次执行",
          (j2_a.get("receipt") or {}).get("status") == "EXECUTED",
          str(j2_a.get("evaluation", {}).get("first_reason")))

    # 不同请求载荷（设备/命令/nonce 均不同），根 B 的首次执行
    payload2_b = {"device": "dev-b", "command": "reboot", "nonce": os.urandom(8).hex()}
    body2_b = {
        "packet_text": canonicalize(testkit.make_packet(root2_b, chain2_b)),
        "request_text": canonicalize(
            {"payload": payload2_b,
             "payload_signature": sign_payload(keys2["leaf"], payload2_b)}
        ),
    }
    _, j2_b = post_execute(body2_b)
    check("根 A 已消费，根 B 首次执行仍 EXECUTED（非 LEAF_CONSUMED）",
          j2_b.get("accepted") is True
          and (j2_b.get("receipt") or {}).get("status") == "EXECUTED"
          and j2_b.get("evaluation", {}).get("first_reason") is None,
          str(j2_b.get("evaluation", {}).get("first_reason")))

    # 隔离不等于放开一次性约束：根 A 再换载荷仍必须 LEAF_CONSUMED
    payload2_a2 = {"device": "dev-b", "command": "reboot", "nonce": os.urandom(8).hex()}
    body2_a2 = {
        "packet_text": canonicalize(testkit.make_packet(keys2["root"], chain2_a)),
        "request_text": canonicalize(
            {"payload": payload2_a2,
             "payload_signature": sign_payload(keys2["leaf"], payload2_a2)}
        ),
    }
    _, j2_a2 = post_execute(body2_a2)
    check("同一根下二次驱动仍 → LEAF_CONSUMED",
          j2_a2.get("accepted") is False
          and j2_a2.get("evaluation", {}).get("first_reason") == C.REASON_LEAF_CONSUMED,
          str(j2_a2.get("evaluation", {}).get("first_reason")))


def scenario_http_smoke() -> None:
    print("\n=== 场景 5：健康/页面/内置演练包冒烟 ===")
    h = httpx.get(BASE_URL + "/healthz", timeout=TIMEOUT)
    check("GET /healthz → 200 status=ok",
          h.status_code == 200 and h.json().get("status") == "ok")

    idx = httpx.get(BASE_URL + "/", timeout=TIMEOUT)
    check("GET / → 值班界面", idx.status_code == 200 and "委托链" in idx.text)

    drill = httpx.get(BASE_URL + "/api/drill", timeout=TIMEOUT)
    check("GET /api/drill → 两套演练包",
          drill.status_code == 200 and "valid" in drill.json() and "revoked" in drill.json())
    d = drill.json()["valid"]
    r = httpx.post(BASE_URL + "/api/inspect", json={
        "packet_text": d["packet_text"], "request_text": d["request_text"]}, timeout=TIMEOUT)
    check("内置演练包逐级核验通过",
          r.status_code == 200 and r.json().get("accepted") is True)

    # 演练包执行：首跑 EXECUTED；持久卷复跑时幂等收敛为同一回执
    code1, j1 = post_execute({"packet_text": d["packet_text"], "request_text": d["request_text"]})
    code2, j2 = post_execute({"packet_text": d["packet_text"], "request_text": d["request_text"]})
    stable = (j1.get("receipt") == j2.get("receipt"))
    accepted_states = {j1.get("receipt", {}).get("status"), j2.get("receipt", {}).get("status")}
    check("内置演练包执行幂等稳定（重启/复跑收敛）",
          code1 == 200 and code2 == 200 and stable and accepted_states <= {"EXECUTED"},
          f"states={accepted_states}")


def run_pytest_suite() -> bool:
    print("\n=== 场景 6：pytest 全量单元/集成测试 ===")
    env = os.environ.copy()
    env["MDMS_DB_PATH"] = "/tmp/mdms-verify.db"
    env["PYTHONPATH"] = str(SRV_DIR)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(SRV_DIR / "tests"), "-q", "-p", "no:cacheprovider"],
        cwd=str(SRV_DIR), env=env,
    )
    return proc.returncode == 0


def main() -> int:
    print(f"[INFO] 验收目标：{BASE_URL}")
    if not wait_for_app():
        print("[FAIL] app 服务在超时内未就绪")
        return 1

    scenario_valid_execution_and_retry()
    scenario_concurrent_retransmit()
    scenario_tamper_rejections()
    scenario_root_isolation()
    scenario_http_smoke()
    pytest_ok = run_pytest_suite()

    print("\n================ 验收汇总 ================")
    if failures:
        for f in failures:
            print(f"  FAIL  {f}")
    print(f"HTTP 场景失败数：{len(failures)}；pytest：{'PASS' if pytest_ok else 'FAIL'}")
    ok = not failures and pytest_ok
    print("结果：" + ("ACCEPT ✅" if ok else "REJECT ❌"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
