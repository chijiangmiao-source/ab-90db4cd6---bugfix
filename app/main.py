"""FastAPI 入口：委托包核验、执行裁决、回执复核与静态值班界面。"""
from __future__ import annotations

import os
import time
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import chain as chain_mod
from . import drill as drill_mod
from .canonical import CanonicalError
from .store import DecisionStore

DB_PATH = os.environ.get("MDMS_DB_PATH", os.path.join(os.getcwd(), "data", "mdms.db"))

app = FastAPI(title="隔离维护站委托链裁决服务", version="1.0.0")
store = DecisionStore(DB_PATH)
_STARTED_AT = int(time.time())


class SubmitBody(BaseModel):
    packet_text: str
    request_text: str | None = None


def _parse_request_envelope(request_text: str | None) -> tuple[Any, str | None]:
    if request_text is None or not request_text.strip():
        return None, None
    env = chain_mod.parse_strict_json(request_text)
    if (
        not isinstance(env, dict)
        or "payload" not in env
        or not isinstance(env.get("payload_signature"), str)
    ):
        raise CanonicalError("请求文本必须是 {\"payload\":{...},\"payload_signature\":\"...\"}")
    return env["payload"], env["payload_signature"]


def _evaluation_view(ev: chain_mod.Evaluation) -> dict[str, Any]:
    view = asdict(ev)
    if ev.first_reason:
        view["first_reason_text"] = chain_mod.REASON_TEXT.get(ev.first_reason)
    else:
        view["first_reason_text"] = None
    return view


def _bad_request(reason: str) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={"code": reason, "message": chain_mod.REASON_TEXT.get(reason, reason)},
    )


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    # 健康响应同时确认持久层可读
    executions = store.execution_count()
    return {
        "status": "ok",
        "service": "mdms-decision",
        "started_at": _STARTED_AT,
        "execution_records": executions,
    }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.get("/api/drill")
def get_drill() -> dict[str, Any]:
    d = drill_mod.build_valid_drill()
    revoked = drill_mod.build_revoked_drill()
    from .canonical import canonicalize

    return {
        "valid": {
            "name": d["name"],
            "packet_text": canonicalize(d["packet"]),
            "request_text": canonicalize(
                {"payload": d["payload"], "payload_signature": d["payload_signature"]}
            ),
            "expected_leaf_id": d["expected_leaf_id"],
        },
        "revoked": {
            "name": revoked["name"],
            "packet_text": canonicalize(revoked["packet"]),
            "request_text": canonicalize(
                {"payload": revoked["payload"], "payload_signature": revoked["payload_signature"]}
            ),
            "expected_leaf_id": revoked["expected_leaf_id"],
        },
    }


@app.post("/api/inspect")
def inspect(body: SubmitBody) -> dict[str, Any]:
    """只核验、不落盘、不驱动设备：展示逐级签名/范围/失效与首个拒因。"""
    try:
        packet = chain_mod.parse_strict_json(body.packet_text)
        payload, sig = _parse_request_envelope(body.request_text)
    except (CanonicalError, UnicodeDecodeError):
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    except Exception:  # noqa: BLE001 - json.JSONDecodeError 等
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)

    ev = chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )
    return {"accepted": ev.ok, "evaluation": _evaluation_view(ev)}


@app.post("/api/execute")
def execute(body: SubmitBody) -> JSONResponse:
    """发起一次执行；并发/重传在一次持久化裁决中收敛为一次执行与同一回执。"""
    try:
        packet = chain_mod.parse_strict_json(body.packet_text)
        payload, sig = _parse_request_envelope(body.request_text)
    except (CanonicalError, UnicodeDecodeError):
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)
    except Exception:  # noqa: BLE001
        raise _bad_request(chain_mod.REASON_MALFORMED_JSON)

    if payload is None:
        raise _bad_request(chain_mod.REASON_PAYLOAD_STRUCTURE)

    ev = chain_mod.evaluate_packet(
        packet, int(time.time()), payload=payload, payload_signature=sig,
        persisted_revoked=store.revoked_set(),
    )
    response: dict[str, Any] = {"accepted": ev.ok, "evaluation": _evaluation_view(ev)}

    if ev.ok:
        decision = store.record_decision(
            ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
            execute=True,
            new_revoked_targets=set(ev.valid_revoked_targets),
        )
        assert decision is not None
        # 运行期条件（末级凭据已消耗 / 并发到达的撤销入册）可能使裁决转拒：
        # accepted 以持久化裁决为准，并回填首个拒因供界面展示。
        if decision.status != "EXECUTED":
            ev.ok = False
            ev.first_reason = decision.reason
            response = {"accepted": False, "evaluation": _evaluation_view(ev)}
        response["duplicate"] = decision.duplicate
        response["receipt"] = decision.receipt()
        return JSONResponse(response, status_code=200)

    # 被撤销 / 越权 / 过期等：仅落 REJECTED 裁决，绝不留下执行记录
    decision = store.record_decision(
        ev.root_pubkey, ev.chain_digest, ev.leaf_id, ev.payload,
        execute=False,
        reason=ev.first_reason,
        new_revoked_targets=set(ev.valid_revoked_targets),
    )
    response["duplicate"] = decision.duplicate if decision else False
    response["receipt"] = decision.receipt() if decision else None
    return JSONResponse(response, status_code=200)


@app.get("/api/receipt/{request_digest}")
def get_receipt(request_digest: str) -> dict[str, Any]:
    if not request_digest.isalnum() or len(request_digest) != 64:
        raise HTTPException(status_code=404, detail="回执标识格式非法")
    decision = store.get(request_digest)
    if decision is None:
        raise HTTPException(status_code=404, detail="无此裁决回执")
    return {"receipt": decision.receipt()}


@app.get("/api/decisions")
def list_decisions(limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(limit, 200))
    return {"decisions": store.list_decisions(limit)}
