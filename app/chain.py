"""Ed25519 委托链的纯校验逻辑。

委托包结构（规范 UTF-8 JSON）::

    {
      "root_pubkey": "<base64 Ed25519 公钥, 32B>",
      "chain": [ item, item, ... ],
      "revocations": [ revocation, ... ]          // 可选，根公钥签署
    }

每个 item::

    {
      "header": {
        "version": 1,
        "subject_pubkey": "<被授权主体公钥 b64>",
        "parent_digest":  "<父项 header 摘要 sha256 hex；根项为 64 个 0>",
        "devices":  ["dev-01", ...],
        "commands": ["reboot", ...],
        "expires_at": 1767225600
      },
      "signature": "<签发者对 header 规范字节的 Ed25519 签名 b64>"
    }

每个 revocation（撤销声明，独立于链，由根公钥签署，避免摘要依赖环）::

    {
      "header": {"version": 1, "revokes": ["<叶项标识 hex>", ...], "expires_at": ts},
      "signature": "<root_pubkey 对 header 规范字节的签名>"
    }

规则：
- 根项由 root_pubkey 自签；其后每项由父项 subject_pubkey 签发；
- 每个子项的 devices / commands 必须是父项的**真子集**（严格收窄）；
- parent_digest 必须等于父项 header 规范字节的 sha256；
- 任一项过期即拒；经合法签名项声明撤销的叶项不得驱动设备；
- 执行请求载荷 {"device","command",...} 须由叶项 subject 私钥签名。

裁决相关的四个身份要素：
root_pubkey、chain_digest（chain 规范字节摘要）、leaf_id（叶项 header 摘要）、
canonical(payload)，由持久层组合为 request_digest。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .canonical import (
    CanonicalError,
    b64d,
    b64e,
    canonical_bytes,
    verify_signature,
)

# ---- 拒因码（按检查先后排列，界面展示“首个拒因”） ----
REASON_MALFORMED_JSON = "MALFORMED_JSON"
REASON_PACKET_STRUCTURE = "PACKET_STRUCTURE"
REASON_ROOT_KEY_INVALID = "ROOT_KEY_INVALID"
REASON_CHAIN_EMPTY = "CHAIN_EMPTY"
REASON_ITEM_STRUCTURE = "ITEM_STRUCTURE"
REASON_PARENT_DIGEST_MISMATCH = "PARENT_DIGEST_MISMATCH"
REASON_SIGNATURE_INVALID = "SIGNATURE_INVALID"
REASON_SCOPE_NOT_NARROWED = "SCOPE_NOT_NARROWED"
REASON_EXPIRED = "EXPIRED"
REASON_REVOKED = "REVOKED"
REASON_PAYLOAD_STRUCTURE = "PAYLOAD_STRUCTURE"
REASON_PAYLOAD_SIGNATURE_INVALID = "PAYLOAD_SIGNATURE_INVALID"
REASON_DEVICE_OUT_OF_SCOPE = "DEVICE_OUT_OF_SCOPE"
REASON_COMMAND_OUT_OF_SCOPE = "COMMAND_OUT_OF_SCOPE"
REASON_LEAF_CONSUMED = "LEAF_CONSUMED"  # 运行期：末级凭据已使用
REASON_REVOCATION_INVALID = "REVOCATION_INVALID"

REASON_TEXT = {
    REASON_MALFORMED_JSON: "委托包不是规范 UTF-8 JSON（含重复键/非法编码）",
    REASON_PACKET_STRUCTURE: "委托包结构不符合约定（仅允许 root_pubkey、chain 与 revocations）",
    REASON_ROOT_KEY_INVALID: "根公钥不是合法的 32 字节 Ed25519 公钥",
    REASON_CHAIN_EMPTY: "委托链为空",
    REASON_ITEM_STRUCTURE: "链项 header 字段缺失或取值非法",
    REASON_PARENT_DIGEST_MISMATCH: "子项未正确绑定父项摘要",
    REASON_SIGNATURE_INVALID: "逐级签名验签失败",
    REASON_SCOPE_NOT_NARROWED: "设备或命令范围未相对父项严格收窄",
    REASON_EXPIRED: "存在已过期的委托项",
    REASON_REVOKED: "末级凭据已被有效撤销声明撤销（撤销在站内全局持久生效）",
    REASON_REVOCATION_INVALID: "撤销声明结构非法、未通过根公钥验签或已过期",
    REASON_PAYLOAD_STRUCTURE: "请求载荷结构非法（需含 device/command 字符串）",
    REASON_PAYLOAD_SIGNATURE_INVALID: "请求载荷未通过叶项主体签名验证",
    REASON_DEVICE_OUT_OF_SCOPE: "请求设备超出叶项设备范围",
    REASON_COMMAND_OUT_OF_SCOPE: "请求命令超出叶项命令集合",
    REASON_LEAF_CONSUMED: "该末级凭据已使用过，不得再次驱动设备",
}

ROOT_ANCHOR_DIGEST = "0" * 64
_ALLOWED_PACKET_KEYS = {"root_pubkey", "chain", "revocations"}
_ALLOWED_HEADER_KEYS = {
    "version",
    "subject_pubkey",
    "parent_digest",
    "devices",
    "commands",
    "expires_at",
}
_ALLOWED_REVOCATION_KEYS = {"version", "revokes", "expires_at"}
_NAME_RE = __import__("re").compile(r"^[a-z0-9_-]{1,64}$")
_HEX32_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


@dataclass
class ItemView:
    """供界面展示的逐级信息。"""

    index: int
    item_id: str | None = None
    issuer_pubkey: str | None = None       # 签发者（父项主体；根项为根公钥）
    subject_pubkey: str | None = None      # 被授权主体
    parent_digest: str | None = None
    parent_binding_ok: bool | None = None
    signature_ok: bool | None = None
    devices: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    scope_narrowed: bool | None = None     # 相对父项是否严格收窄
    expires_at: int | None = None
    expired: bool | None = None
    revoked: bool = False                  # 该级标识是否命中断效集合
    error: str | None = None               # 命中该级的首个拒因


@dataclass
class RevocationView:
    index: int
    revokes: list[str] = field(default_factory=list)
    expires_at: int | None = None
    expired: bool | None = None
    signature_ok: bool | None = None
    error: str | None = None


@dataclass
class Evaluation:
    ok: bool
    first_reason: str | None
    root_pubkey: str | None = None
    chain_digest: str | None = None
    leaf_id: str | None = None
    items: list[ItemView] = field(default_factory=list)
    revocations: list[RevocationView] = field(default_factory=list)
    valid_revoked_targets: list[str] = field(default_factory=list)
    revoked_by_persisted: bool = False
    payload_signature_ok: bool | None = None
    payload: dict[str, Any] | None = None


def _reject(reason: str, items: list[ItemView] | None = None, **kw: Any) -> Evaluation:
    return Evaluation(ok=False, first_reason=reason, items=items or [], **kw)


def _no_duplicates_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError(f"重复键: {key}")
        result[key] = value
    return result


def parse_strict_json(raw: bytes | str) -> Any:
    """严格 UTF-8 解码 + 重复键检测的 JSON 解析。"""
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="strict")
    else:
        raw.encode("utf-8", errors="strict")
        text = raw
    if text[:1] in {"﻿"}:
        raise CanonicalError("不允许 BOM")
    return json.loads(text, object_pairs_hook=_no_duplicates_hook)


def item_id_of(header: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(header)).hexdigest()


def chain_digest_of(chain: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_bytes(chain)).hexdigest()


def _is_b64_pubkey(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(b64d(value)) == 32
    except Exception:  # noqa: BLE001
        return False


def _valid_name_set(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    if len(set(value)) != len(value):
        return False
    return all(isinstance(v, str) and bool(_NAME_RE.match(v)) for v in value)


def _valid_header_shape(header: Any) -> bool:
    if not isinstance(header, dict):
        return False
    if set(header.keys()) - _ALLOWED_HEADER_KEYS:
        return False
    required = {"version", "subject_pubkey", "parent_digest", "devices", "commands", "expires_at"}
    if not required <= set(header.keys()):
        return False
    if header["version"] != 1:
        return False
    if not _is_b64_pubkey(header["subject_pubkey"]):
        return False
    if not isinstance(header["parent_digest"], str) or not _HEX32_RE.match(header["parent_digest"]):
        return False
    if not _valid_name_set(header["devices"]) or not _valid_name_set(header["commands"]):
        return False
    if isinstance(header["expires_at"], bool) or not isinstance(header["expires_at"], int):
        return False
    return True


def _valid_revocation_shape(entry: Any) -> dict[str, Any] | None:
    """撤销声明必须是 {header, signature}，header 仅含 version/revokes/expires_at。"""
    if not isinstance(entry, dict) or set(entry.keys()) != {"header", "signature"}:
        return None
    header = entry["header"]
    signature = entry["signature"]
    if not isinstance(header, dict):
        return None
    if set(header.keys()) != _ALLOWED_REVOCATION_KEYS:
        return None
    if header["version"] != 1:
        return None
    revokes = header["revokes"]
    if not isinstance(revokes, list) or not revokes:
        return None
    if not all(isinstance(r, str) and bool(_HEX32_RE.match(r)) for r in revokes):
        return None
    if isinstance(header["expires_at"], bool) or not isinstance(header["expires_at"], int):
        return None
    if not isinstance(signature, str):
        return None
    return header


def evaluate_packet(
    packet: Any,
    now: int,
    payload: Any = None,
    payload_signature: str | None = None,
    persisted_revoked: set[str] | None = None,
) -> Evaluation:
    """对委托包（可选执行载荷）执行完整裁决，返回结构化结果。

    纯函数：now 由调用方注入，不触碰数据库与网络。
    persisted_revoked 为站内已持久化的全局失效标识集合——撤销一旦经根公钥
    验证并入册，即使后续提交剥离撤销声明，命中集合的叶项仍不得驱动设备。
    """
    persisted_revoked = persisted_revoked or set()
    # ---- 包结构 ----
    if not isinstance(packet, dict) or set(packet.keys()) - _ALLOWED_PACKET_KEYS:
        return _reject(REASON_PACKET_STRUCTURE)
    root_pubkey = packet.get("root_pubkey")
    chain = packet.get("chain")
    if not _is_b64_pubkey(root_pubkey):
        return _reject(REASON_ROOT_KEY_INVALID)
    if not isinstance(chain, list) or not chain:
        return _reject(REASON_CHAIN_EMPTY)

    views: list[ItemView] = []
    parsed: list[dict[str, Any]] = []
    prev_devices: set[str] | None = None
    prev_commands: set[str] | None = None
    prev_digest = ROOT_ANCHOR_DIGEST
    issuer_pubkey = root_pubkey

    # ---- 逐级：结构 → 父摘要绑定 → 签名 → 严格收窄 → 过期 ----
    for index, item in enumerate(chain):
        view = ItemView(index=index)
        if not isinstance(item, dict) or set(item.keys()) != {"header", "signature"}:
            view.error = REASON_ITEM_STRUCTURE
            views.append(view)
            return _reject(REASON_ITEM_STRUCTURE, views)
        header = item["header"]
        signature = item["signature"]
        if not _valid_header_shape(header) or not isinstance(signature, str):
            view.error = REASON_ITEM_STRUCTURE
            views.append(view)
            return _reject(REASON_ITEM_STRUCTURE, views)

        view.subject_pubkey = header["subject_pubkey"]
        view.issuer_pubkey = issuer_pubkey
        view.parent_digest = header["parent_digest"]
        view.devices = list(header["devices"])
        view.commands = list(header["commands"])
        view.expires_at = header["expires_at"]

        digest = item_id_of(header)
        view.item_id = digest
        view.parent_binding_ok = header["parent_digest"] == prev_digest
        if not view.parent_binding_ok:
            view.error = REASON_PARENT_DIGEST_MISMATCH
            views.append(view)
            return _reject(REASON_PARENT_DIGEST_MISMATCH, views)

        message = canonical_bytes(header)
        view.signature_ok = verify_signature(issuer_pubkey, message, signature)
        if not view.signature_ok:
            view.error = REASON_SIGNATURE_INVALID
            views.append(view)
            return _reject(REASON_SIGNATURE_INVALID, views)

        devices = set(header["devices"])
        commands = set(header["commands"])
        if prev_devices is None:
            view.scope_narrowed = True  # 根项确立初始授权范围
        else:
            view.scope_narrowed = devices < prev_devices and commands < prev_commands
        if not view.scope_narrowed:
            view.error = REASON_SCOPE_NOT_NARROWED
            views.append(view)
            return _reject(REASON_SCOPE_NOT_NARROWED, views)

        view.expired = header["expires_at"] <= now
        if view.expired:
            view.error = REASON_EXPIRED
            views.append(view)
            return _reject(REASON_EXPIRED, views)

        views.append(view)
        parsed.append(item)
        prev_devices, prev_commands = devices, commands
        prev_digest = digest
        issuer_pubkey = header["subject_pubkey"]

    chain_digest = chain_digest_of(parsed)
    leaf_id = views[-1].item_id
    leaf_subject = views[-1].subject_pubkey
    leaf_devices = set(views[-1].devices)
    leaf_commands = set(views[-1].commands)
    chain_ids = {v.item_id for v in views}

    # ---- 包级撤销声明：结构 → 根公钥验签 → 未过期；任何一条非法即整包拒绝 ----
    revocation_views: list[RevocationView] = []
    valid_revoked_targets: set[str] = set()
    revocations = packet.get("revocations", [])
    if not isinstance(revocations, list):
        return Evaluation(
            ok=False, first_reason=REASON_PACKET_STRUCTURE,
            root_pubkey=root_pubkey, chain_digest=chain_digest, leaf_id=leaf_id, items=views,
        )
    for index, entry in enumerate(revocations):
        rv = RevocationView(index=index)
        header = _valid_revocation_shape(entry)
        if header is None:
            rv.error = REASON_REVOCATION_INVALID
            revocation_views.append(rv)
            return Evaluation(
                ok=False, first_reason=REASON_REVOCATION_INVALID,
                root_pubkey=root_pubkey, chain_digest=chain_digest, leaf_id=leaf_id,
                items=views, revocations=revocation_views,
            )
        rv.revokes = list(header["revokes"])
        rv.expires_at = header["expires_at"]
        rv.expired = header["expires_at"] <= now
        rv.signature_ok = verify_signature(
            root_pubkey, canonical_bytes(header), entry["signature"]
        )
        if not rv.signature_ok or rv.expired:
            rv.error = REASON_REVOCATION_INVALID
            revocation_views.append(rv)
            return Evaluation(
                ok=False, first_reason=REASON_REVOCATION_INVALID,
                root_pubkey=root_pubkey, chain_digest=chain_digest, leaf_id=leaf_id,
                items=views, revocations=revocation_views,
            )
        revocation_views.append(rv)
        # 只有引用本链真实项标识的撤销才在本裁决中生效
        valid_revoked_targets.update(t for t in header["revokes"] if t in chain_ids)

    effective = persisted_revoked | valid_revoked_targets
    hit_items = [v for v in views if v.item_id in effective]
    if hit_items:
        for v in hit_items:
            v.revoked = True
        return Evaluation(
            ok=False,
            first_reason=REASON_REVOKED,
            root_pubkey=root_pubkey,
            chain_digest=chain_digest,
            leaf_id=leaf_id,
            items=views,
            revocations=revocation_views,
            valid_revoked_targets=sorted(valid_revoked_targets),
            revoked_by_persisted=any(v.item_id in persisted_revoked for v in hit_items),
            # 载荷即使尚未进入签名阶段也随拒绝结果携带，使撤销裁决可持久化、重传可收敛
            payload=payload if isinstance(payload, dict) else None,
        )

    # ---- 请求载荷阶段 ----
    if payload is not None:
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("device"), str)
            or not isinstance(payload.get("command"), str)
        ):
            return Evaluation(
                ok=False, first_reason=REASON_PAYLOAD_STRUCTURE,
                root_pubkey=root_pubkey, chain_digest=chain_digest,
                leaf_id=leaf_id, items=views, revocations=revocation_views,
                valid_revoked_targets=sorted(valid_revoked_targets),
                payload=payload if isinstance(payload, dict) else None,
            )
        if not isinstance(payload_signature, str):
            return Evaluation(
                ok=False, first_reason=REASON_PAYLOAD_SIGNATURE_INVALID,
                root_pubkey=root_pubkey, chain_digest=chain_digest,
                leaf_id=leaf_id, items=views, revocations=revocation_views,
                valid_revoked_targets=sorted(valid_revoked_targets),
                payload_signature_ok=False, payload=payload,
            )
        sig_ok = verify_signature(leaf_subject, canonical_bytes(payload), payload_signature)
        if not sig_ok:
            return Evaluation(
                ok=False, first_reason=REASON_PAYLOAD_SIGNATURE_INVALID,
                root_pubkey=root_pubkey, chain_digest=chain_digest,
                leaf_id=leaf_id, items=views, revocations=revocation_views,
                valid_revoked_targets=sorted(valid_revoked_targets),
                payload_signature_ok=False, payload=payload,
            )
        if payload["device"] not in leaf_devices:
            return Evaluation(
                ok=False, first_reason=REASON_DEVICE_OUT_OF_SCOPE,
                root_pubkey=root_pubkey, chain_digest=chain_digest,
                leaf_id=leaf_id, items=views, revocations=revocation_views,
                valid_revoked_targets=sorted(valid_revoked_targets),
                payload_signature_ok=True, payload=payload,
            )
        if payload["command"] not in leaf_commands:
            return Evaluation(
                ok=False, first_reason=REASON_COMMAND_OUT_OF_SCOPE,
                root_pubkey=root_pubkey, chain_digest=chain_digest,
                leaf_id=leaf_id, items=views, revocations=revocation_views,
                valid_revoked_targets=sorted(valid_revoked_targets),
                payload_signature_ok=True, payload=payload,
            )
        return Evaluation(
            ok=True, first_reason=None,
            root_pubkey=root_pubkey, chain_digest=chain_digest, leaf_id=leaf_id,
            items=views, revocations=revocation_views,
            valid_revoked_targets=sorted(valid_revoked_targets),
            payload_signature_ok=True, payload=payload,
        )

    return Evaluation(
        ok=True, first_reason=None,
        root_pubkey=root_pubkey, chain_digest=chain_digest, leaf_id=leaf_id,
        items=views, revocations=revocation_views,
        valid_revoked_targets=sorted(valid_revoked_targets),
    )


def request_digest(
    root_pubkey_b64: str, chain_digest_hex: str, leaf_id_hex: str, payload: dict[str, Any]
) -> str:
    """四要素共同决定一次裁决的持久化标识。"""
    h = hashlib.sha256()
    h.update(b"MDMS-REQ-v1\n")
    h.update(b64d(root_pubkey_b64))
    h.update(bytes.fromhex(chain_digest_hex))
    h.update(bytes.fromhex(leaf_id_hex))
    h.update(canonical_bytes(payload))
    return h.hexdigest()


def short_id(value: str | None, length: int = 12) -> str:
    if not value:
        return "-"
    return value[:length] + ("…" if len(value) > length else "")
