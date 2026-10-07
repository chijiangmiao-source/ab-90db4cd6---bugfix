"""规范编码与 Ed25519 原语。

委托包只接受规范 UTF-8 JSON：
- 解析后按 RFC 8785 风格重新序列化（键按 UTF-16 码元排序，无空白），
  消除键序/空白差异，保证"改动已签字段"与"父项摘要绑定"可被稳定复核；
- 签名载荷一律是规范化后的字节。
"""
from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "CanonicalError",
    "b64e",
    "b64d",
    "canonicalize",
    "canonical_bytes",
    "canonical_digest",
    "verify_signature",
]


class CanonicalError(ValueError):
    """载荷不是可规范化的 JSON 数据（如出现重复键 / 非法类型）。"""


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> str:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _escape_string(s: str) -> str:
    out: list[str] = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _sort_key(key: str) -> tuple[int, int | str]:
    # JCS: 先按 UTF-16 码元长度，再按码元字典序。BMP 外字符按代理对排序。
    encoded = key.encode("utf-16-be")
    units = [int.from_bytes(encoded[i : i + 2], "big") for i in range(0, len(encoded), 2)]
    return (len(units), "".join(chr(u) for u in units))


def _emit(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, bool):  # pragma: no cover - bool 已在上面处理
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalError("JSON 不允许 NaN/Infinity")
        return json.dumps(value, allow_nan=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_emit(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        if len(set(keys)) != len(keys):
            raise CanonicalError("JSON 对象存在重复键")
        parts = [
            _escape_string(k) + ":" + _emit(value[k]) for k in sorted(keys, key=_sort_key)
        ]
        return "{" + ",".join(parts) + "}"
    raise CanonicalError(f"不可序列化的类型: {type(value).__name__}")


def canonicalize(value: Any) -> str:
    return _emit(value)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def canonical_digest(value: Any) -> bytes:
    import hashlib

    return hashlib.sha256(canonical_bytes(value)).digest()


def _load_public_key(packed_b64: str) -> Ed25519PublicKey:
    try:
        raw = b64d(packed_b64)
    except Exception as exc:  # noqa: BLE001
        raise CanonicalError("公钥不是合法 base64") from exc
    if len(raw) != 32:
        raise CanonicalError("Ed25519 公钥长度必须为 32 字节")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_signature(packed_pubkey_b64: str, message: bytes, signature_b64: str) -> bool:
    """验签；任何编码/长度/签名错误都返回 False，不抛异常。"""
    try:
        key = _load_public_key(packed_pubkey_b64)
        sig = b64d(signature_b64)
    except Exception:  # noqa: BLE001
        return False
    if len(sig) != 64:
        return False
    try:
        key.verify(sig, message)
    except InvalidSignature:
        return False
    return True
