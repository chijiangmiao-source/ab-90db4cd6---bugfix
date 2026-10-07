"""Ed25519 密钥与签名辅助（演练/测试用；生产侧私钥由各主体自持）。"""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import b64e, canonical_bytes


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed 必须为 32 字节")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_b64(private_key: Ed25519PrivateKey) -> str:
    pub = private_key.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)


def public_b64_of(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)


def sign_header(private_key: Ed25519PrivateKey, header: dict) -> str:
    from .canonical import b64e as _b64e

    return _b64e(private_key.sign(canonical_bytes(header)))


def sign_payload(private_key: Ed25519PrivateKey, payload: dict) -> str:
    return b64e(private_key.sign(canonical_bytes(payload)))
