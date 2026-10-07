"""构造委托链的测试/演练工具包（仅用于演练与自动化验收）。"""
from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import b64e
from .chain import ROOT_ANCHOR_DIGEST, item_id_of
from .cryptohelp import private_key_from_seed, public_b64, sign_header, sign_payload
from .cryptohelp import generate_private_key


def seeded_key(label: str) -> Ed25519PrivateKey:
    """由标签派生确定性 Ed25519 私钥，保证演练包跨重启稳定。"""
    import hashlib

    seed = hashlib.sha256(b"mdms-drill-key:" + label.encode("utf-8")).digest()
    return private_key_from_seed(seed)


def make_item(
    issuer_priv: Ed25519PrivateKey,
    subject_pub_b64: str,
    parent_digest: str,
    devices: list[str],
    commands: list[str],
    expires_at: int,
) -> dict[str, Any]:
    header: dict[str, Any] = {
        "version": 1,
        "subject_pubkey": subject_pub_b64,
        "parent_digest": parent_digest,
        "devices": devices,
        "commands": commands,
        "expires_at": expires_at,
    }
    return {"header": header, "signature": sign_header(issuer_priv, header)}


def make_chain(
    root_priv: Ed25519PrivateKey,
    levels: list[tuple[Ed25519PrivateKey, list[str], list[str]]],
    expires_at: int,
) -> list[dict[str, Any]]:
    """按 (主体私钥, 设备, 命令) 层级序列构建完整签名链。"""
    chain: list[dict[str, Any]] = []
    parent_digest = ROOT_ANCHOR_DIGEST
    issuer = root_priv
    for subject_priv, devices, commands in levels:
        item = make_item(
            issuer,
            public_b64(subject_priv),
            parent_digest,
            devices,
            commands,
            expires_at,
        )
        chain.append(item)
        parent_digest = item_id_of(item["header"])
        issuer = subject_priv
    return chain


def make_packet(
    root_priv: Ed25519PrivateKey,
    chain: list[dict[str, Any]],
    revocations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    packet: dict[str, Any] = {"root_pubkey": public_b64(root_priv), "chain": chain}
    if revocations is not None:
        packet["revocations"] = revocations
    return packet


def make_revocation(
    root_priv: Ed25519PrivateKey,
    revoked_leaf_ids: list[str],
    expires_at: int,
) -> dict[str, Any]:
    """构造根公钥签署的撤销声明（包级 CRL）。"""
    header = {
        "version": 1,
        "revokes": revoked_leaf_ids,
        "expires_at": expires_at,
    }
    return {"header": header, "signature": sign_header(root_priv, header)}


def make_payload_signature(leaf_priv: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    return sign_payload(leaf_priv, payload)


def exported_pub_b64(priv: Ed25519PrivateKey) -> str:
    return public_b64(priv)


__all__ = [
    "seeded_key",
    "generate_private_key",
    "make_item",
    "make_chain",
    "make_packet",
    "make_revocation",
    "make_payload_signature",
    "b64e",
]
