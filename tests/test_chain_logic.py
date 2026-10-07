"""纯校验逻辑测试：逐级签名、父子绑定、范围收窄、过期、撤销、载荷裁决。"""
import copy
import json

import pytest

from app import chain as C
from app import testkit
from app.canonical import canonicalize
from app.cryptohelp import sign_payload
from conftest import FAR_FUTURE


def _full(packet, keys, payload, leaf_index=-1):
    return C.evaluate_packet(
        packet, FAR_FUTURE - 10**8,
        payload=payload,
        payload_signature=sign_payload(keys["leaf"] if leaf_index == -1 else keys["leaf"], payload),
    )


def test_valid_chain_accepted(valid_packet, keys, valid_payload):
    packet, chain = valid_packet
    ev = _full(packet, keys, valid_payload)
    assert ev.ok is True
    assert ev.first_reason is None
    assert ev.leaf_id == C.item_id_of(chain[-1]["header"])
    assert ev.chain_digest == C.chain_digest_of(chain)
    assert len(ev.items) == 2
    assert all(it.signature_ok and it.parent_binding_ok for it in ev.items)
    assert ev.items[1].scope_narrowed is True


def test_root_self_signature_binding(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    # 根项 parent_digest 必须是全 0 锚点
    assert packet["chain"][0]["header"]["parent_digest"] == C.ROOT_ANCHOR_DIGEST


def test_tampered_signature_rejected(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    packet["chain"][1]["header"]["devices"] = ["dev-a", "dev-z"]
    ev = _full(packet, keys, valid_payload)
    assert ev.ok is False
    assert ev.first_reason == C.REASON_SIGNATURE_INVALID
    assert ev.items[1].error == C.REASON_SIGNATURE_INVALID


def test_tampered_parent_digest_rejected(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    packet["chain"][1]["header"]["parent_digest"] = "f" * 64
    # 即使由正确签发者（区域主体）对被篡改的 header 重新签名，父摘要绑定仍然失败
    packet["chain"][1]["signature"] = testkit.sign_header(
        keys["org"], packet["chain"][1]["header"]
    )
    ev = C.evaluate_packet(packet, FAR_FUTURE - 10**8, payload=valid_payload)
    assert ev.ok is False
    assert ev.first_reason == C.REASON_PARENT_DIGEST_MISMATCH


def test_scope_must_strictly_narrow_devices(keys, levels, valid_payload):
    # 设备范围与父项相同（非真子集）→ 拒绝
    levels[1] = (keys["leaf"], ["dev-a", "dev-b", "dev-c"], ["reboot", "status"])
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    ev = _full(packet, keys, valid_payload)
    assert ev.first_reason == C.REASON_SCOPE_NOT_NARROWED


def test_scope_must_strictly_narrow_commands(keys, levels, valid_payload):
    levels[1] = (keys["leaf"], ["dev-a"], ["reboot", "status", "diagnose"])
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    packet = testkit.make_packet(keys["root"], chain)
    ev = _full(packet, keys, valid_payload)
    assert ev.first_reason == C.REASON_SCOPE_NOT_NARROWED


def test_scope_widening_mid_chain_rejected(keys, valid_payload):
    chain = testkit.make_chain(
        keys["root"],
        [
            (keys["org"], ["dev-a"], ["status"]),
            (keys["leaf"], ["dev-a", "dev-b"], ["status"]),  # 设备扩大
        ],
        FAR_FUTURE,
    )
    packet = testkit.make_packet(keys["root"], chain)
    ev = _full(packet, keys, valid_payload)
    assert ev.first_reason == C.REASON_SCOPE_NOT_NARROWED


def test_wrong_issuer_signature_rejected(keys, levels, valid_payload):
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    # 用无关私钥重签根项
    chain[0]["signature"] = testkit.sign_header(keys["other"], chain[0]["header"])
    packet = testkit.make_packet(keys["root"], chain)
    ev = C.evaluate_packet(packet, FAR_FUTURE - 10**8)
    assert ev.first_reason == C.REASON_SIGNATURE_INVALID


def test_expired_item_rejected(keys, levels, valid_payload):
    chain = testkit.make_chain(keys["root"], levels, 100)
    packet = testkit.make_packet(keys["root"], chain)
    ev = C.evaluate_packet(packet, 101, payload=valid_payload)
    assert ev.first_reason == C.REASON_EXPIRED
    # 恰好等于失效时间也视为过期
    ev2 = C.evaluate_packet(packet, 100, payload=valid_payload)
    assert ev2.first_reason == C.REASON_EXPIRED


def test_expires_exactly_at_boundary(valid_packet, keys, valid_payload):
    packet, chain = valid_packet
    exp = chain[0]["header"]["expires_at"]
    ev = C.evaluate_packet(packet, exp - 1, payload=valid_payload,
                           payload_signature=sign_payload(keys["leaf"], valid_payload))
    assert ev.ok is True


def test_device_out_of_scope(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    payload = {"device": "dev-c", "command": "status", "nonce": "x"}
    ev = _full(packet, keys, payload)
    assert ev.first_reason == C.REASON_DEVICE_OUT_OF_SCOPE


def test_command_out_of_scope(valid_packet, keys):
    packet, _ = valid_packet
    payload = {"device": "dev-a", "command": "reboot", "nonce": "x"}  # reboot 在范围内
    ev = _full(packet, keys, payload)
    assert ev.ok is True
    payload2 = {"device": "dev-a", "command": "diagnose", "nonce": "y"}  # 叶项无 diagnose
    ev2 = _full(packet, keys, payload2)
    assert ev2.first_reason == C.REASON_COMMAND_OUT_OF_SCOPE


def test_payload_signature_must_be_leaf(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["org"], valid_payload),  # 父项签名无效
    )
    assert ev.first_reason == C.REASON_PAYLOAD_SIGNATURE_INVALID


def test_payload_tamper_invalidates(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    sig = sign_payload(keys["leaf"], valid_payload)
    tampered = dict(valid_payload, command="reboot")
    ev = C.evaluate_packet(packet, FAR_FUTURE - 10**8, payload=tampered, payload_signature=sig)
    assert ev.first_reason == C.REASON_PAYLOAD_SIGNATURE_INVALID


def test_duplicate_json_key_rejected():
    raw = '{"root_pubkey":"x","root_pubkey":"y","chain":[]}'
    with pytest.raises(C.CanonicalError):
        C.parse_strict_json(raw)


def test_non_utf8_rejected():
    with pytest.raises(UnicodeDecodeError):
        C.parse_strict_json(b'{"a":\xff}')


def test_canonical_serialization_stable():
    a = {"b": 1, "a": [3, 2, 1], "c": {"z": 0, "y": 0}}
    b = json.loads(json.dumps(a))
    assert canonicalize(a) == canonicalize(b)
    assert canonicalize(a) == '{"a":[3,2,1],"b":1,"c":{"y":0,"z":0}}'


def test_revoked_leaf_by_valid_crl(valid_packet, keys, valid_payload):
    packet, chain = valid_packet
    leaf_id = C.item_id_of(chain[-1]["header"])
    packet["revocations"] = [testkit.make_revocation(keys["root"], [leaf_id], FAR_FUTURE)]
    ev = _full(packet, keys, valid_payload)
    assert ev.first_reason == C.REASON_REVOKED
    assert ev.items[-1].revoked is True
    assert leaf_id in ev.valid_revoked_targets


def test_revocation_signed_by_non_root_rejected(valid_packet, keys, valid_payload):
    packet, chain = valid_packet
    leaf_id = C.item_id_of(chain[-1]["header"])
    packet["revocations"] = [testkit.make_revocation(keys["org"], [leaf_id], FAR_FUTURE)]
    ev = _full(packet, keys, valid_payload)
    assert ev.first_reason == C.REASON_REVOCATION_INVALID


def test_revocation_for_unknown_id_ignored(valid_packet, keys, valid_payload):
    packet, _ = valid_packet
    packet["revocations"] = [testkit.make_revocation(keys["root"], ["a" * 64], FAR_FUTURE)]
    ev = _full(packet, keys, valid_payload)
    assert ev.ok is True  # 未知目标不影响本链
    assert ev.valid_revoked_targets == []


def test_persisted_revocation_still_blocks_without_crl(valid_packet, keys, valid_payload):
    packet, chain = valid_packet
    leaf_id = C.item_id_of(chain[-1]["header"])
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
        persisted_revoked={(packet["root_pubkey"], leaf_id)},
    )
    assert ev.first_reason == C.REASON_REVOKED
    assert ev.revoked_by_persisted is True


def test_persisted_revocation_scoped_by_root(valid_packet, keys, valid_payload):
    """根 A 对 leaf_id 的入册撤销不得波及根 B 签发的同 leaf_id 合法链。"""
    packet, chain = valid_packet
    leaf_id = C.item_id_of(chain[-1]["header"])
    other_root = testkit.public_b64(keys["other"])
    ev = C.evaluate_packet(
        packet, FAR_FUTURE - 10**8, payload=valid_payload,
        payload_signature=sign_payload(keys["leaf"], valid_payload),
        persisted_revoked={(other_root, leaf_id)},  # 仅在另一根名下撤销
    )
    assert ev.ok is True
    assert ev.first_reason is None
    assert ev.revoked_by_persisted is False


def test_malformed_packet_shapes(keys):
    assert C.evaluate_packet([], 0).first_reason == C.REASON_PACKET_STRUCTURE
    assert C.evaluate_packet({"root_pubkey": "xx", "chain": []}, 0).first_reason == C.REASON_ROOT_KEY_INVALID
    assert C.evaluate_packet({"root_pubkey": "xx", "chain": [], "evil": 1}, 0).first_reason
    # 空链
    good_root = testkit.public_b64(keys["root"])
    assert C.evaluate_packet({"root_pubkey": good_root, "chain": []}, 0).first_reason == C.REASON_CHAIN_EMPTY


def test_request_digest_changes_with_any_element(valid_packet, keys, valid_payload):
    packet, chain = valid_packet
    d1 = C.request_digest(
        packet["root_pubkey"], C.chain_digest_of(chain),
        C.item_id_of(chain[-1]["header"]), valid_payload,
    )
    d2 = C.request_digest(
        packet["root_pubkey"], C.chain_digest_of(chain),
        C.item_id_of(chain[-1]["header"]), {**valid_payload, "nonce": "n-0002"},
    )
    assert d1 != d2
    assert len(d1) == 64
