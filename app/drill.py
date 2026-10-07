"""内置演练包。

确定性种子密钥派生出三级委托主体，重启后演练包的链摘要、叶项标识与
request_digest 均保持不变，便于值班员反复加载、执行并比对历史回执。
层级：
    根维护局 root
      └─ 区域维保中心 org      （设备/命令首次收窄）
          └─ 隔离站值班终端 leaf （再次收窄，为末级一次性凭据）
"""
from __future__ import annotations

import json
from typing import Any

from .canonical import canonicalize
from .chain import item_id_of
from .cryptohelp import sign_payload
from .testkit import (
    make_chain,
    make_packet,
    make_revocation,
    seeded_key,
)

# 远期失效时间（2099-01-01T00:00:00Z），演练包在可预见时间内始终有效。
DRILL_EXPIRES_AT = 4070908800

# 供界面与文档展示的固定设备/命令语料
ALL_DEVICES = ["dev-alpha", "dev-bravo", "dev-charlie", "dev-delta"]
ALL_COMMANDS = ["diagnose", "firmware-update", "reboot", "status"]


def _keys() -> dict[str, Any]:
    return {
        "root": seeded_key("root-authority"),
        "org": seeded_key("regional-maintenance-org"),
        "leaf": seeded_key("station-duty-terminal"),
        # 另一套根，用于"撤销演练"，避免污染正常演练的裁决记录
        "rev_root": seeded_key("rev-drill-root-authority"),
        "rev_org": seeded_key("rev-drill-regional-org"),
        "rev_leaf": seeded_key("rev-drill-duty-terminal"),
    }


def build_valid_drill() -> dict[str, Any]:
    k = _keys()
    chain = make_chain(
        k["root"],
        [
            (k["org"],
             ["dev-alpha", "dev-bravo", "dev-charlie"],
             ["diagnose", "reboot", "status"]),
            (k["leaf"],
             ["dev-alpha", "dev-bravo"],
             ["reboot", "status"]),
        ],
        DRILL_EXPIRES_AT,
    )
    packet = make_packet(k["root"], chain)
    payload: dict[str, Any] = {
        "device": "dev-alpha",
        "command": "status",
        "nonce": "drill-20261007-01",
    }
    return {
        "name": "标准三级委托演练包",
        "packet": packet,
        "payload": payload,
        "payload_signature": sign_payload(k["leaf"], payload),
        "expected_leaf_id": item_id_of(chain[-1]["header"]),
    }


def build_revoked_drill() -> dict[str, Any]:
    """携带有效撤销声明的演练包（撤销末级凭据，执行必须被拒）。"""
    k = _keys()
    chain = make_chain(
        k["rev_root"],
        [
            (k["rev_org"],
             ["dev-alpha", "dev-bravo", "dev-charlie"],
             ["diagnose", "reboot", "status"]),
            (k["rev_leaf"],
             ["dev-alpha", "dev-bravo"],
             ["reboot", "status"]),
        ],
        DRILL_EXPIRES_AT,
    )
    leaf_id = item_id_of(chain[-1]["header"])
    revocation = make_revocation(k["rev_root"], [leaf_id], DRILL_EXPIRES_AT)
    packet = make_packet(k["rev_root"], chain, revocations=[revocation])
    payload: dict[str, Any] = {
        "device": "dev-alpha",
        "command": "reboot",
        "nonce": "drill-20261007-revoked",
    }
    return {
        "name": "撤销生效演练包（应拒绝）",
        "packet": packet,
        "payload": payload,
        "payload_signature": sign_payload(k["rev_leaf"], payload),
        "expected_leaf_id": leaf_id,
    }


def drill_bundle_text() -> str:
    """前端两个粘贴框的可粘贴文本（规范 JSON）。"""
    d = build_valid_drill()
    return json.dumps(
        {
            "packet_text": canonicalize(d["packet"]),
            "request_text": canonicalize(
                {"payload": d["payload"], "payload_signature": d["payload_signature"]}
            ),
            "name": d["name"],
            "expected_leaf_id": d["expected_leaf_id"],
        },
        ensure_ascii=False,
    )
