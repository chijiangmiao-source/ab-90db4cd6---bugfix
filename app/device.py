"""受控设备侧的模拟执行器。

真实维护站中这里会驱动隔离网闸后的设备；演练环境以确定性方式模拟：
同一 request_digest 永远得到同一 command_id 与输出，执行时间在首次执行时
固定并随裁决落盘，因此重传得到的回执逐字段稳定。
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

_OUTPUTS = {
    "reboot": "设备已排队重启，维护窗口生效",
    "status": "设备运行正常，遥测已归档",
    "firmware-update": "固件包校验通过，更新任务已受理",
    "diagnose": "诊断流程已启动，报告待回收",
}


@dataclass(frozen=True)
class ExecutionResult:
    command_id: str
    output: str
    status: str


def execute(request_digest: str, device: str, command: str) -> ExecutionResult:
    command_id = "cmd-" + hashlib.sha256(
        (request_digest + ":execution").encode("ascii")
    ).hexdigest()[:24]
    output = _OUTPUTS.get(command, f"{device}:{command} 已受理（演练模拟）")
    return ExecutionResult(command_id=command_id, output=output, status="EXECUTED")


def now_ts() -> int:
    return int(time.time())
