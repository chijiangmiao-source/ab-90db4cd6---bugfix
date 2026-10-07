import sys
import os
import time
import socket
import subprocess
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import testkit  # noqa: E402
from app import drill as drill_mod  # noqa: E402

FAR_FUTURE = 4070908800


@pytest.fixture
def keys():
    return {
        "root": testkit.seeded_key("t-root"),
        "org": testkit.seeded_key("t-org"),
        "leaf": testkit.seeded_key("t-leaf"),
        "other": testkit.seeded_key("t-other"),
    }


@pytest.fixture
def levels(keys):
    return [
        (keys["org"], ["dev-a", "dev-b", "dev-c"], ["reboot", "status", "diagnose"]),
        (keys["leaf"], ["dev-a", "dev-b"], ["reboot", "status"]),
    ]


@pytest.fixture
def valid_packet(keys, levels):
    chain = testkit.make_chain(keys["root"], levels, FAR_FUTURE)
    return testkit.make_packet(keys["root"], chain), chain


@pytest.fixture
def valid_payload():
    return {"device": "dev-a", "command": "status", "nonce": "n-0001"}


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerProc:
    def __init__(self, base_url: str, proc: subprocess.Popen):
        self.base_url = base_url
        self.proc = proc

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _spawn_server(db_path: str) -> ServerProc:
    port = _free_port()
    env = os.environ.copy()
    env["MDMS_DB_PATH"] = db_path
    env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "app.main:app",
            "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
        ],
        cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    last_err = None
    while time.time() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"server exited early:\n{out}")
        try:
            r = httpx.get(base_url + "/healthz", timeout=1)
            if r.status_code == 200:
                return ServerProc(base_url, proc)
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        time.sleep(0.2)
    proc.terminate()
    raise RuntimeError(f"server did not become ready: {last_err}")


@pytest.fixture
def server(tmp_path):
    srv = _spawn_server(str(tmp_path / "mdms.db"))
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def server_factory(tmp_path):
    procs: list[ServerProc] = []

    def _make():
        srv = _spawn_server(str(tmp_path / "mdms.db"))
        procs.append(srv)
        return srv

    yield _make
    for p in procs:
        p.stop()
