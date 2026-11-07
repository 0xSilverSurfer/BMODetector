import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def lab():
    """Démarre la cible de labo (mock vulnérable) sur un port libre et retourne son URL de base."""
    pytest.importorskip("fastapi")
    pytest.importorskip("uvicorn")
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "target_lab.mock_api:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("Le labo n'a pas démarré")
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=10)


def run_cli(*args, env=None, cwd=ROOT):
    import os
    full_env = {**os.environ, **(env or {})}
    full_env.pop("BMO_API_KEY", None) if not (env and "BMO_API_KEY" in env) else None
    return subprocess.run([sys.executable, str(ROOT / "bmo_detector.py"), *args], capture_output=True, text=True,
                          timeout=180, cwd=str(cwd), env=full_env, stdin=subprocess.DEVNULL)
