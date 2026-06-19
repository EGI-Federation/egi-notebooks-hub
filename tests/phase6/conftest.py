"""
Shared fixtures and helpers for Phase 6 running-Hub tests.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

PHASE6_TOKEN = "phase6-test-admin-token"
HUB_PORT = 18000
TOKEN_ACQUIRER_PORT = 18010
HUB_URL = f"http://127.0.0.1:{HUB_PORT}"
SERVICE_URL = f"{HUB_URL}/services/token-acquirer/"


def repo_root() -> Path:
    """Return the repository root from the Phase 6 tests directory."""
    return Path(__file__).resolve().parents[2]


def auth_headers() -> dict[str, str]:
    """Return the Hub API Authorization header for the test service token."""
    return {"Authorization": f"token {PHASE6_TOKEN}"}


def read_log(log_path: Path) -> str:
    """Read the JupyterHub log file captured by the running_hub fixture."""
    try:
        return log_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def wait_for_hub_api(log_path: Path, timeout: int = 90) -> None:
    """Wait until the running Hub API responds to the service token."""
    deadline = time.monotonic() + timeout
    last_error = ""

    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                f"{HUB_URL}/hub/api",
                headers=auth_headers(),
                timeout=2,
            )
            if response.status_code == 200:
                return
            last_error = f"HTTP {response.status_code}: {response.text[:300]}"
        except httpx.HTTPError as exc:
            last_error = repr(exc)
        time.sleep(1)

    log_tail = read_log(log_path)[-5000:]
    raise AssertionError(
        "JupyterHub did not become ready. "
        f"Last error: {last_error}\n\nHub log tail:\n{log_tail}"
    )


@pytest.fixture(scope="session")
def running_hub() -> Iterator[dict[str, Any]]:
    """Start a JupyterHub process and stop it after the test session."""
    if shutil.which("configurable-http-proxy") is None:
        pytest.skip("configurable-http-proxy is required for running Hub tests")

    root = repo_root()
    config_file = Path(__file__).with_name("jupyterhub_config.py")

    with tempfile.TemporaryDirectory(prefix="egi-hub-phase6-") as tmp:
        runtime_dir = Path(tmp)
        log_path = runtime_dir / "jupyterhub.log"

        env = os.environ.copy()
        env.update(
            {
                "PYTHONPATH": str(root),
                "JUPYTERHUB_TEST_RUNTIME_DIR": str(runtime_dir),
                "JUPYTERHUB_TEST_HUB_PORT": str(HUB_PORT),
                "JUPYTERHUB_TEST_TOKEN_ACQUIRER_PORT": str(TOKEN_ACQUIRER_PORT),
                "CONFIGPROXY_AUTH_TOKEN": "phase6-config-proxy-token",
            }
        )

        with log_path.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                [sys.executable, "-m", "jupyterhub", "-f", str(config_file)],
                cwd=root,
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )

        try:
            wait_for_hub_api(log_path)
            yield {"process": process, "log_path": log_path}
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=20)


@pytest.fixture
def unique_name() -> str:
    """Return a short unique name suitable for Hub users and groups."""
    return f"phase6-{uuid.uuid4().hex[:10]}"


def api_get(path: str, *, token: bool = True) -> httpx.Response:
    """Run a GET request against the Hub API."""
    headers = auth_headers() if token else None
    return httpx.get(f"{HUB_URL}{path}", headers=headers, timeout=5)


def api_post(
    path: str,
    *,
    json: dict[str, Any] | None = None,
    token: bool = True,
) -> httpx.Response:
    """Run a POST request against the Hub API."""
    headers = auth_headers() if token else None
    return httpx.post(f"{HUB_URL}{path}", headers=headers, json=json, timeout=5)


def api_delete(path: str, *, token: bool = True) -> httpx.Response:
    """Run a DELETE request against the Hub API."""
    headers = auth_headers() if token else None
    return httpx.delete(f"{HUB_URL}{path}", headers=headers, timeout=5)


def create_user(name: str) -> httpx.Response:
    """Create a Hub user and accept created or already-existing states."""
    response = api_post(f"/hub/api/users/{name}")
    assert response.status_code in {201, 409}
    return response


def delete_user(name: str) -> httpx.Response:
    """Delete a Hub user and accept deleted or already-missing states."""
    response = api_delete(f"/hub/api/users/{name}")
    assert response.status_code in {204, 404}
    return response


def create_group(name: str) -> httpx.Response:
    """Create a Hub group and accept created or already-existing states."""
    response = api_post(f"/hub/api/groups/{name}")
    assert response.status_code in {201, 409}
    return response


def delete_group(name: str) -> httpx.Response:
    """Delete a Hub group and accept deleted or already-missing states."""
    response = api_delete(f"/hub/api/groups/{name}")
    assert response.status_code in {204, 404}
    return response


def service_names(payload: Any) -> set[str]:
    """Extract service names from Hub API service-list payloads."""
    if isinstance(payload, dict):
        values = payload.values()
    else:
        values = payload
    return {item["name"] for item in values}
