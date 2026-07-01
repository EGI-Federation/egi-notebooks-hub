"""
Unified JupyterHub configuration used by Phase 6 running-Hub tests.

The same config supports:
- Hub API and service tests
- Hub user/group tests
- Hub spawner lifecycle tests
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from jupyterhub.auth import DummyAuthenticator

from egi_notebooks_hub.egispawner import EGISpawner

try:
    c: Any = get_config()  # type: ignore[name-defined]  # noqa: F821
except NameError:
    c = None

runtime_dir = Path(os.environ["JUPYTERHUB_TEST_RUNTIME_DIR"])
runtime_dir.mkdir(parents=True, exist_ok=True)

hub_port = int(os.environ.get("JUPYTERHUB_TEST_HUB_PORT", "18000"))
share_manager_port = int(os.environ.get("JUPYTERHUB_TEST_SHARE_MANAGER_PORT", "18010"))
spawner_events_file = runtime_dir / "spawner-events.jsonl"


class Phase6RecordingEGISpawner(EGISpawner):
    """EGISpawner subclass used by running-Hub lifecycle tests."""

    def _record_event(self, event, **extra):
        payload = {
            "event": event,
            "user": self.user.name,
            "spawner_class": type(self).__name__,
            "namespace": getattr(self, "namespace", None),
            "token_secret_name": getattr(self, "token_secret_name", None),
            "token_secret_volume_name": getattr(
                self,
                "_token_secret_volume_name",
                None,
            ),
            "token_mount_path": getattr(self, "token_mount_path", None),
            "mount_secrets_volume": getattr(self, "mount_secrets_volume", None),
            "pvc_name": getattr(self, "pvc_name", None),
            "timestamp": time.time(),
        }
        payload.update(extra)
        with spawner_events_file.open("a", encoding="utf-8") as events:
            events.write(json.dumps(payload, sort_keys=True) + "\n")

    @staticmethod
    def _free_port():
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        _, port = sock.getsockname()
        sock.close()
        return port

    async def start(self):
        server_dir = runtime_dir / f"server-{self.user.name}-{self.name or 'default'}"
        server_dir.mkdir(parents=True, exist_ok=True)
        (server_dir / "index.html").write_text(
            f"phase6 user server for {self.user.name}\n",
            encoding="utf-8",
        )

        port = self._free_port()
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "http.server",
                str(port),
                "--bind",
                "127.0.0.1",
                "--directory",
                str(server_dir),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.phase6_process = process
        self.phase6_port = port
        self._record_event(
            "start",
            port=port,
            pid=process.pid,
            server_name=self.name,
        )

        return "127.0.0.1", port

    async def stop(self, now=False):
        process = getattr(self, "phase6_process", None)
        if process is not None and process.poll() is None:
            if now:
                process.kill()
            else:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)

        self._record_event("stop", now=now, server_name=self.name)

    async def poll(self):
        process = getattr(self, "phase6_process", None)
        if process is None:
            return 0
        return process.poll()


c.JupyterHub.bind_url = f"http://127.0.0.1:{hub_port}"
c.JupyterHub.hub_ip = "127.0.0.1"
c.JupyterHub.hub_connect_ip = "127.0.0.1"
c.JupyterHub.db_url = f"sqlite:///{runtime_dir / 'jupyterhub.sqlite'}"
c.JupyterHub.cookie_secret_file = str(runtime_dir / "jupyterhub_cookie_secret")
c.JupyterHub.pid_file = str(runtime_dir / "jupyterhub.pid")
c.JupyterHub.log_level = "DEBUG"
c.JupyterHub.allow_named_servers = True

c.JupyterHub.authenticator_class = DummyAuthenticator
c.Authenticator.admin_users = {"alice"}
c.Authenticator.allowed_users = {"alice"}

c.JupyterHub.spawner_class = Phase6RecordingEGISpawner
c.KubeSpawner.namespace = os.environ.get("JUPYTERHUB_TEST_K8S_NAMESPACE", "default")

c.JupyterHub.services = [
    {
        "name": "test-admin",
        "api_token": "phase6-test-admin-token",
    },
    {
        "name": "share-manager",
        "url": f"http://127.0.0.1:{share_manager_port}",
        "command": [
            sys.executable,
            "-m",
            "uvicorn",
            "egi_notebooks_hub.services.share_manager:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(share_manager_port),
        ],
        "environment": {
            "JUPYTERHUB_SERVICE_PREFIX": "/services/share-manager",
            "JUPYTERHUB_API_URL": f"http://127.0.0.1:{hub_port}/hub/api",
            "JUPYTERHUB_API_TOKEN": "phase6-test-admin-token",
        },
    },
]

c.JupyterHub.load_roles = [
    {
        "name": "admin",
        "services": ["test-admin"],
    },
    {
        "name": "share-manager",
        "scopes": [
            "read:users",
            "read:servers",
            "read:tokens",
            "admin:auth_state",
            "shares",
        ],
        "services": ["share-manager"],
    },
]
