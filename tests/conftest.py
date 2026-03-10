import os

import pytest
from traitlets.config import Config

from egi_notebooks_hub.egiauthenticator import EGICheckinAuthenticator


@pytest.fixture
def auth_config():
    c = Config()
    c.EGICheckinAuthenticator = Config(
        {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "allowed_groups": {"vo-2", "vo-1"},
            "auth_refresh_age": 300,
        }
    )
    return c


@pytest.fixture(autouse=True)
def clear_checkin_host_env(monkeypatch):
    monkeypatch.delenv("EGICHECKIN_HOST", raising=False)


@pytest.fixture
def authenticator(auth_config):
    return EGICheckinAuthenticator(config=auth_config)
