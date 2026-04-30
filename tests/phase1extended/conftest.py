# Phase 1 fixtures for EGICheckinAuthenticator and related handler tests.
# These helpers are intentionally kept small and stable so individual tests can focus
# on one behavior at a time without repeatedly rebuilding the same configuration.

import pytest
from traitlets.config import Config

from egi_notebooks_hub.egiauthenticator import EGICheckinAuthenticator, EOSCNodeAuthenticator


@pytest.fixture(autouse=True)
def clear_checkin_host_env(monkeypatch):
    monkeypatch.delenv("EGICHECKIN_HOST", raising=False)


@pytest.fixture
def auth_config():
    c = Config()
    c.EGICheckinAuthenticator = Config(
        {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "allowed_groups": {"vo-1", "vo-2"},
            "auth_refresh_age": 300,
            "auth_refresh_leeway": 60,
        }
    )
    return c


@pytest.fixture
def authenticator(auth_config):
    return EGICheckinAuthenticator(config=auth_config)


@pytest.fixture
def eosc_authenticator():
    c = Config()
    c.EOSCNodeAuthenticator = Config(
        {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "allowed_groups": {"vo-1", "vo-2"},
        }
    )
    return EOSCNodeAuthenticator(config=c)
