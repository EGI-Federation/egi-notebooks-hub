"""
Phase 4 integration tests for the share_manager service.

These tests exercise the FastAPI endpoints in
`egi_notebooks_hub.services.share_manager` using a fake async HTTP client
that simulates the upstream JupyterHub API.
"""

import pytest
from fastapi.testclient import TestClient

from egi_notebooks_hub.services import share_manager

from . import DummyResponse, FakeAsyncClient


@pytest.fixture
def share_manager_client(monkeypatch):
    FakeAsyncClient.reset()
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)
    return TestClient(share_manager.app)


def upstream_url(path: str) -> str:
    return f"{share_manager.settings.jupyterhub_api_url.rstrip('/')}/{path.lstrip('/')}"


# phase4-services-1
# Component: share_manager /token_details endpoint
# Purpose: Verify the happy path where the service returns oauth_user data from
# the user's auth_state.
def test_token_details_returns_oauth_user_data(share_manager_client):
    FakeAsyncClient.responses = {
        upstream_url("user"): DummyResponse(
            json_data={
                "name": "alice",
                "kind": "user",
                "token_id": "tok-1",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
            }
        ),
        upstream_url("users/alice/tokens/tok-1"): DummyResponse(
            json_data={
                "oauth_client": "JupyterHub server at /user/alice/my-server/",
                "session_id": "sess-1",
                "user": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
            }
        ),
        upstream_url("users/alice?include_stopped_servers"): DummyResponse(
            json_data={
                "name": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
                "servers": {
                    "my-server": {"name": "my-server", "url": "/user/alice/my-server"}
                },
                "auth_state": {
                    "access_token": "egi-access-token",
                    "oauth_user": {"id": "alice@example.com"},
                },
            },
        ),
        upstream_url("shares/alice/my-server"): DummyResponse(json_data={"items": []}),
        upstream_url("share-codes/alice/my-server"): DummyResponse(
            json_data={"items": []}
        ),
    }

    response = share_manager_client.get(
        "/token_details", headers={"Authorization": "Bearer user-token"}
    )

    assert response.status_code == 200
    assert response.json() == {"id": "alice@example.com"}
    assert FakeAsyncClient.calls[0]["url"] == upstream_url("user")
    assert "authorization" in FakeAsyncClient.calls[0]["headers"]
    assert FakeAsyncClient.calls[1]["url"] == upstream_url("users/alice/tokens/tok-1")
    assert FakeAsyncClient.calls[2]["url"] == upstream_url(
        "users/alice?include_stopped_servers"
    )
    assert FakeAsyncClient.calls[3]["url"] == upstream_url(
        "share-codes/alice/my-server"
    )
    assert FakeAsyncClient.calls[4]["url"] == upstream_url("shares/alice/my-server")
    assert (
        FakeAsyncClient.calls[4]["headers"]["authorization"]
        == f"bearer {share_manager.settings.jupyterhub_api_token}"
    )


# phase4-services-2
# Component: share_manager /token_details endpoint
# Purpose: Ensure a missing oauth_user section produces a clear 404 response.
def test_token_details_returns_404_when_oauth_user_missing(share_manager_client):
    FakeAsyncClient.responses = {
        upstream_url("user"): DummyResponse(
            json_data={
                "name": "alice",
                "kind": "user",
                "token_id": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
            }
        ),
        upstream_url("users/alice/tokens/alice"): DummyResponse(
            json_data={
                "oauth_client": "Server at /user/alice/my-server",
                "session_id": "sess-1",
                "user": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
            }
        ),
        upstream_url("users/alice?include_stopped_servers"): DummyResponse(
            json_data={
                "name": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
                "servers": {
                    "my-server": {"name": "my-server", "url": "/user/alice/my-server"}
                },
                "auth_state": {},
            },
        ),
        upstream_url("shares/alice/my-server"): DummyResponse(json_data={"items": []}),
        upstream_url("share-codes/alice/my-server"): DummyResponse(
            json_data={"items": []}
        ),
    }

    response = share_manager_client.get(
        "/token_details", headers={"Authorization": "Bearer user-token"}
    )

    assert response.status_code == 404
    assert response.json()["message"] == "No user data available"


# phase4-services-3
# Component: share_manager /token endpoint
# Purpose: Validate the happy path where a valid server token returns the user's
# access token from auth_state.
def test_token_returns_access_token_for_valid_server_token(share_manager_client):
    FakeAsyncClient.responses = {
        upstream_url("user"): DummyResponse(
            json_data={
                "name": "alice",
                "kind": "user",
                "token_id": "tok-1",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
            }
        ),
        upstream_url("users/alice/tokens/tok-1"): DummyResponse(
            json_data={
                "oauth_client": "JupyterHub server at /user/alice/my-server/",
                "session_id": "sess-1",
                "user": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
            }
        ),
        upstream_url("users/alice?include_stopped_servers"): DummyResponse(
            json_data={
                "name": "alice",
                "scopes": [
                    "access:servers!server=alice/my-server",
                    "access:services!service=share-manager",
                    share_manager.settings.token_acquirer_scope,
                ],
                "servers": {
                    "my-server": {"name": "my-server", "url": "/user/alice/my-server"}
                },
                "auth_state": {
                    "access_token": "egi-access-token",
                    "oauth_user": {"id": "alice@example.com"},
                },
            },
        ),
        upstream_url("shares/alice/my-server"): DummyResponse(json_data={"items": []}),
        upstream_url("share-codes/alice/my-server"): DummyResponse(
            json_data={"items": []}
        ),
    }

    response = share_manager_client.get(
        "/token", headers={"Authorization": "Bearer user-token"}
    )

    assert response.status_code == 200
    assert response.json() == {"access_token": "egi-access-token"}
    assert FakeAsyncClient.calls[0]["url"] == upstream_url("user")
    assert FakeAsyncClient.calls[1]["url"] == upstream_url("users/alice/tokens/tok-1")
    assert FakeAsyncClient.calls[2]["url"] == upstream_url(
        "users/alice?include_stopped_servers"
    )
    assert FakeAsyncClient.calls[3]["url"] == upstream_url(
        "share-codes/alice/my-server"
    )
    assert FakeAsyncClient.calls[4]["url"] == upstream_url("shares/alice/my-server")
