
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from egi_notebooks_hub.services import share_manager


@pytest.fixture
def client():
    return TestClient(share_manager.app)


def test_get_user_token_accepts_bearer_header():
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer abc123")]}
    request = __import__("starlette.requests", fromlist=["Request"]).Request(scope)

    assert share_manager.get_user_token(request) == "abc123"


def test_get_user_token_rejects_missing_header():
    scope = {"type": "http", "headers": []}
    request = __import__("starlette.requests", fromlist=["Request"]).Request(scope)

    with pytest.raises(HTTPException) as exc:
        share_manager.get_user_token(request)

    assert exc.value.status_code == 401


def test_get_server_name_extracts_named_server():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub server at /user/alice/my-server/",
    }

    assert share_manager.get_server_name(token_info) == "my-server"


def test_get_server_name_returns_none_for_default_server():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub server at /user/alice/",
    }

    assert share_manager.get_server_name(token_info) is None


def test_get_server_name_returns_none_when_token_is_not_server_token():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub",  # not a server token description
    }

    assert share_manager.get_server_name(token_info) is None


def test_get_token_returns_access_token_for_non_shared_server(client, monkeypatch):
    calls = []

    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        calls.append({"path": path, "base_url": base_url, "method": method, "token": token})
        if path == "user":
            return {"name": "alice", "token_id": "tok-1"}
        if path == "users/alice/tokens/tok-1":
            return {
                "oauth_client": "JupyterHub server at /user/alice/my-server/",
                "session_id": "sess-1",
                "user": "alice",
                "scopes": [share_manager.settings.token_acquirer_scope],
            }
        if path == "shares/alice/my-server":
            return {"items": []}
        if path == "users/alice":
            return {"auth_state": {"access_token": "egi-access-token"}}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)

    response = client.get("/token", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 200
    assert response.json() == {"access_token": "egi-access-token"}
    assert [c["path"] for c in calls] == [
        "user",
        "users/alice/tokens/tok-1",
        "shares/alice/my-server",
        "users/alice",
    ]
    assert calls[0]["token"] == "user-token"
    assert calls[-1]["token"] == share_manager.settings.api_token


def test_get_token_rejects_missing_scope(client, monkeypatch):
    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        if path == "user":
            return {"name": "alice", "token_id": "tok-1"}
        if path == "users/alice/tokens/tok-1":
            return {
                "oauth_client": "JupyterHub server at /user/alice/my-server/",
                "session_id": "sess-1",
                "user": "alice",
                "scopes": ["something-else"],
            }
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)

    response = client.get("/token", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 403
    assert share_manager.settings.token_acquirer_scope in response.text


def test_get_token_rejects_shared_server(client, monkeypatch):
    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        if path == "user":
            return {"name": "alice", "token_id": "tok-1"}
        if path == "users/alice/tokens/tok-1":
            return {
                "oauth_client": "JupyterHub server at /user/alice/my-server/",
                "session_id": "sess-1",
                "user": "alice",
                "scopes": [share_manager.settings.token_acquirer_scope],
            }
        if path == "shares/alice/my-server":
            return {"items": [{"code": "abc"}]}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)

    response = client.get("/token", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 403
    assert "server is shared" in response.text


def test_create_share_code_revokes_token_on_first_share(client, monkeypatch):
    calls = []

    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        calls.append({
            "path": path,
            "base_url": base_url,
            "method": method,
            "headers": headers or {},
            "token": token,
            "content": content,
        })
        if path == "shares/alice/my-server":
            return {"items": []}
        if path == "token_revoke":
            return {"status": "revoked"}
        if path == "/share-codes/alice/my-server":
            return {"code": "share-code"}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)

    response = client.post(
        "/share-codes/alice/my-server",
        headers={"Authorization": "Bearer user-token", "Content-Type": "application/json"},
        content=b'{"expires_in": 3600}',
    )

    assert response.status_code == 200
    assert response.json() == {"code": "share-code"}
    assert [c["path"] for c in calls] == [
        "shares/alice/my-server",
        "token_revoke",
        "/share-codes/alice/my-server",
    ]
    assert calls[1]["base_url"] == share_manager.settings.jupyterhub_url
    assert calls[2]["method"] == "post"
    assert calls[2]["token"] == share_manager.settings.api_token
    assert calls[2]["content"] == b'{"expires_in": 3600}'
