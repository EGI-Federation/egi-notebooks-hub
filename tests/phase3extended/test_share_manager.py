import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from egi_notebooks_hub.services import share_manager


@pytest.fixture
def client():
    return TestClient(share_manager.app)


def make_request(headers=None):
    raw_headers = []
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode(), v.encode()))
    return Request({"type": "http", "headers": raw_headers})


def test_get_user_token_accepts_bearer_header():
    request = make_request({"Authorization": "Bearer abc123"})
    assert share_manager.get_user_token(request) == "abc123"


def test_get_user_token_accepts_token_scheme():
    request = make_request({"Authorization": "Token abc123"})
    assert share_manager.get_user_token(request) == "abc123"


def test_get_user_token_is_case_insensitive_for_scheme():
    request = make_request({"Authorization": "bEaReR abc123"})
    assert share_manager.get_user_token(request) == "abc123"


def test_get_user_token_rejects_missing_header():
    request = make_request()
    with pytest.raises(HTTPException) as exc:
        share_manager.get_user_token(request)
    assert exc.value.status_code == 401


def test_get_user_token_rejects_invalid_header_format():
    request = make_request({"Authorization": "Bearer"})
    with pytest.raises(HTTPException) as exc:
        share_manager.get_user_token(request)
    assert exc.value.status_code == 401


def test_get_user_token_rejects_unsupported_scheme():
    request = make_request({"Authorization": "Basic abc123"})
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


def test_get_server_name_returns_none_when_session_missing():
    token_info = {
        "user": "alice",
        "oauth_client": "JupyterHub server at /user/alice/my-server/",
    }
    assert share_manager.get_server_name(token_info) is None


def test_get_server_name_returns_none_when_oauth_client_missing():
    token_info = {"user": "alice", "session_id": "sess-1"}
    assert share_manager.get_server_name(token_info) is None


def test_get_server_name_returns_none_when_not_server_token():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub",
    }
    assert share_manager.get_server_name(token_info) is None


def test_get_server_name_accepts_case_insensitive_prefix():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "server at /user/alice/my-server/",
    }
    assert share_manager.get_server_name(token_info) == "my-server"


class FakeAsyncClient:
    response = None
    calls = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, content=None, headers=None):
        self.calls.append(("get", url, content, headers or {}))
        return self.response

    async def post(self, url, content=None, headers=None):
        self.calls.append(("post", url, content, headers or {}))
        return self.response


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON")
        return self._json_data


@pytest.mark.asyncio
async def test_call_hub_api_sends_bearer_token_and_returns_json(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeResponse(json_data={"ok": True})
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)

    result = await share_manager.call_hub_api("users/alice", token="abc")

    assert result == {"ok": True}
    method, url, content, headers = FakeAsyncClient.calls[-1]
    assert method == "get"
    assert url.endswith("/hub/api/users/alice")
    assert headers["authorization"] == "bearer abc"
    assert content is None


@pytest.mark.asyncio
async def test_call_hub_api_returns_raw_content_for_non_json(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeResponse(content=b"raw-bytes")
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)

    result = await share_manager.call_hub_api("users/alice")

    assert result == b"raw-bytes"


@pytest.mark.asyncio
async def test_call_hub_api_raises_http_exception_on_non_200(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeResponse(status_code=404, content=b"missing")
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)

    with pytest.raises(HTTPException) as exc:
        await share_manager.call_hub_api("users/alice")

    assert exc.value.status_code == 404
    assert exc.value.detail == "missing"


@pytest.mark.asyncio
async def test_call_hub_api_uses_custom_base_url_and_content(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeResponse(json_data={"created": True})
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)

    result = await share_manager.call_hub_api(
        "/token_revoke",
        base_url="http://hub.example/hub",
        content=b"payload",
        method="post",
        headers={"x-test": "1"},
        token="abc",
    )

    assert result == {"created": True}
    method, url, content, headers = FakeAsyncClient.calls[-1]
    assert method == "post"
    assert url == "http://hub.example/hub/token_revoke"
    assert content == b"payload"
    assert headers["x-test"] == "1"
    assert headers["authorization"] == "bearer abc"


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


def test_get_token_rejects_non_server_token(client, monkeypatch):
    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        if path == "user":
            return {"name": "alice", "token_id": "tok-1"}
        if path == "users/alice/tokens/tok-1":
            return {"oauth_client": "JupyterHub", "session_id": "sess-1", "user": "alice", "scopes": [share_manager.settings.token_acquirer_scope]}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)
    response = client.get("/token", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 403
    assert "no server token" in response.text.lower()


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
    assert "server is shared" in response.text.lower()


def test_get_token_returns_404_when_auth_state_missing(client, monkeypatch):
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
            return {"items": []}
        if path == "users/alice":
            return {}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)
    response = client.get("/token", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 404
    assert "No access token" in response.text


def test_get_token_returns_404_when_access_token_missing(client, monkeypatch):
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
            return {"items": []}
        if path == "users/alice":
            return {"auth_state": {"refresh_token": "x"}}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)
    response = client.get("/token", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 404


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
    assert [c["path"] for c in calls] == ["shares/alice/my-server", "token_revoke", "/share-codes/alice/my-server"]
    assert calls[1]["base_url"] == share_manager.settings.jupyterhub_url
    assert calls[2]["method"] == "post"
    assert calls[2]["token"] == share_manager.settings.api_token
    assert calls[2]["content"] == b'{"expires_in": 3600}'


def test_create_share_code_skips_revoke_when_server_already_shared(client, monkeypatch):
    calls = []

    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        calls.append(path)
        if path == "shares/alice/my-server":
            return {"items": [{"code": "existing"}]}
        if path == "/share-codes/alice/my-server":
            return {"code": "share-code"}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)
    response = client.post(
        "/share-codes/alice/my-server",
        headers={"Authorization": "Bearer user-token"},
        content=b'{}',
    )

    assert response.status_code == 200
    assert response.json() == {"code": "share-code"}
    assert calls == ["shares/alice/my-server", "/share-codes/alice/my-server"]


def test_call_wrapper_forwards_method_body_and_api_token(client, monkeypatch):
    seen = {}

    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        seen.update({
            "path": path,
            "base_url": base_url,
            "content": content,
            "method": method,
            "headers": headers,
            "token": token,
        })
        return {"ok": True}

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)
    response = client.patch(
        "/shares/alice/server1",
        headers={"Authorization": "Bearer user-token", "Content-Type": "application/json"},
        content=b'{"enabled": true}',
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert seen["path"] == "shares/alice/server1"
    assert seen["method"] == "PATCH".lower()
    assert seen["content"] == b'{"enabled": true}'
    assert seen["token"] == share_manager.settings.api_token


def test_delete_share_codes_wraps_correct_path(client, monkeypatch):
    seen = {}

    async def fake_call_hub_api(path, base_url=None, content=None, method="get", headers=None, token=None):
        seen.update({"path": path, "method": method, "token": token})
        return {"deleted": True}

    monkeypatch.setattr(share_manager, "call_hub_api", fake_call_hub_api)
    response = client.delete("/share-codes/alice/server1/code1", headers={"Authorization": "Bearer user-token"})

    assert response.status_code == 200
    assert response.json() == {"deleted": True}
    assert seen == {"path": "share-codes/alice/server1/code1", "method": "delete", "token": share_manager.settings.api_token}
