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

# phase3-1
# Component: share_manager.get_user_token
# Purpose: Verify the normal Authorization header format used by most HTTP clients.
# Example pass case: the request contains 'Authorization: Bearer abc123' and the helper
# returns just 'abc123'.
# Example fail case: the helper keeps the 'Bearer' prefix, returns None, or rejects a
# perfectly valid bearer header.
def test_get_user_token_accepts_bearer_header():
    request = make_request({"Authorization": "Bearer abc123"})
    assert share_manager.get_user_token(request) == "abc123"


# phase3-2
# Component: share_manager.get_user_token
# Purpose: Document support for the alternative 'Token' scheme used in some JupyterHub
# contexts.
# Example pass case: 'Authorization: Token abc123' is accepted and the token string is
# returned.
# Example fail case: only 'Bearer' works and the 'Token' form is incorrectly rejected.
def test_get_user_token_accepts_token_scheme():
    request = make_request({"Authorization": "Token abc123"})
    assert share_manager.get_user_token(request) == "abc123"

# phase3-3
# Component: share_manager.get_user_token
# Purpose: Ensure the scheme parser is case-insensitive so clients are not required to
# match one exact capitalization.
# Example pass case: headers such as 'bEaReR abc123' still return 'abc123'.
# Example fail case: mixed-case schemes are rejected even though the token itself is
# valid.
def test_get_user_token_is_case_insensitive_for_scheme():
    request = make_request({"Authorization": "bEaReR abc123"})
    assert share_manager.get_user_token(request) == "abc123"

# phase3-4
# Component: share_manager.get_user_token
# Purpose: Verify that requests with no Authorization header are rejected instead of
# being treated like anonymous access.
# Example pass case: a missing header results in an HTTPException.
# Example fail case: the helper returns an empty string or silently accepts a request
# without credentials.
def test_get_user_token_rejects_missing_header():
    request = make_request()
    with pytest.raises(HTTPException) as exc:
        share_manager.get_user_token(request)
    assert exc.value.status_code == 401

# phase3-5
# Component: share_manager.get_user_token
# Purpose: Ensure malformed Authorization values are rejected early.
# Example pass case: a header without the expected two-part format raises an error.
# Example fail case: the helper splits incorrectly and returns a partial or invalid
# token.
def test_get_user_token_rejects_invalid_header_format():
    request = make_request({"Authorization": "Bearer"})
    with pytest.raises(HTTPException) as exc:
        share_manager.get_user_token(request)
    assert exc.value.status_code == 401

# phase3-6
# Component: share_manager.get_user_token
# Purpose: Confirm that unsupported authentication schemes are not accepted by mistake.
# Example pass case: 'Basic ...' causes an HTTPException.
# Example fail case: any unknown scheme is treated like a valid bearer token.
def test_get_user_token_rejects_unsupported_scheme():
    request = make_request({"Authorization": "Basic abc123"})
    with pytest.raises(HTTPException) as exc:
        share_manager.get_user_token(request)
    assert exc.value.status_code == 401

# phase3-7
# Component: share_manager.get_server_name
# Purpose: Verify extraction of the named server from a valid server-token descriptor.
# Example pass case: token_info describes '/user/alice/my-server/' and the helper
# returns 'my-server'.
# Example fail case: the parser returns None or a wrong server name for a valid named
# server token.
def test_get_server_name_extracts_named_server():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub server at /user/alice/my-server/",
    }
    assert share_manager.get_server_name(token_info) == "my-server"

# phase3-8
# Component: share_manager.get_server_name
# Purpose: Ensure the default unnamed server is not misclassified as a named server.
# Example pass case: token_info refers to the default server path and the helper returns
# None.
# Example fail case: the helper invents a server name for the default server.
def test_get_server_name_returns_none_for_default_server():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub server at /user/alice/",
    }
    assert share_manager.get_server_name(token_info) is None

# phase3-9
# Component: share_manager.get_server_name
# Purpose: Verify that required token metadata must be present before the token is
# treated as a valid server token.
# Example pass case: session_id is missing and the helper returns None.
# Example fail case: partial metadata is accepted and a server name is extracted from an
# otherwise invalid token structure.
def test_get_server_name_returns_none_when_session_missing():
    token_info = {
        "user": "alice",
        "oauth_client": "JupyterHub server at /user/alice/my-server/",
    }
    assert share_manager.get_server_name(token_info) is None

# phase3-10
# Component: share_manager.get_server_name
# Purpose: Ensure tokens without oauth_client metadata are rejected as non-server tokens.
# Example pass case: oauth_client is missing and the helper returns None.
# Example fail case: the helper crashes on a missing field or guesses a server name.
def test_get_server_name_returns_none_when_oauth_client_missing():
    token_info = {"user": "alice", "session_id": "sess-1"}
    assert share_manager.get_server_name(token_info) is None

# phase3-11
# Component: share_manager.get_server_name
# Purpose: Verify that generic user tokens are not mistaken for server tokens.
# Example pass case: oauth_client contains a non-server value and the helper returns
# None.
# Example fail case: any token with a user field is treated like a server token.
def test_get_server_name_returns_none_when_not_server_token():
    token_info = {
        "user": "alice",
        "session_id": "sess-1",
        "oauth_client": "JupyterHub",
    }
    assert share_manager.get_server_name(token_info) is None

# phase3-12
# Component: share_manager.get_server_name
# Purpose: Check that the server-token prefix matching is case-insensitive.
# Example pass case: a mixed-case variant of the expected prefix still yields the server
# name.
# Example fail case: valid tokens fail to parse only because of capitalization.
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

# phase3-13
# Component: share_manager.call_hub_api
# Purpose: Verify the common successful call path: build the outgoing request, attach the
# bearer token, and parse a JSON response.
# Example pass case: the upstream returns status 200 with JSON and the helper returns the
# decoded object.
# Example fail case: the Authorization header is missing, the wrong URL is called, or the
# response is not decoded from JSON.
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

# phase3-14
# Component: share_manager.call_hub_api
# Purpose: Ensure non-JSON successful responses are returned as raw bytes/content instead
# of causing JSON decode errors.
# Example pass case: upstream returns 200 with plain bytes and the helper returns those
# bytes unchanged.
# Example fail case: the helper always assumes JSON and crashes on raw content.
@pytest.mark.asyncio
async def test_call_hub_api_returns_raw_content_for_non_json(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeResponse(content=b"raw-bytes")
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)

    result = await share_manager.call_hub_api("users/alice")

    assert result == b"raw-bytes"

# phase3-15
# Component: share_manager.call_hub_api
# Purpose: Confirm that upstream failures are surfaced as HTTPException rather than being
# silently converted into empty responses.
# Example pass case: upstream returns 403 or 500 and the helper raises an exception with
# the same status information.
# Example fail case: non-200 responses are treated like success or their status is lost.
@pytest.mark.asyncio
async def test_call_hub_api_raises_http_exception_on_non_200(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.response = FakeResponse(status_code=404, content=b"missing")
    monkeypatch.setattr(share_manager.httpx, "AsyncClient", FakeAsyncClient)

    with pytest.raises(HTTPException) as exc:
        await share_manager.call_hub_api("users/alice")

    assert exc.value.status_code == 404
    assert exc.value.detail == "missing"

# phase3-16
# Component: share_manager.call_hub_api
# Purpose: Check that callers can override the default base URL and send request content
# and headers through the helper.
# Example pass case: the request goes to the supplied base_url and includes the provided
# content.
# Example fail case: the helper always uses the default service URL or drops the request
# body.
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

# phase3-17
# Component: share_manager /token endpoint
# Purpose: Validate the main success path: a user token identifies a server token with
# the required scope, the server is not shared, and the endpoint returns the stored EGI
# access token from auth_state.
# Example pass case: all upstream Hub API calls return the expected token metadata and
# auth_state contains access_token, so /token responds with 200 and that token.
# Example fail case: the endpoint rejects a valid non-shared server token or queries the
# wrong Hub API resources.
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

# phase3-18
# Component: share_manager /token endpoint
# Purpose: Ensure access is denied when the user token lacks the special scope required
# for the token-acquirer flow.
# Example pass case: token metadata contains unrelated scopes and /token responds 403.
# Example fail case: any server token is accepted even without the dedicated scope.
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

# phase3-19
# Component: share_manager /token endpoint
# Purpose: Verify that regular user tokens cannot be used where a server token is
# required.
# Example pass case: get_server_name cannot extract a server name and /token responds
# with 403 'no server token'.
# Example fail case: non-server tokens are accepted and can read another user's access
# token.
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

# phase3-20
# Component: share_manager /token endpoint
# Purpose: Check that shared servers are blocked from this endpoint, matching the design
# that only non-shared servers should retrieve the owner's access token.
# Example pass case: Hub API reports an existing share and /token returns 403.
# Example fail case: shared servers can still retrieve access tokens meant only for the
# private owner context.
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

# phase3-21
# Component: share_manager /token endpoint
# Purpose: Ensure a clear 404-style error is returned when the user exists but has no
# auth_state entry holding the desired token information.
# Example pass case: users/alice returns no auth_state and /token responds with 404.
# Example fail case: the endpoint returns 200 with empty data or crashes on missing
# auth_state.
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

# phase3-22
# Component: share_manager /token endpoint
# Purpose: Distinguish between auth_state existing and the access_token field actually
# being present.
# Example pass case: auth_state exists but lacks access_token, and /token returns 404.
# Example fail case: the endpoint returns a partial auth_state or incorrectly treats the
# refresh token as a substitute.
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

# phase3-23
# Component: share_manager POST /share-codes/{owner}/{server_name}
# Purpose: Verify the 'first share' workflow: if the server is not already shared, the
# service first revokes the old token and only then creates the share code.
# Example pass case: shares list is empty, token_revoke is called, and the share-code
# creation request is forwarded with the original body.
# Example fail case: revoke is skipped on the first share or the forwarded share-code
# request loses its payload.
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

# phase3-24
# Component: share_manager POST /share-codes/{owner}/{server_name}
# Purpose: Confirm that once a server is already shared, the service does not revoke the
# token again unnecessarily.
# Example pass case: shares list is non-empty, no revoke call is made, and the share code
# is created directly.
# Example fail case: every share-code request triggers an unnecessary revoke.
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

# phase3-25
# Component: share_manager wrapper endpoint
# Purpose: Verify that the generic forwarding wrapper passes through HTTP method, body,
# and uses the service API token for authenticated Hub API calls.
# Example pass case: a PATCH request arrives and call_hub_api sees the same path, body,
# method, and the configured API token.
# Example fail case: the method changes, body is dropped, or the wrong token is used.
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

# phase3-26
# Component: share_manager DELETE /share-codes/... endpoint
# Purpose: Ensure the delete endpoint wraps the correct downstream Hub API path and HTTP
# method.
# Example pass case: deleting /share-codes/alice/server1/code1 results in a downstream
# call to the exact same logical path using method delete.
# Example fail case: the path is malformed, truncated, or the request is sent with the
# wrong method.
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
