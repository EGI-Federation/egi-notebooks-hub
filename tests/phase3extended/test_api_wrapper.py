import httpx
import pytest
from fastapi.testclient import TestClient

from egi_notebooks_hub.services import api_wrapper


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = text or (
            content.decode() if isinstance(content, (bytes, bytearray)) else str(content)
        )

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON")
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://example.test")
            response = httpx.Response(self.status_code, request=request, text=self.text)
            raise httpx.HTTPStatusError("error", request=request, response=response)


class FakeAsyncClient:
    login_response = DummyResponse(status_code=200, json_data={"token": "hub-user-token"})
    forwarded_response = DummyResponse(status_code=200, json_data={"ok": True})
    calls = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        FakeAsyncClient.calls.append({"event": "enter", "kwargs": self.kwargs})
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "get", "url": url, "content": content, "headers": headers or {}})
        if url.endswith(api_wrapper.settings.jwt_login_suffix):
            return FakeAsyncClient.login_response
        return FakeAsyncClient.forwarded_response

    async def post(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "post", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

    async def delete(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "delete", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

    async def patch(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "patch", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

    async def put(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "put", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

    async def options(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "options", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

    async def head(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "head", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

    async def trace(self, url, content=None, headers=None):
        FakeAsyncClient.calls.append({"method": "trace", "url": url, "content": content, "headers": headers or {}})
        return FakeAsyncClient.forwarded_response

@pytest.fixture
def client(monkeypatch):
    FakeAsyncClient.calls = []
    FakeAsyncClient.login_response = DummyResponse(status_code=200, json_data={"token": "hub-user-token"})
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"ok": True})
    monkeypatch.setattr(api_wrapper.httpx, "AsyncClient", FakeAsyncClient)
    return TestClient(api_wrapper.app)


def forwarded_call():
    for call in reversed(FakeAsyncClient.calls):
        if call.get("method") in {"get", "post", "delete", "patch", "put", "options", "head", "trace"} and not call["url"].endswith(api_wrapper.settings.jwt_login_suffix):
            return call
    raise AssertionError("No forwarded call recorded")

# phase3-27
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify the main success path for Bearer-authenticated requests: exchange the
# incoming JWT for a Hub token via /jwt_login, then forward the original API request with
# 'Authorization: token <hub-token>'.
# Example pass case: /jwt_login returns {'token': 'hub-user-token'} and the forwarded
# request uses that token against the Hub API URL.
# Example fail case: the wrapper forwards the original bearer token unchanged, forgets to
# call /jwt_login, or targets the wrong URL.
def test_wrapper_exchanges_bearer_for_hub_token(client):
    response = client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token", "X-Test": "1"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    login_call = FakeAsyncClient.calls[1]
    upstream_call = forwarded_call()
    assert login_call["url"] == "http://localhost:8000/hub/jwt_login"
    assert login_call["headers"]["authorization"] == "Bearer jwt-token"
    assert upstream_call["url"] == "http://localhost:8000/hub/api/users/alice"
    assert upstream_call["headers"]["authorization"] == "token hub-user-token"
    assert upstream_call["headers"]["x-test"] == "1"

# phase3-28
# Component: api_wrapper generic forwarding endpoint
# Purpose: Document the fallback behavior when JWT login explicitly denies access with
# 403: the request is still forwarded, but without an Authorization header.
# Example pass case: /jwt_login returns 403 and the wrapper forwards the request while
# stripping authorization.
# Example fail case: a 403 login blocks the request entirely even though the service is
# supposed to allow pass-through in this branch.
def test_wrapper_passes_request_through_when_jwt_login_returns_403(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=403, text="forbidden")
    response = client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert "authorization" not in forwarded_call()["headers"]

# phase3-29
# Component: api_wrapper generic forwarding endpoint
# Purpose: Ensure that unexpected jwt_login failures (for example 500) are surfaced to the
# caller instead of silently ignored.
# Example pass case: /jwt_login returns 500 and the wrapper responds with 500.
# Example fail case: all login failures are treated like 403 and passed through.
def test_wrapper_returns_error_for_non_403_login_failure(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=500, text="boom")
    response = client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 500
    assert "boom" in response.text

# phase3-30
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify that requests without Authorization do not trigger a jwt_login attempt.
# Example pass case: no Authorization header is present, /jwt_login is never called, and
# the original request is forwarded as-is.
# Example fail case: the wrapper still attempts login or injects unexpected auth data.
def test_wrapper_skips_login_when_authorization_header_missing(client):
    response = client.get("/services/jwt/users/alice", headers={"X-Test": "1"})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert all(not c.get("url", "").endswith(api_wrapper.settings.jwt_login_suffix) for c in FakeAsyncClient.calls if c.get("method") == "get")
    assert forwarded_call()["headers"]["x-test"] == "1"

# phase3-31
# Component: api_wrapper generic forwarding endpoint
# Purpose: Confirm that only Bearer tokens trigger the JWT login exchange. Other schemes
# should pass through unchanged.
# Example pass case: Authorization: Token existing-hub-token does not call /jwt_login.
# Example fail case: any Authorization header is treated as a JWT that must be exchanged.
def test_wrapper_skips_login_for_non_bearer_authorization(client):
    response = client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Token existing-hub-token"},
    )

    assert response.status_code == 200
    assert all(not c.get("url", "").endswith(api_wrapper.settings.jwt_login_suffix) for c in FakeAsyncClient.calls if c.get("method") == "get")
    assert "authorization" not in forwarded_call()["headers"]

# phase3-32
# Component: api_wrapper generic forwarding endpoint
# Purpose: Check that after a 403 jwt_login result, the original Bearer header is removed
# before the request is forwarded upstream.
# Example pass case: X-Other remains, Authorization disappears.
# Example fail case: the forbidden bearer token leaks to the upstream Hub API.
def test_wrapper_strips_original_auth_header_before_forwarding_when_login_fails_403(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=403, text="forbidden")
    response = client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token", "X-Other": "2"},
    )

    assert response.status_code == 200
    upstream_call = forwarded_call()
    assert "authorization" not in upstream_call["headers"]
    assert upstream_call["headers"]["x-other"] == "2"

# phase3-33
# Component: api_wrapper generic forwarding endpoint
# Purpose: Ensure PATCH requests keep their method, body, and custom headers during the
# exchange-and-forward flow.
# Example pass case: a JSON PATCH body reaches the upstream request unchanged and custom
# headers are preserved next to the exchanged token.
# Example fail case: PATCH is converted to another method, body is lost, or headers are
# dropped.
def test_wrapper_preserves_method_body_and_headers_for_patch(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"patched": True})
    response = client.patch(
        "/services/jwt/hub/api/shares/alice/server1",
        headers={"Authorization": "Bearer jwt-token", "Content-Type": "application/json", "X-Test": "1"},
        content=b'{"enabled": true}',
    )

    assert response.status_code == 200
    assert response.json() == {"patched": True}
    upstream_call = forwarded_call()
    assert upstream_call["method"] == "patch"
    assert upstream_call["content"] == b'{"enabled": true}'
    assert upstream_call["headers"]["authorization"] == "token hub-user-token"
    assert upstream_call["headers"]["x-test"] == "1"

# phase3-34
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify that PUT requests are forwarded with the correct method and payload.
# Example pass case: a PUT request remains PUT when sent upstream.
# Example fail case: method mapping is incomplete and PUT either fails or is sent as
# POST/GET.
def test_wrapper_forwards_put_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"put": True})
    response = client.put(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
        content=b"payload",
    )

    assert response.status_code == 200
    assert response.json() == {"put": True}
    assert forwarded_call()["method"] == "put"
    assert forwarded_call()["content"] == b"payload"

# phase3-35
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify forwarding support for DELETE requests.
# Example pass case: a DELETE request is forwarded as DELETE.
# Example fail case: the wrapper lacks delete support or forwards with the wrong method.
def test_wrapper_forwards_delete_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"deleted": True})
    response = client.delete(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"deleted": True}
    assert forwarded_call()["method"] == "delete"

# phase3-36
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify forwarding support for OPTIONS requests.
# Example pass case: an OPTIONS request is forwarded as OPTIONS.
# Example fail case: preflight-style requests are blocked or mapped incorrectly.
def test_wrapper_forwards_options_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"options": True})
    response = client.options(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"options": True}
    assert forwarded_call()["method"] == "options"

# phase3-37
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify forwarding support for HEAD requests.
# Example pass case: a HEAD request reaches upstream with method head and returns 200.
# Example fail case: the wrapper tries to parse a HEAD body like JSON or routes it via
# GET instead.
def test_wrapper_forwards_head_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, content=b"", text="")
    response = client.head(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert forwarded_call()["method"] == "head"

# phase3-38
# Component: api_wrapper generic forwarding endpoint
# Purpose: Verify forwarding support for TRACE requests.
# Example pass case: TRACE is sent upstream as TRACE and the JSON response is returned.
# Example fail case: unusual HTTP verbs are not supported and TRACE fails unexpectedly.
def test_wrapper_forwards_trace_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"trace": True})
    response = client.request(
        "TRACE",
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"trace": True}
    assert forwarded_call()["method"] == "trace"

# phase3-39
# Component: api_wrapper generic forwarding endpoint
# Purpose: Ensure successful upstream responses that are not JSON are returned in a raw
# form rather than causing JSON parsing failures.
# Example pass case: upstream returns plain bytes and the client receives those bytes.
# Example fail case: the wrapper always forces JSON decoding and breaks on binary/plain
# text content.
def test_wrapper_returns_raw_content_when_upstream_is_not_json(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, content=b"raw-response")
    response = client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == "raw-response"

# phase3-40
# Component: api_wrapper HTTP client creation
# Purpose: Verify that the wrapper passes the configured api_timeout into the async HTTP
# client so slow upstream calls are bounded consistently.
# Example pass case: AsyncClient is constructed with timeout equal to settings.api_timeout.
# Example fail case: timeout is omitted, hardcoded elsewhere, or differs from settings.
def test_wrapper_uses_configured_timeout_for_upstream_client(client):
    client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    enter_events = [c for c in FakeAsyncClient.calls if c.get("event") == "enter"]
    assert any(e["kwargs"].get("timeout") == api_wrapper.settings.api_timeout for e in enter_events)

# phase3-41
# Component: api_wrapper path rewriting
# Purpose: Check that the service-specific prefix (/services/jwt/) is removed before the
# request is forwarded to the Hub API. The upstream should see only the logical Hub path.
# Example pass case: '/services/jwt/shares/alice/server1' becomes
# 'http://localhost:8000/hub/api/shares/alice/server1'.
# Example fail case: the forwarded URL still contains the service prefix or loses part of
# the remaining path.
def test_wrapper_removes_service_prefix_from_path_before_forwarding(client):
    response = client.get(
        "/services/jwt/shares/alice/server1",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert forwarded_call()["url"] == "http://localhost:8000/hub/api/shares/alice/server1"
