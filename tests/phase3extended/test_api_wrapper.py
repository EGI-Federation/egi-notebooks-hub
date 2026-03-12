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


def test_wrapper_exchanges_bearer_for_hub_token(client):
    response = client.get(
        "/services/jwt/hub/api/users/alice",
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


def test_wrapper_passes_request_through_when_jwt_login_returns_403(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=403, text="forbidden")
    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert "authorization" not in forwarded_call()["headers"]


def test_wrapper_returns_error_for_non_403_login_failure(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=500, text="boom")
    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 500
    assert "boom" in response.text


def test_wrapper_skips_login_when_authorization_header_missing(client):
    response = client.get("/services/jwt/hub/api/users/alice", headers={"X-Test": "1"})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert all(not c.get("url", "").endswith(api_wrapper.settings.jwt_login_suffix) for c in FakeAsyncClient.calls if c.get("method") == "get")
    assert forwarded_call()["headers"]["x-test"] == "1"


def test_wrapper_skips_login_for_non_bearer_authorization(client):
    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Token existing-hub-token"},
    )

    assert response.status_code == 200
    assert all(not c.get("url", "").endswith(api_wrapper.settings.jwt_login_suffix) for c in FakeAsyncClient.calls if c.get("method") == "get")
    assert "authorization" not in forwarded_call()["headers"]


def test_wrapper_strips_original_auth_header_before_forwarding_when_login_fails_403(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=403, text="forbidden")
    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token", "X-Other": "2"},
    )

    assert response.status_code == 200
    upstream_call = forwarded_call()
    assert "authorization" not in upstream_call["headers"]
    assert upstream_call["headers"]["x-other"] == "2"


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


def test_wrapper_forwards_put_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"put": True})
    response = client.put(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
        content=b"payload",
    )

    assert response.status_code == 200
    assert response.json() == {"put": True}
    assert forwarded_call()["method"] == "put"
    assert forwarded_call()["content"] == b"payload"


def test_wrapper_forwards_delete_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"deleted": True})
    response = client.delete(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"deleted": True}
    assert forwarded_call()["method"] == "delete"


def test_wrapper_forwards_options_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"options": True})
    response = client.options(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"options": True}
    assert forwarded_call()["method"] == "options"


def test_wrapper_forwards_head_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, content=b"", text="")
    response = client.head(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert forwarded_call()["method"] == "head"


def test_wrapper_forwards_trace_method(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"trace": True})
    response = client.request(
        "TRACE",
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"trace": True}
    assert forwarded_call()["method"] == "trace"


def test_wrapper_returns_raw_content_when_upstream_is_not_json(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, content=b"raw-response")
    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.content == b"raw-response"


def test_wrapper_uses_configured_timeout_for_upstream_client(client):
    client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    enter_events = [c for c in FakeAsyncClient.calls if c.get("event") == "enter"]
    assert any(e["kwargs"].get("timeout") == api_wrapper.settings.api_timeout for e in enter_events)


def test_wrapper_removes_service_prefix_from_path_before_forwarding(client):
    response = client.get(
        "/services/jwt/shares/alice/server1",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert forwarded_call()["url"] == "http://localhost:8000/hub/api/shares/alice/server1"
