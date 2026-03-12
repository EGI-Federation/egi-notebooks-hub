
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from egi_notebooks_hub.services import api_wrapper


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = text or (content.decode() if isinstance(content, (bytes, bytearray)) else str(content))

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


def test_wrapper_exchanges_bearer_for_hub_token(client):
    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token", "X-Test": "1"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert len(FakeAsyncClient.calls) == 2

    login_call = FakeAsyncClient.calls[0]
    forwarded_call = FakeAsyncClient.calls[1]

    assert login_call["url"] == "http://localhost:8000/hub/jwt_login"
    assert login_call["headers"]["authorization"] == "Bearer jwt-token"

    assert forwarded_call["url"] == "http://localhost:8000/hub/api/users/alice"
    assert forwarded_call["headers"]["authorization"] == "token hub-user-token"
    assert forwarded_call["headers"]["x-test"] == "1"


def test_wrapper_passes_request_through_when_jwt_login_returns_403(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=403, text="forbidden")

    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    forwarded_call = FakeAsyncClient.calls[-1]
    assert "authorization" not in forwarded_call["headers"]


def test_wrapper_returns_error_for_non_403_login_failure(client):
    FakeAsyncClient.login_response = DummyResponse(status_code=500, text="boom")

    response = client.get(
        "/services/jwt/hub/api/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 500
    assert "boom" in response.text


def test_wrapper_preserves_method_body_and_headers(client):
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"patched": True})

    response = client.patch(
        "/services/jwt/hub/api/shares/alice/server1",
        headers={"Authorization": "Bearer jwt-token", "Content-Type": "application/json", "X-Test": "1"},
        content=b'{"enabled": true}',
    )

    assert response.status_code == 200
    assert response.json() == {"patched": True}
    forwarded_call = FakeAsyncClient.calls[-1]
    assert forwarded_call["method"] == "patch"
    assert forwarded_call["content"] == b'{"enabled": true}'
    assert forwarded_call["headers"]["authorization"] == "token hub-user-token"
    assert forwarded_call["headers"]["x-test"] == "1"
