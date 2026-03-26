"""
Phase 4 integration tests for service-to-service flows.

These tests combine multiple service-level components and mocks to validate
complete request paths without a real Hub, IdP, or Kubernetes cluster.
The goal is to exercise realistic service behavior while still keeping the
tests fast, deterministic, and CI-friendly.
"""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient
from tornado.web import HTTPError

from egi_notebooks_hub.services import api_wrapper, token_acquirer


class DummyResponse:
    """
    Small helper that mimics enough of httpx.Response for our tests.

    Why this helper exists:
    - api_wrapper expects objects that support raise_for_status()
    - some tests inspect json()
    - some tests rely on raw content/text behavior

    This fake keeps those interactions explicit and easy to reason about.
    """

    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://dummy")
            response = httpx.Response(self.status_code, request=request, content=self.content)
            raise httpx.HTTPStatusError("error", request=request, response=response)

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("not json")


class FakeAsyncClient:
    """
    Fake httpx.AsyncClient used to drive end-to-end wrapper scenarios.

    Typical flow in these tests:
    1. first GET is the call to /jwt_login
    2. the next call is the forwarded upstream Hub API request

    The class stores every call in `calls` so tests can assert the exact
    sequence, URLs, headers, and methods that were used.
    """

    calls = []
    login_response = DummyResponse(status_code=200, json_data={"token": "hub-user-token"})
    forwarded_response = DummyResponse(status_code=200, json_data={"ok": True})

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    @classmethod
    def reset(cls):
        cls.calls = []
        cls.login_response = DummyResponse(status_code=200, json_data={"token": "hub-user-token"})
        cls.forwarded_response = DummyResponse(status_code=200, json_data={"ok": True})

    async def get(self, url, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "GET", "url": url, "headers": headers or {}, "kwargs": kwargs}
        )
        if url.endswith("/jwt_login"):
            return FakeAsyncClient.login_response
        return FakeAsyncClient.forwarded_response

    async def post(self, url, content=None, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "POST", "url": url, "content": content, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response

    async def put(self, url, content=None, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "PUT", "url": url, "content": content, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response

    async def delete(self, url, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "DELETE", "url": url, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response

    async def patch(self, url, content=None, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "PATCH", "url": url, "content": content, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response

    async def options(self, url, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "OPTIONS", "url": url, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response

    async def head(self, url, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "HEAD", "url": url, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response

    async def trace(self, url, headers=None, **kwargs):
        FakeAsyncClient.calls.append(
            {"method": "TRACE", "url": url, "headers": headers or {}, "kwargs": kwargs}
        )
        return FakeAsyncClient.forwarded_response


@pytest.fixture
def api_client(monkeypatch):
    """
    Provide a FastAPI TestClient wired to the fake async HTTP client.

    This fixture lets the tests exercise api_wrapper through real HTTP requests
    against the FastAPI app while still controlling all upstream behavior.
    """
    FakeAsyncClient.reset()
    monkeypatch.setattr(api_wrapper.httpx, "AsyncClient", FakeAsyncClient)
    return TestClient(api_wrapper.app)


def forwarded_call():
    """
    Return the last recorded fake upstream call.

    In successful wrapper tests this is the forwarded Hub API request that
    happens after jwt_login.
    """
    return FakeAsyncClient.calls[-1]


# phase4-services-1
# Component: api_wrapper end-to-end request flow
# Purpose: Verify the full happy path for Bearer JWT authentication.
# What this test checks:
# - the incoming request hits the wrapper
# - wrapper calls /jwt_login first
# - wrapper receives a Hub token
# - wrapper forwards the original request to /hub/api/... using that token
# - non-auth headers are preserved
# Example pass:
# - jwt_login returns {"token": "hub-user-token"} and the upstream call uses
#   Authorization: token hub-user-token.
# Example fail:
# - wrapper forwards the request without logging in, constructs the wrong URL,
#   or drops important headers like X-Test.
def test_wrapper_performs_full_login_then_forwards_request(api_client):
    """
    Full integration flow:
    - incoming Bearer JWT hits the wrapper
    - wrapper calls /jwt_login
    - wrapper receives a Hub token
    - wrapper forwards the real API request with Authorization: token ...
    """
    response = api_client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token", "X-Test": "1"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    login_call = FakeAsyncClient.calls[0]
    upstream_call = forwarded_call()

    assert login_call["url"] == "http://localhost:8000/hub/jwt_login"
    assert login_call["headers"]["authorization"] == "Bearer jwt-token"
    assert upstream_call["url"] == "http://localhost:8000/hub/api/users/alice"
    assert upstream_call["headers"]["authorization"] == "token hub-user-token"
    assert upstream_call["headers"]["x-test"] == "1"


# phase4-services-2
# Component: api_wrapper fallback behavior
# Purpose: Verify the special-case fallback when jwt_login rejects the request
# with HTTP 403.
# What this test checks:
# - jwt_login returns 403
# - wrapper does not fail immediately
# - wrapper still forwards the request
# - wrapper does not inject a Hub token into the forwarded request
# Example pass:
# - login endpoint returns 403 and the wrapper forwards the request without an
#   Authorization header.
# Example fail:
# - wrapper incorrectly raises 403 to the client or injects a token anyway.
def test_wrapper_falls_back_to_plain_forwarding_on_403_from_jwt_login(api_client):
    """
    Integration scenario:
    - jwt_login rejects the JWT with 403
    - wrapper does not fail hard
    - wrapper forwards request without injected Hub token
    """
    FakeAsyncClient.login_response = DummyResponse(status_code=403, content=b"forbidden")
    response = api_client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    upstream_call = forwarded_call()
    assert upstream_call["url"] == "http://localhost:8000/hub/api/users/alice"
    assert "authorization" not in upstream_call["headers"]


# phase4-services-3
# Component: api_wrapper error propagation
# Purpose: Verify that non-403 jwt_login failures are not silently swallowed.
# What this test checks:
# - jwt_login returns 500
# - wrapper propagates the failure to the client
# Example pass:
# - client receives 500 and the response body contains the upstream failure
#   message.
# Example fail:
# - wrapper treats 500 like 403 fallback, or hides the error and returns 200.
def test_wrapper_returns_error_for_non_403_jwt_login_failure(api_client):
    """
    Integration scenario:
    - jwt_login fails with 500
    - wrapper must propagate the failure as an HTTP error instead of silently
      forwarding the request
    """
    FakeAsyncClient.login_response = DummyResponse(status_code=500, content=b"hub login failed")
    response = api_client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 500
    assert "hub login failed" in response.text.lower()


# phase4-services-4
# Component: api_wrapper request forwarding with body
# Purpose: Verify that the wrapper preserves request body content after a
# successful login.
# What this test checks:
# - login succeeds
# - a POST request body is forwarded intact
# - the upstream call uses the expected URL and method
# Example pass:
# - POST JSON {"hello": "world"} appears in the forwarded content.
# Example fail:
# - the wrapper drops the body, changes the method, or mangles the JSON.
def test_wrapper_forwards_post_body_after_successful_login(api_client):
    """
    Integration scenario:
    - wrapper authenticates through jwt_login
    - then forwards a POST request with its original body intact
    """
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, json_data={"accepted": True})
    response = api_client.post(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token", "Content-Type": "application/json"},
        json={"hello": "world"},
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": True}
    upstream_call = forwarded_call()
    assert upstream_call["method"] == "POST"
    assert upstream_call["url"] == "http://localhost:8000/hub/api/users/alice"
    assert b'"hello":"world"' in upstream_call["content"] or b'"hello": "world"' in upstream_call["content"]


# phase4-services-5
# Component: api_wrapper non-JSON upstream handling
# Purpose: Document the current behavior when the upstream response body is not
# JSON-decodable.
# What this test checks:
# - wrapper returns a 200 response
# - the fallback payload is exposed to the client as a JSON string
# Example pass:
# - upstream raw bytes b"raw-response" become client-visible JSON
#   string "raw-response".
# Example fail:
# - wrapper crashes on non-JSON, or returns a completely different payload.
def test_wrapper_returns_json_string_for_non_json_upstream_payload(api_client):
    """
    This documents current wrapper behavior:
    if upstream content is not JSON, FastAPI serializes the returned bytes-like
    fallback as a JSON string.
    """
    FakeAsyncClient.forwarded_response = DummyResponse(status_code=200, content=b"raw-response")
    response = api_client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == "raw-response"


class RecordingHubAuth:
    """
    Fake HubAuthenticated helper for token_acquirer end-to-end tests.

    It records the Hub API requests made by the handler and returns
    preconfigured payloads for token metadata and user data.
    """

    def __init__(self, token_info=None, user_data=None):
        self.api_url = "http://hub.example/api"
        self.api_token = "hub-api-token"
        self.token_info = token_info if token_info is not None else {}
        self.user_data = user_data if user_data is not None else {}
        self.calls = []

    def _api_request(self, *args, **kwargs):
        raise AssertionError("Should not be called directly")

    def _call_coroutine(self, sync, api_request, method, url=None, headers=None):
        self.calls.append(
            {
                "sync": sync,
                "api_request": api_request,
                "method": method,
                "url": url,
                "headers": headers,
            }
        )
        if len(self.calls) == 1:
            return self.token_info
        if len(self.calls) == 2:
            return self.user_data
        raise AssertionError("Unexpected extra Hub API call")


def make_token_handler(token_info=None, user_data=None, current_user=None):
    """
    Build a lightweight fake TokenAcquirerHandler context.

    The fake object captures:
    - current_user lookup
    - Hub API interactions
    - response headers
    - response body writes
    """
    writes = []
    headers = []
    handler = SimpleNamespace()
    handler.hub_auth = RecordingHubAuth(token_info=token_info, user_data=user_data)
    handler.get_current_user = Mock(return_value=current_user or {"name": "alice", "token_id": "tok-1"})
    handler.set_header = Mock(side_effect=lambda name, value: headers.append((name, value)))
    handler.write = Mock(side_effect=lambda payload: writes.append(payload))
    handler._writes = writes
    handler._headers = headers
    return handler


GET_IMPL = getattr(
    token_acquirer.TokenAcquirerHandler.get,
    "__wrapped__",
    token_acquirer.TokenAcquirerHandler.get,
)


# phase4-services-6
# Component: token_acquirer end-to-end success flow
# Purpose: Verify the complete happy path for exchanging a valid server token
# into an EGI access token response.
# What this test checks:
# - current user identity is read
# - token metadata is fetched from the Hub API
# - token metadata is validated as a server token
# - user auth_state is fetched from the Hub API
# - access_token is returned as JSON
# Example pass:
# - oauth_client starts with "server at", session_id exists, and auth_state has
#   access_token.
# Example fail:
# - wrong Hub API URLs are used, access_token is not extracted, or response JSON
#   is malformed.
def test_token_acquirer_full_flow_returns_access_token_json():
    """
    End-to-end service flow:
    - get current user
    - fetch token metadata
    - validate server token metadata
    - fetch user auth_state
    - return JSON with access_token
    """
    handler = make_token_handler(
        token_info={
            "oauth_client": "server at /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    GET_IMPL(handler)

    assert handler.hub_auth.calls[0]["url"] == "http://hub.example/api/users/alice/tokens/tok-1"
    assert handler.hub_auth.calls[1]["url"] == "http://hub.example/api/users/alice"
    assert json.loads(handler._writes[0]) == {"access_token": "egi-access-token"}


# phase4-services-7
# Component: token_acquirer authorization validation
# Purpose: Ensure invalid server-token metadata is rejected early.
# What this test checks:
# - token metadata fails server-token validation
# - handler raises HTTP 401
# - the second Hub API call is never made
# Example pass:
# - oauth_client is "service token" and session_id exists -> 401 is raised.
# Example fail:
# - the handler continues anyway and tries to fetch user auth_state.
def test_token_acquirer_rejects_invalid_server_metadata_before_fetching_auth_state():
    """
    Integration scenario:
    token metadata is incomplete, so the handler must reject early and never
    perform the second Hub API call.
    """
    handler = make_token_handler(
        token_info={"oauth_client": "service token", "session_id": "sess-1"},
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    with pytest.raises(HTTPError) as exc_info:
        GET_IMPL(handler)

    assert exc_info.value.status_code == 401
    assert len(handler.hub_auth.calls) == 1
    handler.write.assert_not_called()


# phase4-services-8
# Component: token_acquirer missing access token path
# Purpose: Verify the failure mode when user auth_state exists but does not
# contain access_token.
# What this test checks:
# - valid token metadata still leads to the second Hub API call
# - missing access_token causes HTTP 404
# - no response body is written
# Example pass:
# - auth_state only contains refresh_token and the handler returns 404.
# Example fail:
# - the handler returns refresh_token instead, or pretends the request succeeded.
def test_token_acquirer_returns_404_when_auth_state_lacks_access_token():
    """
    Integration scenario:
    token metadata is valid, but auth_state does not provide access_token.
    This should fail with 404 after both Hub API calls.
    """
    handler = make_token_handler(
        token_info={
            "oauth_client": "server at /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"refresh_token": "only-refresh"}},
    )

    with pytest.raises(HTTPError) as exc_info:
        GET_IMPL(handler)

    assert exc_info.value.status_code == 404
    assert len(handler.hub_auth.calls) == 2
    handler.write.assert_not_called()
