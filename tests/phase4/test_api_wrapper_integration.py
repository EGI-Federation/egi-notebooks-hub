"""
Phase 4 integration tests for service-to-service flows.

These tests combine multiple service-level components and mocks to validate
complete request paths without a real Hub, IdP, or Kubernetes cluster.
The goal is to exercise realistic service behavior while still keeping the
tests fast, deterministic, and CI-friendly.
"""

import pytest
from fastapi.testclient import TestClient

from egi_notebooks_hub.services import api_wrapper

from . import DummyResponse, FakeAsyncClient


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
    FakeAsyncClient.login_response = DummyResponse(
        status_code=403, content=b"forbidden"
    )
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
    FakeAsyncClient.login_response = DummyResponse(
        status_code=500, content=b"hub login failed"
    )
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
    FakeAsyncClient.forwarded_response = DummyResponse(
        status_code=200, json_data={"accepted": True}
    )
    response = api_client.post(
        "/services/jwt/users/alice",
        headers={
            "Authorization": "Bearer jwt-token",
            "Content-Type": "application/json",
        },
        json={"hello": "world"},
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": True}
    upstream_call = forwarded_call()
    assert upstream_call["method"] == "POST"
    assert upstream_call["url"] == "http://localhost:8000/hub/api/users/alice"
    assert (
        b'"hello":"world"' in upstream_call["content"]
        or b'"hello": "world"' in upstream_call["content"]
    )


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
    FakeAsyncClient.forwarded_response = DummyResponse(
        status_code=200, content=b"raw-response"
    )
    response = api_client.get(
        "/services/jwt/users/alice",
        headers={"Authorization": "Bearer jwt-token"},
    )

    assert response.status_code == 200
    assert response.json() == "raw-response"
