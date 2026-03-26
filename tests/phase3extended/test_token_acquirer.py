"""
Integration-style service tests for the token acquirer component.

These tests exercise the public behavior of the Tornado handler and the service
bootstrap function without starting a real JupyterHub instance or a real HTTP
server. The goal is to verify that the token acquirer performs the correct Hub
API calls, validates authorization metadata correctly, and returns the expected
JSON payload or HTTP error in each scenario.
"""

import json
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from tornado.web import HTTPError

from egi_notebooks_hub.services import token_acquirer


# The handler is written as a Tornado RequestHandler method. In tests we want to
# call the underlying implementation directly with a lightweight fake handler
# object instead of constructing a full Tornado application and request cycle.
GET_IMPL = getattr(token_acquirer.TokenAcquirerHandler.get, "__wrapped__", token_acquirer.TokenAcquirerHandler.get)
class RecordingHubAuth:
    """
    Small fake replacement for the Hub auth object used by TokenAcquirerHandler.

    The real handler uses hub_auth._call_coroutine(...) twice:
    1. to fetch token metadata from the Hub API
    2. to fetch user data (including auth_state) from the Hub API

    This fake object records every call so tests can assert which URLs, headers,
    and options were used, and it returns preconfigured payloads for the first
    and second call.
    """

    def __init__(self, token_info=None, user_data=None):
        self.api_url = "http://hub.example/api"
        self.api_token = "hub-api-token"
        self.token_info = token_info if token_info is not None else {}
        self.user_data = user_data if user_data is not None else {}
        self.calls = []

    def _api_request(self, *args, **kwargs):
        raise AssertionError("This helper should not be called directly in tests")

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


def make_handler(token_info=None, user_data=None, current_user=None):
    """
    Build a lightweight fake handler object with the minimal attributes and
    methods needed by TokenAcquirerHandler.get().

    The handler records:
    - outgoing Hub API calls through RecordingHubAuth
    - response headers set by the handler
    - response body written by the handler

    This lets tests inspect both internal behavior and external output.
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


# phase3-token-1
# Component: TokenAcquirerHandler.get
# Purpose: Verify the happy path for an authorized named-server token.
# What it checks:
# - the handler reads token metadata from the Hub API
# - the handler reads the user model from the Hub API
# - the handler extracts access_token from auth_state
# - the response is returned as JSON with the expected content-type header
# Example pass:
# - oauth_client starts with "server at", session_id is present, and auth_state
#   contains access_token -> the test should return {"access_token": "..."}.
# Example fail:
# - the handler builds a wrong Hub API URL, omits the header, or returns a
#   different JSON payload.
def test_get_returns_access_token_json_for_authorized_server_token():
    handler = make_handler(
        token_info={
            "oauth_client": "server at /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    GET_IMPL(handler)

    assert handler.get_current_user.called
    assert handler.hub_auth.calls[0]["method"] == "GET"
    assert handler.hub_auth.calls[0]["url"] == "http://hub.example/api/users/alice/tokens/tok-1"
    assert handler.hub_auth.calls[0]["headers"] == {"Authorization": "token hub-api-token"}

    assert handler.hub_auth.calls[1]["method"] == "GET"
    assert handler.hub_auth.calls[1]["url"] == "http://hub.example/api/users/alice"
    assert handler.hub_auth.calls[1]["headers"] == {"Authorization": "token hub-api-token"}

    handler.set_header.assert_called_once_with("content-type", "application/json")
    handler.write.assert_called_once()
    assert json.loads(handler._writes[0]) == {"access_token": "egi-access-token"}


# phase3-token-2
# Component: TokenAcquirerHandler.get
# Purpose: Confirm that server-token detection is case-insensitive.
# What it checks:
# - uppercase "SERVER AT" is still treated as a valid server token marker.
# Example pass:
# - oauth_client is "SERVER AT /user/alice/lab/" and access_token exists.
# Example fail:
# - the implementation requires lowercase only and wrongly rejects uppercase
#   metadata.
def test_get_accepts_uppercase_server_prefix():
    handler = make_handler(
        token_info={
            "oauth_client": "SERVER AT /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    GET_IMPL(handler)

    assert json.loads(handler._writes[0]) == {"access_token": "egi-access-token"}


# phase3-token-3
# Component: TokenAcquirerHandler.get
# Purpose: Verify that incomplete token metadata is rejected before the handler
# tries to fetch the user model.
# What it checks:
# - missing session_id
# - missing oauth_client
# - completely empty token_info
# all produce HTTP 401 and stop after the first Hub API call.
# Example pass:
# - token metadata lacks required server-related fields -> 401 is raised.
# Example fail:
# - the handler continues anyway, fetches user data, or writes a response.
@pytest.mark.parametrize(
    "token_info",
    [
        {"oauth_client": "server at /user/alice/lab/"},
        {"session_id": "sess-1"},
        {},
    ],
)
def test_get_rejects_token_without_required_server_metadata(token_info):
    handler = make_handler(
        token_info=token_info,
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    with pytest.raises(HTTPError) as exc_info:
        GET_IMPL(handler)

    assert exc_info.value.status_code == 401
    assert "Token not authorized" in str(exc_info.value)
    assert len(handler.hub_auth.calls) == 1
    handler.write.assert_not_called()


# phase3-token-4
# Component: TokenAcquirerHandler.get
# Purpose: Ensure non-server tokens are rejected even if they contain a
# session_id.
# What it checks:
# - oauth_client must represent a server token, not an arbitrary service token.
# Example pass:
# - oauth_client is "service token for automation" -> 401 is raised.
# Example fail:
# - the handler treats any token with session_id as valid and leaks access_token.
def test_get_rejects_non_server_token():
    handler = make_handler(
        token_info={
            "oauth_client": "service token for automation",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    with pytest.raises(HTTPError) as exc_info:
        GET_IMPL(handler)

    assert exc_info.value.status_code == 401
    assert len(handler.hub_auth.calls) == 1
    handler.write.assert_not_called()


# phase3-token-5
# Component: TokenAcquirerHandler.get
# Purpose: Verify the error path when the user model does not expose auth_state.
# What it checks:
# - after successful token validation, the second Hub API call happens
# - missing auth_state results in HTTP 404
# - no response body is written
# Example pass:
# - token is valid but user_data == {} -> 404 is raised.
# Example fail:
# - the handler silently returns an empty JSON object or crashes later.
def test_get_returns_404_when_auth_state_missing():
    handler = make_handler(
        token_info={
            "oauth_client": "server at /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={},
    )

    with pytest.raises(HTTPError) as exc_info:
        GET_IMPL(handler)

    assert exc_info.value.status_code == 404
    assert "No access token available for the user" in str(exc_info.value)
    assert len(handler.hub_auth.calls) == 2
    handler.write.assert_not_called()


# phase3-token-6
# Component: TokenAcquirerHandler.get
# Purpose: Verify the error path when auth_state exists but access_token is
# missing inside it.
# What it checks:
# - refresh_token alone is not sufficient
# - the handler still responds with HTTP 404
# Example pass:
# - auth_state only contains refresh_token -> 404 is raised.
# Example fail:
# - the handler returns refresh_token instead of access_token or pretends the
#   request succeeded.
def test_get_returns_404_when_access_token_missing_inside_auth_state():
    handler = make_handler(
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


# phase3-token-7
# Component: TokenAcquirerHandler.get
# Purpose: Confirm that the handler uses the authenticated user's actual name
# and token_id instead of hardcoded defaults.
# What it checks:
# - URLs for Hub API requests are built from current_user["name"] and
#   current_user["token_id"].
# Example pass:
# - current_user is bob/tok-9 -> both Hub API URLs use bob and tok-9.
# Example fail:
# - the handler always queries alice/tok-1 regardless of current_user.
def test_get_uses_name_and_token_id_from_current_user():
    handler = make_handler(
        token_info={
            "oauth_client": "server at /user/bob/workbench/",
            "session_id": "sess-9",
        },
        user_data={"auth_state": {"access_token": "token-9"}},
        current_user={"name": "bob", "token_id": "tok-9"},
    )

    GET_IMPL(handler)

    assert handler.hub_auth.calls[0]["url"] == "http://hub.example/api/users/bob/tokens/tok-9"
    assert handler.hub_auth.calls[1]["url"] == "http://hub.example/api/users/bob"


# phase3-token-8
# Component: TokenAcquirerHandler.get
# Purpose: Verify that the handler writes a JSON string, not a Python dict or
# bytes payload.
# What it checks:
# - write() receives a serialized JSON string
# - the JSON decodes to the expected access_token payload
# Example pass:
# - payload is a string like '{"access_token": "..."}'.
# Example fail:
# - payload is a dict, malformed JSON, or contains the wrong field.
def test_get_writes_valid_json_string():
    handler = make_handler(
        token_info={
            "oauth_client": "server at /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    GET_IMPL(handler)

    payload = handler._writes[0]
    assert isinstance(payload, str)
    assert json.loads(payload)["access_token"] == "egi-access-token"


# phase3-token-9
# Component: TokenAcquirerHandler.get
# Purpose: Ensure that Hub API calls are executed through _call_coroutine with
# sync=True, matching the current synchronous handler implementation.
# What it checks:
# - both internal Hub API calls use sync=True
# Example pass:
# - both recorded calls have sync=True.
# Example fail:
# - one of the calls uses async mode unexpectedly or forgets to pass sync.
def test_get_passes_sync_true_to_hub_auth():
    handler = make_handler(
        token_info={
            "oauth_client": "server at /user/alice/lab/",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    GET_IMPL(handler)

    assert handler.hub_auth.calls[0]["sync"] is True
    assert handler.hub_auth.calls[1]["sync"] is True


# phase3-token-10
# Component: TokenAcquirerHandler.get
# Purpose: Verify that authorization failures do not partially write response
# headers or body.
# What it checks:
# - on HTTP 401 the handler stops before set_header() or write()
# Example pass:
# - invalid token metadata raises HTTPError and no output methods are called.
# Example fail:
# - the handler writes partial JSON or sets content-type before failing.
def test_get_does_not_set_header_or_write_on_authorization_failure():
    handler = make_handler(
        token_info={
            "oauth_client": "not a server token",
            "session_id": "sess-1",
        },
        user_data={"auth_state": {"access_token": "egi-access-token"}},
    )

    with pytest.raises(HTTPError):
        GET_IMPL(handler)

    handler.set_header.assert_not_called()
    handler.write.assert_not_called()


# phase3-token-11
# Component: token_acquirer.main
# Purpose: Verify service bootstrap with a realistic service prefix and service
# URL from the environment.
# What it checks:
# - the main route is registered under JUPYTERHUB_SERVICE_PREFIX
# - a fallback route is also registered
# - the HTTP server listens on the host and port parsed from
#   JUPYTERHUB_SERVICE_URL
# - the IOLoop is started
# Example pass:
# - prefix /services/token-acquirer and URL http://127.0.0.1:8090 produce the
#   expected routes and listen tuple.
# Example fail:
# - the handler is mounted under the wrong path, or the server listens on the
#   wrong interface/port.
def test_main_registers_service_prefix_and_fallback_route(monkeypatch):
    captured = {}

    class DummyApplication:
        def __init__(self, handlers):
            captured["handlers"] = handlers

    class DummyHTTPServer:
        def __init__(self, app):
            captured["app"] = app

        def listen(self, port, host):
            captured["listen"] = (port, host)

    class DummyLoop:
        def start(self):
            captured["started"] = True

    monkeypatch.setenv("JUPYTERHUB_SERVICE_PREFIX", "/services/token-acquirer")
    monkeypatch.setenv("JUPYTERHUB_SERVICE_URL", "http://127.0.0.1:8090")
    monkeypatch.setattr(token_acquirer, "Application", DummyApplication)
    monkeypatch.setattr(token_acquirer, "HTTPServer", DummyHTTPServer)
    monkeypatch.setattr(token_acquirer.IOLoop, "current", lambda: DummyLoop())

    token_acquirer.main()

    assert captured["handlers"][0][0] == "/services/token-acquirer/?"
    assert captured["handlers"][0][1] is token_acquirer.TokenAcquirerHandler
    assert captured["handlers"][1][0] == r".*"
    assert captured["handlers"][1][1] is token_acquirer.TokenAcquirerHandler
    assert captured["listen"] == (8090, "127.0.0.1")
    assert captured["started"] is True


# phase3-token-12
# Component: token_acquirer.main
# Purpose: Confirm that host and port parsing works for a different service URL.
# What it checks:
# - the bootstrap code does not hardcode host/port values
# - the values come from JUPYTERHUB_SERVICE_URL
# Example pass:
# - URL http://0.0.0.0:9999 results in listen(9999, "0.0.0.0").
# Example fail:
# - the code always binds to localhost or ignores the configured port.
def test_main_parses_hostname_and_port_from_service_url(monkeypatch):
    captured = {}

    class DummyApplication:
        def __init__(self, handlers):
            captured["handlers"] = handlers

    class DummyHTTPServer:
        def __init__(self, app):
            captured["app"] = app

        def listen(self, port, host):
            captured["listen"] = (port, host)

    class DummyLoop:
        def start(self):
            captured["started"] = True

    monkeypatch.setenv("JUPYTERHUB_SERVICE_PREFIX", "/svc/token")
    monkeypatch.setenv("JUPYTERHUB_SERVICE_URL", "http://0.0.0.0:9999")
    monkeypatch.setattr(token_acquirer, "Application", DummyApplication)
    monkeypatch.setattr(token_acquirer, "HTTPServer", DummyHTTPServer)
    monkeypatch.setattr(token_acquirer.IOLoop, "current", lambda: DummyLoop())

    token_acquirer.main()

    assert captured["listen"] == (9999, "0.0.0.0")
