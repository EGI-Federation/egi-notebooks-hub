import base64
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import jwt
import pytest
from oauthenticator.generic import GenericOAuthenticator
from tornado import web

from egi_notebooks_hub.egiauthenticator import (
    EGICheckinAuthenticator,
    EOSCNodeAuthenticator,
    JWTHandler,
)


def make_jwt(payload):
    return jwt.encode(payload, "this-is-a-safely-long-test-secret-key", algorithm="HS256")


def test_checkin_host_default(authenticator):
    assert authenticator.checkin_host == "aai.egi.eu"


def test_checkin_host_from_env(monkeypatch, auth_config):
    monkeypatch.setenv("EGICHECKIN_HOST", "checkin.dev.example")
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.checkin_host == "checkin.dev.example"


def test_explicit_checkin_host_overrides_env(monkeypatch, auth_config):
    monkeypatch.setenv("EGICHECKIN_HOST", "from-env.example")
    auth_config.EGICheckinAuthenticator.checkin_host = "from-config.example"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.checkin_host == "from-config.example"


def test_default_urls_are_derived_from_checkin_host(auth_config):
    auth_config.EGICheckinAuthenticator.checkin_host = "checkin.example.org"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    base = "https://checkin.example.org/auth/realms/egi/protocol/openid-connect"
    assert authenticator.authorize_url == f"{base}/auth"
    assert authenticator.token_url == f"{base}/token"
    assert authenticator.userdata_url == f"{base}/userinfo"
    assert authenticator.introspect_url == f"{base}/token/introspect"
    assert authenticator.revoke_url == f"{base}/revoke"


def test_scope_validator_inserts_openid_when_missing(auth_config):
    auth_config.EGICheckinAuthenticator.scope = ["profile", "offline_access"]
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.scope == ["openid", "profile", "offline_access"]


def test_scope_validator_keeps_existing_openid(auth_config):
    auth_config.EGICheckinAuthenticator.scope = ["openid", "profile", "offline_access"]
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.scope == ["openid", "profile", "offline_access"]


def test_scope_validator_turns_empty_scope_into_openid_only(auth_config):
    auth_config.EGICheckinAuthenticator.scope = []
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.scope == ["openid"]


def test_manage_groups_defaults_to_true(authenticator):
    assert authenticator.manage_groups is True


def test_username_claim_uses_preferred_username(authenticator):
    user_info = {"preferred_username": "alice", "client_id": "service-account-name"}
    assert authenticator.username_claim(user_info) == "alice"


def test_username_claim_falls_back_to_client_id(authenticator):
    user_info = {"client_id": "service-account-name"}
    assert authenticator.username_claim(user_info) == "service-account-name"


def test_username_claim_respects_custom_claim_names(auth_config):
    auth_config.EGICheckinAuthenticator.aai_username_claim = "custom_name"
    auth_config.EGICheckinAuthenticator.aai_servicename_claim = "service_name"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    user_info = {"custom_name": "renamed-user", "service_name": "fallback-service"}
    assert authenticator.username_claim(user_info) == "renamed-user"


def test_username_claim_generates_stable_anonymous_name(authenticator):
    user_info = {"sub": "12345", "name": "Anonymous User"}
    first = authenticator.username_claim(user_info)
    second = authenticator.username_claim(json.loads(json.dumps(user_info)))
    assert first == second
    assert first.startswith(f"{authenticator.anonymous_username_prefix}-")
    assert len(first.split("-", 1)[1]) == 64


def test_username_claim_respects_custom_anonymous_prefix(auth_config):
    auth_config.EGICheckinAuthenticator.anonymous_username_prefix = "guest"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    username = authenticator.username_claim({"sub": "no-visible-name"})
    assert username.startswith("guest-")


def test_username_claim_returns_none_when_anonymous_disabled(auth_config):
    auth_config.EGICheckinAuthenticator.allow_anonymous = False
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.username_claim({"sub": "missing-usable-claims"}) is None


def test_get_primary_group_returns_none_when_no_groups_match(authenticator):
    assert authenticator.get_primary_group({"groups": ["other-vo"]}) is None


def test_get_primary_group_returns_none_when_groups_missing(authenticator):
    assert authenticator.get_primary_group({}) is None


def test_get_primary_group_uses_allowed_groups_iteration_order(auth_config):
    auth_config.EGICheckinAuthenticator.allowed_groups = ["vo-2", "vo-1", "vo-3"]
    authenticator = EGICheckinAuthenticator(config=auth_config)
    user_info = {"groups": ["vo-1", "vo-2", "vo-3"]}
    assert authenticator.get_primary_group(user_info) == "vo-2"


@pytest.mark.asyncio
async def test_token_to_auth_model_adds_primary_group_to_auth_state(authenticator):
    token_info = {"access_token": "token"}
    base_model = {
        "name": "alice",
        "groups": ["vo-2", "other"],
        "auth_state": {"access_token": "token"},
    }
    with patch.object(GenericOAuthenticator, "_token_to_auth_model", AsyncMock(return_value=base_model)):
        result = await authenticator._token_to_auth_model(token_info)
    assert result["auth_state"]["primary_group"] == "vo-2"


@pytest.mark.asyncio
async def test_token_to_auth_model_leaves_auth_state_untouched_without_matching_group(authenticator):
    base_model = {"name": "alice", "groups": ["other"], "auth_state": {"access_token": "token"}}
    with patch.object(GenericOAuthenticator, "_token_to_auth_model", AsyncMock(return_value=base_model)):
        result = await authenticator._token_to_auth_model({"access_token": "token"})
    assert "primary_group" not in result["auth_state"]


@pytest.mark.asyncio
async def test_revoke_token_posts_expected_request(authenticator):
    authenticator.httpfetch = AsyncMock(return_value=SimpleNamespace(code=200))
    await authenticator.revoke_token("access-token-123")
    _, kwargs = authenticator.httpfetch.call_args
    assert kwargs["label"] == "Token revocation"
    assert kwargs["parse_json"] is False
    assert kwargs["auth_username"] == "test-client"
    assert kwargs["auth_password"] == "test-secret"
    assert kwargs["method"] == "POST"
    assert "token=access-token-123" in kwargs["body"]
    assert "token_type_hint=access_token" in kwargs["body"]


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_true_without_auth_state(authenticator):
    assert await authenticator.refresh_user_hook(authenticator, None, None) is True


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_true_without_access_token(authenticator):
    auth_state = {"refresh_token": "r1"}
    assert await authenticator.refresh_user_hook(authenticator, None, auth_state) is True


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_none_for_revoke_marker(authenticator):
    auth_state = {"access_token": "revoke"}
    assert await authenticator.refresh_user_hook(authenticator, None, auth_state) is None


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_true_for_still_valid_token(auth_config):
    auth_config.EGICheckinAuthenticator.auth_refresh_age = 30
    auth_config.EGICheckinAuthenticator.auth_refresh_leeway = 10
    authenticator = EGICheckinAuthenticator(config=auth_config)
    now = int(time.time())
    token = make_jwt({"iat": now, "exp": now + 3600, "sub": "user-1"})
    auth_state = {"access_token": token}
    assert await authenticator.refresh_user_hook(authenticator, None, auth_state) is True


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_none_for_expired_token(authenticator):
    now = int(time.time())
    token = make_jwt({"iat": now - 7200, "exp": now - 3600, "sub": "user-1"})
    auth_state = {"access_token": token}
    assert await authenticator.refresh_user_hook(authenticator, None, auth_state) is None


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_none_for_token_expiring_within_leeway(auth_config):
    auth_config.EGICheckinAuthenticator.auth_refresh_age = 300
    auth_config.EGICheckinAuthenticator.auth_refresh_leeway = 60
    authenticator = EGICheckinAuthenticator(config=auth_config)
    now = int(time.time())
    token = make_jwt({"iat": now - 100, "exp": now + 100, "sub": "user-1"})
    auth_state = {"access_token": token}
    assert await authenticator.refresh_user_hook(authenticator, None, auth_state) is None


@pytest.mark.asyncio
async def test_refresh_user_hook_returns_none_for_invalid_token_string(authenticator):
    auth_state = {"access_token": "not-a-jwt"}
    assert await authenticator.refresh_user_hook(authenticator, None, auth_state) is None


def test_build_access_tokens_request_params_marks_jwt_introspection(authenticator):
    data = {"access_token": "jwt-token", "token_type": "bearer"}
    params = authenticator.build_access_tokens_request_params(handler=None, data=data)
    assert params == {"data": {"access_token": "jwt-token", "token_type": "bearer", "introspect": True}}


def test_build_access_tokens_request_params_delegates_to_parent_without_data(authenticator):
    with patch.object(GenericOAuthenticator, "build_access_tokens_request_params", return_value={"parent": True}) as patched:
        params = authenticator.build_access_tokens_request_params(handler="handler", data=None)
    patched.assert_called_once_with("handler", None)
    assert params == {"parent": True}


@pytest.mark.asyncio
async def test_get_token_info_returns_data_directly_for_jwt(authenticator):
    params = {"data": {"access_token": "jwt-token", "introspect": True}}
    token_info = await authenticator.get_token_info(handler=None, params=params)
    assert token_info == params["data"]


@pytest.mark.asyncio
async def test_get_token_info_delegates_to_parent_without_data(authenticator):
    with patch.object(GenericOAuthenticator, "get_token_info", AsyncMock(return_value={"parent": True})) as patched:
        token_info = await authenticator.get_token_info(handler="handler", params={})
    patched.assert_awaited_once_with("handler", {})
    assert token_info == {"parent": True}


@pytest.mark.asyncio
async def test_token_to_user_uses_introspection_for_jwt(authenticator):
    token_info = {"access_token": "jwt-token", "introspect": True}

    async def fake_introspect(data):
        return {"active": True, "sub": "user-1", "received": data}

    authenticator.introspect_token = fake_introspect
    user = await authenticator.token_to_user(token_info)
    assert user == {"active": True, "sub": "user-1", "received": token_info}


@pytest.mark.asyncio
async def test_token_to_user_delegates_to_parent_for_regular_flow(authenticator):
    token_info = {"access_token": "oauth-token"}
    with patch.object(GenericOAuthenticator, "token_to_user", AsyncMock(return_value={"sub": "user-1"})) as patched:
        user = await authenticator.token_to_user(token_info)
    patched.assert_awaited_once_with(token_info)
    assert user == {"sub": "user-1"}


@pytest.mark.asyncio
async def test_introspect_token_raises_if_access_token_missing(authenticator):
    with pytest.raises(web.HTTPError) as exc_info:
        await authenticator.introspect_token({"introspect": True})
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_introspect_token_builds_expected_http_request(authenticator):
    authenticator.httpfetch = AsyncMock(return_value={"active": True})
    result = await authenticator.introspect_token({"access_token": "jwt-token"})
    assert result == {"active": True}
    _, kwargs = authenticator.httpfetch.call_args
    assert kwargs["label"] == "Introspecting token..."
    assert kwargs["method"] == "POST"
    assert kwargs["validate_cert"] == authenticator.validate_server_cert
    assert kwargs["body"] == b"token=jwt-token"
    auth_header = kwargs["headers"]["Authorization"]
    expected_basic = base64.b64encode(b"test-client:test-secret").decode("utf8")
    assert auth_header == f"Basic {expected_basic}"


def test_get_handlers_appends_custom_routes(authenticator):
    base_handlers = [(r"/oauth_callback", object())]
    with patch.object(GenericOAuthenticator, "get_handlers", return_value=list(base_handlers)):
        handlers = authenticator.get_handlers(app=None)
    routes = [route for route, _handler in handlers]
    assert "/oauth_callback" in routes
    assert "/jwt_login" in routes
    assert "/token_revoke" in routes
    handler_map = dict(handlers)
    assert handler_map["/jwt_login"] is JWTHandler


def test_eosc_primary_group_returns_personal_project_name(eosc_authenticator):
    user_info = {"groups": ["urn:geant:eosc-federation.eu:group:pp-123456", "vo-1"]}
    assert eosc_authenticator.get_primary_group(user_info) == "pp-123456"


def test_eosc_primary_group_returns_none_without_personal_project(eosc_authenticator):
    user_info = {"groups": ["vo-1", "vo-2"]}
    assert eosc_authenticator.get_primary_group(user_info) is None


def test_eosc_primary_group_respects_custom_regex_without_capturing_group():
    from traitlets.config import Config

    c = Config()
    c.EOSCNodeAuthenticator = Config(
        {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "personal_project_re": r"^special-group$",
        }
    )
    authenticator = EOSCNodeAuthenticator(config=c)
    assert authenticator.get_primary_group({"groups": ["special-group"]}) == "special-group"
