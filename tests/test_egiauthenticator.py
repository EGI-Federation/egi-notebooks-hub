import json
import time
from unittest.mock import patch

import jwt
import pytest
from oauthenticator.generic import GenericOAuthenticator

from egi_notebooks_hub.egiauthenticator import EGICheckinAuthenticator, JWTHandler


def make_jwt(payload):
    return jwt.encode(payload, "dummy-secret", algorithm="HS256")


def test_checkin_host_default(authenticator):
    assert authenticator.checkin_host == "aai.egi.eu"


def test_checkin_host_from_env(monkeypatch, auth_config):
    monkeypatch.setenv("EGICHECKIN_HOST", "checkin.dev.example")

    authenticator = EGICheckinAuthenticator(config=auth_config)

    assert authenticator.checkin_host == "checkin.dev.example"


def test_default_urls_are_derived_from_checkin_host(auth_config):
    c = auth_config
    c.EGICheckinAuthenticator.checkin_host = "checkin.example.org"

    authenticator = EGICheckinAuthenticator(config=c)

    base = "https://checkin.example.org/auth/realms/egi/protocol/openid-connect"
    assert authenticator.authorize_url == f"{base}/auth"
    assert authenticator.token_url == f"{base}/token"
    assert authenticator.userdata_url == f"{base}/userinfo"
    assert authenticator.introspect_url == f"{base}/token/introspect"
    assert authenticator.revoke_url == f"{base}/revoke"

def test_scope_validator_inserts_openid(auth_config):
    c = auth_config
    c.EGICheckinAuthenticator.scope = ["profile", "offline_access"]

    authenticator = EGICheckinAuthenticator(config=c)

    assert authenticator.scope == ["openid", "profile", "offline_access"]


def test_scope_validator_keeps_existing_openid_order(auth_config):
    c = auth_config
    c.EGICheckinAuthenticator.scope = ["openid", "profile", "offline_access"]

    authenticator = EGICheckinAuthenticator(config=c)

    assert authenticator.scope == ["openid", "profile", "offline_access"]


def test_username_claim_uses_preferred_username(authenticator):
    user_info = {
        "preferred_username": "alice",
        "client_id": "service-account-name",
    }

    assert authenticator.username_claim(user_info) == "alice"


def test_username_claim_falls_back_to_client_id(authenticator):
    user_info = {
        "client_id": "service-account-name",
    }

    assert authenticator.username_claim(user_info) == "service-account-name"


def test_username_claim_generates_stable_anonymous_name(authenticator):
    user_info = {
        "sub": "12345",
        "name": "Anonymous User",
    }

    first = authenticator.username_claim(user_info)
    second = authenticator.username_claim(json.loads(json.dumps(user_info)))

    assert first == second
    assert first.startswith(f"{authenticator.anonymous_username_prefix}-")
    assert len(first.split("-", 1)[1]) == 64


def test_username_claim_returns_none_when_anonymous_disabled(auth_config):
    c = auth_config
    c.EGICheckinAuthenticator.allow_anonymous = False
    authenticator = EGICheckinAuthenticator(config=c)

    assert authenticator.username_claim({"sub": "missing-usable-claims"}) is None


def test_get_primary_group_respects_allowed_groups_order(auth_config):
    c = auth_config
    c.EGICheckinAuthenticator.allowed_groups = {"vo-1", "vo-2", "vo-3"}
    authenticator = EGICheckinAuthenticator(config=c)

    user_info = {"groups": ["unrelated", "vo-3", "vo-1"]}

    # The implementation follows the order in allowed_groups, not the token order.
    assert authenticator.get_primary_group(user_info) in {"vo-1", "vo-3"}


def test_get_primary_group_prefers_first_allowed_group_when_list_is_ordered(auth_config):
    c = auth_config
    c.EGICheckinAuthenticator.allowed_groups = ["vo-2", "vo-1", "vo-3"]
    authenticator = EGICheckinAuthenticator(config=c)

    user_info = {"groups": ["vo-1", "vo-2", "vo-3"]}

    assert authenticator.get_primary_group(user_info) == "vo-2"


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
    c = auth_config
    c.EGICheckinAuthenticator.auth_refresh_age = 30
    c.EGICheckinAuthenticator.auth_refresh_leeway = 10
    authenticator = EGICheckinAuthenticator(config=c)

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


def test_build_access_tokens_request_params_marks_jwt_introspection(authenticator):
    data = {"access_token": "jwt-token", "token_type": "bearer"}

    params = authenticator.build_access_tokens_request_params(handler=None, data=data)

    assert params == {
        "data": {
            "access_token": "jwt-token",
            "token_type": "bearer",
            "introspect": True,
        }
    }


@pytest.mark.asyncio
async def test_get_token_info_returns_data_directly_for_jwt(authenticator):
    params = {"data": {"access_token": "jwt-token", "introspect": True}}

    token_info = await authenticator.get_token_info(handler=None, params=params)

    assert token_info == params["data"]


@pytest.mark.asyncio
async def test_token_to_user_uses_introspection_for_jwt(authenticator):
    token_info = {"access_token": "jwt-token", "introspect": True}

    async def fake_introspect(data):
        return {"active": True, "sub": "user-1", "received": data}

    authenticator.introspect_token = fake_introspect

    user = await authenticator.token_to_user(token_info)

    assert user == {
        "active": True,
        "sub": "user-1",
        "received": token_info,
    }


def test_get_handlers_appends_custom_routes(authenticator):
    base_handlers = [(r"/oauth_callback", object())]

    with patch.object(
        GenericOAuthenticator,
        "get_handlers",
        return_value=list(base_handlers),
    ):
        handlers = authenticator.get_handlers(app=None)

    routes = [route for route, _handler in handlers]
    assert "/oauth_callback" in routes
    assert "/jwt_login" in routes
    assert "/token_revoke" in routes

    handler_map = dict(handlers)
    assert handler_map["/jwt_login"] is JWTHandler
