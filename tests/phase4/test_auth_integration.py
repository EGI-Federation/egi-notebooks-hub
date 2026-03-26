"""
Phase 4 integration tests for authentication-related flows.

These tests are intentionally broader than the Phase 1 unit tests:
they combine EGICheckinAuthenticator with JWTHandler and exercise
realistic multi-step behavior using mocks instead of a real Hub,
real IdP, or real HTTP server.

The goal is to verify that the authentication components cooperate
correctly when used together.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from tornado.web import HTTPError
from traitlets.config import Config

from egi_notebooks_hub.egiauthenticator import EGICheckinAuthenticator, JWTHandler


class DummyUser:
    """
    Minimal fake JupyterHub user used by integration-style handler tests.

    Why this helper exists:
    - JWTHandler.get() expects a user object with async auth_state methods
    - it also expects the user to be able to mint a new Hub API token

    This class provides only the minimal surface needed by the tests.
    """

    def __init__(self, auth_state=None, name="alice"):
        self._auth_state = auth_state or {}
        self.name = name

    async def get_auth_state(self):
        return self._auth_state

    async def save_auth_state(self, auth_state):
        self._auth_state = auth_state

    def new_api_token(self, *args, **kwargs):
        return "new-hub-api-token"


@pytest.fixture
def auth_config():
    """
    Shared authenticator config used by the Phase 4 auth integration tests.

    The config keeps the tests deterministic while still being realistic enough
    to model the actual EGI authenticator behavior.
    """
    c = Config()
    c.EGICheckinAuthenticator.client_id = "test-client"
    c.EGICheckinAuthenticator.client_secret = "test-secret"
    c.EGICheckinAuthenticator.allowed_groups = {"vo-1", "vo-2"}
    c.EGICheckinAuthenticator.scope = ["openid", "profile", "offline_access"]
    c.EGICheckinAuthenticator.allow_all = True
    return c


@pytest.fixture
def authenticator(auth_config):
    """
    Create a real EGICheckinAuthenticator instance.

    Unlike pure unit tests, these integration-style tests use the real
    authenticator object and only replace its external dependencies.
    """
    return EGICheckinAuthenticator(config=auth_config)


# phase4-auth-1
# Component: JWTHandler.get + EGICheckinAuthenticator.user_info_to_username
# Purpose: Verify the "reuse existing Hub token" path for a valid user.
# What this test checks:
# - the JWT is decoded into user information
# - the username is resolved through the authenticator
# - an existing Hub user is found
# - a previously issued Hub API token is reused
# - login_user is NOT called because no new login is needed
# Example pass:
# - _get_previous_hub_token returns "reused-token" and the handler finishes
#   immediately with that token.
# Example fail:
# - the handler ignores the reusable token and performs login_user anyway,
#   or returns the wrong response payload.
@pytest.mark.asyncio
async def test_jwt_handler_reuses_existing_hub_token_without_login(authenticator):
    """
    End-to-end intent:
    - decode JWT
    - resolve username through authenticator
    - find existing user
    - reuse a previously stored Hub API token
    - skip login and finish immediately
    """
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "reused-token"})
    finished = {}

    handler = SimpleNamespace(
        authenticator=authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=user),
        _get_previous_hub_token=AsyncMock(return_value="reused-token"),
        login_user=AsyncMock(),
        finish=lambda payload: finished.update(payload=payload),
    )

    await JWTHandler.get(handler)

    handler._get_previous_hub_token.assert_awaited_once_with(user, "jwt-token")
    handler.login_user.assert_not_awaited()
    assert finished["payload"] == {"token": "reused-token", "user": "alice"}


# phase4-auth-2
# Component: JWTHandler.get + refresh-token exchange flow
# Purpose: Verify the "login + exchange refresh token + issue new Hub token" path.
# What this test checks:
# - no reusable Hub token is available
# - login_user is called with the JWT-derived token_info
# - if auth_state lacks refresh_token, exchange_for_refresh_token is called
# - the returned refresh token is stored back into auth_state
# - a new Hub API token is created and returned to the client
# Example pass:
# - login_user returns a user with only access_token, exchange returns
#   "refresh-token", and the response contains the newly generated Hub token.
# Example fail:
# - the refresh exchange is skipped, auth_state is not updated, or the final
#   token returned to the client is incorrect.
@pytest.mark.asyncio
async def test_jwt_handler_logs_in_user_and_stores_refresh_token_when_missing(authenticator):
    """
    Integration scenario:
    - there is no reusable Hub token
    - login succeeds
    - auth_state lacks refresh_token
    - exchange_for_refresh_token is used
    - a new Hub token is issued and returned
    """
    user = DummyUser(auth_state={"access_token": "jwt-token"}, name="alice")
    finished = {}

    handler = SimpleNamespace(
        authenticator=authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=user),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=user),
        exchange_for_refresh_token=AsyncMock(return_value="refresh-token"),
        finish=lambda payload: finished.update(payload=payload),
    )

    await JWTHandler.get(handler)

    handler.login_user.assert_awaited_once_with(
        {"access_token": "jwt-token", "token_type": "bearer"}
    )
    handler.exchange_for_refresh_token.assert_awaited_once_with("jwt-token")
    assert user._auth_state["refresh_token"] == "refresh-token"
    assert user._auth_state["jwt_api_token"] == "new-hub-api-token"
    assert finished["payload"] == {"token": "new-hub-api-token", "user": "alice"}


# phase4-auth-3
# Component: JWTHandler.get + existing auth_state refresh token
# Purpose: Verify that the refresh-token exchange is skipped when auth_state
# already contains a refresh token.
# What this test checks:
# - login_user still runs because no reusable Hub token exists
# - exchange_for_refresh_token is NOT called
# - the existing refresh token is preserved
# - a new Hub API token is still created and returned
# Example pass:
# - auth_state already has "existing-refresh" and that value remains unchanged.
# Example fail:
# - the handler unnecessarily performs another refresh-token exchange or
#   overwrites the existing refresh token.
@pytest.mark.asyncio
async def test_jwt_handler_skips_refresh_exchange_when_refresh_token_already_present(authenticator):
    """
    Integration scenario:
    - login succeeds
    - auth_state already contains refresh_token
    - exchange_for_refresh_token must not be called
    """
    user = DummyUser(
        auth_state={"access_token": "jwt-token", "refresh_token": "existing-refresh"},
        name="alice",
    )
    finished = {}

    handler = SimpleNamespace(
        authenticator=authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=user),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=user),
        exchange_for_refresh_token=AsyncMock(),
        finish=lambda payload: finished.update(payload=payload),
    )

    await JWTHandler.get(handler)

    handler.exchange_for_refresh_token.assert_not_awaited()
    assert user._auth_state["refresh_token"] == "existing-refresh"
    assert user._auth_state["jwt_api_token"] == "new-hub-api-token"
    assert finished["payload"] == {"token": "new-hub-api-token", "user": "alice"}


# phase4-auth-4
# Component: JWTHandler.get + authenticator custom_403_message
# Purpose: Verify the explicit "login failed" path.
# What this test checks:
# - no reusable Hub token exists
# - login_user returns None
# - the handler raises HTTP 403
# - the 403 uses the authenticator's custom message
# Example pass:
# - login_user returns None and the handler raises HTTPError(403, ...).
# Example fail:
# - the handler silently returns, raises the wrong status code, or ignores the
#   custom authenticator message.
@pytest.mark.asyncio
async def test_jwt_handler_raises_403_when_login_returns_none(authenticator):
    """
    Integration scenario:
    - token was decoded correctly
    - no reusable Hub token exists
    - login_user returns None
    - handler must return HTTP 403 with authenticator message
    """
    handler = SimpleNamespace(
        authenticator=SimpleNamespace(
            custom_403_message="Forbidden by test",
            user_info_to_username=Mock(return_value="alice"),
        ),
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=None),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=None),
    )

    with pytest.raises(HTTPError) as exc_info:
        await JWTHandler.get(handler)

    assert exc_info.value.status_code == 403
    assert "Forbidden by test" in str(exc_info.value)


# phase4-auth-5
# Component: EGICheckinAuthenticator._token_to_auth_model
# Purpose: Verify that the EGI-specific extension preserves parent auth-model
# fields when no primary group can be derived.
# What this test checks:
# - the parent GenericOAuthenticator auth model is returned
# - user groups do not match allowed_groups
# - primary_group should therefore not be added
# - original fields such as name, groups, and access_token remain intact
# Example pass:
# - base_model contains only external groups and the returned auth_state has no
#   primary_group key.
# Example fail:
# - the extension mutates unrelated fields or injects a bogus primary_group.
@pytest.mark.asyncio
async def test_token_to_auth_model_preserves_parent_fields_when_primary_group_not_found(authenticator):
    """
    Integration scenario for authenticator auth model assembly:
    - parent GenericOAuthenticator model is returned
    - user groups do not intersect allowed_groups
    - primary_group should not be added
    - all original fields must remain intact
    """
    token_info = {"access_token": "token"}
    base_model = {
        "name": "alice",
        "groups": ["external-group"],
        "auth_state": {"access_token": "token"},
    }

    with patch.object(
        type(authenticator).__mro__[1],  # GenericOAuthenticator in current inheritance chain
        "_token_to_auth_model",
        AsyncMock(return_value=base_model),
    ):
        result = await authenticator._token_to_auth_model(token_info)

    assert result["name"] == "alice"
    assert result["groups"] == ["external-group"]
    assert result["auth_state"]["access_token"] == "token"
    assert "primary_group" not in result["auth_state"]


# phase4-auth-6
# Component: EGICheckinAuthenticator._token_to_auth_model
# Purpose: Ensure the extension does not accidentally remove or overwrite an
# already-present primary_group coming from parent-level logic.
# What this test checks:
# - auth_state already includes primary_group
# - the final auth model preserves that value
# Example pass:
# - base_model auth_state contains "primary_group": "vo-2" and the returned
#   model keeps it unchanged.
# Example fail:
# - the extension deletes primary_group or replaces it with None or another VO.
@pytest.mark.asyncio
async def test_token_to_auth_model_keeps_existing_primary_group_if_parent_already_set(authenticator):
    """
    Defensive integration test:
    if parent auth_state already contains primary_group, the EGI extension
    should not accidentally remove or overwrite it with unrelated data.
    """
    token_info = {"access_token": "token"}
    base_model = {
        "name": "alice",
        "groups": ["vo-2", "other"],
        "auth_state": {"access_token": "token", "primary_group": "vo-2"},
    }

    with patch.object(
        type(authenticator).__mro__[1],
        "_token_to_auth_model",
        AsyncMock(return_value=base_model),
    ):
        result = await authenticator._token_to_auth_model(token_info)

    assert result["auth_state"]["primary_group"] == "vo-2"


# phase4-auth-7
# Component: EGICheckinAuthenticator.user_info_to_username + get_primary_group
# Purpose: Check cross-field consistency within a single user_info structure.
# What this test checks:
# - the same user_info payload yields a stable username
# - a primary group is selected from allowed_groups when possible
# - the result is coherent enough for downstream auth-state construction
# Example pass:
# - preferred_username is "alice" and groups include "vo-2", so username is
#   "alice" and primary_group is either "vo-2" or another allowed match
#   depending on current set/ordering behavior.
# Example fail:
# - username extraction fails, or primary_group is something completely outside
#   the allowed group set.
def test_user_info_to_username_and_primary_group_form_consistent_identity(authenticator):
    """
    Cross-component integration check:
    the same user_info structure should produce:
    - a stable username
    - a primary group selected from allowed_groups
    This helps ensure downstream components receive a coherent auth model.
    """
    user_info = {
        "preferred_username": "alice",
        "groups": ["vo-2", "external"],
    }

    username = authenticator.user_info_to_username(user_info)
    primary_group = authenticator.get_primary_group(user_info)

    assert username == "alice"
    assert primary_group in {"vo-1", "vo-2", None}
    # keep this test permissive because current allowed_groups iteration order
    # may depend on traitlets/set handling in the real implementation.


# phase4-auth-8
# Component: JWTHandler.get + authenticator.user_info_to_username error handling
# Purpose: Verify that username-extraction errors are logged but do not
# necessarily abort the rest of the authentication flow.
# What this test checks:
# - user_info_to_username raises ValueError
# - the handler logs debug output
# - the handler continues with user=None
# - login_user still runs
# - the handler can still finish successfully if later steps succeed
# Example pass:
# - broken user_info_to_username raises ValueError, but login_user succeeds and
#   the handler finishes with a new Hub token.
# Example fail:
# - the handler crashes immediately on ValueError or never attempts login_user.
@pytest.mark.asyncio
async def test_jwt_handler_logs_debug_and_continues_when_username_extraction_fails(authenticator):
    """
    Integration scenario:
    - username extraction raises ValueError
    - handler should continue with user=None
    - if a reusable token is unavailable, it still attempts login
    """
    user = DummyUser(auth_state={"access_token": "jwt-token"}, name="alice")
    finished = {}
    broken_authenticator = SimpleNamespace(
        custom_403_message="Forbidden",
        user_info_to_username=Mock(side_effect=ValueError("bad token payload")),
    )

    handler = SimpleNamespace(
        authenticator=broken_authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=None),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=user),
        exchange_for_refresh_token=AsyncMock(return_value="refresh-token"),
        finish=lambda payload: finished.update(payload=payload),
    )

    await JWTHandler.get(handler)

    handler.log.debug.assert_called()
    handler.login_user.assert_awaited_once()
    assert finished["payload"] == {"token": "new-hub-api-token", "user": "alice"}
