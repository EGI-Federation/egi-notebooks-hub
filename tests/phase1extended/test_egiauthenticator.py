import base64
import json
from unittest.mock import AsyncMock, patch
import pytest
from oauthenticator.generic import GenericOAuthenticator
from tornado import web
from egi_notebooks_hub.egiauthenticator import (
    EGICheckinAuthenticator,
    EOSCNodeAuthenticator,
    JWTHandler,
)
# Retained helper for JWT-related tests in this module.
def make_jwt(payload):
    import jwt
    return jwt.encode(payload, "this-is-a-safely-long-test-secret-key", algorithm="HS256")

# phase1-1
# Component: EGICheckinAuthenticator configuration defaults.
# Purpose: Verify that a newly created authenticator uses the built-in default Check-in host.
# Pass example: no EGICHECKIN_HOST environment variable is set, so the host stays "aai.egi.eu".
# Fail example: a refactor accidentally changes the default host string or leaves it unset.
def test_checkin_host_default(authenticator):
    assert authenticator.checkin_host == "aai.egi.eu"

# phase1-2
# Component: EGICheckinAuthenticator configuration loading from environment variables.
# Purpose: Check that the authenticator honors EGICHECKIN_HOST when no explicit config value is given.
# Pass example: EGICHECKIN_HOST=checkin.dev.example results in checkin_host == "checkin.dev.example".
# Fail example: the environment variable is ignored and the code keeps using the hard-coded default host.
def test_checkin_host_from_env(monkeypatch, auth_config):
    monkeypatch.setenv("EGICHECKIN_HOST", "checkin.dev.example")
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.checkin_host == "checkin.dev.example"

# phase1-3
# Component: EGICheckinAuthenticator configuration precedence.
# Purpose: Confirm that explicit traitlets config wins over the environment variable.
# Pass example: config says "from-config.example" while env says "from-env.example", and config wins.
# Fail example: the environment variable silently overrides administrator-supplied config.
def test_explicit_checkin_host_overrides_env(monkeypatch, auth_config):
    monkeypatch.setenv("EGICHECKIN_HOST", "from-env.example")
    auth_config.EGICheckinAuthenticator.checkin_host = "from-config.example"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.checkin_host == "from-config.example"

# phase1-4
# Component: EGICheckinAuthenticator OpenID Connect endpoint construction.
# Purpose: Ensure all important URLs are derived consistently from the chosen Check-in host.
# Pass example: checkin.example.org produces matching authorize/token/userinfo/introspect/revoke URLs.
# Fail example: one endpoint still points to the old default host or uses a wrong path suffix.
def test_default_urls_are_derived_from_checkin_host(auth_config):
    auth_config.EGICheckinAuthenticator.checkin_host = "checkin.example.org"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    base = "https://checkin.example.org/auth/realms/egi/protocol/openid-connect"
    assert authenticator.authorize_url == f"{base}/auth"
    assert authenticator.token_url == f"{base}/token"
    assert authenticator.userdata_url == f"{base}/userinfo"
    assert authenticator.introspect_url == f"{base}/token/introspect"

# phase1-5
# Component: EGICheckinAuthenticator scope validation.
# Purpose: Verify that "openid" is automatically inserted when a custom scope omits it.
# Pass example: ["profile", "offline_access"] becomes ["openid", "profile", "offline_access"].
# Fail example: the authenticator asks the provider for scopes without "openid" and breaks OIDC assumptions.
def test_scope_validator_inserts_openid_when_missing(auth_config):
    auth_config.EGICheckinAuthenticator.scope = ["profile", "offline_access"]
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.scope == ["openid", "profile", "offline_access"]

# phase1-6
# Component: EGICheckinAuthenticator scope validation.
# Purpose: Confirm that an already-correct scope is preserved and not duplicated or reordered badly.
# Pass example: ["openid", "profile", "offline_access"] stays exactly the same.
# Fail example: validation appends a second "openid" or mutates a valid scope unexpectedly.
def test_scope_validator_keeps_existing_openid(auth_config):
    auth_config.EGICheckinAuthenticator.scope = ["openid", "profile", "offline_access"]
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.scope == ["openid", "profile", "offline_access"]

# phase1-7
# Component: EGICheckinAuthenticator scope validation.
# Purpose: Make sure even an empty scope still results in the minimal valid OIDC scope.
# Pass example: [] is normalized to ["openid"].
# Fail example: empty scope remains empty, leading to invalid or incomplete authentication requests.
def test_scope_validator_turns_empty_scope_into_openid_only(auth_config):
    auth_config.EGICheckinAuthenticator.scope = []
    authenticator = EGICheckinAuthenticator(config=auth_config)
    assert authenticator.scope == ["openid"]

# phase1-8
# Component: group management behavior in EGICheckinAuthenticator.
# Purpose: Check that group synchronization is enabled by default.
# Pass example: a fresh authenticator exposes manage_groups == True.
# Fail example: a default change disables group management and downstream group-based logic stops working.
def test_manage_groups_defaults_to_true(authenticator):
    assert authenticator.manage_groups is True

# phase1-9
# Component: username extraction from user info.
# Purpose: Verify that the human-facing username claim has priority over service-style fallback claims.
# Pass example: user info contains preferred_username="alice", so username_claim returns "alice".
# Fail example: the code ignores preferred_username and falls back to a less appropriate identifier.
def test_username_claim_uses_preferred_username(authenticator):
    user_info = {"preferred_username": "alice", "client_id": "service-account-name"}
    assert authenticator.user_info_to_username(user_info) == "alice"

# phase1-10
# Component: username extraction fallback logic.
# Purpose: Ensure that service or machine identities can still get a username when preferred_username is absent.
# Pass example: only client_id exists, and username_claim returns that value.
# Fail example: service accounts get None even though client_id is available.
def test_username_claim_falls_back_to_client_id(authenticator):
    user_info = {"client_id": "service-account-name"}
    assert authenticator.user_info_to_username(user_info) == "service-account-name"

# phase1-11
# Component: configurable claim names for username extraction.
# Purpose: Confirm that administrators can rename the claims used for normal users and services.
# Pass example: custom_name is used instead of preferred_username after config changes.
# Fail example: the code ignores configured claim names and only looks at the defaults.
def test_username_claim_respects_custom_claim_names(auth_config):
    auth_config.EGICheckinAuthenticator.username_claim = "custom_name"
    auth_config.EGICheckinAuthenticator.servicename_claim = "service_name"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    user_info = {"custom_name": "renamed-user", "service_name": "fallback-service"}
    assert authenticator.user_info_to_username(user_info) == "renamed-user"

# phase1-12
# Component: anonymous username generation.
# Purpose: Verify that anonymous identities are deterministic and therefore stable across repeated logins.
# Pass example: the same anonymous source data always produces the same prefixed SHA-256-based username.
# Fail example: two equivalent user_info payloads generate different usernames and break account continuity.
def test_username_claim_generates_stable_anonymous_name(authenticator):
    user_info = {"sub": "12345", "name": "Anonymous User"}
    first = authenticator.user_info_to_username(user_info)
    second = authenticator.user_info_to_username(json.loads(json.dumps(user_info)))
    assert first == second
    assert first.startswith(f"{authenticator.anonymous_username_prefix}-")
    assert len(first.split("-", 1)[1]) == 64

# phase1-13
# Component: anonymous username customization.
# Purpose: Ensure that deployments can change the visible prefix used for anonymous accounts.
# Pass example: configured prefix "guest" produces usernames starting with "guest-".
# Fail example: the code hard-codes the default prefix and ignores administrator preferences.
def test_username_claim_respects_custom_anonymous_prefix(auth_config):
    auth_config.EGICheckinAuthenticator.anonymous_username_prefix = "guest"
    authenticator = EGICheckinAuthenticator(config=auth_config)
    username = authenticator.user_info_to_username({"sub": "no-visible-name"})
    assert username.startswith("guest-")

# phase1-14
# Component: anonymous-login policy enforcement.
# Purpose: Check that the authenticator refuses to invent anonymous usernames when that feature is disabled.
# Pass example: allow_anonymous=False and missing usable claims lead to a None result.
# Fail example: anonymous usernames are still generated despite explicit policy disabling them.
def test_username_claim_returns_value_error_when_anonymous_disabled(auth_config):
    auth_config.EGICheckinAuthenticator.allow_anonymous = False
    authenticator = EGICheckinAuthenticator(config=auth_config)
    with pytest.raises(ValueError):
        authenticator.user_info_to_username({"sub": "missing-usable-claims"})

# phase1-15
# Component: primary group selection.
# Purpose: Verify that no primary group is chosen when user groups do not intersect with allowed_groups.
# Pass example: user belongs only to "other-vo", so get_primary_group returns None.
# Fail example: the method invents or leaks an unrelated group as the primary group.
def test_get_primary_group_returns_none_when_no_groups_match(authenticator):
    assert authenticator.get_primary_group({"groups": ["other-vo"]}) is None

# phase1-16
# Component: primary group selection input handling.
# Purpose: Ensure that missing group information is handled safely and simply returns None.
# Pass example: {} returns None without raising an exception.
# Fail example: the method crashes on users whose token does not contain a groups field.
def test_get_primary_group_returns_none_when_groups_missing(authenticator):
    assert authenticator.get_primary_group({}) is None

# phase1-17
# Component: primary group priority logic.
# Purpose: Check that when multiple allowed groups match, the first allowed group wins.
# Pass example: allowed_groups prioritizes vo-2 before vo-1, so a user in both gets vo-2.
# Fail example: the code ignores configured priority and returns a different matching group.
def test_get_primary_group_uses_allowed_groups_iteration_order(auth_config):
    auth_config.EGICheckinAuthenticator.allowed_groups = ["vo-2", "vo-1", "vo-3"]
    authenticator = EGICheckinAuthenticator(config=auth_config)
    user_info = {"groups": ["vo-1", "vo-2", "vo-3"]}
    assert authenticator.get_primary_group(user_info) == "vo-2"
    
# phase1-18
# Component: auth model enrichment after token processing.
# Purpose: Verify that the computed primary group is stored in auth_state for later consumers.
# Pass example: a user in vo-2 gets auth_state["primary_group"] == "vo-2".
# Fail example: downstream code cannot see the selected primary group because it was never saved.
async def test_token_to_auth_model_adds_primary_group_to_auth_state(authenticator):
    token_info = {"access_token": "token"}
    base_model = {
        "name": "alice",
        "groups": ["vo-2", "other"],
        "auth_state": {"access_token": "token"},
    }

    with patch.object(
        GenericOAuthenticator,
        "_token_to_auth_model",
        AsyncMock(return_value=base_model),
    ):
        result = await authenticator._token_to_auth_model(token_info)

    assert result == base_model
    
# phase1-19
# Component: auth model enrichment safeguards.
# Purpose: Ensure that primary_group is only written when a meaningful matching group exists.
# Pass example: a user with only unrelated groups keeps auth_state unchanged.
# Fail example: the code adds a bogus primary_group key even when no eligible group exists.
async def test_token_to_auth_model_leaves_auth_state_untouched_without_matching_group(authenticator):
    base_model = {"name": "alice", "groups": ["other"], "auth_state": {"access_token": "token"}}
    with patch.object(GenericOAuthenticator, "_token_to_auth_model", AsyncMock(return_value=base_model)):
        result = await authenticator._token_to_auth_model({"access_token": "token"})
    assert "primary_group" not in result["auth_state"]

# phase1-20
# Component: token request parameter construction for JWT login.
# Purpose: Verify that JWT-based access tokens are marked for introspection rather than normal OAuth exchange.
# Pass example: returned params include the original access_token plus introspect=True.
# Fail example: the handler treats raw JWT login as a normal OAuth token exchange path.
def test_build_access_tokens_request_params_marks_jwt_introspection(authenticator):
    data = {"access_token": "jwt-token", "token_type": "bearer"}
    params = authenticator.build_access_tokens_request_params(handler=None, data=data)
    assert params == {"data": {"access_token": "jwt-token", "token_type": "bearer", "introspect": True}}

# phase1-21
# Component: integration with GenericOAuthenticator defaults.
# Purpose: Confirm that the EGI override only changes the custom path and otherwise delegates to the parent class.
# Pass example: when data=None, the parent implementation is called exactly once.
# Fail example: the override breaks standard OAuth behavior by bypassing the parent logic.
def test_build_access_tokens_request_params_delegates_to_parent_without_data(authenticator):
    with patch.object(GenericOAuthenticator, "build_access_tokens_request_params", return_value={"parent": True}) as patched:
        params = authenticator.build_access_tokens_request_params(handler="handler", data=None)
    patched.assert_called_once_with("handler", None)
    assert params == {"parent": True}
    
# phase1-22
# Component: token info extraction in JWT mode.
# Purpose: Check that when JWT mode is active, the provided token data is already the token info source of truth.
# Pass example: params["data"] is returned directly without external requests.
# Fail example: the code makes unnecessary network calls for information already present in the JWT flow.
async def test_get_token_info_returns_data_directly_for_jwt(authenticator):
    params = {"data": {"access_token": "jwt-token", "introspect": True}}
    token_info = await authenticator.get_token_info(handler=None, params=params)
    assert token_info == params["data"]
    
# phase1-23
# Component: conversion from token info to user info in JWT mode.
# Purpose: Verify that JWT login uses introspection and passes the token_info payload through to it.
# Pass example: token_info with introspect=True results in a call to introspect_token.
# Fail example: JWT tokens are treated like standard OAuth tokens and skip the custom introspection path.
async def test_token_to_user_uses_introspection_for_jwt(authenticator):
    token_info = {"access_token": "jwt-token", "introspect": True}
    async def fake_introspect(data):
        return {"active": True, "sub": "user-1", "received": data}
    authenticator.introspect_token = fake_introspect
    user = await authenticator.token_to_user(token_info)
    assert user == {"active": True, "sub": "user-1", "received": token_info}
    
# phase1-24
# Component: conversion from token info to user info in normal OAuth mode.
# Purpose: Confirm that regular access tokens still use the parent class implementation.
# Pass example: a normal oauth-token causes GenericOAuthenticator.token_to_user to be awaited.
# Fail example: the override hijacks all token flows, even the ones it should not customize.
async def test_token_to_user_delegates_to_parent_for_regular_flow(authenticator):
    token_info = {"access_token": "oauth-token"}
    with patch.object(GenericOAuthenticator, "token_to_user", AsyncMock(return_value={"sub": "user-1"})) as patched:
        user = await authenticator.token_to_user(token_info)
    patched.assert_awaited_once_with(token_info)
    assert user == {"sub": "user-1"}
    
# phase1-25
# Component: introspection input validation.
# Purpose: Ensure introspect_token fails loudly if required token data is missing.
# Pass example: calling with only {"introspect": True} raises HTTP 500.
# Fail example: the code sends an empty introspection request and hides a programming error.
async def test_introspect_token_raises_if_access_token_missing(authenticator):
    with pytest.raises(web.HTTPError) as exc_info:
        await authenticator.introspect_token({"introspect": True})
    assert exc_info.value.status_code == 500

# phase1-26
# Component: authenticator HTTP route registration.
# Purpose: Confirm that EGI-specific routes are appended without losing parent routes.
# Pass example: the final handler list contains /oauth_callback, /jwt_login, and /token_revoke.
# Fail example: custom routes are missing or the parent routes are accidentally discarded.
def test_get_handlers_appends_custom_routes(authenticator):
    base_handlers = [(r"/oauth_callback", object())]
    with patch.object(GenericOAuthenticator, "get_handlers", return_value=list(base_handlers)):
        handlers = authenticator.get_handlers(app=None)
    routes = [route for route, _handler in handlers]
    assert "/oauth_callback" in routes
    assert "/jwt_login" in routes
    handler_map = dict(handlers)
    assert handler_map["/jwt_login"] is JWTHandler

# phase1-27
# Component: EOSCNodeAuthenticator personal project extraction.
# Purpose: Verify that EOSC-specific group names are reduced to the personal project identifier.
# Pass example: urn:...:pp-123456 produces primary group "pp-123456".
# Fail example: the whole URN is returned or no project is recognized at all.
def test_eosc_primary_group_returns_personal_project_name(eosc_authenticator):
    user_info = {"groups": ["urn:geant:eosc-federation.eu:group:pp-123456", "vo-1"]}
    assert eosc_authenticator.get_primary_group(user_info) == "pp-123456"

# phase1-28
# Component: EOSCNodeAuthenticator custom regex handling.
# Purpose: Verify that custom regexes still work even when they do not define an explicit capturing group.
# Pass example: regex ^special-group$ returns "special-group" for that exact group.
# Fail example: custom patterns only work when they contain a capture group, reducing configurability.
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
    
# phase1-29
# Component: token info extraction in normal OAuth mode.
# Purpose: Ensure standard flows still use the inherited GenericOAuthenticator behavior.
# Pass example: with no JWT-style data present, the parent get_token_info is awaited.
# Fail example: normal OAuth logins break because the EGI override never delegates back.
async def test_get_token_info_delegates_to_parent_without_data(authenticator):
    with patch.object(GenericOAuthenticator, "get_token_info", AsyncMock(return_value={"parent": True})) as patched:
        token_info = await authenticator.get_token_info(handler="handler", params={})
    patched.assert_awaited_once_with("handler", {})
    assert token_info == {"parent": True} 
    
# phase1-30
# Component: EOSCNodeAuthenticator personal project detection.
# Purpose: Ensure the EOSC-specific helper does not invent a project when none matches the regex.
# Pass example: ordinary VO groups return None.
# Fail example: unrelated groups are misclassified as personal project identifiers.
def test_eosc_primary_group_returns_none_without_personal_project(eosc_authenticator):
    user_info = {"groups": ["vo-1", "vo-2"]}
    assert eosc_authenticator.get_primary_group(user_info) is None  
    
# phase1-31
# Component: token introspection request generation.
# Purpose: Verify the exact HTTP request sent to the introspection endpoint, including Basic Auth.
# Pass example: body is b"token=jwt-token" and Authorization contains base64(client_id:client_secret).
# Fail example: wrong request body, wrong auth header, or wrong label/method is used.
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
