from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
import pytest
from jupyterhub import orm
from tornado.httpclient import HTTPClientError
from tornado.web import HTTPError
from egi_notebooks_hub.egiauthenticator import JWTHandler

class DummyResponse:
    def __init__(self, body):
        self.body = body

class DummyUser:
    def __init__(self, auth_state=None, name="alice"):
        self._auth_state = auth_state
        self.saved_auth_state = None
        self.name = name
        self.api_token_created = None
    async def get_auth_state(self):
        return self._auth_state
    async def save_auth_state(self, state):
        self.saved_auth_state = state
        self._auth_state = state
    def new_api_token(self, note=None, expires_in=None):
        self.api_token_created = {"note": note, "expires_in": expires_in}
        return "new-hub-api-token"

# phase1-32
# Component: JWTHandler refresh-token exchange error handling.
# Purpose: Ensure malformed JSON from the provider is handled gracefully.
# Pass example: body b"not-json" returns None.
# Fail example: invalid JSON propagates as an uncaught exception and breaks login flow.
async def test_exchange_for_refresh_token_returns_none_for_invalid_json(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b"not-json")))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token is None

# phase1-33
# Component: JWTHandler refresh-token exchange network error handling.
# Purpose: Verify that provider-side HTTP failures are converted into a safe None result.
# Pass example: HTTP 500 from AsyncHTTPClient leads to None.
# Fail example: transient provider errors bubble up and crash the handler.
async def test_exchange_for_refresh_token_returns_none_on_http_error(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(side_effect=HTTPClientError(500, message="boom")))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token is None

# phase1-34
# Component: JWTHandler Authorization header parsing.
# Purpose: Confirm that requests without an auth token are rejected with HTTP 401.
# Pass example: get_auth_token returns None and _get_token raises HTTPError(401).
# Fail example: unauthenticated requests slip through into JWT processing.
def test_get_token_raises_401_when_header_missing():
    handler = SimpleNamespace(get_auth_token=lambda: None, log=Mock())
    with pytest.raises(HTTPClientError) as exc_info:
        JWTHandler._get_token(handler)
    assert exc_info.value.code == 401

# phase1-35
# Component: JWTHandler token decoding.
# Purpose: Verify that _get_token returns both the original raw token and its decoded payload.
# Pass example: a valid signed JWT yields the same raw string plus a decoded dict with preferred_username.
# Fail example: the helper loses the raw token or decodes the payload incorrectly.
def test_get_token_returns_original_and_decoded_token():
    from jwt import encode
    raw = encode({"preferred_username": "alice", "exp": 4102444800}, "dummy-secret", algorithm="HS256")
    handler = SimpleNamespace(get_auth_token=lambda: raw, log=Mock())
    original, decoded = JWTHandler._get_token(handler)
    assert original == raw
    assert decoded["preferred_username"] == "alice"

# phase1-36
# Component: reuse of previously minted Hub API tokens.
# Purpose: Check that reuse is impossible when there is no known JupyterHub user object.
# Pass example: user=None returns None.
# Fail example: the code attempts DB lookup or token reuse without a user context.
async def test_get_previous_hub_token_returns_none_without_user():
    handler = SimpleNamespace(db=object(), log=Mock())
    result = await JWTHandler._get_previous_hub_token(handler, None, "jwt-token")
    assert result is None

# phase1-37
# Component: reuse of previously minted Hub API tokens.
# Purpose: Ensure an old Hub API token is only reused if it belongs to the same upstream JWT access token.
# Pass example: stored access_token differs from current jwt-token, so reuse is denied.
# Fail example: a Hub API token from a previous login session is incorrectly reused.
async def test_get_previous_hub_token_returns_none_when_access_token_does_not_match():
    user = DummyUser(auth_state={"access_token": "different-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None

# phase1-38
# Component: reuse of previously minted Hub API tokens.
# Purpose: Verify that missing jwt_api_token metadata prevents reuse.
# Pass example: auth_state lacks jwt_api_token and the helper returns None.
# Fail example: the helper claims reuse is possible even though no token id is stored.
async def test_get_previous_hub_token_returns_none_when_api_token_missing():
    user = DummyUser(auth_state={"access_token": "jwt-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None

# phase1-39
# Component: reuse of previously minted Hub API tokens.
# Purpose: Confirm that the helper fails safely if the stored token cannot be found in the Hub database.
# Pass example: orm.APIToken.find returns None and reuse is rejected.
# Fail example: the code assumes the DB token exists and dereferences None.
async def test_get_previous_hub_token_returns_none_when_orm_token_missing():
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    with patch.object(orm.APIToken, "find", return_value=None):
        result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None

# phase1-40
# Component: reuse of previously minted Hub API tokens.
# Purpose: Ensure expired Hub API tokens are never reused.
# Pass example: orm token with expires_in=0 leads to None.
# Fail example: expired Hub API tokens continue to be handed out to clients.
async def test_get_previous_hub_token_returns_none_when_orm_token_expired():
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    with patch.object(orm.APIToken, "find", return_value=SimpleNamespace(expires_in=0)):
        result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None

# phase1-41
# Component: reuse of previously minted Hub API tokens.
# Purpose: Verify the positive path where a still-valid stored token is reused.
# Pass example: matching access token plus non-expired ORM token returns "api-token".
# Fail example: the code needlessly creates a new Hub API token every time.
async def test_get_previous_hub_token_reuses_existing_valid_token():
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    with patch.object(orm.APIToken, "find", return_value=SimpleNamespace(expires_in=3600)):
        result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result == "api-token"

# phase1-42
# Component: JWTHandler main GET flow.
# Purpose: Confirm that the handler returns an already-valid Hub API token instead of logging in again.
# Pass example: _get_previous_hub_token returns "api-token" and finish() receives it for user "alice".
# Fail example: the handler ignores reusable tokens and performs unnecessary authentication work.
async def test_jwt_get_reuses_previous_hub_token(authenticator):
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"}, name="alice")
    finished = {}
    handler = SimpleNamespace(
        authenticator=authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=user),
        _get_previous_hub_token=AsyncMock(return_value="api-token"),
        finish=lambda payload: finished.update(payload=payload),
    )
    await JWTHandler.get(handler)
    handler._get_previous_hub_token.assert_awaited_once_with(user, "jwt-token")
    assert finished["payload"] == {"token": "api-token", "user": "alice"}

# phase1-43
# Component: JWTHandler main GET flow for first-time or non-reusable logins.
# Purpose: Verify that the handler logs in the user, creates a Hub API token, saves it, and returns it.
# Pass example: no previous Hub token exists, so login_user is awaited and user.new_api_token is called.
# Fail example: the handler authenticates successfully but never persists or returns a usable Hub token.
async def test_jwt_get_logs_in_user_and_creates_new_api_token(authenticator):
    user = DummyUser(auth_state={"access_token": "jwt-token"}, name="alice")
    finished = {}
    handler = SimpleNamespace(
        authenticator=authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice", "iat": 1000, "exp": 4600})),
        find_user=Mock(return_value=user),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=user),
        exchange_for_refresh_token=AsyncMock(return_value="refresh-token"),
        finish=lambda payload: finished.update(payload=payload),
    )
    await JWTHandler.get(handler)
    handler.login_user.assert_awaited_once_with({"access_token": "jwt-token", "token_type": "bearer"})
    assert user.api_token_created == {"note": "JWT auth token", "expires_in": 3600}
    assert user.saved_auth_state["jwt_api_token"] == "new-hub-api-token"
    assert finished["payload"] == {"token": "new-hub-api-token", "user": "alice"}

# phase1-44
# Component: JWTHandler main GET flow refresh-token recovery.
# Purpose: Ensure the handler tries to obtain and store a refresh token when auth_state lacks one.
# Pass example: exchange_for_refresh_token returns "refresh-123", which is then saved into auth_state.
# Fail example: login succeeds but refresh capabilities are silently omitted for JWT-only sessions.
async def test_jwt_get_exchanges_for_refresh_token_when_missing(authenticator):
    user = DummyUser(auth_state={"access_token": "jwt-token"}, name="alice")
    finished = {}
    handler = SimpleNamespace(
        authenticator=authenticator,
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice", "iat": 100, "exp": 4600})),
        find_user=Mock(return_value=user),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=user),
        exchange_for_refresh_token=AsyncMock(return_value="refresh-123"),
        finish=lambda payload: finished.update(payload=payload),
    )
    await JWTHandler.get(handler)
    handler.exchange_for_refresh_token.assert_awaited_once_with("jwt-token")
    assert user.saved_auth_state["refresh_token"] == "refresh-123"
    assert finished["payload"]["user"] == "alice"

# phase1-45
# Component: JWTHandler error path for failed authentication.
# Purpose: Confirm that failed login_user results in an explicit HTTP 403.
# Pass example: login_user returns None and the handler raises HTTPError(403).
# Fail example: the handler returns success or crashes with a less meaningful exception.
async def test_jwt_get_returns_403_when_login_fails():
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
    
# phase1-46
# Component: JWTHandler Authorization header parsing.
# Purpose: Ensure obviously invalid JWT strings are rejected.
# Pass example: "not-a-jwt" raises HTTP 401.
# Fail example: malformed tokens reach later code paths and produce harder-to-debug errors.
def test_get_token_raises_401_for_invalid_jwt():
    handler = SimpleNamespace(get_auth_token=lambda: "not-a-jwt", log=Mock())
    with pytest.raises(HTTPError) as exc_info:
        JWTHandler._get_token(handler)
    assert exc_info.value.status_code == 401 
    
# phase1-27
# Component: JWTHandler refresh-token exchange helper.
# Purpose: Verify that the handler can exchange a JWT-style access token for a refresh token.
# Pass example: the IdP responds with {"refresh_token": "..."} and the helper returns that value.
# Fail example: the helper ignores the response body or posts to the wrong token endpoint.
async def test_exchange_for_refresh_token_returns_refresh_token(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b'{"refresh_token": "refresh-123"}')))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token == "refresh-123"
    request = fake_client.fetch.await_args.args[0]
    assert request.url == authenticator.token_url
    assert request.auth_username == authenticator.client_id
    assert request.auth_password == authenticator.client_secret
    assert b"subject_token=jwt-access-token" in request.body

# phase1-48
# Component: JWTHandler refresh-token exchange compatibility behavior.
# Purpose: Ensure the helper still works if a provider returns the token in access_token rather than refresh_token.
# Pass example: {"access_token": "refresh-in-access-field"} is accepted as a usable fallback.
# Fail example: the helper rejects otherwise workable provider responses due to strict field expectations.
async def test_exchange_for_refresh_token_falls_back_to_access_token_field(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b'{"access_token": "refresh-in-access-field"}')))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token == "refresh-in-access-field"

# phase1-49
# Component: JWTHandler refresh-token exchange error handling.
# Purpose: Check that an empty IdP response fails safely and returns None.
# Pass example: an empty body produces None and no crash.
# Fail example: JSON parsing crashes on empty content or returns garbage.
async def test_exchange_for_refresh_token_returns_none_for_empty_response(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b"")))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token is None    
