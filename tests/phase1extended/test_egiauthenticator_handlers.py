import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from jupyterhub import orm
from tornado.httpclient import HTTPClientError
from tornado.web import HTTPError

from egi_notebooks_hub.egiauthenticator import JWTHandler, TokenRevokeHandler


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


@pytest.mark.asyncio
async def test_exchange_for_refresh_token_returns_refresh_token(authenticator):
    handler = SimpleNamespace(
        log=Mock(),
        authenticator=authenticator,
    )
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b'{"refresh_token": "refresh-123"}')))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token == "refresh-123"
    request = fake_client.fetch.await_args.args[0]
    assert request.url == authenticator.token_url
    assert request.auth_username == authenticator.client_id
    assert request.auth_password == authenticator.client_secret
    assert "subject_token=jwt-access-token" in request.body


@pytest.mark.asyncio
async def test_exchange_for_refresh_token_falls_back_to_access_token_field(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b'{"access_token": "refresh-in-access-field"}')))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token == "refresh-in-access-field"


@pytest.mark.asyncio
async def test_exchange_for_refresh_token_returns_none_for_empty_response(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b"")))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token is None


@pytest.mark.asyncio
async def test_exchange_for_refresh_token_returns_none_for_invalid_json(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(return_value=DummyResponse(b"not-json")))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token is None


@pytest.mark.asyncio
async def test_exchange_for_refresh_token_returns_none_on_http_error(authenticator):
    handler = SimpleNamespace(log=Mock(), authenticator=authenticator)
    fake_client = SimpleNamespace(fetch=AsyncMock(side_effect=HTTPClientError(500, message="boom")))
    with patch("egi_notebooks_hub.egiauthenticator.AsyncHTTPClient", return_value=fake_client):
        token = await JWTHandler.exchange_for_refresh_token(handler, "jwt-access-token")
    assert token is None


def test_get_token_raises_401_when_header_missing():
    handler = SimpleNamespace(get_auth_token=lambda: None, log=Mock())
    with pytest.raises(HTTPError) as exc_info:
        JWTHandler._get_token(handler)
    assert exc_info.value.status_code == 401


def test_get_token_raises_401_for_invalid_jwt():
    handler = SimpleNamespace(get_auth_token=lambda: "not-a-jwt", log=Mock())
    with pytest.raises(HTTPError) as exc_info:
        JWTHandler._get_token(handler)
    assert exc_info.value.status_code == 401


def test_get_token_returns_original_and_decoded_token():
    from jwt import encode

    raw = encode({"preferred_username": "alice", "exp": 4102444800}, "dummy-secret", algorithm="HS256")
    handler = SimpleNamespace(get_auth_token=lambda: raw, log=Mock())
    original, decoded = JWTHandler._get_token(handler)
    assert original == raw
    assert decoded["preferred_username"] == "alice"


@pytest.mark.asyncio
async def test_get_previous_hub_token_returns_none_without_user(authenticator):
    handler = SimpleNamespace(db=object(), log=Mock())
    result = await JWTHandler._get_previous_hub_token(handler, None, "jwt-token")
    assert result is None


@pytest.mark.asyncio
async def test_get_previous_hub_token_returns_none_when_access_token_does_not_match(authenticator):
    user = DummyUser(auth_state={"access_token": "different-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None


@pytest.mark.asyncio
async def test_get_previous_hub_token_returns_none_when_api_token_missing():
    user = DummyUser(auth_state={"access_token": "jwt-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None


@pytest.mark.asyncio
async def test_get_previous_hub_token_returns_none_when_orm_token_missing():
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    with patch.object(orm.APIToken, "find", return_value=None):
        result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None


@pytest.mark.asyncio
async def test_get_previous_hub_token_returns_none_when_orm_token_expired():
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    with patch.object(orm.APIToken, "find", return_value=SimpleNamespace(expires_in=0)):
        result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result is None


@pytest.mark.asyncio
async def test_get_previous_hub_token_reuses_existing_valid_token():
    user = DummyUser(auth_state={"access_token": "jwt-token", "jwt_api_token": "api-token"})
    handler = SimpleNamespace(db=object(), log=Mock())
    with patch.object(orm.APIToken, "find", return_value=SimpleNamespace(expires_in=3600)):
        result = await JWTHandler._get_previous_hub_token(handler, user, "jwt-token")
    assert result == "api-token"


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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
        finish=lambda payload: finished.update(payload=payload),
    )

    await JWTHandler.get(handler)

    handler.login_user.assert_awaited_once_with({"access_token": "jwt-token", "token_type": "bearer"})
    assert user.api_token_created == {"note": "JWT auth token", "expires_in": 3600}
    assert user.saved_auth_state["jwt_api_token"] == "new-hub-api-token"
    assert finished["payload"] == {"token": "new-hub-api-token", "user": "alice"}


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_jwt_get_returns_403_when_login_fails(authenticator):
    handler = SimpleNamespace(
        authenticator=SimpleNamespace(custom_403_message="Forbidden by test"),
        log=Mock(),
        _get_token=Mock(return_value=("jwt-token", {"preferred_username": "alice"})),
        find_user=Mock(return_value=None),
        _get_previous_hub_token=AsyncMock(return_value=None),
        login_user=AsyncMock(return_value=None),
    )

    with pytest.raises(HTTPError) as exc_info:
        await JWTHandler.get(handler)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_token_revoke_handler_rejects_missing_user():
    handler = SimpleNamespace(current_user=None)
    with pytest.raises(HTTPError) as exc_info:
        await TokenRevokeHandler.post(handler)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_token_revoke_handler_rejects_missing_auth_state():
    handler = SimpleNamespace(current_user=DummyUser(auth_state=None))
    with pytest.raises(HTTPError) as exc_info:
        await TokenRevokeHandler.post(handler)
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_token_revoke_handler_refreshes_user_and_revokes_old_token(authenticator):
    user = DummyUser(
        auth_state={
            "access_token": "old-token",
            "token_response": {"access_token": "old-token"},
        },
        name="alice",
    )
    auth_to_user = AsyncMock()
    authenticator.refresh_user = AsyncMock(return_value={"auth_state": {"access_token": "new-token"}})
    authenticator.revoke_token = AsyncMock()

    handler = SimpleNamespace(
        current_user=user,
        authenticator=authenticator,
        auth_to_user=auth_to_user,
    )

    await TokenRevokeHandler.post(handler)

    assert user.saved_auth_state["access_token"] == "revoke"
    assert user.saved_auth_state["token_response"]["access_token"] == "revoke"
    authenticator.refresh_user.assert_awaited_once_with(user, handler)
    auth_to_user.assert_awaited_once()
    authenticator.revoke_token.assert_awaited_once_with("old-token")
