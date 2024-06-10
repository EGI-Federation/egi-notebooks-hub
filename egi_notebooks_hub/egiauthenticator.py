"""EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""

import json
import os
import time
from urllib.parse import urlencode

import jwt
from jupyterhub.handlers import BaseHandler
from oauthenticator.generic import GenericOAuthenticator
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPError, HTTPRequest
from traitlets import List, Unicode, default, validate


class JWTHandler(BaseHandler):
    _pubkeys = None

    async def _get_public_keys(self):
        if self._pubkeys:
            return self._pubkeys
        self.log.debug(
            "Getting OIDC discovery info at %s",
            self.authenticator.openid_configuration_url,
        )
        http_client = AsyncHTTPClient()
        req = HTTPRequest(self.authenticator.openid_configuration_url, method="GET")
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning("Discovery endpoint not working? %s", e)
            raise web.HTTPError(403)
        jwks_uri = json.loads(resp.body.decode("utf8", "replace"))["jwks_uri"]
        self.log.debug("Getting JWKS info at %s", jwks_uri)
        req = HTTPRequest(jwks_uri, method="GET")
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning("Unable to get jwks info: %s", e)
            raise web.HTTPError(403)
        self._pubkeys = {}
        jwks_keys = json.loads(resp.body.decode("utf8", "replace"))["keys"]
        for jwk in jwks_keys:
            kid = jwk["kid"]
            self._pubkeys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        return self._pubkeys

    async def get(self):
        auth_header = self.request.headers.get("Authorization", "")
        if auth_header:
            try:
                bearer, token = auth_header.split()
                if bearer.lower() != "bearer":
                    self.log.debug("Unexpected authorization header format")
                    raise HTTPError(401)
            except ValueError:
                self.log.debug("Unexpected authorization header format")
                raise HTTPError(401)
        else:
            self.log.debug("No authorization header")
            raise HTTPError(401)
        # build a token info dict
        # what about the refresh token?
        token_info = {
            "access_token": token,
            "token_type": "bearer",
        }
        user = await self.login_user(token_info)
        if user is None:
            raise web.HTTPError(403, self.authenticator.custom_403_message)

        api_token = user.new_api_token(
            note="JWT created token",
            # TODO: this should be tuned
            # expires_in=body.get('expires_in', None),
            # roles=token_roles,
            # scopes=token_scopes,
        )
        # what does the user expects to see here? a hub token?
        # Return a hub token, same duration as incoming token?
        self.finish({"token": api_token, "user": user.name})
        # offline validation - not needed?
        # kid = jwt.get_unverified_header(token)["kid"]
        # probably this should be done just once for all users
        # so this is not the right place
        # key = (await self._get_public_keys())[kid]
        # decoded_token = jwt.decode(
        #    token,
        #    key=key,
        #    audience=None,
        #    algorithms=["RS256"],
        # )


class EGICheckinAuthenticator(GenericOAuthenticator):
    login_service = "EGI Check-in"
    jwt_handler = JWTHandler

    checkin_host_env = "EGICHECKIN_HOST"
    checkin_host = Unicode(config=True, help="""The EGI Check-in host to use""")

    @default("checkin_host")
    def _checkin_host_default(self):
        default = "aai.egi.eu"
        if self.checkin_host_env:
            return os.getenv(self.checkin_host_env, default)
        return default

    @default("authorize_url")
    def _authorize_url_default(self):
        return (
            "https://%s/auth/realms/egi/protocol/openid-connect/auth"
            % self.checkin_host
        )

    @default("token_url")
    def _token_url_default(self):
        return (
            "https://%s/auth/realms/egi/protocol/openid-connect/token"
            % self.checkin_host
        )

    @default("userdata_url")
    def _userdata_url_default(self):
        return (
            "https://%s/auth/realms/egi/protocol/openid-connect/userinfo"
            % self.checkin_host
        )

    openid_configuration_url = Unicode(
        config=True, help="""The OpenID configuration URL"""
    )

    @default("openid_configuration_url")
    def _openid_configuration_url_default(self):
        return (
            "https://%s/auth/realms/egi/.well-known/openid-configuration"
            % self.checkin_host
        )

    client_id_env = "EGICHECKIN_CLIENT_ID"
    client_secret_env = "EGICHECKIN_CLIENT_SECRET"

    scope = List(
        Unicode(),
        default_value=[
            "openid",
            "profile",
            "eduperson_scoped_affiliation",
            "eduperson_entitlement",
            "offline_access",
        ],
        config=True,
        help="""The OAuth scopes to request.

        See https://wiki.egi.eu/wiki/AAI_guide_for_SPs
        #OpenID_Connect_Service_Provider for details.

        At least 'openid' is required.
        """,
    )

    @validate("scope")
    def _validate_scope(self, proposal):
        """ensure openid is requested"""
        if "openid" not in proposal.value:
            return ["openid"] + proposal.value
        return proposal.value

    # User name in Check-in comes in sub, but we are defaulting to
    # preferred_username as sub is too long to be used as id for
    # volumes
    username_claim = Unicode(
        "preferred_username",
        config=True,
        help="""
        Claim name to use for getting the user name. 'sub' is unique but it's
        too long.
        """,
    )

    async def jwt_authenticate(self, handler, data=None):
        try:
            user_info = await self.token_to_user(data)
        except HTTPClientError:
            raise web.HTTPError(403)
        # this code below comes is from oauthenticator authenticate
        # we cannot directly call that method as we don't obtain the access
        # token with the code grant but they pass it to us directly
        username = self.user_info_to_username(user_info)
        username = self.normalize_username(username)

        # check if there any refresh_token in the token_info dict
        refresh_token = data.get("refresh_token", None)
        if self.enable_auth_state and not refresh_token:
            self.log.debug(
                "Refresh token was empty, will try to pull refresh_token from "
                "previous auth_state"
            )
            refresh_token = await self.get_prev_refresh_token(handler, username)
            if refresh_token:
                data["refresh_token"] = refresh_token
        # build the auth model to be read if authentication goes right
        auth_model = {
            "name": username,
            "admin": True if username in self.admin_users else None,
            "auth_state": self.build_auth_state_dict(data, user_info),
        }
        # update the auth_model with info to later authorize the user in
        # check_allowed, such as admin status and group memberships
        return await self.update_auth_model(auth_model)

    async def authenticate(self, handler, data=None):
        # "regular" authentication does not have any data, assume that if
        # receive something in there, we are dealing with jwt, still if
        # not successful keep trying the usual way
        if data:
            user_info = await self.jwt_authenticate(handler, data)
        else:
            user_info = await super().authenticate(handler, data)
        if user_info is None or self.claim_groups_key is None:
            return user_info
        auth_state = user_info.get("auth_state", {})
        oauth_user = auth_state.get("oauth_user", {})
        if not oauth_user:
            self.log.warning("Missing OAuth info")
            return user_info

        # get groups by "claim_group_key"
        groups = []
        if callable(self.claim_groups_key):
            groups = self.claim_groups_key(oauth_user)
        else:
            groups = oauth_user.get(self.claim_groups_key, [])
        self.log.info("Groups: %s", groups)
        auth_state["groups"] = groups

        # first group as the primary, priority is governed by ordering in
        # Authenticator.allowed_groups
        first_group = next((v for v in self.allowed_groups if v in groups), None)
        self.log.info("Primary group: %s", first_group)
        if first_group:
            auth_state["primary_group"] = first_group

        return user_info

    # Refresh auth data for user
    async def refresh_user(self, user, handler=None):
        auth_state = await user.get_auth_state()
        if not auth_state:
            self.log.debug("No auth state, assuming user is not managed with Check-in")
            return True

        access_token = auth_state.get("access_token", None)
        refresh_token = auth_state.get("refresh_token", None)

        if not access_token:
            self.log.debug(
                "No access token, assuming user is not managed with Check-in"
            )
            return True

        now = time.time()
        refresh_info = auth_state.get("refresh_info", {})
        # if the token is still valid, avoid refreshing
        time_left = refresh_info.get("expiry_time", 0) - now
        if time_left > self.auth_refresh_age:
            self.log.debug("Credentials still valid, time left: %f", time_left)
            return True

        if not refresh_token:
            self.log.debug("No refresh token, cannot refresh user")
            return False

        # performing the refresh token call
        self.log.debug("Perform refresh call to Check-in")
        http_client = AsyncHTTPClient()
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }
        body = urlencode(
            dict(
                client_id=self.client_id,
                client_secret=self.client_secret,
                grant_type="refresh_token",
                refresh_token=refresh_token,
                scope=" ".join(self.scope),
            )
        )
        req = HTTPRequest(
            self.token_url,
            auth_username=self.client_id,
            auth_password=self.client_secret,
            headers=headers,
            method="POST",
            body=body,
        )
        try:
            resp = http_client.fetch(req)
        except HTTPClientError as e:
            self.log.warning("Unable to refresh token, maybe expired: %s", e)
            return False
        refresh_info = json.loads(resp.body.decode("utf8", "replace"))
        refresh_info["expiry_time"] = now + refresh_info["expires_in"]
        auth_state["refresh_info"] = refresh_info
        auth_state["access_token"] = refresh_info["access_token"]
        if "refresh_token" in refresh_info:
            auth_state["refresh_token"] = refresh_info["refresh_token"]
        if "id_token" in refresh_info:
            auth_state["id_token"] = refresh_info["id_token"]
        self.log.debug("Refreshed token for user!")
        if callable(getattr(user.spawner, "set_access_token", None)):
            await user.spawner.set_access_token(
                auth_state["access_token"], refresh_info.get("id_token", None)
            )
        return {"auth_state": auth_state}

    def get_handlers(self, app):
        handlers = super().get_handlers(app)
        handlers.append(
            (r"/jwt_login", self.jwt_handler),
        )
        return handlers
