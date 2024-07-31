"""EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""

import json
import os
import re
import time
from urllib.parse import urlencode

import jwt
import jwt.exceptions
from jupyterhub import orm
from jupyterhub.handlers import BaseHandler
from oauthenticator.generic import GenericOAuthenticator
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPError, HTTPRequest
from traitlets import List, Unicode, default, validate


class JWTHandler(BaseHandler):
    async def exchange_for_refresh_token(self, access_token):
        self.log.debug("Exchanging access token for refresh")
        http_client = AsyncHTTPClient()
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }
        body = urlencode(
            dict(
                grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
                requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
                subject_token_type="urn:ietf:params:oauth:token-type:access_token",
                subject_token=access_token,
                # beware that this requires the "offline_access" or similar
                # to be included, otherwise the refresh token will not be
                # released. Also the access token must have this scope.
                scope=" ".join(self.authenticator.scope),
            )
        )
        req = HTTPRequest(
            self.authenticator.token_url,
            auth_username=self.authenticator.client_id,
            auth_password=self.authenticator.client_secret,
            headers=headers,
            method="POST",
            body=body,
        )
        try:
            resp = await http_client.fetch(req)
        except HTTPClientError as e:
            self.log.warning(f"Unable to get refresh token: {e}")
            if e.response:
                self.log.debug(e.response.body)
            return None
        token_info = json.loads(resp.body.decode("utf8", "replace"))
        if "refresh_token" in token_info:
            return token_info.get("refresh_token")
        # EOSC AAI returns the token into "access_token" field, so be it
        return token_info.get("access_token", None)

    async def _get_previous_hub_token(self, user, jwt_token):
        if not user:
            return None
        auth_state = await user.get_auth_state()
        if auth_state and auth_state.get("access_token", None) == jwt_token:
            api_token = auth_state.get("jwt_api_token", None)
            if api_token is None:
                return None
            orm_token = orm.APIToken.find(self.db, api_token)
            if not orm_token or orm_token.expires_in <= 0:
                return None
            self.log.debug("Reusing previously available API token for this JWT")
            return api_token

    def _get_token(self):
        jwt_token = self.get_auth_token()
        if not jwt_token:
            self.log.debug("No token found in header")
            raise HTTPError(401)
        try:
            decoded_token = jwt.decode(
                jwt_token,
                options=dict(verify_signature=False, verify_exp=True),
            )
        except jwt.exceptions.InvalidTokenError as e:
            self.log.debug(f"Invalid token {e}")
            raise web.HTTPError(401)
        return jwt_token, decoded_token

    async def get(self):
        user = None
        jwt_token, decoded_token = self._get_token()
        try:
            username = self.authenticator.user_info_to_username(decoded_token)
            user = self.find_user(username)
        except ValueError as e:
            self.log.debug(f"Unable to get username from token: {e}")
        api_token = await self._get_previous_hub_token(user, jwt_token)
        if not api_token:
            self.log.debug("Authenticating user")
            token_info = {
                "access_token": jwt_token,
                "token_type": "bearer",
            }
            user = await self.login_user(token_info)
            if user is None:
                raise web.HTTPError(403, self.authenticator.custom_403_message)
            auth_state = await user.get_auth_state()
            if auth_state and not auth_state.get("refresh_token", None):
                self.log.debug("Refresh token is not available")
                refresh_token = await self.exchange_for_refresh_token(jwt_token)
                if refresh_token:
                    self.log.debug("Got refresh token from exchange")
                    auth_state["refresh_token"] = refresh_token

            # default: 1h token
            expires_in = 3600
            if "exp" in decoded_token and "iat" in decoded_token:
                expires_in = decoded_token["exp"] - decoded_token["iat"]

            # Possible optimisation here: instead of creating a new token every time,
            # go through user.api_tokens and get one from there
            api_token = user.new_api_token(
                note="JWT auth token",
                expires_in=expires_in,
                # TODO: this may be tuned, but should be a post
                #       call with a body specifying the roles and scopes
                # roles=token_roles,
                # scopes=token_scopes,
            )
            auth_state["jwt_api_token"] = api_token
            await user.save_auth_state(auth_state)
        self.finish({"token": api_token, "user": user.name})


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

    @default("manage_groups")
    def _manage_groups_default(self):
        return True

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

    def get_primary_group(self, oauth_user):
        groups = self.get_user_groups(oauth_user)
        # first group as the primary, priority is governed by ordering in
        # Authenticator.allowed_groups
        first_group = next((v for v in self.allowed_groups if v in groups), None)
        return first_group

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
        oauth_user = auth_state.get(self.user_auth_state_key, {})
        if not oauth_user:
            self.log.warning("Missing OAuth info")
            return user_info

        first_group = self.get_primary_group(oauth_user)
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
            resp = await http_client.fetch(req)
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


class EOSCNodeAuthenticator(EGICheckinAuthenticator):
    """Adaptation of the EGI Check-in Authenticator to the
    EOSC EU Node authorization needs"""

    login_service = "EOSC AAI"

    personal_project_re = Unicode(
        r"^urn:geant:eosc-federation.eu:group:(pp-.*)$",
        config=True,
        help="""Regular expression to match the personal groups.
                If the regular expression contains a group and matches, it will be
                used as the name of the Personal project group""",
    )

    def get_primary_group(self, oauth_user):
        # first group is the personal project, which is different for every user
        # if not available call super()
        for g in self.get_user_groups(oauth_user):
            m = re.match(self.personal_project_re, g)
            if m:
                if m.groups():
                    return m.groups()[0]
                else:
                    return g
        return super().get_primary_group(oauth_user)
