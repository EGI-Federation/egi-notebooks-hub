"""EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""

import base64
import hashlib
import json
import os
import re
from urllib.parse import urlencode

import jwt
import jwt.exceptions
from jupyterhub import orm
from jupyterhub.handlers import BaseHandler
from oauthenticator.generic import GenericOAuthenticator
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPError, HTTPRequest
from traitlets import Bool, Int, List, Unicode, default, validate


class JWTHandler(BaseHandler):
    """Handler for authentication with JWT tokens"""

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
        resp_body = resp.body.decode("utf8", "replace")
        if not resp_body:
            self.log.warning("Empty reply from refresh call when exchanging token")
            return None
        try:
            token_info = json.loads(resp_body)
        except json.JSONDecodeError as e:
            self.log.error(
                f"Invalid JSON from server: {e}, server response: {resp_body}"
            )
            return None
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
            if auth_state:
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

    introspect_url = Unicode(
        config=True,
        help="""
        The URL to where this authenticator makes a request to
        introspect user tokens received via the jwt authentication

        For more context, see `RFC7622
        <https://datatracker.ietf.org/doc/html/rfc7662>`_.
        """,
    )

    @default("introspect_url")
    def _introspect_url_default(self):
        return (
            "https://%s/auth/realms/egi/protocol/openid-connect/token/introspect"
            % self.checkin_host
        )

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
    # Note: this is `username_claim` in the OAuth2 Authenticator
    #       but since we are overrinding this one, it needs a different
    #       name
    aai_username_claim = Unicode(
        "preferred_username",
        config=True,
        help="""
        Claim name to use for getting the user name. 'sub' is unique but it's
        too long.
        """,
    )

    # Service accounts may not have "sub", so this is an alternative
    # claim for those accounts
    aai_servicename_claim = Unicode(
        "client_id",
        config=True,
        help="""
        Claim name to use for getting the name for services where
        the `aai_username_claim` is not available. See also `allow_anonymous`.
        """,
    )

    allow_anonymous = Bool(
        True,
        config=True,
        help="""Whether to allow for users without available username
                claim and create usernames for them on the fly""",
    )
    anonymous_username_prefix = Unicode(
        "anon",
        config=True,
        help="""A prefix for the the anonymous users""",
    )

    auth_refresh_leeway = Int(
        60,
        config=True,
        help="""Additional leeway time (in seconds) on top
                of the auth_refresh_age to renew tokens""",
    )

    @default("manage_groups")
    def _manage_groups_default(self):
        return True

    def username_claim(self, user_info):
        """Customises the OAuth.username_claim to consider also
        service accounts and potentially anonymous users"""
        username = user_info.get(
            self.aai_username_claim, user_info.get(self.aai_servicename_claim, None)
        )
        if not username:
            if not self.allow_anonymous:
                self.log.error("Anonymous users not enabled!")
                return None
            # let's treat this as an anonymous user with a name
            # that's generated as a hash of user_info
            info_str = json.dumps(user_info, sort_keys=True).encode("utf-8")
            username = "{0}-{1}".format(
                self.anonymous_username_prefix,
                hashlib.sha256(info_str).hexdigest(),
            )
        return username

    async def _token_to_auth_model(self, token_info):
        """Overriding this to add the `primary_group` information to the
        auth_state - useful for accounting purposes"""
        auth_model = super()._token_to_auth_model(token_info)
        auth_state = auth_model["auth_state"]
        first_group = self.get_primary_group(auth_model)
        self.log.info("Primary group: %s", first_group)
        if first_group:
            auth_state["primary_group"] = first_group
        return auth_model

    def get_primary_group(self, user_info):
        groups = user_info.get("groups", [])
        # first group as the primary, priority is governed by ordering in
        # Authenticator.allowed_groups
        first_group = next((v for v in self.allowed_groups if v in groups), None)
        return first_group

    async def refresh_user_hook(self, authenticator, user, auth_state):
        """Force the refresh if the current token is to expire soon"""
        access_token = auth_state.get("access_token", None)
        if not access_token:
            self.log.debug(
                "No access token, assuming user is not managed with Check-in"
            )
            return True

        try:
            # We want to fall on the safe side for refreshing, hence using
            # the auth_refresh_age plus a configurable leeway
            # Set as negative as the code checks that the token is
            # valid as of (now - leeway)
            # See PyJWT code here:
            # https://github.com/jpadilla/pyjwt/blob/868cf4ab2ca5a0a39da40e5a14dd740b203662b2/jwt/api_jwt.py#L306
            leeway = -float(self.auth_refresh_age + self.auth_refresh_leeway)
            if jwt.decode(
                access_token,
                options=dict(
                    verify_signature=False,
                    verify_exp=True,
                ),
                leeway=leeway,
            ):
                # access token is good, no need to keep going
                self.log.debug("Access token is still good, no refresh needed")
                return True
        except jwt.exceptions.InvalidTokenError as e:
            self.log.debug(f"Invalid access token, will try to refresh: {e}")

        return None

    #
    # JWT auth and introspection
    #
    # The regular authentication flow (code grant) obtains the access token in the
    # authentication process itself, but when dealing with JWTs directly we are not
    # really doing authentication but re-using a previous authentication. In that
    # case we want to introspect the token to obtain any additional information that
    # the AAI can give us.
    #
    # To not override `.authenticate()` from parent class, we override the
    # functions called from there: `build_access_tokens_request_params`,
    # `get_token_info` and `token_to_user`.
    #

    def build_access_tokens_request_params(self, handler, data=None):
        # "regular" authentication does not have any data, assume that if
        # receive something in there, we are dealing with jwt, still if
        # not successful keep trying the usual way
        if data:
            data["introspect"] = True
            return {"data": data}
        else:
            return super().build_access_tokens_request_params(handler, data)

    async def get_token_info(self, handler, params):
        if "data" in params and params["data"]:
            # access token is already here no need to do anything else
            return params["data"]
        else:
            return await super().get_token_info(handler, params)

    async def token_to_user(self, token_info):
        if "introspect" in token_info:
            return await self.introspect_token(token_info)
        else:
            return await super().token_to_user(token_info)

    async def introspect_token(self, data):
        if "access_token" not in data:
            raise web.HTTPError(500, "No access token available")

        # Taken from build_token_info_request_headers of oauthenticator
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "User-Agent": "JupyterHub",
        }
        b64key = base64.b64encode(
            bytes(f"{self.client_id}:{self.client_secret}", "utf8")
        )
        headers.update({"Authorization": f'Basic {b64key.decode("utf8")}'})
        params = {"token": data["access_token"]}
        return await self.httpfetch(
            self.introspect_url,
            label="Introspecting token...",
            method="POST",
            headers=headers,
            body=urlencode(params).encode("utf-8"),
            validate_cert=self.validate_server_cert,
        )

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

    # Namespaces used in the EOSC EU Node:
    # Testing: urn:geant:eosc-federation.eu
    # Staging: urn:geant:eosc-federation.eu
    # Production: urn:geant:open-science-cloud.ec.europa.eu
    #
    # Personal projects are in the form:
    # <urn-namespace>:group:pp-0190356a-ac97-db53-21c0-df7cd31a47c4
    personal_project_re = Unicode(
        r"^urn:geant:[^:]+:group:(pp-.*)$",
        config=True,
        help="""Regular expression to match the personal groups.
                If the regular expression contains a group and matches, it will be
                used as the name of the Personal project group""",
    )

    def get_primary_group(self, user_info):
        # first group is the personal project, which is different for every user
        # if not available return None
        for g in user_info.get("groups", []):
            m = re.match(self.personal_project_re, g)
            if m:
                if m.groups():
                    return m.groups()[0]
                else:
                    return g
        return None
