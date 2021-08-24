"""EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""


import json
import os
import time

from oauthenticator.generic import GenericOAuthenticator
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest
from tornado.httputil import url_concat
from traitlets import List, Unicode, default, validate


class EGICheckinAuthenticator(GenericOAuthenticator):
    login_service = "EGI Check-in"

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
        return "https://%s/oidc/authorize" % self.checkin_host

    @default("token_url")
    def _token_url_default(self):
        return "https://%s/oidc/token" % self.checkin_host

    @default("userdata_url")
    def _userdata_url_default(self):
        return "https://%s/oidc/userinfo" % self.checkin_host

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

    #  User name in Check-in comes in sub, but we are defaulting to
    # preferred_username as sub is too long to be used as id for
    # volumes
    username_key = Unicode(
        "preferred_username",
        config=True,
        help="""
        Claim name to use for getting the user name. 'sub' is unique but it's
        too long.
        """,
    )

    # Refresh auth data for user
    async def refresh_user(self, user, handler=None):
        auth_state = await user.get_auth_state()
        if not auth_state or "refresh_token" not in auth_state:
            self.log.warning("Cannot refresh user info without refresh token")
            return False

        now = time.time()
        refresh_info = auth_state.get("refresh_info", {})
        # if the token is still valid, avoid refreshing
        time_left = refresh_info.get("expiry_time", 0) - now
        if time_left > self.auth_refresh_age:
            self.log.debug("Credentials still valid, time left: %f", time_left)
            return True

        # performing the refresh token call
        self.log.debug("Perform refresh call to Check-in")
        http_client = AsyncHTTPClient()
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="refresh_token",
            refresh_token=auth_state["refresh_token"],
            scope=" ".join(self.scope),
        )
        url = url_concat(self.token_url, params)
        req = HTTPRequest(
            url,
            auth_username=self.client_id,
            auth_password=self.client_secret,
            headers=headers,
            method="POST",
            body="",
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
        auth_state["refresh_token"] = refresh_info["refresh_token"]
        self.log.debug("Refreshed token for user!")
        if callable(getattr(user.spawner, "set_access_token", None)):
            user.spawner.set_access_token(
                auth_state["access_token"], refresh_info.get("id_token", None)
            )
        return {"auth_state": auth_state}

    async def pre_spawn_start(self, user, spawner):
        auth_state = await user.get_auth_state()
        if auth_state and callable(getattr(user.spawner, "set_access_token", None)):
            user.spawner.set_access_token(auth_state["access_token"])
