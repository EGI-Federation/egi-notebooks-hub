"""EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""


import json
import os
import time
from urllib.parse import urlencode

from oauthenticator.generic import GenericOAuthenticator
from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPRequest
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

    async def authenticate(self, handler, data=None):
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
        body = urlencode(
            dict(
                client_id=self.client_id,
                client_secret=self.client_secret,
                grant_type="refresh_token",
                refresh_token=auth_state["refresh_token"],
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
        return {"auth_state": auth_state}
