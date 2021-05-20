"""D4Science Authenticator for JupyterHub
"""

import base64
import datetime
import json
import os
from urllib.parse import unquote, urlencode
from xml.etree import ElementTree

import jwt
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from kubespawner import KubeSpawner
from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPError, HTTPRequest
from tornado.httputil import url_concat
from traitlets import Dict, List, Unicode

D4SCIENCE_SOCIAL_URL = os.environ.get(
    "D4SCIENCE_SOCIAL_URL",
    "https://socialnetworking1.d4science.org/social-networking-library-ws/rest/",
)
D4SCIENCE_PROFILE = "2/people/profile"
D4SCIENCE_DM_REGISTRY_URL = os.environ.get(
    "D4SCIENCE_REGISTRY_URL",
    "https://registry.d4science.org/icproxy/gcube/"
    "service/ServiceEndpoint/DataAnalysis/DataMiner",
)
D4SCIENCE_DISCOVER_WPS = os.environ.get(
    "D4SCIENCE_DISCOVER_WPS",
    "false",
)
D4SCIENCE_OIDC_DISCOVER_URL = (
    "https://accounts.d4science.org/auth/realms/d4science/"
    ".well-known/openid-configuration"
)


class D4ScienceLoginHandler(BaseHandler):
    # override implementation of clear_cookies from tornado to add extra
    # options
    def clear_cookie(self, name, path="/", domain=None):
        kwargs = self.settings.get("cookie_options", {})
        expires = datetime.datetime.utcnow() - datetime.timedelta(days=365)
        self.set_cookie(
            name, value="", path=path, expires=expires, domain=domain, **kwargs
        )

    async def get(self):
        self.log.debug("Authenticating user")
        user = await self.get_current_user()
        token = self.get_argument("gcube-token")
        if user and token:
            self.log.debug("Clearing login cookie, new user?")
            # clear login cookies with full set of options

            self.clear_login_cookie()
            # make sure we don't do a mess here
            self.redirect(
                url_concat(
                    self.authenticator.login_url(self.hub.base_url),
                    {"gcube-token": token},
                ),
                permanent=False,
            )
            return
        if not token:
            self.log.error("No gcube token. Out!")
            raise web.HTTPError(403)
        http_client = AsyncHTTPClient()
        # discover user info
        user_url = url_concat(
            url_path_join(D4SCIENCE_SOCIAL_URL, D4SCIENCE_PROFILE),
            {"gcube-token": token},
        )
        req = HTTPRequest(user_url, method="GET")
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning("Something happened with gcube service: %s", e)
            raise web.HTTPError(403)
        resp_json = json.loads(resp.body.decode("utf8", "replace"))
        username = resp_json.get("result", {}).get("username", "")
        context = resp_json.get("result", {}).get("context", "")

        if not username or not context:
            self.log.error("Unable to get the user or context from gcube?")
            raise web.HTTPError(403)

        # discover WPS if enabled
        wps_endpoint = ""
        if D4SCIENCE_DISCOVER_WPS.lower() in ["true", "1"]:
            self.log.debug("Discover wps")
            discovery_url = url_concat(
                D4SCIENCE_DM_REGISTRY_URL, {"gcube-token": token}
            )
            req = HTTPRequest(discovery_url, method="GET")
            try:
                self.log.debug("fetch")
                resp = await http_client.fetch(req)
            except HTTPError as e:
                # whatever, get out
                self.log.error("Something happened with gcube service: %s", e)
                raise web.HTTPError(403)
            root = ElementTree.fromstring(resp.body.decode("utf8", "replace"))
            self.log.debug("root %s", root)
            for child in root.findall(
                "Resource/Profile/AccessPoint/" "Interface/Endpoint"
            ):
                entry_name = child.attrib["EntryName"]
                self.log.debug("entry_name %s", entry_name)
                if entry_name != "GetCapabilities":
                    wps_endpoint = child.text
                    self.log.debug("WPS endpoint: %s", wps_endpoint)
                    break
        self.log.info("D4Science user is %s", username)
        data = {
            "gcube-token": token,
            "gcube-user": username,
            "wps-endpoint": wps_endpoint,
            "context": context,
        }
        data.update(resp_json["result"])
        user = await self.login_user(data)
        if user:
            self._jupyterhub_user = user
            self.redirect(self.get_next_url(user), permanent=False)


class D4ScienceAuthenticator(Authenticator):
    login_handler = D4ScienceLoginHandler

    async def authenticate(self, handler, data=None):
        if data and data.get("gcube-user"):
            return {"name": data["gcube-user"], "auth_state": data}
        return None

    async def pre_spawn_start(self, user, spawner):
        """Pass gcube-token to spawner via environment variable"""
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        spawner.environment["GCUBE_TOKEN"] = auth_state["gcube-token"]
        spawner.environment["DATAMINER_URL"] = auth_state["wps-endpoint"]
        spawner.environment["GCUBE_VRE"] = auth_state["context"]

    def get_handlers(self, app):
        return [(r"/login", self.login_handler)]


class D4ScienceContextHandler(OAuthLoginHandler):
    def get_state(self):
        context = self.get_argument("context", None)
        self.authenticator.d4science_context = context
        return super().get_state()


class D4ScienceOauthenticator(GenericOAuthenticator):
    login_handler = D4ScienceContextHandler
    oidc_discovery_url = Unicode(
        D4SCIENCE_OIDC_DISCOVER_URL,
        config=True,
        help="""The OIDC discovery URL""",
    )
    _pubkeys = None

    async def get_iam_public_keys(self):
        if self._pubkeys:
            return self._pubkeys
        self.log.debug("Getting OIDC discovery info at %s", self.oidc_discovery_url)
        http_client = AsyncHTTPClient()
        req = HTTPRequest(self.oidc_discovery_url, method="GET")
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

    async def authenticate(self, handler, data=None):
        # first get authorized upstream
        user_data = await super().authenticate(handler, data)
        context = getattr(self, "d4science_context", None)
        if not context:
            self.log.error("Unable to get the user context")
            raise web.HTTPError(403)
        self.log.debug("Context is %s", context)
        # TODO: do we need to check anything on the context?
        body = urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                "claim_token_format": "urn:ietf:params:oauth:token-type:jwt",
                "audience": self.client_id,
                "claim_token": base64.b64encode(
                    json.dumps({"context": [f"{context}"]}).encode("utf-8")
                ),
            }
        )
        http_client = AsyncHTTPClient()
        req = HTTPRequest(
            self.token_url,
            method="POST",
            auth_username=self.client_id,
            auth_password=self.client_secret,
            auth_mode="basic",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
            },
            body=body,
        )
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning("Unable to get the permission for user: %s", e)
            raise web.HTTPError(403)
        self.log.debug("Got UMA ticket from server...")
        token = json.loads(resp.body.decode("utf8", "replace"))["access_token"]
        kid = jwt.get_unverified_header(token)["kid"]
        key = (await self.get_iam_public_keys())[kid]
        decoded_token = jwt.decode(
            token,
            key=key,
            audience=self.client_id,
            algorithms=["RS256"],
        )
        # TODO: add extra checks?
        user_data["auth_state"].update(
            {
                "uma_token": token,
                "permissions": decoded_token["authorization"]["permissions"],
                "context": context,
            }
        )
        return user_data

    async def pre_spawn_start(self, user, spawner):
        """Pass gcube-token to spawner via environment variable"""
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        spawner.environment["GCUBE_TOKEN"] = auth_state["uma_token"]
        # spawner.environment["DATAMINER_URL"] = auth_state["wps-endpoint"]
        spawner.environment["GCUBE_VRE"] = unquote(auth_state["context"])


class D4ScienceSpawner(KubeSpawner):
    frame_ancestors = Unicode(
        "https://*.d4science.org 'self'",
        config=True,
        help="""Frame ancestors for embedding the hub in d4science""",
    )
    sidecar_image = Unicode(
        "eginotebooks/d4science-storage",
        config=True,
        help="""the D4science storage image to use""",
    )
    d4science_profiles = List(
        trait=Dict(),
        config=True,
        help="""
        List of profiles for the spawners, follows same config as
        profile_list from kubespawner but gets filtered according
        to the permissions of the user.
        """,
    )

    def get_args(self):
        args = super().get_args()
        tornado_settings = {
            "headers": {
                "Content-Security-Policy": "frame-ancestors %s" % self.frame_ancestors
            },
            "cookie_options": {"samesite": "None", "secure": True},
        }
        # TODO: check if this keeps making sense
        return [
            "--SingleUserNotebookApp.tornado_settings=%s" % tornado_settings,
            "--FileCheckpoints.checkpoint_dir='/home/jovyan/.notebookCheckpoints'",
            "--FileContentsManager.use_atomic_writing=False",
            "--NotebookApp.ResourceUseDisplay.track_cpu_percent=True",
        ] + args

    async def pre_spawn_hook(self, spawner):
        gcube_token = spawner.environment.get("GCUBE_TOKEN", "")
        vre = spawner.environment.get("GCUBE_VRE", "")
        if vre:
            vre = vre[vre.rindex("/") + 1 :]
            spawner.log.info("VRE: %s", vre)
            spawner.environment["VRE"] = vre
        if gcube_token:
            spawner.extra_containers = [
                {
                    "name": "sh",
                    "image": self.sidecar_image,
                    "securityContext": {
                        "privileged": True,
                        "capabilities": {"add": ["SYS_ADMIN"]},
                        "runAsGroup": 0,
                        "runAsUser": 1000,
                    },
                    "env": [
                        {"name": "MNTPATH", "value": "/workspace"},
                        {"name": "GCUBE_TOKEN", "value": gcube_token},
                    ],
                    "volumeMounts": [
                        {"mountPath": "/workspace:shared", "name": "workspace"},
                    ],
                    "lifecycle": {
                        "preStop": {
                            "exec": {"command": ["fusermount", "-uz", "/workspace"]}
                        },
                    },
                }
            ]

    # async def profile_list(self, spawner):
    #    # TODO: filter out options
    #    return self.d4science_profiles
