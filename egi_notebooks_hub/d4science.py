"""D4Science Authenticator for JupyterHub
"""

import base64
import datetime
import json
import os
from urllib.parse import parse_qs, quote_plus, unquote, urlencode, urlparse, urlunparse
from xml.etree import ElementTree

import jwt
import xmltodict
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
    "https://api.d4science.org/social-networking-library-ws/rest/",
)
D4SCIENCE_PROFILE = "2/people/profile"
D4SCIENCE_REGISTRY_BASE_URL = os.environ.get(
    "D4SCIENCE_REGISTRY_BASE_URL",
    "https://registry.d4science.org/icproxy/gcube/service",
)
D4SCIENCE_DM_REGISTRY_URL = os.environ.get(
    "D4SCIENCE_REGISTRY_URL",
    D4SCIENCE_REGISTRY_BASE_URL + "/ServiceEndpoint/DataAnalysis/DataMiner",
)
D4SCIENCE_DISCOVER_WPS = os.environ.get(
    "D4SCIENCE_DISCOVER_WPS",
    "false",
)
D4SCIENCE_OIDC_URL = os.environ.get(
    "D4SCIENCE_OIDC_URL", "https://accounts.d4science.org/auth/realms/d4science/"
)
JUPYTERHUB_INFOSYS_URL = os.environ.get(
    "JUPYTERHUB_INFOSYS_URL",
    D4SCIENCE_REGISTRY_BASE_URL + "/GenericResource/JupyterHub",
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
                "Resource/Profile/AccessPoint/Interface/Endpoint"
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
            # we need to remove gcube-token from the url query to avoid
            # the spawner not showing the the options form
            # this code is basically taken from Stack Overflow
            # https://stackoverflow.com/a/7734686
            next_url = urlparse(self.get_next_url(user))
            query = parse_qs(next_url.query, keep_blank_values=True)
            query.pop("gcube-token", None)
            next_url = next_url._replace(query=urlencode(query, True))
            self.redirect(urlunparse(next_url), permanent=False)


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
        spawner.environment["GCUBE_CONTEXT"] = auth_state["context"]

    def get_handlers(self, app):
        return [(r"/login", self.login_handler)]


class D4ScienceContextHandler(OAuthLoginHandler):
    def get_state(self):
        context = self.get_argument("context", None)
        self.authenticator.d4science_context = context
        return super().get_state()


class D4ScienceOauthenticator(GenericOAuthenticator):
    login_handler = D4ScienceContextHandler
    d4science_oidc_url = Unicode(
        D4SCIENCE_OIDC_URL,
        config=True,
        help="""The OIDC URL for D4science""",
    )
    jupyterhub_infosys_url = Unicode(
        JUPYTERHUB_INFOSYS_URL,
        config=True,
        help="""The URL for getting JupyterHub profiles from the
                Information System of D4science""",
    )

    _pubkeys = None

    async def get_iam_public_keys(self):
        if self._pubkeys:
            return self._pubkeys
        discovery_url = url_path_join(
            self.d4science_oidc_url, ".well-known/openid-configuration"
        )
        self.log.debug("Getting OIDC discovery info at %s", discovery_url)
        http_client = AsyncHTTPClient()
        req = HTTPRequest(discovery_url, method="GET")
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

    async def get_uma_token(self, context, audience, access_token, extra_params={}):
        body = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "claim_token_format": "urn:ietf:params:oauth:token-type:jwt",
            "audience": audience,
        }
        body.update(extra_params)
        http_client = AsyncHTTPClient()
        req = HTTPRequest(
            self.token_url,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Authorization": f"Bearer {access_token}",
            },
            body=urlencode(body),
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
            audience=audience,
            algorithms=["RS256"],
        )
        self.log.debug("Decoded token: %s", decoded_token)
        return token, decoded_token

    async def get_resources(self, access_token):
        http_client = AsyncHTTPClient()
        req = HTTPRequest(
            self.jupyterhub_infosys_url,
            method="GET",
            headers={
                "Authorization": f"Bearer {access_token}",
            },
        )
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning("Unable to get the resources for user: %s", e)
            self.log.debug(req)
            raise web.HTTPError(403)
        self.log.debug("Got resources description...")
        # Assume that this will fly
        return xmltodict.parse(resp.body)

    async def authenticate(self, handler, data=None):
        # first get authorized upstream
        user_data = await super().authenticate(handler, data)
        context = quote_plus(getattr(self, "d4science_context", None))
        self.log.debug("Context is %s", context)
        if not context:
            self.log.error("Unable to get the user context")
            raise web.HTTPError(403)
        access_token = user_data["auth_state"]["access_token"]
        extra_params = {
            "claim_token": base64.b64encode(
                json.dumps({"context": [f"{context}"]}).encode("utf-8")
            )
        }
        token, decoded_token = await self.get_uma_token(
            context, self.client_id, access_token, extra_params
        )
        ws_token, _ = await self.get_uma_token(context, context, access_token)
        permissions = decoded_token["authorization"]["permissions"]
        self.log.debug("Permissions: %s", permissions)
        resources = await self.get_resources(ws_token)
        self.log.debug("Resources: %s", resources)
        user_data["auth_state"].update(
            {
                "context_token": ws_token,
                "permissions": permissions,
                "context": context,
                "resources": resources,
            }
        )
        return user_data

    async def pre_spawn_start(self, user, spawner):
        """Pass gcube-token to spawner via environment variable"""
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        spawner.environment["GCUBE_TOKEN"] = auth_state["context_token"]
        # spawner.environment["DATAMINER_URL"] = auth_state["wps-endpoint"]
        spawner.environment["GCUBE_CONTEXT"] = unquote(auth_state["context"])


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
    volume_mappings = Dict(
        {},
        config=True,
        help="""Mapping of extra volumes from the information system to k8s volumes
                Dicts should have an entry for each of the extra volumes as follows:
                {
                    'name-of-extra-volume': {
                        'mount_path': '/home/jovyan/dataspace',
                        'volume': { k8s object defining the volume},
                    }
                }
            """,
    )
    extra_profiles = List(
        [],
        config=True,
        help="""Extra profiles to add to user options independently of the configuration
                from the D4Science Information System. The profiles should be a list of
                dictionaries as defined in the Kubespanwer
                https://jupyterhub-kubespawner.readthedocs.io/en/latest/spawner.html#kubespawner.KubeSpawner.profile_list
            """,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_profiles = []
        self.server_options = []
        self._orig_volumes = self.volumes
        self._orig_volume_mounts = self.volume_mounts

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
            "--ResourceUseDisplay.track_cpu_percent=True",
            "--NotebookApp.iopub_data_rate_limit=100000000",
        ] + args

    def get_volume_name(self, name):
        return name.strip().lower().replace(" ", "-")

    async def auth_state_hook(self, spawner, auth_state):
        if not auth_state:
            return
        # just get from the authenticator
        permissions = auth_state.get("permissions", [])
        self.allowed_profiles = [claim["rsname"] for claim in permissions]
        resources = auth_state.get("resources", {})
        self.server_options = {}
        volume_options = {}
        try:
            resource_list = resources["genericResources"]["Resource"]
            if not isinstance(resource_list, list):
                resource_list = [resource_list]
            for opt in resource_list:
                p = opt.get("Profile", {}).get("Body", {})
                if p.get("ServerOption", None):
                    self.server_options[p["ServerOption"]["AuthId"]] = p["ServerOption"]
                elif p.get("VolumeOption", None):
                    volume_options[p["VolumeOption"]["Name"]] = p["VolumeOption"][
                        "Permission"
                    ]
        except KeyError:
            self.log.debug("Unexpected resource response from D4Science")

        self.volumes = self._orig_volumes.copy()
        self.volume_mounts = self._orig_volume_mounts.copy()
        for name, permission in volume_options.items():
            if name in self.volume_mappings:
                vol_name = self.get_volume_name(name)
                vol = {"name": (vol_name)}
                vol.update(self.volume_mappings[name]["volume"])
                self.volumes.append(vol)
                self.volume_mounts.append(
                    {
                        "name": vol_name,
                        "mountPath": self.volume_mappings[name]["mount_path"],
                        "readOnly": permission == "Read-only",
                    },
                )
        self.log.debug("allowed: %s", self.allowed_profiles)
        self.log.debug("opts: %s", self.server_options)
        self.log.debug("volume_options %s", volume_options)
        self.log.debug("volumes: %s", self.volumes)
        self.log.debug("volume_mounts: %s", self.volume_mounts)
        self.log.debug("volume_mappings: %s", self.volume_mappings)

    def profile_list(self, spawner):
        # returns the list of profiles built according to the permissions
        # and resource definition that the authenticator obtained initially
        if not (self.allowed_profiles and self.server_options):
            return []

        profiles = []
        for allowed in self.allowed_profiles:
            p = self.server_options.get(allowed, None)
            if not p:
                continue
            override = {}
            name = p.get("Info", {}).get("Name", "")
            if "ImageId" in p:
                override["image"] = p.get("ImageId", None)
            if "Cut" in p:
                cut_info = []
                if "Cores" in p["Cut"]:
                    override["cpu_limit"] = float(p["Cut"]["Cores"])
                    cut_info.append(f"{p['Cut']['Cores']} Cores")
                if "Memory" in p["Cut"]:
                    override["mem_limit"] = "%(#text)s%(@unit)s" % p["Cut"]["Memory"]
                    cut_info.append(f"{override['mem_limit']} RAM")
                name += " - %s" % " / ".join(cut_info)
            profile = {
                "display_name": name,
                "description": p.get("Info", {}).get("Description", ""),
                "slug": p.get("AuthId", ""),
                "kubespawner_override": override,
                "default": p.get("@default", {}) == "true",
            }
            if profile["default"]:
                profiles.insert(0, profile)
            else:
                profiles.append(profile)
        if self.extra_profiles:
            profiles.extend(self.extra_profiles)
        sorted_profiles = sorted(profiles, key=lambda x: x["display_name"])
        return sorted_profiles

    async def pre_spawn_hook(self, spawner):
        # add volumes as defined in the D4Science info sys
        gcube_token = spawner.environment.get("GCUBE_TOKEN", "")
        context = spawner.environment.get("GCUBE_CONTEXT", "")
        if context:
            # set the whole context as annotation (needed for accounting)
            spawner.extra_annotations["d4science_context"] = context
            # set only the VRE name in the environment (needed for NFS subpath)
            vre = context[context.rindex("/") + 1 :]
            spawner.log.info("VRE: %s", vre)
            spawner.environment["VRE"] = vre
        if gcube_token:
            spawner.extra_containers = [
                {
                    "name": "workspace-sidecar",
                    "image": self.sidecar_image,
                    "securityContext": {
                        "privileged": True,
                        "capabilities": {"add": ["SYS_ADMIN"]},
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
