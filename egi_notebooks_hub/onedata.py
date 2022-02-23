"""
Onedata extras for the Oauthenticator
"""

import json

from egi_notebooks_hub.egiauthenticator import EGICheckinAuthenticator
from egi_notebooks_hub.egispawner import EGISpawner
from tornado.httpclient import AsyncHTTPClient, HTTPError, HTTPRequest
from traitlets import Bool, Dict, List, Unicode


class OnedataAuthenticator(EGICheckinAuthenticator):
    """
    Onedata authenticator for JupyterHub
    Expands the authenticator to fetch DataHub tokens
    and keep them in auth_state
    """

    onezone_url = Unicode(
        "https://datahub.egi.eu", config=True, help="""Onedata onezone URL"""
    )

    onezone_token_prefix = Unicode(
        "egi:",
        config=True,
        help="""Prefix for the the access token passed to Onezone""",
    )

    oneprovider_host = Unicode(
        "plg-cyfronet-01.datahub.egi.eu",
        config=True,
        help="""Onedata oneprovider hostname""",
    )

    onepanel_url = Unicode(
        "",
        config=True,
        help="""Endpoint of the oneprovider to establish mappings,
                if undefined, it will use https://<oneprovider_host>:9443/""",
    )

    oneprovider_token = Unicode("", config=True, help="""Onedata oneprovider token""")

    map_users = Bool(False, config=True, help="""perform mapping""")

    onedata_failsafe = Bool(
        True, config=True, help="""do not fail if onedata is not responsive"""
    )

    oneclient_token_name = Unicode(
        "oneclient.notebooks.egi.eu",
        config=True,
        help="""Name of token in the onezone for oneclient""",
    )

    onezone_token_name = Unicode(
        "onezone.notebooks.egi.eu",
        config=True,
        help="""Name of token in the onezone for the onezone""",
    )

    storage_id = Unicode("", config=True, help="""Storage id to use for mapping""")

    async def create_onedata_token(self, access_token, token_name, caveats):
        onedata_token = None
        onedata_user = None
        http_client = AsyncHTTPClient()
        headers = {
            "content-type": "application/json",
            "x-auth-token": f"{self.onezone_token_prefix}{access_token}",
        }
        token_url = (
            self.onezone_url + "/api/v3/onezone/user/tokens/named/name/%s" % token_name
        )
        req = HTTPRequest(token_url, headers=headers, method="GET")
        try:
            resp = await http_client.fetch(req)
            datahub_response = json.loads(resp.body.decode("utf8", "replace"))
            onedata_token = datahub_response["token"]
            onedata_user = datahub_response["subject"]["id"]
            self.log.debug("Reusing existing token!")
        except HTTPError as e:
            if e.code != 404:
                self.log.info("Something failed! %s", e)
                if self.onedata_failsafe:
                    return onedata_token, onedata_user
                raise e
        if not onedata_token:
            # we don't have a token, create one
            token_desc = {
                "name": token_name,
                "type": {"accessToken": {}},
                "caveats": caveats,
            }
            req = HTTPRequest(
                self.onezone_url + "/api/v3/onezone/user/tokens/named",
                headers=headers,
                method="POST",
                body=json.dumps(token_desc),
            )
            try:
                resp = await http_client.fetch(req)
                datahub_response = json.loads(resp.body.decode("utf8", "replace"))
                onedata_token = datahub_response["token"]
            except HTTPError as e:
                self.log.info("Something failed! %s", e)
                if self.onedata_failsafe:
                    return onedata_token, onedata_user
                raise e
            # Finally get the user information
            req = HTTPRequest(
                self.onezone_url + "/api/v3/onezone/user",
                headers=headers,
                method="GET",
            )
            try:
                resp = await http_client.fetch(req)
                datahub_response = json.loads(resp.body.decode("utf8", "replace"))
                onedata_user = datahub_response["userId"]
            except HTTPError as e:
                self.log.info("Something failed! %s", e)
                if self.onedata_failsafe:
                    return onedata_token, onedata_user
                raise e
        return onedata_token, onedata_user

    async def authenticate(self, handler, data=None):
        user_data = await super(OnedataAuthenticator, self).authenticate(handler, data)
        if not user_data:
            return user_data
        access_token = user_data.get("auth_state", {}).get("access_token", None)
        if not access_token:
            return None
        caveats = [{"type": "interface", "interface": "oneclient"}]
        oneclient_token, onedata_user = await self.create_onedata_token(
            access_token, self.oneclient_token_name, caveats
        )
        caveats = [
            {"type": "interface", "interface": "rest"},
            {"whitelist": ["ozw-onezone"], "type": "service"},
        ]
        onezone_token, _ = await self.create_onedata_token(
            access_token, self.onezone_token_name, caveats
        )
        onedata_info = {
            "oneclient_token": oneclient_token,
            "onedata_user": onedata_user,
            "oneprovider": self.oneprovider_host,
            "onezone_url": self.onezone_url,
            "onezone_token": onezone_token,
        }
        user_data["auth_state"].update(onedata_info)
        return user_data

    async def pre_spawn_start(self, user, spawner):
        await super(OnedataAuthenticator, self).pre_spawn_start(user, spawner)
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        if self.map_users and auth_state.get("onedata_user", None):
            if self.onepanel_url:
                map_url = self.onepanel_url
            else:
                map_url = f"https://{self.oneprovider_host}:9443"
            map_url += (
                f"/api/v3/onepanel/provider/storages/{self.storage_id}"
                "/luma/local_feed/storage_access/all"
                "/onedata_user_to_credentials"
            )
            headers = {
                "content-type": "application/json",
                "x-auth-token": self.oneprovider_token,
            }
            http_client = AsyncHTTPClient()
            user_id = auth_state.get("onedata_user")
            req = HTTPRequest(map_url + f"/{user_id}", headers=headers, method="GET")
            try:
                resp = await http_client.fetch(req)
                self.log.info("Mapping exists: %s", resp.body)
            except HTTPError as e:
                if e.code == 404:
                    mapping = {
                        "onedataUser": {
                            "mappingScheme": "onedataUser",
                            "onedataUserId": user_id,
                        },
                        "storageUser": {
                            "storageCredentials": {"type": "posix", "uid": "1000"},
                            "displayUid": "1000",
                        },
                    }
                    req = HTTPRequest(
                        map_url,
                        headers=headers,
                        method="POST",
                        body=json.dumps(mapping),
                    )
                    try:
                        resp = await http_client.fetch(req)
                        self.log.info("Mapping created: %s", resp.body)
                    except HTTPError as e:
                        self.log.info("Something failed! %s", e)
                        raise e
                else:
                    self.log.info("Something failed! %s", e)
                    raise e


class OnedataSpawner(EGISpawner):
    onedata_user_env = Unicode(
        "ONEDATA_USER",
        config=True,
        help="""Environment variable that contains the onedata user""",
    )

    onezone_env = Unicode(
        "ONEZONE_URL",
        config=True,
        help="""Environment variable that contains the onezone URL""",
    )

    token_env = Unicode(
        "ONECLIENT_ACCESS_TOKEN",
        config=True,
        help="""Name of the environment variable to store the token""",
    )

    onezone_token_env = Unicode(
        "ONEZONE_ACCESS_TOKEN",
        config=True,
        help="""Name of the environment variable to store the token for onezone""",
    )

    oneprovider_env = Unicode(
        "ONEPROVIDER_HOST",
        config=True,
        help="""Name of the environment variable to store the oneprovider
                host""",
    )

    force_proxy_io = Bool(False, config=True, help="""Force the use of proxied I/O""")

    force_direct_io = Bool(False, config=True, help="""Force the use of direct I/O""")

    only_local_spaces = Bool(
        True, config=True, help="""Only mount those spaces local to the provider"""
    )

    oneclient_extra_args = List(
        [], config=True, help="""Extra arguments for the oneclient"""
    )

    mount_point = Unicode(
        "/mnt/oneclient",
        config=True,
        help="""Mountpoint for oneclient""",
    )

    sidecar_image = Unicode(
        "eginotebooks/oneclient-sidecar",
        config=True,
        help="""Oneclient image to use""",
    )

    sidecar_resources = Dict(
        {
            "requests": {"memory": "512Mi", "cpu": "250m"},
            "limits": {"memory": "1Gi", "cpu": "500m"},
        },
        config=True,
        help="""resource limits for the sidecar""",
    )

    oneprovider_storage_mapping = List(
        [],
        config=True,
        help="""
        List of dicts like:
            {"storage_id": "<oneprovider storage id>",
             "mount_point": "volume mount point"}
        """,
    )

    extra_mounts = List([], config=True, help="""extra volume mounts in k8s""")

    def auth_state_hook(self, spawner, auth_state):
        # get onedata stuff ready to be used later on
        if auth_state is None:
            self.log.warning("No auth_state provided")
            return
        spawner.environment[self.token_env] = auth_state.get("oneclient_token")
        spawner.environment[self.onezone_env] = auth_state.get("onezone_url")
        spawner.environment[self.oneprovider_env] = auth_state.get("oneprovider")
        spawner.environment[self.onezone_token_env] = auth_state.get("onezone_token")
        spawner.environment[self.onedata_user_env] = auth_state.get("onedata_user")

    async def _get_local_spaces(self, oneprovider_host, onezone_url, onezone_token):
        # 1. Get the id of the oneprovider (this may be just config?)
        http_client = AsyncHTTPClient()
        req = HTTPRequest(
            f"https://{oneprovider_host}/api/v3/oneprovider/configuration", method="GET"
        )
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            self.log.warning("Unable to connect to oneprovider: %s", e)
            raise HTTPError(403)
        resp_json = json.loads(resp.body.decode("utf8", "replace"))
        provider_id = resp_json.get("providerId", None)
        if not provider_id:
            self.log.warning("Unable to get provider id: %s", resp_json)
            raise HTTPError(403)
        # 2. Get the spaces supported by the oneprovider
        req = HTTPRequest(
            f"{onezone_url}/api/v3/onezone/user/effective_providers/"
            f"{provider_id}/spaces",
            method="GET",
            headers={"X-Auth-Token": f"{onezone_token}"},
        )
        try:
            resp = await http_client.fetch(req)
        except HTTPError as e:
            self.log.warning("Unable to get spaces from onezone: %s", e)
            raise HTTPError(403)
        resp_json = json.loads(resp.body.decode("utf8", "replace"))
        self.log.debug(resp_json.get("spaces", []))
        return resp_json.get("spaces", [])

    async def pre_spawn_hook(self, spawner):
        host = spawner.environment.get(self.oneprovider_env, "")
        token = spawner.environment.get(self.token_env, "")
        onezone_url = spawner.environment.get(self.onezone_env, "")
        onezone_token = spawner.environment.get(self.onezone_token_env, "")
        if not all([host, token, onezone_url, onezone_token]):
            self.log.warning(
                "Missing environment values for onedata mounting, skipping"
            )
            return
        cmd = ["oneclient", "-f", "-H", f"{host}"]
        if self.only_local_spaces:
            # limit the spaces we mount to avoid issues
            for space_id in await self._get_local_spaces(
                host, onezone_url, onezone_token
            ):
                cmd.extend(["--space-id", f"{space_id}"])
            self.log.debug("CMD: %s", cmd)
        if self.force_proxy_io:
            cmd.append("--force-proxy-io")
        if self.force_direct_io:
            cmd.append("--force-direct-io")
        if self.oneprovider_storage_mapping:
            for mapping in self.oneprovider_storage_mapping:
                cmd.append("--override")
                cmd.append("%(storage_id)s:mountPoint:%(mount_point)s" % mapping)
        if self.oneclient_extra_args:
            cmd.extend(self.oneclient_extra_args)
        cmd.append(self.mount_point)
        volume_mounts = [
            {"mountPath": f"{self.mount_point}:shared", "name": "oneclient"},
        ]
        if self.extra_mounts:
            volume_mounts.extend(self.extra_mounts)
        spawner.extra_containers = [
            {
                "name": "oneclient",
                "image": self.sidecar_image,
                "env": [
                    {"name": self.oneprovider_env, "value": host},
                    {"name": self.token_env, "value": token},
                ],
                "resources": self.sidecar_resources,
                "command": cmd,
                "securityContext": {
                    "runAsUser": 1000,
                    "privileged": True,
                    "capabilities": {"add": ["SYS_ADMIN"]},
                },
                "volumeMounts": volume_mounts,
                "lifecycle": {
                    "preStop": {
                        "exec": {"command": ["fusermount", "-u", self.mount_point]}
                    },
                },
            }
        ]
