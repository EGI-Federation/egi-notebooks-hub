"""A Spawner for the EGI Notebooks service
"""

import base64
import json
import uuid

from kubernetes.client import V1ObjectMeta, V1Secret
from kubernetes.client.rest import ApiException
from kubespawner import KubeSpawner
from tornado import web
from tornado.httpclient import AsyncHTTPClient, HTTPError, HTTPRequest
from traitlets import Bool, Dict, List, Unicode


class EGISpawner(KubeSpawner):
    token_secret_name_template = Unicode(
        "access-token-{userid}",
        config=True,
        help="""
        Template to use to form the name of secret to store user's token.
        `{username}` is expanded to the escaped, dns-label safe username.
        This must be unique within the namespace the pvc are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """,
    )

    token_secret_volume_name_template = Unicode(
        "secret-{userid}",
        config=True,
        help="""
        Template to use to form the name of secret to store user's token.
        `{username}` is expanded to the escaped, dns-label safe username.
        This must be unique within the namespace the pvc are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """,
    )

    token_mount_path = Unicode(
        "/var/run/secrets/egi.eu/",
        config=True,
        help="""
        Path where the token secret will be mounted.
        """,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pvc_name = uuid.uuid4().hex
        self.token_secret_name = self._expand_user_properties(
            self.token_secret_name_template
        )
        token_secret_volume_name = self._expand_user_properties(
            self.token_secret_volume_name_template
        )
        self.volumes.append(
            {
                "name": token_secret_volume_name,
                "secret": {"secretName": self.token_secret_name},
            }
        )
        self.volume_mounts.append(
            {
                "name": token_secret_volume_name,
                "mountPath": self.token_mount_path,
                "readOnly": True,
            }
        )
        self._create_token_secret()

    def get_pvc_manifest(self):
        """Tries to fix volumes of to avoid issues with too long user names"""
        pvcs = self.api.list_namespaced_persistent_volume_claim(
            namespace=self.namespace
        )
        for pvc in pvcs.items:
            if (
                pvc.metadata.annotations.get("hub.jupyter.org/username", "")
                == self.user.name
            ):
                self.pvc_name = pvc.metadata.name
                break
        vols = []
        # pylint: disable=access-member-before-definition
        for v in self.volumes:
            claim = v.get("persistentVolumeClaim", {})
            if claim.get("claimName", "").startswith("claim-"):
                v["persistentVolumeClaim"]["claimName"] = self.pvc_name
            vols.append(v)
        self.volumes = vols
        return super().get_pvc_manifest()

    # overriding this one to avoid long usernames as labels
    def _build_common_labels(self, extra_labels):
        labels = super()._build_common_labels(extra_labels)
        del labels["hub.jupyter.org/username"]
        return labels

    def _get_secret_manifest(self, data):
        """creates a secret in k8s that will contain the token of the user"""
        meta = V1ObjectMeta(
            name=self.token_secret_name,
            labels=self._build_common_labels({}),
            annotations=self._build_common_annotations({}),
        )
        secret = V1Secret(metadata=meta, type="Opaque", data=data)
        return secret

    def _create_token_secret(self):
        secret = self._get_secret_manifest({})
        try:
            self.api.create_namespaced_secret(namespace=self.namespace, body=secret)
            self.log.info("Created access token secret %s", self.token_secret_name)
        except ApiException as e:
            if e.status == 409:
                self.log.info("Secret %s exists, not creating", self.token_secret_name)
            else:
                raise

    def _update_token_secret(self, data):
        secret = self._get_secret_manifest(data)
        try:
            self.api.patch_namespaced_secret(
                name=self.token_secret_name, namespace=self.namespace, body=secret
            )
        except ApiException:
            raise

    def set_access_token(self, access_token, id_token=None):
        """updates the secret in k8s with the token of the user"""
        data = {
            "access_token": base64.b64encode(access_token.encode()).decode(),
            "id_token": None,
        }
        if id_token:
            data["id_token"] = base64.b64encode(id_token.encode()).decode()
        self._update_token_secret(data)


class DataHubSpawner(EGISpawner):
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
        spawner.environment[self.token_env] = auth_state.get("oneclient_token")
        spawner.environment[self.onezone_env] = auth_state.get("onezone_url")
        spawner.environment[self.oneprovider_env] = auth_state.get("oneprovider")
        spawner.environment[self.onezone_token_env] = auth_state.get("onezone_token")
        spawner.environment[self.onedata_user_env] = auth_state.get("onedata_user")

    async def pre_spawn_hook(self, spawner):
        host = spawner.environment.get(self.oneprovider_env, "")
        token = spawner.environment.get(self.token_env, "")
        onezone_url = spawner.environment.get(self.onezone_env, "")
        onezone_token = spawner.environment.get(self.onezone_token_env, "")
        cmd = ["oneclient", "-f", "-H", f"{host}"]
        if self.only_local_spaces:
            # 1. Get the id of the oneprovider
            http_client = AsyncHTTPClient()
            req = HTTPRequest(
                f"https://{host}/api/v3/oneprovider/configration", method="GET"
            )
            try:
                resp = await http_client.fetch(req)
            except HTTPError as e:
                self.log.warning("Unable to connect to oneprovider: %s", e)
                raise web.HTTPError(403)
            resp_json = json.loads(resp.body.decode("utf8", "replace"))
            provider_id = resp_json.get("providerId", None)
            if not provider_id:
                self.log.warning("Unable to get provider id: %s", resp_json)
                raise web.HTTPError(403)
            # 2. Get the spaces supported by the oneprovider
            req = HTTPRequest(
                f"{onezone_url}/api/v3/onezone/providers/{provider_id}/spaces",
                method="GET",
                headers={"X-Auth-Token", f"{onezone_token}"},
            )
            try:
                resp = await http_client.fetch(req)
            except HTTPError as e:
                self.log.warning("Unable to get spaces from onezone: %s", e)
                raise web.HTTPError(403)
            resp_json = json.loads(resp.body.decode("utf8", "replace"))
            # also limit the spaces we mount to avoid issues
            for space_id in resp_json.get("spaces", []):
                cmd.append("--spaceid")
                cmd.append(f"{space_id}" % space_id)
        if self.force_proxy_io:
            cmd.append("--force-proxy-io")
        if self.force_direct_io:
            cmd.append("--force-direct-io")
        if self.oneprovider_storage_mapping:
            for mapping in self.oneprovider_storage_mapping:
                cmd.append("--override")
                cmd.append("%(storage_id)s:mountPoint:%(mount_point)s" % mapping)
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
