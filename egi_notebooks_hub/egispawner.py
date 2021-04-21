"""A Spawner for the EGI Notebooks service
"""

import base64
import uuid

from kubernetes.client import V1ObjectMeta, V1Secret
from kubernetes.client.rest import ApiException
from kubespawner import KubeSpawner
from traitlets import Bool, List, Unicode


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

    oneprovider_env = Unicode(
        "ONEPROVIDER_HOST",
        config=True,
        help="""Name of the environment variable to store the oneprovider
                host""",
    )

    force_proxy_io = Bool(False, config=True, help="""Force the use of proxied I/O""")

    force_direct_io = Bool(False, config=True, help="""Force the use of direct I/O""")

    mount_point = Unicode(
        "/mnt/oneclient",
        config=True,
        help="""Mountpoint for oneclient""",
    )

    client_image = Unicode(
        "onedata/oneclient:20.02.7",
        config=True,
        help="""Oneclient image to use""",
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

    async def pre_spawn_hook(self, spawner):
        host = spawner.environment.get("ONEPROVIDER_HOST", "")
        token = spawner.environment.get("ONECLIENT_ACCESS_TOKEN", "")
        cmd = ["oneclient", "-f"]
        cmd.append(f"-H {host}")
        if self.force_proxy_io:
            cmd.append("--force-proxy-io")
        if self.force_direct_io:
            cmd.append("--force-direct-io")
        if self.oneprovider_storage_mapping:
            for mapping in self.oneprovider_storage_mapping:
                cmd.append(
                    "--override %(storage_id)s:mountPoint:%(mount_point)s" % mapping
                )
        cmd.append(self.mount_point)
        volume_mounts = [
            {"mountPath": f"{self.mount_point}:shared", "name": "oneclient"},
        ]
        if self.extra_mounts:
            volume_mounts.extend(self.extra_mounts)
        spawner.extra_containers = [
            {
                "name": "oneclient",
                "image": self.client_image,
                "env": [
                    {"name": "ONECLIENT_PROVIDER_HOST", "value": host},
                    {"name": "ONECLIENT_ACCESS_TOKEN", "value": token},
                ],
                "resources": {
                    "requests": {"memory": "512Mi", "cpu": "250m"},
                    "limits": {"memory": "4Gi", "cpu": "500m"},
                },
                "command": [
                    "sh",
                    "-c",
                    "useradd -u 1000 -g 100 jovyan && su -p jovyan -c '%s'"
                    % " ".join(cmd),
                ],
                "securityContext": {
                    "runAsUser": 0,
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
