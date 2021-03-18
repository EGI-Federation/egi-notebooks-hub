"""A Spawner for the EGI Notebooks service
"""

import base64
import json
import uuid

from kubernetes.client import V1ObjectMeta, V1Secret
from kubernetes.client.rest import ApiException
from kubespawner import KubeSpawner
from tornado.httpclient import AsyncHTTPClient, HTTPError, HTTPRequest
from traitlets import Bool, Unicode


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

    manager_class = Unicode(
        "eginotebooks.manager.MixedContentsManager",
        config=True,
        help="""DataHub Content Manager""",
    )

    force_proxy_io = Bool(False, config=True, help="""Force the use of proxied I/O""")

    force_direct_io = Bool(True, config=True, help="""Force the use of direct I/O""")

    async def add_datahub_args(self, pod):
        # if coming via binder, this shouldn't be done
        token = self.environment.get(self.token_env, "")
        if token:
            onezone_url = self.environment.get(self.onezone_env, "")
            url = onezone_url + "/api/v3/onezone/user/effective_spaces"
            headers = {"content-type": "application/json", "x-auth-token": token}
            http_client = AsyncHTTPClient()
            req = HTTPRequest(url, headers=headers, method="GET")
            try:
                resp = await http_client.fetch(req)
                datahub_response = json.loads(resp.body.decode("utf8", "replace"))
            except HTTPError as e:
                self.log.warn("Something failed! %s", e)
                raise e
            scheme = []
            for space in datahub_response["spaces"]:
                url = onezone_url + "/api/v3/onezone/user/spaces/%s" % space
                req = HTTPRequest(url, headers=headers, method="GET")
                try:
                    resp = await http_client.fetch(req)
                    datahub_response = json.loads(resp.body.decode("utf8", "replace"))
                    scheme.append(
                        {
                            "root": datahub_response["name"],
                            "class": "onedatafs_jupyter.OnedataFSContentsManager",
                            "config": {"space": "/" + datahub_response["name"]},
                        }
                    )
                except HTTPError as e:
                    self.log.info("Something failed! %s", e)
                    raise e
            pod.spec.containers[0].args = pod.spec.containers[0].args + [
                ("--NotebookApp.contents_manager_class=%s" % self.manager_class),
                (
                    "--OnedataFSContentsManager.oneprovider_host=$(%s)"
                    % self.oneprovider_env
                ),
                ("--OnedataFSContentsManager.access_token=$(%s)" % self.token_env),
                ('--OnedataFSContentsManager.path=""'),
                ("--OnedataFSContentsManager.force_proxy_io=%s" % self.force_proxy_io),
                (
                    "--OnedataFSContentsManager.force_direct_io=%s"
                    % self.force_direct_io
                ),
                ("--MixedContentsManager.filesystem_scheme=%s" % json.dumps(scheme)),
            ]
            self.log.info("POD: %s", pod.spec.containers[0].args)
        return pod
