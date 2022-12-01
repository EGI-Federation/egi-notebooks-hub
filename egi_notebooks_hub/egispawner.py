"""A Spawner for the EGI Notebooks service
"""

import base64
import uuid

from kubernetes_asyncio.client import V1ObjectMeta, V1Secret
from kubernetes_asyncio.client.rest import ApiException
from kubespawner import KubeSpawner
from traitlets import Unicode


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

    async def _update_secret(self, new_data):
        """Updates the secret.

        Remove keys with a dict with None or "" as value for those keys"""
        secret_data = {}
        try:
            current_secret = await self.api.read_namespaced_secret(
                self.token_secret_name, self.namespace
            )
            if current_secret and current_secret.data:
                secret_data = current_secret.data
        except ApiException:
            # no secret, no problem
            pass
        # encode coming data
        new_encoded = {
            k: base64.b64encode(v.encode()).decode()
            for k, v in new_data.items()
            if v is not None
        }
        secret_data.update(new_encoded)
        # remove empty data
        data = {k: v for k, v in secret_data.items() if v}
        secret = self._get_secret_manifest(data)
        try:
            await self.api.replace_namespaced_secret(
                name=self.token_secret_name, namespace=self.namespace, body=secret
            )
        except ApiException as e:
            # maybe it does not exist yet?
            if e.status == 404:
                try:
                    self.log.info(
                        "Creating access token secret %s", self.token_secret_name
                    )
                    await self.api.create_namespaced_secret(
                        namespace=self.namespace, body=secret
                    )
                except ApiException:
                    raise
            else:
                raise

    async def set_access_token(self, access_token, id_token=None):
        """updates the secret in k8s with the token of the user"""
        await self._update_secret(
            {
                "access_token": access_token,
                "id_token": id_token,
            }
        )

    async def auth_state_hook(self, spawner, auth_state):
        if not auth_state:
            return
        await spawner.set_access_token(
            auth_state.get("access_token", None), auth_state.get("id_token", None)
        )
        groups = auth_state.get("groups", [])
        if spawner.profile_list:
            new_profile_list = []
            for profile in spawner.profile_list:
                profile_vos = profile.get("vo_claims", [])
                if not profile_vos:
                    new_profile_list.append(profile)
                else:
                    if any(i in groups for i in profile_vos):
                        new_profile_list.append(profile)
            spawner.profile_list = new_profile_list

        primary_group = auth_state.get("primary_group", None)
        if primary_group:
            spawner.extra_annotations["egi.eu/primary_group"] = auth_state[
                "primary_group"
            ]

    async def pre_spawn_hook(self, spawner):
        # deal here with the pvc names as there is no async option
        # in the get_pvc_manifest
        pvcs = await self.api.list_namespaced_persistent_volume_claim(
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
        # ensure we have a secret
        await self._update_secret({})
