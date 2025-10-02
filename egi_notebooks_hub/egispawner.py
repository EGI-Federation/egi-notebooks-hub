"""A Spawner for the EGI Notebooks service"""

import base64
import uuid

from kubernetes_asyncio.client import V1ObjectMeta, V1Secret
from kubernetes_asyncio.client.rest import ApiException
from kubespawner import KubeSpawner
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
        """,
    )

    token_mount_path = Unicode(
        "/var/run/secrets/egi.eu/",
        config=True,
        help="""
        Path where the token secret will be mounted.
        """,
    )

    mount_secrets_volume = Bool(
        False,
        config=True,
        help="""Whether to mount or not the secrets as a volume in the
                user space at the `token_mount_path`. If False, then a
                in-memory volume will be provided instead""",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # change to a method so we can filter
        self._profile_config = self.profile_list
        self.profile_list = self._profile_filter
        self.pvc_name = uuid.uuid4().hex
        self.token_secret_name = self._expand_user_properties(
            self.token_secret_name_template
        )
        self._token_secret_volume_name = self._expand_user_properties(
            self.token_secret_volume_name_template
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
        primary_group = auth_state.get("primary_group", None)
        if primary_group:
            spawner.extra_annotations["egi.eu/primary_group"] = auth_state[
                "primary_group"
            ]

    async def configure_secret_volumes(self):
        # ensure we have a secret
        await self._update_secret({})
        user_secret_volume_name = f"{self._token_secret_volume_name}-user"
        # Remove the secret from mounts and re-add it
        # just to ensure we don't have it duplicated
        new_mounts = list(
            filter(
                lambda x: x["name"]
                not in [self.secret_volume_name, self.secret_sidecar_volume_name],
                self._sorted_dict_values(self.volume_mounts),
            )
        )
        new_mounts.append(
            {
                "name": user_secret_volume_name,
                "mountPath": self.token_mount_path,
                # read only when is the real secret, otherwise not
                "readOnly": self.mount_secrets_volume,
            }
        )
        self.volume_mounts = new_mounts
        # Do the same for the secret volume, remove and then add
        # We setup two volumes: one towards the user and another for sidecars
        # depending on whether the mount_secrets_volume option, the user
        # will have the actual content or just an emptyDir
        new_volumes = list(
            filter(
                lambda x: x["name"]
                not in [self._token_secret_volume_name, user_secret_volume_name],
                self.volumes,
            )
        )
        sidecar_secret = {
            "name": self._token_secret_volume_name,
            "secret": {"secretName": self.token_secret_name},
        }
        new_volumes.append(sidecar_secret)
        user_secret = {"name": user_secret_volume_name}
        if not self.mount_secrets_volume:
            user_secret.update({"emptyDir": {"medium": "Memory"}})
        else:
            user_secret.update({"secret": {"secretName": self.token_secret_name}})
        new_volumes.append(user_secret)
        self.volumes = new_volumes
        # set also the env
        self.environment.update(
            {"SECRETS_VOLUME_MOUNTED": f"{int(self.mount_secrets_volume)}"}
        )

    async def configure_user_volumes(self):
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

    def _profile_filter(self, spawner):
        profile_list = []
        if spawner._profile_config:
            groups = [g.name for g in spawner.user.groups]
            for profile in spawner._profile_config:
                profile_vos = profile.get("vo_claims", [])
                if not profile_vos or any(i in groups for i in profile_vos):
                    profile_list.append(profile)
        return profile_list

    def _options_from_form(self, formdata):
        user_options = super()._options_from_form(formdata)
        form_secrets_mount = formdata.get("secrets-volume-setting", [None])[0] == "1"
        user_options.update({"mount_secrets_volume": form_secrets_mount})
        return user_options

    async def load_user_options(self):
        # applies overrides from the spawner
        await super().load_user_options()
        if not self.user_options:
            return
        if "mount_secrets_volume" in self.user_options:
            self.mount_secrets_volume = self.user_options.get("mount_secrets_volume")

    async def pre_spawn_hook(self, spawner):
        """
        Do actions before spawning.
        """
        await self.load_user_options()
        await self.configure_user_volumes()
        await self.configure_secret_volumes()

    def get_args(self):
        args = super().get_args()
        if not self.mount_secrets_volume:
            args.append(
                f"--TokenAcquirerApp.secrets_mount_path={self.token_mount_path}"
            )
        args.append(f"--UserSharingApp.secrets_mount_path={self.token_mount_path}")
        return args
