"""
B2Drop extension on top of onedataspawner
"""

import base64

from jinja2 import (
    BaseLoader,
    ChoiceLoader,
    Environment,
    FileSystemLoader,
    PackageLoader,
)

from egi_notebooks_hub.onedata import OnedataSpawner

from kubernetes_asyncio.client.rest import ApiException


class B2DropSpawner(OnedataSpawner):
    async def auth_state_hook(self, spawner, auth_state):
        await super().auth_state_hook(spawner, auth_state)
        self.b2drop_ready = False
        self.b2drop_user = ""
        self.b2drop_pwd = ""
        try:
            secret = await self.api.read_namespaced_secret(
                self.token_secret_name, self.namespace
            )
        except ApiException:
            return
        if secret and secret.data:
            self.b2drop_user = base64.b64decode(
                secret.data.get("b2drop-user", "")
            ).decode()
            self.b2drop_pwd = base64.b64decode(
                secret.data.get("b2drop-pwd", "")
            ).decode()
            self.b2drop_ready = self.b2drop_user and self.b2drop_pwd

    def _render_options_form(self, profile_list):
        """
        Adapts the KubeSpawner options form rendering to add the b2drop stuff.
        """
        profile_list = self._get_initialized_profile_list(profile_list)

        loader = ChoiceLoader(
            [
                FileSystemLoader(self.additional_profile_form_template_paths),
                PackageLoader("egi_notebooks_hub", "templates"),
            ]
        )
        env = Environment(loader=loader)
        env.policies["json.dumps_kwargs"] = {"sort_keys": False}

        if self.profile_form_template != "":
            profile_form_template = env.from_string(self.profile_form_template)
        else:
            profile_form_template = env.get_template("b2drop-form.html")
        return profile_form_template.render(
            profile_list=self._profile_list,
            b2drop_ready=self.b2drop_ready,
            b2drop_user=self.b2drop_user,
            b2drop_pwd=self.b2drop_pwd,
        )

    async def pre_spawn_hook(self, spawner):
        await super().pre_spawn_hook(spawner)
        b2drop_user = self.user_options.get("b2drop-user", "")
        b2drop_pwd = self.user_options.get("b2drop-pwd", "")
        b2drop_remember = self.user_options.get("b2drop-remember", None)
        if not (b2drop_user and b2drop_pwd):
            secret = await self.api.read_namespaced_secret(
                self.token_secret_name, self.namespace
            )
            if secret and secret.data:
                b2drop_user = base64.b64decode(
                    secret.data.get("b2drop-user", "")
                ).decode()
                b2drop_pwd = base64.b64decode(
                    secret.data.get("b2drop-pwd", "")
                ).decode()
        if b2drop_user and b2drop_pwd:
            volume_mounts = [
                {"mountPath": "/b2drop:shared", "name": "b2drop"},
            ]
            spawner.extra_containers.append(
                {
                    "name": "b2drop",
                    "image": "eginotebooks/webdav-sidecar:sha-e5e8df2",
                    "env": [
                        {
                            "name": "WEBDAV_URL",
                            "value": "https://b2drop.eudat.eu/remote.php/webdav",
                        },
                        {"name": "WEBDAV_PWD", "value": b2drop_pwd},
                        {"name": "WEBDAV_USER", "value": b2drop_user},
                        {"name": "MOUNT_PATH", "value": "/b2drop"},
                    ],
                    "resources": self.sidecar_resources,
                    "securityContext": {
                        "runAsUser": 0,
                        "privileged": True,
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                    "volumeMounts": volume_mounts,
                    "lifecycle": {
                        "preStop": {"exec": {"command": ["umount", "-l", "/b2drop"]}},
                    },
                }
            )
        if b2drop_remember:
            await self._update_secret(
                {"b2drop-user": b2drop_user, "b2drop-pwd": b2drop_pwd}
            )
        else:
            await self._update_secret({"b2drop-user": "", "b2drop-pwd": ""})

    def options_from_form(self, formdata):
        data = super()._options_from_form(formdata)
        data.update(
            {
                "b2drop-user": formdata.get("b2drop-user", [None])[0],
                "b2drop-remember": formdata.get("b2drop-remember", [None])[0],
                "b2drop-pwd": formdata.get("b2drop-pwd", [None])[0],
            }
        )
        return data
