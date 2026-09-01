"""A Spawner for e-INFRA CZ Notebooks with Kerberos"""

import base64

from egi_notebooks_hub.egispawner import EGISpawner


class EInfraSpawner(EGISpawner):

    async def set_access_token(
        self, access_token, id_token=None, kerberos_ticket=None, kerberos_token=None
    ):
        """updates the secret in k8s with the token of the user"""
        await self._update_secret(
            {
                "access_token": access_token,
                "id_token": id_token,
                "kerberos_token": kerberos_token,
                "krb5cc": kerberos_ticket,
            }
        )

    async def auth_state_hook(self, spawner, auth_state):
        if not auth_state:
            return
        kerberos_ticket = auth_state.get("kerberos_ticket", None)
        if kerberos_ticket:
            kerberos_ticket = base64.b64decode(kerberos_ticket)
            self.environment.update(
                {"KRB5CCNAME": f"FILE:{self.token_mount_path}/krb5cc"}
            )
        await spawner.set_access_token(
            auth_state.get("access_token", None),
            auth_state.get("id_token", None),
            kerberos_ticket,
            auth_state.get("kerberos_token", None),
        )
        primary_group = auth_state.get("primary_group", None)
        if primary_group:
            spawner.extra_annotations["egi.eu/primary_group"] = auth_state[
                "primary_group"
            ]
