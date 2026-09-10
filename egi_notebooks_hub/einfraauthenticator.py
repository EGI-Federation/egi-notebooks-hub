"""E-INFRA CZ authenticator for JupyterHub

Uses OpenID Connect with specific e-INFRA CZ AAI Kerberos extension
"""

import base64
import os
import tempfile

import krb5cc
from oauthenticator.generic import GenericOAuthenticator


class EInfraAuthenticator(GenericOAuthenticator):

    def _kerberos_exchange(self, auth_state):
        subject_token = auth_state["access_token"]
        if subject_token:
            self.log.info("subject_token: length %d", len(subject_token))
        else:
            self.log.info("subject_token: (None)")
            return
        krbctx = krb5cc.Krb5cc()
        self.log.info("krb5-cred2cc context: %s", str(krbctx))
        kerberos_token = krbctx.oidc_token_exchange(
            self.token_url, subject_token, self.client_id, self.client_secret
        )
        if kerberos_token:
            self.log.info("kerberos_token: length %d", len(kerberos_token))
        else:
            self.log.info("kerberos_token: (None)")
            return
        fd, fname = tempfile.mkstemp(prefix="krb5cc.", suffix=".dat")
        os.close(fd)
        self.log.info("temporary file for CC: %s", fname)
        krbctx.write(kerberos_token, ccache=fname)
        self.log.info("Kerberos ticket saved")
        with open(fname, "rb") as fh:
            krb5cc_ticket = fh.read()
        self.log.info("read CC data: length %d", len(krb5cc_ticket))
        os.unlink(fname)
        auth_state["kerberos_ticket"] = base64.b64encode(krb5cc_ticket).decode("UTF-8")
        auth_state["kerberos_token"] = kerberos_token

    async def authenticate(self, handler, data=None):
        self.log.info("authenticate()")
        user_info = await super().authenticate(handler, data)
        # self.log.debug("authenticate(): user_info: %s", user_info)
        if user_info is None:
            self.log.warn("No user info, stop authenticate")
            return user_info
        auth_state = user_info.get("auth_state", {})
        self._kerberos_exchange(auth_state)
        # self.log.debug("authenticate(): => auth_state: %s", auth_state)
        return user_info

    async def refresh_user(self, user, handler=None):
        self.log.info("refresh()")
        auth_model = await super().refresh_user(user, handler)
        auth_state = await user.get_auth_state()
        if not auth_state:
            # (already logged by oauth2)
            return auth_model
        self._kerberos_exchange(auth_state)
        for k in ["kerberos_ticket", "kerberos_token"]:
            if k in auth_state:
                auth_model["auth_state"][k] = auth_state[k]
        # self.log.debug("refresh(): => auth_state: %s", auth_model["auth_state"])
        return auth_model
