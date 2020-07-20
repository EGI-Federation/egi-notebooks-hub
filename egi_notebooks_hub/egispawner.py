"""
A Spawner for the EGI Notebooks service
"""

import base64
import uuid

from kubespawner import KubeSpawner
from kubernetes.client.rest import ApiException
from kubernetes.client import V1Secret, V1ObjectMeta


from traitlets import Unicode


class EGISpawner(KubeSpawner):
    token_secret_name_template = Unicode(
        'access-token-{userid}',
        config=True,
        help="""
        Template to use to form the name of secret to store user's token.
        `{username}` is expanded to the escaped, dns-label safe username.
        This must be unique within the namespace the pvc are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """
    )

    token_secret_volume_name_template = Unicode(
        'secret-{userid}',
        config=True,
        help="""
        Template to use to form the name of secret to store user's token.
        `{username}` is expanded to the escaped, dns-label safe username.
        This must be unique within the namespace the pvc are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pvc_name = uuid.uuid4().hex
        self.token_secret_name = self._expand_user_properties(
                self.token_secret_name_template)
        token_secret_volume_name = self._expand_user_properties(
                self.token_secret_volume_name_template)
        self.volumes.append({"name": token_secret_volume_name,
                             "secret": {"secretName": self.token_secret_name}})
        self.volume_mounts.append({"name": token_secret_volume_name,
                                  "mountPath": "/etc/egi",
                                  "readOnly": True})

    def get_pvc_manifest(self):
        """ Tries to fix volumes of to avoid issues with too long user name for k8s """
        pvcs = self.api.list_namespaced_persistent_volume_claim(namespace=self.namespace)
        for pvc in pvcs.items:
            if pvc.metadata.annotations.get('hub.jupyter.org/username', '') == self.user.name:
                self.pvc_name = pvc.metadata.name
                break
        vols = []
        for v in self.volumes:
            if v.get('persistentVolumeClaim', {}).get('claimName', '').startswith('claim-'):
                v['persistentVolumeClaim']['claimName'] = self.pvc_name
            vols.append(v)
        self.volumes = vols

    def set_access_token(self, token):
        """creates a secret in k8s with the token of the user"""
        meta = V1ObjectMeta(name=self.token_secret_name,
                            labels=self._build_common_labels({}),
                            annotations=self._build_common_annotations({}))
        data = {"CHECKIN_TOKEN": base64.b64encode(token.encode()).decode()}
        secret = V1Secret(metadata=meta,
                          type="Opaque",
                          data=data)
        try:
            self.api.create_namespaced_secret(namespace=self.namespace,
                                              body=secret)
            self.log.info("Created access token secret %s",
                          self.token_secret_name)
        except ApiException as e:
            if e.status == 409:
                self.log.info("Updating secret %s", self.token_secret_name)
                try:
                    self.api.patch_namespaced_secret(name=self.token_secret_name,
                                                     namespace=self.namespace,
                                                     body=secret)
                except ApiException as e:
                    raise
            else:
                raise
