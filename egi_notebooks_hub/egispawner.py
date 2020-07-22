"""
A Spawner for the EGI Notebooks service
"""

import base64
import json
import uuid

from kubespawner import KubeSpawner
from kubernetes.client.rest import ApiException
from kubernetes.client import V1Secret, V1ObjectMeta

from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from traitlets import Bool, Unicode


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
        return super().get_pvc_manifest()

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


class DataHubSpawner(EGISpawner):
    onezone_env = Unicode(
        "ONEZONE_URL",
        config=True,
        help="""Environment variable that contains the onezone URL"""
                
    )

    token_env = Unicode(
        'ONECLIENT_ACCESS_TOKEN',
        config=True,
        help="""Name of the environment variable to store the token"""
    )

    oneprovider_env = Unicode(
        'ONEPROVIDER_HOST',
        config=True,
        help="""Name of the environment variable to store the oneprovider host"""
    )

    manager_class = Unicode(
        'eginotebooks.manager.MixedContentsManager',
        config=True,
        help="""DataHub Content Manager"""
    )
 
    force_proxy_io = Bool(
        False,
        config=True,
        help="""Force the use of proxied I/O"""
    )

    force_direct_io = Bool(
        True,
        config=True,
        help="""Force the use of direct I/O"""
    )

    async def add_datahub_args(self, pod):
        # if coming via binder, this shouldn't be done
        if self.environment.get(self.token_env, ''):
            onezone_url = self.environment.get(self.onezone_env, "")
            http_client = AsyncHTTPClient()
            req = HTTPRequest(onezone_url + '/api/v3/onezone/user/effective_spaces',
                    headers={'content-type': 'application/json',
                             'x-auth-token': self.environment[self.token_env]},
                    method='GET')
            try:
                resp = await http_client.fetch(req)
                datahub_response = json.loads(resp.body.decode('utf8', 'replace'))
            except HTTPError as e:
                self.log.warn("Something failed! %s", e)
                raise e
            scheme = []
            for space in datahub_response['spaces']:
                req = HTTPRequest(onezone_url + '/api/v3/onezone/user/spaces/%s' % space,
                        headers={'content-type': 'application/json',
                                 'x-auth-token': self.environment[self.token_env]},
                        method='GET')
                try:
                    resp = await http_client.fetch(req)
                    datahub_response = json.loads(resp.body.decode('utf8', 'replace'))
                    scheme.append({
                        "root": datahub_response["name"],
                        "class": "onedatafs_jupyter.OnedataFSContentsManager",
                        "config": {"space": "/" + datahub_response["name"] },
                    })
                except HTTPError as e:
                    self.log.info("Something failed! %s", e)
                    raise e
            pod.spec.containers[0].args = (pod.spec.containers[0].args +
                [
                    '--NotebookApp.contents_manager_class=%s' % self.manager_class,
                    '--OnedataFSContentsManager.oneprovider_host=$(%s)' % self.oneprovider_env,
                    '--OnedataFSContentsManager.access_token=$(%s)' % self.token_env,
                    '--OnedataFSContentsManager.path=""',
                    '--OnedataFSContentsManager.force_proxy_io=%s' % self.force_proxy_io,
                    '--OnedataFSContentsManager.force_direct_io=%s' % self.force_direct_io,
                    '--MixedContentsManager.filesystem_scheme=%s' % json.dumps(scheme)
                ]
            )
            self.log.info("POD: %s", pod.spec.containers[0].args)
        return pod
