
"""
Phase 5 Kubernetes-backed tests for EGI spawner-related behavior.
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="traitlets")

import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.rest import ApiException

from egi_notebooks_hub.egispawner import EGISpawner


class AsyncCoreV1Api:
    def __init__(self, core_v1):
        self.core_v1 = core_v1

    async def read_namespaced_secret(self, name, namespace):
        return await self.core_v1.read_namespaced_secret(name=name, namespace=namespace)

    async def replace_namespaced_secret(self, name, namespace, body):
        return await self.core_v1.replace_namespaced_secret(
            name=name, namespace=namespace, body=body
        )

    async def create_namespaced_secret(self, namespace, body):
        return await self.core_v1.create_namespaced_secret(namespace=namespace, body=body)

    async def list_namespaced_persistent_volume_claim(self, namespace):
        return await self.core_v1.list_namespaced_persistent_volume_claim(namespace=namespace)


@pytest_asyncio.fixture
async def kube():
    await config.load_kube_config()
    api = client.CoreV1Api()
    try:
        yield api
    finally:
        await api.api_client.close()


@pytest_asyncio.fixture
async def namespace(kube):
    ns_name = f"phase5-{uuid.uuid4().hex[:10]}"
    await kube.create_namespace(
        client.V1Namespace(metadata=client.V1ObjectMeta(name=ns_name))
    )
    try:
        yield ns_name
    finally:
        try:
            await kube.delete_namespace(name=ns_name)
        except ApiException:
            pass


@pytest.fixture
def async_api(kube):
    return AsyncCoreV1Api(kube)


def make_lightweight_spawner(async_api, namespace, username="alice"):
    spawner = SimpleNamespace()
    spawner.api = async_api
    spawner.namespace = namespace
    spawner.user = SimpleNamespace(name=username)
    spawner.token_secret_name = f"access-token-{username}"
    spawner.pvc_name = f"claim-{username}"
    spawner.log = SimpleNamespace(
        info=lambda *a, **k: None,
        debug=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        error=lambda *a, **k: None,
    )

    def _get_secret_manifest(data):
        return client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=spawner.token_secret_name,
                namespace=namespace,
            ),
            type="Opaque",
            data=data,
        )

    def _sorted_dict_values(values):
        if isinstance(values, dict):
            return [values[k] for k in sorted(values.keys())]
        return list(values)

    spawner._get_secret_manifest = _get_secret_manifest
    spawner._sorted_dict_values = _sorted_dict_values
    return spawner


@pytest.mark.asyncio
async def test_k3s_cluster_is_reachable(kube):
    ns_list = await kube.list_namespace()
    names = {item.metadata.name for item in ns_list.items}
    assert "default" in names


@pytest.mark.asyncio
async def test_update_secret_creates_real_secret_in_k3s(async_api, kube, namespace):
    spawner = make_lightweight_spawner(async_api, namespace, username="alice")

    await EGISpawner._update_secret(spawner, {"access_token": "abc", "id_token": "xyz"})

    secret = await kube.read_namespaced_secret(name="access-token-alice", namespace=namespace)
    assert secret.data["access_token"] == "YWJj"
    assert secret.data["id_token"] == "eHl6"


@pytest.mark.asyncio
async def test_update_secret_updates_existing_secret_in_k3s(async_api, kube, namespace):
    await kube.create_namespaced_secret(
        namespace=namespace,
        body=client.V1Secret(
            metadata=client.V1ObjectMeta(name="access-token-alice", namespace=namespace),
            type="Opaque",
            data={"old": "b2xk", "empty": ""},
        ),
    )

    spawner = make_lightweight_spawner(async_api, namespace, username="alice")

    await EGISpawner._update_secret(spawner, {"access_token": "abc", "id_token": None})

    secret = await kube.read_namespaced_secret(name="access-token-alice", namespace=namespace)
    assert secret.data["old"] == "b2xk"
    assert secret.data["access_token"] == "YWJj"


@pytest.mark.asyncio
async def test_configure_user_volumes_rewrites_claim_name_using_real_pvc(async_api, kube, namespace):
    await kube.create_namespaced_persistent_volume_claim(
        namespace=namespace,
        body=client.V1PersistentVolumeClaim(
            metadata=client.V1ObjectMeta(
                name="claim-alice",
                namespace=namespace,
                annotations={"hub.jupyter.org/username": "alice"},
            ),
            spec=client.V1PersistentVolumeClaimSpec(
                access_modes=["ReadWriteOnce"],
                resources=client.V1VolumeResourceRequirements(requests={"storage": "1Gi"}),
            ),
        ),
    )

    spawner = make_lightweight_spawner(async_api, namespace, username="alice")
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await EGISpawner.configure_user_volumes(spawner)

    assert spawner.pvc_name == "claim-alice"
    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"
