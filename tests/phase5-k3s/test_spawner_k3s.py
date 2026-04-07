
"""
Phase 5 Kubernetes-backed tests for EGI spawner-related behavior.

These tests run against a real temporary k3s cluster provided by GitHub Actions
or against a real local Kubernetes cluster when kubeconfig is available.

Unlike the earlier phases, Kubernetes itself is not mocked here.

The goal is not to spawn a full notebook server yet. Instead, the tests focus on
the first high-value cluster interactions:
- cluster accessibility
- real Secret creation/update through EGISpawner._update_secret
- real PVC discovery for volume configuration

This keeps the first k3s layer small, understandable, and CI-friendly.
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
    """
    Thin async wrapper around the async kubernetes_asyncio CoreV1Api.

    EGISpawner in the current codebase uses kubernetes_asyncio and catches
    kubernetes_asyncio.client.rest.ApiException. Using the same library in tests
    avoids mismatches between sync and async exception types.
    """

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
    """
    Load kubeconfig and expose a real async CoreV1Api client.

    This fixture is function-scoped on purpose. kubernetes_asyncio binds the
    client session to the currently running event loop, so reusing one client
    across multiple pytest-asyncio loops causes cross-loop failures.
    """
    await config.load_kube_config()
    api = client.CoreV1Api()
    try:
        yield api
    finally:
        await api.api_client.close()


@pytest_asyncio.fixture
async def namespace(kube):
    """
    Create an isolated namespace for each test.

    Isolation matters because these tests create real Secrets and PVCs in a live
    cluster. Each test gets its own namespace and then removes it.
    """
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
    """Return the async wrapper used by the lightweight spawner test objects."""
    return AsyncCoreV1Api(kube)


def make_lightweight_spawner(async_api, namespace, username="alice"):
    """
    Build a minimal object that can execute selected EGISpawner methods.

    We intentionally do not instantiate the full real spawner here because the
    goal of these first k3s tests is to validate Kubernetes interactions, not
    all JupyterHub initialization mechanics at once.
    """
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


# phase5-1
# Component: Kubernetes connectivity
# Purpose: Verify that the temporary k3s cluster or local Kubernetes cluster is
# reachable from the test job.
# What this test checks:
# - kubeconfig was loaded successfully
# - CoreV1Api can talk to the cluster
# - the API returns a namespace list
# Example pass:
# - list_namespace() succeeds and returns at least the default namespaces.
# Example fail:
# - kubeconfig is missing, the cluster failed to start, or kubectl/client
#   connectivity is broken.
@pytest.mark.asyncio
async def test_k3s_cluster_is_reachable(kube):
    ns_list = await kube.list_namespace()
    names = {item.metadata.name for item in ns_list.items}
    assert "default" in names


# phase5-2
# Component: EGISpawner._update_secret
# Purpose: Verify that the spawner can create a real Secret in Kubernetes.
# What this test checks:
# - the method talks to the real API server
# - a Secret is created in the test namespace
# - token values are stored in Kubernetes Secret.data format
# Example pass:
# - no Secret exists initially, _update_secret creates it, and reading the
#   Secret back shows the expected encoded values.
# Example fail:
# - the method crashes against the real API, creates the Secret in the wrong
#   namespace, or stores the wrong data.
@pytest.mark.asyncio
async def test_update_secret_creates_real_secret_in_k3s(async_api, kube, namespace):
    spawner = make_lightweight_spawner(async_api, namespace, username="alice")

    await EGISpawner._update_secret(spawner, {"access_token": "abc", "id_token": "xyz"})

    secret = await kube.read_namespaced_secret(name="access-token-alice", namespace=namespace)
    assert secret.metadata.name == "access-token-alice"
    assert secret.data["access_token"] == "YWJj"
    assert secret.data["id_token"] == "eHl6"


# phase5-3
# Component: EGISpawner._update_secret
# Purpose: Verify that an existing Secret is updated rather than recreated.
# What this test checks:
# - an existing Secret is read from the cluster
# - old keys are preserved when appropriate
# - incoming non-empty values overwrite previous values
# - empty/None values do not create bogus entries
# Example pass:
# - an existing Secret with {"old": "..."} becomes {"old": "...", "access_token": "..."}
#   after _update_secret runs.
# Example fail:
# - the update path ignores existing data, fails to replace the Secret, or
#   writes incorrect encoded values.
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
    assert "id_token" not in (secret.data or {})


# phase5-4
# Component: EGISpawner.configure_user_volumes
# Purpose: Verify that the spawner can discover a real PVC in Kubernetes and
# rewrite the configured claimName to the existing per-user PVC.
# What this test checks:
# - list_namespaced_persistent_volume_claim hits the real API server
# - the correct PVC is selected for the current username
# - the configured persistentVolumeClaim.claimName is rewritten
# Example pass:
# - a PVC named claim-alice exists in the namespace and includes the username
#   annotation expected by the current implementation.
# Example fail:
# - the method fails to query PVCs, leaves the placeholder claim unchanged, or
#   rewrites to the wrong PVC.
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
        {
            "name": "workspace",
            "persistentVolumeClaim": {"claimName": "claim-placeholder"},
        }
    ]

    await EGISpawner.configure_user_volumes(spawner)

    assert spawner.pvc_name == "claim-alice"
    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"


# phase5-5
# Component: EGISpawner._update_secret
# Purpose: Verify that calling _update_secret with an empty payload still cleans
# empty keys from an already existing Secret instead of leaving invalid data behind.
# What this test checks:
# - existing empty-string values are removed
# - unrelated non-empty keys are preserved
# Example pass:
# - a Secret with {"keep": "...", "empty": ""} becomes {"keep": "..."}.
# Example fail:
# - the empty key remains in the stored Secret or non-empty keys are lost.
@pytest.mark.asyncio
async def test_update_secret_removes_empty_existing_keys(async_api, kube, namespace):
    await kube.create_namespaced_secret(
        namespace=namespace,
        body=client.V1Secret(
            metadata=client.V1ObjectMeta(name="access-token-alice", namespace=namespace),
            type="Opaque",
            data={"keep": "a2VlcA==", "empty": ""},
        ),
    )
    spawner = make_lightweight_spawner(async_api, namespace, username="alice")

    await EGISpawner._update_secret(spawner, {})

    secret = await kube.read_namespaced_secret(name="access-token-alice", namespace=namespace)
    assert secret.data["keep"] == "a2VlcA=="
    assert "empty" not in (secret.data or {})


# phase5-6
# Component: EGISpawner._update_secret
# Purpose: Verify that a new access token overwrites an older stored access token.
# What this test checks:
# - the same key is replaced with the newly encoded value
# - unrelated keys survive the update
# Example pass:
# - existing access_token "old" becomes "new" after the update.
# Example fail:
# - the old token remains, duplicate keys appear, or unrelated keys disappear.
@pytest.mark.asyncio
async def test_update_secret_overwrites_existing_access_token(async_api, kube, namespace):
    await kube.create_namespaced_secret(
        namespace=namespace,
        body=client.V1Secret(
            metadata=client.V1ObjectMeta(name="access-token-alice", namespace=namespace),
            type="Opaque",
            data={"access_token": "b2xk", "refresh_token": "cmVm"},
        ),
    )
    spawner = make_lightweight_spawner(async_api, namespace, username="alice")

    await EGISpawner._update_secret(spawner, {"access_token": "new"})

    secret = await kube.read_namespaced_secret(name="access-token-alice", namespace=namespace)
    assert secret.data["access_token"] == "bmV3"
    assert secret.data["refresh_token"] == "cmVm"


# phase5-7
# Component: EGISpawner._update_secret
# Purpose: Verify that the per-user secret naming logic works for a different username.
# What this test checks:
# - the created Secret name follows access-token-<username>
# - a second username does not accidentally reuse alice's Secret name
# Example pass:
# - username "bob" creates Secret "access-token-bob".
# Example fail:
# - the method writes into the wrong Secret name or wrong namespace.
@pytest.mark.asyncio
async def test_update_secret_creates_user_specific_secret_name(async_api, kube, namespace):
    spawner = make_lightweight_spawner(async_api, namespace, username="bob")

    await EGISpawner._update_secret(spawner, {"access_token": "bob-token"})

    secret = await kube.read_namespaced_secret(name="access-token-bob", namespace=namespace)
    assert secret.metadata.name == "access-token-bob"
    assert secret.data["access_token"] == "Ym9iLXRva2Vu"


# phase5-8
# Component: EGISpawner.configure_user_volumes
# Purpose: Document current behavior when no PVC annotation matches the current user.
# What this test checks:
# - no matching annotated PVC is found
# - claim-prefixed volume names are still rewritten to the spawner's default pvc_name
# Example pass:
# - with only bob's PVC present, alice's claim placeholder becomes claim-alice.
# Example fail:
# - the method crashes, rewrites to bob's PVC, or leaves the placeholder unchanged
#   despite the current implementation's fallback behavior.
@pytest.mark.asyncio
async def test_configure_user_volumes_falls_back_to_default_pvc_name_without_match(async_api, kube, namespace):
    await kube.create_namespaced_persistent_volume_claim(
        namespace=namespace,
        body=client.V1PersistentVolumeClaim(
            metadata=client.V1ObjectMeta(
                name="claim-bob",
                namespace=namespace,
                annotations={"hub.jupyter.org/username": "bob"},
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


# phase5-9
# Component: EGISpawner.configure_user_volumes
# Purpose: Verify that only claim-prefixed PVC references are rewritten.
# What this test checks:
# - claim names starting with "claim-" are rewritten
# - non-claim PVC names remain unchanged
# - non-PVC volumes are left untouched
# Example pass:
# - claim-placeholder becomes claim-alice, while workspace-static and configMap stay unchanged.
# Example fail:
# - the method rewrites every volume blindly or mutates unrelated volume definitions.
@pytest.mark.asyncio
async def test_configure_user_volumes_rewrites_only_claim_prefixed_volumes(async_api, kube, namespace):
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
        {"name": "rewrite-me", "persistentVolumeClaim": {"claimName": "claim-placeholder"}},
        {"name": "leave-static", "persistentVolumeClaim": {"claimName": "workspace-static"}},
        {"name": "config", "configMap": {"name": "settings"}},
    ]

    await EGISpawner.configure_user_volumes(spawner)

    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"
    assert spawner.volumes[1]["persistentVolumeClaim"]["claimName"] == "workspace-static"
    assert spawner.volumes[2]["configMap"]["name"] == "settings"


# phase5-10
# Component: EGISpawner.configure_user_volumes
# Purpose: Verify that the correct annotated PVC is selected when the namespace
# contains PVCs for multiple users.
# What this test checks:
# - the method scans several PVCs
# - the current user's annotated PVC is selected
# - the resulting pvc_name points to the correct claim
# Example pass:
# - both alice and bob PVCs exist, and alice's spawner selects claim-alice.
# Example fail:
# - the method selects the wrong user's PVC or ignores the annotations entirely.
@pytest.mark.asyncio
async def test_configure_user_volumes_selects_matching_user_pvc_among_multiple(async_api, kube, namespace):
    for pvc_name, username in [("claim-bob", "bob"), ("claim-alice", "alice")]:
        await kube.create_namespaced_persistent_volume_claim(
            namespace=namespace,
            body=client.V1PersistentVolumeClaim(
                metadata=client.V1ObjectMeta(
                    name=pvc_name,
                    namespace=namespace,
                    annotations={"hub.jupyter.org/username": username},
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
