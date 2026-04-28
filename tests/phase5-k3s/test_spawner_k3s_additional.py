
"""
Additional Phase 5 Kubernetes-backed tests for EGISpawner behavior.

This file is meant to be added next to the existing Phase 5 k3s tests as:

    tests/phase5-k3s/test_spawner_k3s_additional.py

The tests intentionally use a real Kubernetes/k3s API server. They extend the
first Phase 5 file with coverage for:
- configure_secret_volumes()
- set_access_token()
- auth_state_hook()
- pre_spawn_hook()
- Secret metadata
- PVC edge cases

"""

import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="traitlets")

import types
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.rest import ApiException

from egi_notebooks_hub.egispawner import EGISpawner


class AsyncCoreV1Api:
    """
    Async Kubernetes API wrapper used by lightweight spawner objects.

    It wraps kubernetes_asyncio CoreV1Api and exposes only the methods that
    EGISpawner calls in the tested paths.
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
        return await self.core_v1.list_namespaced_persistent_volume_claim(
            namespace=namespace
        )


@pytest_asyncio.fixture
async def kube():
    """
    Load kubeconfig and create a fresh async Kubernetes client per test.

    Function scope avoids cross-event-loop aiohttp/kubernetes_asyncio failures.
    """
    await config.load_kube_config()
    api = client.CoreV1Api()
    try:
        yield api
    finally:
        await api.api_client.close()


@pytest_asyncio.fixture
async def namespace(kube):
    """Create and later delete an isolated namespace for each test."""
    ns_name = f"phase5-extra-{uuid.uuid4().hex[:10]}"
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
    """Return the API wrapper used by lightweight spawner test objects."""
    return AsyncCoreV1Api(kube)


def make_spawner(
    async_api,
    namespace,
    username="alice",
    mount_secrets_volume=False,
    token_mount_path="/var/run/secrets/egi.eu/",
):
    """
    Build a minimal spawner-like object for testing selected EGISpawner methods.

    The object is deliberately small, but it contains the attributes and helper
    methods that the tested EGISpawner methods access.
    """
    spawner = SimpleNamespace()
    spawner.api = async_api
    spawner.namespace = namespace
    spawner.user = SimpleNamespace(name=username)
    spawner.token_secret_name = f"access-token-{username}"
    spawner._token_secret_volume_name = f"secret-{username}"
    spawner.pvc_name = f"claim-{username}"
    spawner.token_mount_path = token_mount_path
    spawner.mount_secrets_volume = mount_secrets_volume
    spawner.volumes = []
    spawner.volume_mounts = []
    spawner.environment = {}
    spawner.extra_annotations = {}
    spawner.log = SimpleNamespace(
        info=lambda *a, **k: None,
        debug=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        error=lambda *a, **k: None,
    )

    def _sorted_dict_values(values):
        if isinstance(values, dict):
            return [values[k] for k in sorted(values.keys())]
        return list(values)

    def _build_common_labels(extra_labels):
        labels = {"hub.jupyter.org/servername": "", "app": "jupyterhub"}
        labels.update(extra_labels or {})
        labels.pop("hub.jupyter.org/username", None)
        return labels

    def _build_common_annotations(extra_annotations):
        annotations = {"test-suite": "phase5-k3s"}
        annotations.update(extra_annotations or {})
        return annotations

    spawner._sorted_dict_values = _sorted_dict_values
    spawner._build_common_labels = _build_common_labels
    spawner._build_common_annotations = _build_common_annotations

    # Use the real implementation for manifest generation, then the real
    # Kubernetes-backed methods can exercise actual API behavior.
    spawner._get_secret_manifest = types.MethodType(
        EGISpawner._get_secret_manifest, spawner
    )
    spawner._update_secret = types.MethodType(EGISpawner._update_secret, spawner)
    spawner.set_access_token = types.MethodType(EGISpawner.set_access_token, spawner)
    spawner.configure_secret_volumes = types.MethodType(
        EGISpawner.configure_secret_volumes, spawner
    )
    spawner.configure_user_volumes = types.MethodType(
        EGISpawner.configure_user_volumes, spawner
    )
    spawner.auth_state_hook = types.MethodType(EGISpawner.auth_state_hook, spawner)
    spawner.pre_spawn_hook = types.MethodType(EGISpawner.pre_spawn_hook, spawner)
    return spawner


async def create_user_pvc(kube, namespace, pvc_name, username=None):
    """Create a real PVC, optionally annotated for a JupyterHub username."""
    annotations = None
    if username is not None:
        annotations = {"hub.jupyter.org/username": username}

    await kube.create_namespaced_persistent_volume_claim(
        namespace=namespace,
        body=client.V1PersistentVolumeClaim(
            metadata=client.V1ObjectMeta(
                name=pvc_name,
                namespace=namespace,
                annotations=annotations,
            ),
            spec=client.V1PersistentVolumeClaimSpec(
                access_modes=["ReadWriteOnce"],
                resources=client.V1VolumeResourceRequirements(
                    requests={"storage": "1Gi"}
                ),
            ),
        ),
    )


# phase5-extra-1
# Component: EGISpawner.set_access_token
# Purpose: Verify the public token-setting method, not only private _update_secret.
# What this test checks:
# - set_access_token() creates a real Kubernetes Secret
# - access_token and id_token are stored base64-encoded
# Example pass:
# - access_token "abc" and id_token "xyz" appear as "YWJj" and "eHl6".
# Example fail:
# - set_access_token() does not call the Kubernetes-backed update path or writes
#   the wrong keys.
@pytest.mark.asyncio
async def test_set_access_token_creates_secret_with_access_and_id_token(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace)

    await EGISpawner.set_access_token(spawner, "abc", "xyz")

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.data["access_token"] == "YWJj"
    assert secret.data["id_token"] == "eHl6"


# phase5-extra-2
# Component: EGISpawner.set_access_token
# Purpose: Verify that id_token is optional.
# What this test checks:
# - access_token is stored
# - id_token is omitted when None
# Example pass:
# - Secret contains access_token but no id_token key.
# Example fail:
# - id_token is stored as an empty/invalid value or the access token is missing.
@pytest.mark.asyncio
async def test_set_access_token_omits_id_token_when_none(async_api, kube, namespace):
    spawner = make_spawner(async_api, namespace)

    await EGISpawner.set_access_token(spawner, "abc", None)

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.data["access_token"] == "YWJj"
    assert "id_token" not in (secret.data or {})


# phase5-extra-3
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify the emptyDir user-facing secret mount mode.
# What this test checks:
# - a sidecar Secret volume is created
# - the user-facing volume is an in-memory emptyDir
# - SECRETS_VOLUME_MOUNTED is "0"
# Example pass:
# - mount_secrets_volume=False produces emptyDir for the user mount.
# Example fail:
# - user-facing volume exposes the real Secret when it should not.
@pytest.mark.asyncio
async def test_configure_secret_volumes_uses_emptydir_when_secret_mount_disabled(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace, mount_secrets_volume=False)

    await EGISpawner.configure_secret_volumes(spawner)

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.metadata.name == "access-token-alice"

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    user_volume = volumes["secret-alice-user"]
    sidecar_volume = volumes["secret-alice"]

    assert sidecar_volume["secret"]["secretName"] == "access-token-alice"
    assert user_volume["emptyDir"] == {"medium": "Memory"}
    assert "secret" not in user_volume
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "0"


# phase5-extra-4
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify the real Secret user-facing mount mode.
# What this test checks:
# - both sidecar and user-facing volumes point to the real Secret
# - the mount is marked readOnly
# - SECRETS_VOLUME_MOUNTED is "1"
# Example pass:
# - mount_secrets_volume=True creates Secret-backed user volume.
# Example fail:
# - the user-facing volume remains emptyDir or readOnly is false.
@pytest.mark.asyncio
async def test_configure_secret_volumes_uses_secret_when_secret_mount_enabled(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace, mount_secrets_volume=True)

    await EGISpawner.configure_secret_volumes(spawner)

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    mounts = {mount["name"]: mount for mount in spawner.volume_mounts}

    assert volumes["secret-alice"]["secret"]["secretName"] == "access-token-alice"
    assert volumes["secret-alice-user"]["secret"]["secretName"] == "access-token-alice"
    assert "emptyDir" not in volumes["secret-alice-user"]
    assert mounts["secret-alice-user"]["readOnly"] is True
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "1"


# phase5-extra-5
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify that repeated configuration does not duplicate volume entries.
# What this test checks:
# - calling configure_secret_volumes() twice remains idempotent
# - old generated entries are removed before new ones are added
# Example pass:
# - generated volume and mount names appear exactly once after two calls.
# Example fail:
# - duplicate generated volumes or mounts accumulate.
@pytest.mark.asyncio
async def test_configure_secret_volumes_is_idempotent(async_api, namespace):
    spawner = make_spawner(async_api, namespace, mount_secrets_volume=True)

    await EGISpawner.configure_secret_volumes(spawner)
    await EGISpawner.configure_secret_volumes(spawner)

    volume_names = [volume["name"] for volume in spawner.volumes]
    mount_names = [mount["name"] for mount in spawner.volume_mounts]

    assert volume_names.count("secret-alice") == 1
    assert volume_names.count("secret-alice-user") == 1
    assert mount_names.count("secret-alice-user") == 1


# phase5-extra-6
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify that unrelated existing volumes and mounts are preserved.
# What this test checks:
# - custom volumes survive reconfiguration
# - custom mounts survive reconfiguration
# Example pass:
# - pre-existing configMap volume and /data mount remain after generated secret
#   volumes are added.
# Example fail:
# - configure_secret_volumes() wipes unrelated user configuration.
@pytest.mark.asyncio
async def test_configure_secret_volumes_preserves_unrelated_existing_entries(
    async_api, namespace
):
    spawner = make_spawner(async_api, namespace)
    spawner.volumes = [{"name": "config", "configMap": {"name": "settings"}}]
    spawner.volume_mounts = [{"name": "data", "mountPath": "/data", "readOnly": False}]

    await EGISpawner.configure_secret_volumes(spawner)

    assert {"name": "config", "configMap": {"name": "settings"}} in spawner.volumes
    assert {"name": "data", "mountPath": "/data", "readOnly": False} in spawner.volume_mounts


# phase5-extra-7
# Component: EGISpawner.auth_state_hook
# Purpose: Verify auth_state_hook stores tokens in Kubernetes and propagates
# primary_group into pod annotations.
# What this test checks:
# - access_token and id_token are written into a real Secret
# - extra_annotations gets egi.eu/primary_group
# Example pass:
# - auth_state contains tokens and primary_group, and both Secret + annotation
#   are updated.
# Example fail:
# - tokens are not persisted or the primary group annotation is missing.
@pytest.mark.asyncio
async def test_auth_state_hook_stores_tokens_and_primary_group_annotation(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace)
    auth_state = {
        "access_token": "abc",
        "id_token": "xyz",
        "primary_group": "vo.example",
    }

    await EGISpawner.auth_state_hook(spawner, spawner, auth_state)

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.data["access_token"] == "YWJj"
    assert secret.data["id_token"] == "eHl6"
    assert spawner.extra_annotations["egi.eu/primary_group"] == "vo.example"


# phase5-extra-8
# Component: EGISpawner.auth_state_hook
# Purpose: Verify auth_state_hook safely ignores missing auth_state.
# What this test checks:
# - no Secret is created
# - no annotations are added
# Example pass:
# - auth_state is None and the hook returns without side effects.
# Example fail:
# - the hook crashes or creates an empty Secret unnecessarily.
@pytest.mark.asyncio
async def test_auth_state_hook_ignores_empty_auth_state(async_api, kube, namespace):
    spawner = make_spawner(async_api, namespace)

    await EGISpawner.auth_state_hook(spawner, spawner, None)

    with pytest.raises(ApiException) as exc_info:
        await kube.read_namespaced_secret("access-token-alice", namespace)

    assert exc_info.value.status == 404
    assert spawner.extra_annotations == {}


# phase5-extra-9
# Component: EGISpawner.auth_state_hook
# Purpose: Verify that primary_group is optional.
# What this test checks:
# - tokens are still stored
# - no primary_group annotation is added when missing
# Example pass:
# - Secret is updated, but extra_annotations remains unchanged.
# Example fail:
# - the hook requires primary_group or writes a bogus annotation.
@pytest.mark.asyncio
async def test_auth_state_hook_does_not_add_primary_group_when_missing(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace)
    auth_state = {"access_token": "abc", "id_token": "xyz"}

    await EGISpawner.auth_state_hook(spawner, spawner, auth_state)

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.data["access_token"] == "YWJj"
    assert "egi.eu/primary_group" not in spawner.extra_annotations


# phase5-extra-10
# Component: EGISpawner._get_secret_manifest + _update_secret
# Purpose: Verify metadata on a Secret persisted through the real Kubernetes API.
# What this test checks:
# - Secret type is Opaque
# - labels from _build_common_labels are present
# - annotations from _build_common_annotations are present
# Example pass:
# - the Kubernetes Secret has expected type, labels, and annotations after creation.
# Example fail:
# - metadata helpers are not used when the Secret is created.
@pytest.mark.asyncio
async def test_created_secret_contains_expected_metadata(async_api, kube, namespace):
    spawner = make_spawner(async_api, namespace)

    await EGISpawner._update_secret(spawner, {"access_token": "abc"})

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.type == "Opaque"
    assert secret.metadata.labels["app"] == "jupyterhub"
    assert secret.metadata.annotations["test-suite"] == "phase5-k3s"


# phase5-extra-11
# Component: EGISpawner.pre_spawn_hook
# Purpose: Verify a minimal real-k8s pre-spawn sequence.
# What this test checks:
# - load_user_options() is called
# - configure_user_volumes() finds the real annotated PVC
# - configure_secret_volumes() creates the real Secret and volume configuration
# Example pass:
# - hook completes, PVC is selected, Secret exists, and secret env flag is set.
# Example fail:
# - the hook order breaks, Kubernetes calls fail, or generated config is missing.
@pytest.mark.asyncio
async def test_pre_spawn_hook_runs_minimal_k8s_sequence(async_api, kube, namespace):
    await create_user_pvc(kube, namespace, pvc_name="claim-alice", username="alice")

    spawner = make_spawner(async_api, namespace, mount_secrets_volume=False)
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]
    spawner.load_user_options = AsyncMock()

    await EGISpawner.pre_spawn_hook(spawner, spawner)

    spawner.load_user_options.assert_awaited_once()
    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.metadata.name == "access-token-alice"
    assert spawner.pvc_name == "claim-alice"
    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "0"


# phase5-extra-12
# Component: EGISpawner.configure_user_volumes
# Purpose: Expose the current behavior for PVCs without annotations.
# What this test checks:
# - real Kubernetes PVCs may have metadata.annotations == None
# - the current implementation does not guard against that
# Example pass:
# - currently expected to xfail until configure_user_volumes handles missing
#   annotations defensively.
# Example fail:
# - if this unexpectedly passes, the production code was probably fixed and the
#   xfail marker should be removed.
@pytest.mark.xfail(
    reason=(
        "Current configure_user_volumes assumes pvc.metadata.annotations is not None. "
        "Real Kubernetes PVCs can have no annotations."
    ),
    strict=False,
)
@pytest.mark.asyncio
async def test_configure_user_volumes_handles_pvc_without_annotations(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, pvc_name="claim-unannotated", username=None)

    spawner = make_spawner(async_api, namespace, username="alice")
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await EGISpawner.configure_user_volumes(spawner)

    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"
