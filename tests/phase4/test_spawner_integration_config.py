
"""
Additional Phase 4 integration-style tests for EGISpawner configuration flows.

These tests combine multiple EGISpawner methods with an in-memory Kubernetes API
replacement. They verify method interactions and resulting configuration without
requiring a live cluster.
"""

import types
from types import SimpleNamespace

import pytest
from kubernetes_asyncio.client.rest import ApiException

from egi_notebooks_hub.egispawner import EGISpawner


class DummyLog:
    """Small logger replacement used by lightweight spawner objects."""

    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class MemoryKubeApi:
    """In-memory async API that mimics the Kubernetes calls used by EGISpawner."""

    def __init__(self):
        self.secrets = {}
        self.pvcs = {}
        self.calls = []

    async def read_namespaced_secret(self, name, namespace):
        self.calls.append(("read_secret", namespace, name))
        key = (namespace, name)
        if key not in self.secrets:
            raise ApiException(status=404)
        return self.secrets[key]

    async def replace_namespaced_secret(self, name, namespace, body):
        self.calls.append(("replace_secret", namespace, name))
        key = (namespace, name)
        if key not in self.secrets:
            raise ApiException(status=404)
        self.secrets[key] = body
        return body

    async def create_namespaced_secret(self, namespace, body):
        name = body.metadata.name
        self.calls.append(("create_secret", namespace, name))
        self.secrets[(namespace, name)] = body
        return body

    async def list_namespaced_persistent_volume_claim(self, namespace):
        self.calls.append(("list_pvc", namespace))
        return SimpleNamespace(items=list(self.pvcs.get(namespace, [])))

    def add_pvc(self, namespace, name, username):
        pvc = SimpleNamespace(
            metadata=SimpleNamespace(
                name=name,
                annotations={"hub.jupyter.org/username": username},
            )
        )
        self.pvcs.setdefault(namespace, []).append(pvc)


def make_spawner(api=None, username="alice", mount_secrets_volume=False):
    """Create a lightweight spawner object with real EGISpawner methods bound."""
    spawner = SimpleNamespace()
    spawner.api = api or MemoryKubeApi()
    spawner.namespace = "test-ns"
    spawner.user = SimpleNamespace(name=username)
    spawner.token_secret_name = f"access-token-{username}"
    spawner._token_secret_volume_name = f"secret-{username}"
    spawner.token_mount_path = "/var/run/secrets/egi.eu/"
    spawner.mount_secrets_volume = mount_secrets_volume
    spawner.pvc_name = f"claim-{username}"
    spawner.volumes = []
    spawner.volume_mounts = []
    spawner.environment = {}
    spawner.extra_annotations = {}
    spawner.log = DummyLog()

    async def load_user_options():
        spawner.load_user_options_called = True

    spawner.load_user_options_called = False
    spawner.load_user_options = load_user_options

    def _sorted_dict_values(values):
        if isinstance(values, dict):
            return [values[k] for k in sorted(values.keys())]
        return list(values)

    def _build_common_labels(extra_labels):
        labels = {"app": "jupyterhub", "component": "singleuser-server"}
        labels.update(extra_labels or {})
        return labels

    def _build_common_annotations(extra_annotations):
        annotations = dict(spawner.extra_annotations)
        annotations.update(extra_annotations or {})
        return annotations

    spawner._sorted_dict_values = _sorted_dict_values
    spawner._build_common_labels = _build_common_labels
    spawner._build_common_annotations = _build_common_annotations
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


# phase4-spawner-1
# Component: auth_state_hook + Kubernetes Secret update
# Purpose: Verify auth_state is transformed into Secret data and primary group annotation.
# Example pass: tokens are stored and extra_annotations contains egi.eu/primary_group.
# Example fail: token storage succeeds but pod annotation data is lost.
@pytest.mark.asyncio
async def test_auth_state_hook_persists_tokens_and_primary_group():
    api = MemoryKubeApi()
    spawner = make_spawner(api=api)

    await spawner.auth_state_hook(
        spawner,
        {
            "access_token": "access",
            "id_token": "id",
            "primary_group": "vo.example",
        },
    )

    secret = api.secrets[("test-ns", "access-token-alice")]
    assert secret.data["access_token"] == "YWNjZXNz"
    assert secret.data["id_token"] == "aWQ="
    assert spawner.extra_annotations["egi.eu/primary_group"] == "vo.example"


# phase4-spawner-2
# Component: auth_state_hook + _get_secret_manifest
# Purpose: Verify primary group annotation is included in later generated metadata.
# Example pass: after auth_state_hook, a newly generated Secret manifest contains egi.eu/primary_group.
# Example fail: primary group is stored on the spawner but not used by metadata generation.
@pytest.mark.asyncio
async def test_auth_state_primary_group_flows_into_secret_metadata():
    spawner = make_spawner()

    await spawner.auth_state_hook(
        spawner,
        {
            "access_token": "access",
            "id_token": "id",
            "primary_group": "vo.example",
        },
    )

    manifest = spawner._get_secret_manifest({"access_token": "YWNjZXNz"})
    assert manifest.metadata.annotations["egi.eu/primary_group"] == "vo.example"


# phase4-spawner-3
# Component: configure_user_volumes + configure_secret_volumes
# Purpose: Verify PVC and Secret configuration can be built together.
# Example pass: workspace claim is rewritten and Secret volumes are added.
# Example fail: one configuration step destroys the result of the other.
@pytest.mark.asyncio
async def test_user_and_secret_volume_configuration_combine_cleanly():
    api = MemoryKubeApi()
    api.add_pvc("test-ns", "claim-alice", "alice")
    spawner = make_spawner(api=api, mount_secrets_volume=True)
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await spawner.configure_user_volumes()
    await spawner.configure_secret_volumes()

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    assert volumes["workspace"]["persistentVolumeClaim"]["claimName"] == "claim-alice"
    assert volumes["secret-alice"]["secret"]["secretName"] == "access-token-alice"
    assert volumes["secret-alice-user"]["secret"]["secretName"] == "access-token-alice"


# phase4-spawner-4
# Component: pre_spawn_hook end-to-end configuration
# Purpose: Verify pre_spawn_hook orchestrates user volume and Secret setup.
# Example pass: load_user_options is called, PVC is selected, and Secret configuration exists.
# Example fail: hook sequence completes with missing workspace or Secret configuration.
@pytest.mark.asyncio
async def test_pre_spawn_hook_builds_workspace_and_secret_configuration():
    api = MemoryKubeApi()
    api.add_pvc("test-ns", "claim-alice", "alice")
    spawner = make_spawner(api=api, mount_secrets_volume=False)
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await spawner.pre_spawn_hook(spawner)

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    assert spawner.load_user_options_called is True
    assert volumes["workspace"]["persistentVolumeClaim"]["claimName"] == "claim-alice"
    assert volumes["secret-alice-user"]["emptyDir"] == {"medium": "Memory"}
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "0"
    assert ("test-ns", "access-token-alice") in api.secrets


# phase4-spawner-5
# Component: pre_spawn_hook idempotency
# Purpose: Verify repeated pre_spawn_hook calls do not duplicate generated entries.
# Example pass: generated Secret volumes and mounts appear once after two hook calls.
# Example fail: repeated spawning preparation accumulates duplicate generated objects.
@pytest.mark.asyncio
async def test_pre_spawn_hook_is_idempotent_for_generated_entries():
    api = MemoryKubeApi()
    api.add_pvc("test-ns", "claim-alice", "alice")
    spawner = make_spawner(api=api, mount_secrets_volume=True)
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await spawner.pre_spawn_hook(spawner)
    await spawner.pre_spawn_hook(spawner)

    volume_names = [volume["name"] for volume in spawner.volumes]
    mount_names = [mount["name"] for mount in spawner.volume_mounts]
    assert volume_names.count("secret-alice") == 1
    assert volume_names.count("secret-alice-user") == 1
    assert mount_names.count("secret-alice-user") == 1
    assert volume_names.count("workspace") == 1


# phase4-spawner-6
# Component: set_access_token + configure_secret_volumes
# Purpose: Verify explicit token update remains visible after volume configuration.
# Example pass: existing token Secret data is preserved while volumes are generated.
# Example fail: configure_secret_volumes overwrites a populated Secret with empty data.
@pytest.mark.asyncio
async def test_configure_secret_volumes_preserves_existing_token_secret_data():
    api = MemoryKubeApi()
    spawner = make_spawner(api=api, mount_secrets_volume=True)

    await spawner.set_access_token("access", "id")
    await spawner.configure_secret_volumes()

    secret = api.secrets[("test-ns", "access-token-alice")]
    assert secret.data["access_token"] == "YWNjZXNz"
    assert secret.data["id_token"] == "aWQ="


# phase4-spawner-7
# Component: multi-user Secret generation
# Purpose: Verify different users produce isolated Secret names and data.
# Example pass: Alice and Bob have different Secret names and token values.
# Example fail: one user's token overwrites the other user's Secret.
@pytest.mark.asyncio
async def test_multi_user_secret_configuration_is_isolated():
    api = MemoryKubeApi()
    alice = make_spawner(api=api, username="alice")
    bob = make_spawner(api=api, username="bob")

    await alice.set_access_token("alice-token", None)
    await bob.set_access_token("bob-token", None)

    assert api.secrets[("test-ns", "access-token-alice")].data["access_token"] == (
        "YWxpY2UtdG9rZW4="
    )
    assert api.secrets[("test-ns", "access-token-bob")].data["access_token"] == (
        "Ym9iLXRva2Vu"
    )


# phase4-spawner-8
# Component: multi-user PVC selection
# Purpose: Verify spawner selects the matching user's PVC from a shared namespace.
# Example pass: Bob's spawner selects claim-bob when Alice and Bob PVCs both exist.
# Example fail: first PVC in the namespace is selected without checking annotations.
@pytest.mark.asyncio
async def test_multi_user_pvc_selection_uses_current_user_annotation():
    api = MemoryKubeApi()
    api.add_pvc("test-ns", "claim-alice", "alice")
    api.add_pvc("test-ns", "claim-bob", "bob")
    bob = make_spawner(api=api, username="bob")
    bob.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await bob.configure_user_volumes()

    assert bob.pvc_name == "claim-bob"
    assert bob.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-bob"


# phase4-spawner-9
# Component: update Secret merge behavior
# Purpose: Verify repeated token updates merge and replace expected keys.
# Example pass: access_token is updated and refresh_token-like existing data remains.
# Example fail: update path drops unrelated non-empty Secret keys.
@pytest.mark.asyncio
async def test_repeated_secret_updates_merge_existing_non_empty_data():
    api = MemoryKubeApi()
    spawner = make_spawner(api=api)

    await spawner._update_secret({"access_token": "old", "refresh_token": "refresh"})
    await spawner._update_secret({"access_token": "new", "id_token": None})

    secret = api.secrets[("test-ns", "access-token-alice")]
    assert secret.data["access_token"] == "bmV3"
    assert secret.data["refresh_token"] == "cmVmcmVzaA=="
    assert "id_token" not in secret.data


# phase4-spawner-10
# Component: mount mode switch
# Purpose: Verify changing mount_secrets_volume changes generated configuration on next run.
# Example pass: emptyDir user volume becomes Secret-backed user volume after switch.
# Example fail: old emptyDir configuration remains after enabling Secret mount.
@pytest.mark.asyncio
async def test_secret_volume_configuration_updates_when_mount_mode_changes():
    api = MemoryKubeApi()
    spawner = make_spawner(api=api, mount_secrets_volume=False)

    await spawner.configure_secret_volumes()
    spawner.mount_secrets_volume = True
    await spawner.configure_secret_volumes()

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    mounts = {mount["name"]: mount for mount in spawner.volume_mounts}
    assert "emptyDir" not in volumes["secret-alice-user"]
    assert volumes["secret-alice-user"]["secret"]["secretName"] == "access-token-alice"
    assert mounts["secret-alice-user"]["readOnly"] is True
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "1"
