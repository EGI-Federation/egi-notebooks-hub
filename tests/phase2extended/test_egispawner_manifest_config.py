
"""
Additional Phase 2 tests for EGISpawner configuration assembly.

These tests focus on Python-side spawner configuration before Kubernetes receives
the resulting objects: Secret manifests, volume definitions, mounts, environment
variables, profile filtering, and hook sequencing.
"""

import types
from types import SimpleNamespace
from unittest.mock import AsyncMock

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


def make_spawner(username="alice", mount_secrets_volume=False):
    """Create a lightweight spawner object with the attributes used by EGISpawner."""
    spawner = SimpleNamespace()
    spawner.namespace = "test-ns"
    spawner.user = SimpleNamespace(name=username)
    spawner.token_secret_name = f"access-token-{username}"
    spawner._token_secret_volume_name = f"secret-{username}"
    spawner.token_mount_path = "/var/run/secrets/egi.eu/"
    spawner.mount_secrets_volume = mount_secrets_volume
    spawner.volumes = []
    spawner.volume_mounts = []
    spawner.environment = {}
    spawner.extra_annotations = {}
    spawner.log = DummyLog()

    def _sorted_dict_values(values):
        if isinstance(values, dict):
            return [values[k] for k in sorted(values.keys())]
        return list(values)

    def _build_common_labels(extra_labels):
        labels = {
            "app": "jupyterhub",
            "component": "singleuser-server",
            "hub.jupyter.org/username": username,
        }
        labels.update(extra_labels or {})
        labels.pop("hub.jupyter.org/username", None)
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


# phase2-manifest-1
# Component: EGISpawner._get_secret_manifest
# Purpose: Verify Secret manifest metadata and type before it is sent to Kubernetes.
# Example pass: the manifest is Opaque and uses access-token-alice as its name.
# Example fail: labels, annotations, or Secret type are missing from the manifest.
def test_get_secret_manifest_contains_expected_metadata():
    spawner = make_spawner()
    spawner.extra_annotations["egi.eu/primary_group"] = "vo.example"

    secret = EGISpawner._get_secret_manifest(spawner, {"access_token": "YWJj"})

    assert secret.metadata.name == "access-token-alice"
    assert secret.type == "Opaque"
    assert secret.data == {"access_token": "YWJj"}
    assert secret.metadata.labels["app"] == "jupyterhub"
    assert "hub.jupyter.org/username" not in secret.metadata.labels
    assert secret.metadata.annotations["egi.eu/primary_group"] == "vo.example"


# phase2-manifest-2
# Component: EGISpawner._update_secret
# Purpose: Verify that new token data is base64-encoded before Secret replacement.
# Example pass: access_token "abc" becomes "YWJj".
# Example fail: plaintext token data is written into the manifest.
@pytest.mark.asyncio
async def test_update_secret_base64_encodes_new_values():
    spawner = make_spawner()
    existing = SimpleNamespace(data={})
    spawner.api = SimpleNamespace(
        read_namespaced_secret=AsyncMock(return_value=existing),
        replace_namespaced_secret=AsyncMock(),
        create_namespaced_secret=AsyncMock(),
    )

    await EGISpawner._update_secret(spawner, {"access_token": "abc"})

    body = spawner.api.replace_namespaced_secret.await_args.kwargs["body"]
    assert body.data["access_token"] == "YWJj"
    spawner.api.create_namespaced_secret.assert_not_awaited()


# phase2-manifest-3
# Component: EGISpawner._update_secret
# Purpose: Verify that a missing Secret is created after replace returns 404.
# Example pass: read/replace 404 is followed by create_namespaced_secret.
# Example fail: missing Secret causes the update path to abort.
@pytest.mark.asyncio
async def test_update_secret_creates_secret_after_404_replace():
    spawner = make_spawner()
    spawner.api = SimpleNamespace(
        read_namespaced_secret=AsyncMock(side_effect=ApiException(status=404)),
        replace_namespaced_secret=AsyncMock(side_effect=ApiException(status=404)),
        create_namespaced_secret=AsyncMock(),
    )

    await EGISpawner._update_secret(spawner, {"access_token": "abc"})

    spawner.api.create_namespaced_secret.assert_awaited_once()
    body = spawner.api.create_namespaced_secret.await_args.kwargs["body"]
    assert body.metadata.name == "access-token-alice"
    assert body.data["access_token"] == "YWJj"


# phase2-manifest-4
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify emptyDir mode for user-facing token mount configuration.
# Example pass: user volume is emptyDir and SECRETS_VOLUME_MOUNTED is "0".
# Example fail: user-facing volume points to the real Secret when disabled.
@pytest.mark.asyncio
async def test_configure_secret_volumes_emptydir_mode():
    spawner = make_spawner(mount_secrets_volume=False)
    spawner._update_secret = AsyncMock()

    await EGISpawner.configure_secret_volumes(spawner)

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    mounts = {mount["name"]: mount for mount in spawner.volume_mounts}
    assert volumes["secret-alice"]["secret"]["secretName"] == "access-token-alice"
    assert volumes["secret-alice-user"]["emptyDir"] == {"medium": "Memory"}
    assert mounts["secret-alice-user"]["readOnly"] is False
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "0"


# phase2-manifest-5
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify real Secret mount mode for user-facing token mount configuration.
# Example pass: user volume references the Secret and the mount is read-only.
# Example fail: user volume remains emptyDir when Secret mount is enabled.
@pytest.mark.asyncio
async def test_configure_secret_volumes_secret_mount_mode():
    spawner = make_spawner(mount_secrets_volume=True)
    spawner._update_secret = AsyncMock()

    await EGISpawner.configure_secret_volumes(spawner)

    volumes = {volume["name"]: volume for volume in spawner.volumes}
    mounts = {mount["name"]: mount for mount in spawner.volume_mounts}
    assert volumes["secret-alice-user"]["secret"]["secretName"] == "access-token-alice"
    assert "emptyDir" not in volumes["secret-alice-user"]
    assert mounts["secret-alice-user"]["readOnly"] is True
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "1"


# phase2-manifest-6
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify idempotency of generated Secret volumes and mounts.
# Example pass: generated names appear exactly once after repeated calls.
# Example fail: repeated calls accumulate duplicate generated volumes.
@pytest.mark.asyncio
async def test_configure_secret_volumes_is_idempotent():
    spawner = make_spawner(mount_secrets_volume=True)
    spawner._update_secret = AsyncMock()

    await EGISpawner.configure_secret_volumes(spawner)
    await EGISpawner.configure_secret_volumes(spawner)

    volume_names = [volume["name"] for volume in spawner.volumes]
    mount_names = [mount["name"] for mount in spawner.volume_mounts]
    assert volume_names.count("secret-alice") == 1
    assert volume_names.count("secret-alice-user") == 1
    assert mount_names.count("secret-alice-user") == 1


# phase2-manifest-7
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify unrelated user-defined volumes and mounts are preserved.
# Example pass: pre-existing configMap volume and custom mount remain present.
# Example fail: generated Secret configuration wipes unrelated entries.
@pytest.mark.asyncio
async def test_configure_secret_volumes_preserves_unrelated_entries():
    spawner = make_spawner()
    spawner._update_secret = AsyncMock()
    spawner.volumes = [{"name": "config", "configMap": {"name": "settings"}}]
    spawner.volume_mounts = [{"name": "data", "mountPath": "/data", "readOnly": False}]

    await EGISpawner.configure_secret_volumes(spawner)

    assert {"name": "config", "configMap": {"name": "settings"}} in spawner.volumes
    assert {"name": "data", "mountPath": "/data", "readOnly": False} in spawner.volume_mounts


# phase2-manifest-8
# Component: EGISpawner.configure_user_volumes
# Purpose: Verify that matching PVC annotations select the current user's claim.
# Example pass: Alice's annotated PVC rewrites claim-placeholder to claim-alice.
# Example fail: another user's PVC is selected.
@pytest.mark.asyncio
async def test_configure_user_volumes_selects_matching_annotated_pvc():
    spawner = make_spawner(username="alice")
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]
    pvcs = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name="claim-bob",
                    annotations={"hub.jupyter.org/username": "bob"},
                )
            ),
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name="claim-alice",
                    annotations={"hub.jupyter.org/username": "alice"},
                )
            ),
        ]
    )
    spawner.api = SimpleNamespace(
        list_namespaced_persistent_volume_claim=AsyncMock(return_value=pvcs)
    )

    await EGISpawner.configure_user_volumes(spawner)

    assert spawner.pvc_name == "claim-alice"
    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"


# phase2-manifest-9
# Component: EGISpawner.configure_user_volumes
# Purpose: Verify only claim-prefixed PVC references are rewritten.
# Example pass: workspace-static remains unchanged.
# Example fail: all persistentVolumeClaim entries are rewritten blindly.
@pytest.mark.asyncio
async def test_configure_user_volumes_rewrites_only_claim_prefixed_references():
    spawner = make_spawner(username="alice")
    spawner.volumes = [
        {"name": "rewrite", "persistentVolumeClaim": {"claimName": "claim-placeholder"}},
        {"name": "static", "persistentVolumeClaim": {"claimName": "workspace-static"}},
    ]
    pvcs = SimpleNamespace(
        items=[
            SimpleNamespace(
                metadata=SimpleNamespace(
                    name="claim-alice",
                    annotations={"hub.jupyter.org/username": "alice"},
                )
            )
        ]
    )
    spawner.api = SimpleNamespace(
        list_namespaced_persistent_volume_claim=AsyncMock(return_value=pvcs)
    )

    await EGISpawner.configure_user_volumes(spawner)

    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice"
    assert spawner.volumes[1]["persistentVolumeClaim"]["claimName"] == "workspace-static"


# phase2-manifest-10
# Component: EGISpawner.auth_state_hook
# Purpose: Verify tokens are delegated to set_access_token and primary_group is annotated.
# Example pass: set_access_token receives access/id tokens and annotation is set.
# Example fail: primary group is lost before pod annotation generation.
@pytest.mark.asyncio
async def test_auth_state_hook_delegates_tokens_and_sets_primary_group():
    spawner = make_spawner()
    spawner.set_access_token = AsyncMock()

    await EGISpawner.auth_state_hook(
        spawner,
        spawner,
        {
            "access_token": "access",
            "id_token": "id",
            "primary_group": "vo.example",
        },
    )

    spawner.set_access_token.assert_awaited_once_with("access", "id")
    assert spawner.extra_annotations["egi.eu/primary_group"] == "vo.example"


# phase2-manifest-11
# Component: EGISpawner.auth_state_hook
# Purpose: Verify missing auth_state is ignored.
# Example pass: set_access_token is not called and annotations remain unchanged.
# Example fail: empty auth_state creates an empty Secret or raises unexpectedly.
@pytest.mark.asyncio
async def test_auth_state_hook_ignores_missing_auth_state():
    spawner = make_spawner()
    spawner.set_access_token = AsyncMock()

    await EGISpawner.auth_state_hook(spawner, spawner, None)

    spawner.set_access_token.assert_not_awaited()
    assert spawner.extra_annotations == {}


# phase2-manifest-12
# Component: EGISpawner._profile_filter
# Purpose: Verify profiles without vo_claims are always visible.
# Example pass: a default profile without vo_claims is returned.
# Example fail: public/default profile disappears for users without matching groups.
def test_profile_filter_keeps_profiles_without_vo_claims():
    spawner = make_spawner()
    spawner._profile_config = [
        {"display_name": "Default"},
        {"display_name": "Restricted", "vo_claims": ["vo-1"]},
    ]
    user_context = SimpleNamespace(
        _profile_config=spawner._profile_config,
        user=SimpleNamespace(groups=[]),
    )

    profiles = EGISpawner._profile_filter(spawner, user_context)

    assert profiles == [{"display_name": "Default"}]


# phase2-manifest-13
# Component: EGISpawner._profile_filter
# Purpose: Verify profiles are filtered by the current user's VO groups.
# Example pass: a user in vo-2 sees the vo-2 profile but not the vo-1 profile.
# Example fail: restricted profiles are shown to unrelated users.
def test_profile_filter_keeps_matching_vo_profiles():
    spawner = make_spawner()
    spawner._profile_config = [
        {"display_name": "VO1", "vo_claims": ["vo-1"]},
        {"display_name": "VO2", "vo_claims": ["vo-2"]},
    ]
    user_context = SimpleNamespace(
        _profile_config=spawner._profile_config,
        user=SimpleNamespace(groups=[SimpleNamespace(name="vo-2")]),
    )

    profiles = EGISpawner._profile_filter(spawner, user_context)

    assert profiles == [{"display_name": "VO2", "vo_claims": ["vo-2"]}]


# phase2-manifest-14
# Component: EGISpawner.pre_spawn_hook
# Purpose: Verify pre-spawn hook calls the expected configuration steps in order.
# Example pass: load_user_options, configure_user_volumes, configure_secret_volumes are awaited.
# Example fail: hook skips one of the required setup steps.
@pytest.mark.asyncio
async def test_pre_spawn_hook_runs_expected_setup_steps():
    spawner = make_spawner()
    calls = []

    async def load_user_options():
        calls.append("load_user_options")

    async def configure_user_volumes():
        calls.append("configure_user_volumes")

    async def configure_secret_volumes():
        calls.append("configure_secret_volumes")

    spawner.load_user_options = load_user_options
    spawner.configure_user_volumes = configure_user_volumes
    spawner.configure_secret_volumes = configure_secret_volumes

    await EGISpawner.pre_spawn_hook(spawner, spawner)

    assert calls == [
        "load_user_options",
        "configure_user_volumes",
        "configure_secret_volumes",
    ]


# phase2-manifest-15
# Component: EGISpawner.set_access_token
# Purpose: Verify public set_access_token builds the expected update payload.
# Example pass: _update_secret receives access_token and id_token keys.
# Example fail: id_token is dropped or wrong key names are used.
@pytest.mark.asyncio
async def test_set_access_token_builds_expected_update_payload():
    spawner = make_spawner()
    spawner._update_secret = AsyncMock()

    await EGISpawner.set_access_token(spawner, "access", "id")

    spawner._update_secret.assert_awaited_once_with(
        {"access_token": "access", "id_token": "id"}
    )
