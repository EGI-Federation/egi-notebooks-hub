import base64
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from kubernetes_asyncio.client.rest import ApiException

from egi_notebooks_hub.egispawner import EGISpawner
from kubespawner import KubeSpawner

@pytest.fixture
def spawner():
    s = EGISpawner.__new__(EGISpawner)
    s.namespace = "test-ns"
    s.user = SimpleNamespace(
        name="alice",
        groups=[SimpleNamespace(name="vo-1"), SimpleNamespace(name="vo-2")],
    )
    s.api = SimpleNamespace()
    s.log = logging.getLogger("test-egispawner")
    s.token_secret_name = "access-token-alice"
    s._token_secret_volume_name = "secret-alice"
    s.token_mount_path = "/var/run/secrets/egi.eu/"
    s.mount_secrets_volume = False
    s.environment = {"KEEP_ENV": "1"}
    s.extra_annotations = {"existing": "annotation"}
    s.pvc_name = "generated-pvc"
    s.profile_list = []
    s._profile_config = []
    s.volume_mounts = {
        "old-user-secret": {
            "name": "secret-alice-user",
            "mountPath": "/old/path",
        },
        "keep": {"name": "workspace", "mountPath": "/workspace"},
        "old-sidecar-secret": {"name": "secret-alice", "mountPath": "/sidecar"},
    }
    s.volumes = {
        "old-user-secret": {"name": "secret-alice-user", "emptyDir": {}},
        "keep": {
            "name": "home",
            "persistentVolumeClaim": {"claimName": "claim-old"},
        },
        "old-sidecar-secret": {
            "name": "secret-alice",
            "secret": {"secretName": "old-secret"},
        },
    }
    s._sorted_dict_values = (
        lambda value: list(value.values()) if isinstance(value, dict) else list(value)
    )
    s._build_common_annotations = lambda extra: {"anno": "1", **extra}
    return s

# phase2-3
# Component: EGISpawner._build_common_labels
# Purpose: Confirm that EGI-specific label generation removes the username label from
# the parent KubeSpawner output while preserving other labels. This matters because the
# EGI variant intentionally avoids exposing username in Kubernetes labels.
# Example pass case: parent returns labels including hub.jupyter.org/username and app;
# the EGI wrapper removes only the username label and keeps app plus extra labels.
# Example fail case: username is still present after wrapping, or unrelated labels are
# accidentally removed.
def test_build_common_labels_removes_username_label(spawner, monkeypatch):
    monkeypatch.setattr(
        KubeSpawner,
        "_build_common_labels",
        lambda self, extra: {
            "hub.jupyter.org/username": "alice",
            "app": "notebook",
            **extra,
        },
    )

    labels = spawner._build_common_labels({"extra": "x"})

    assert labels == {"app": "notebook", "extra": "x"}

# phase2-4
# Component: EGISpawner._build_common_labels
# Purpose: Check what happens when the parent implementation does not provide the
# username label that the EGI override expects to remove. The current implementation
# raises KeyError, and this test documents that behavior.
# Example pass case: parent labels do not include the username key and the method
# raises KeyError, signalling that the assumption about parent output was violated.
# Example fail case: the method silently ignores the missing key when the contract was
# expected to be strict, or raises a different unexpected exception.
def test_build_common_labels_raises_if_parent_does_not_return_username_label(spawner, monkeypatch):
    monkeypatch.setattr(
        KubeSpawner,
        "_build_common_labels",
        lambda self, extra: {"app": "notebook", **extra},
    )

    with pytest.raises(KeyError):
        spawner._build_common_labels({})

# phase2-5
# Component: EGISpawner._get_secret_manifest
# Purpose: Verify that the Kubernetes Secret manifest is created with the correct name,
# labels, annotations, type, and encoded data payload.
# Example pass case: helper methods return deterministic labels/annotations and the
# manifest contains the spawner secret name, opaque secret type, and the provided data.
# Example fail case: metadata name is wrong, labels/annotations are missing, or the
# manifest body stores data in the wrong field.
def test_get_secret_manifest_contains_expected_metadata(spawner, monkeypatch):
    monkeypatch.setattr(spawner, "_build_common_labels", lambda extra: {"label": "1"})

    secret = spawner._get_secret_manifest({"access_token": "YWJj"})

    assert secret.metadata.name == "access-token-alice"
    assert secret.metadata.labels == {"label": "1"}
    assert secret.metadata.annotations == {"anno": "1"}
    assert secret.type == "Opaque"
    assert secret.data == {"access_token": "YWJj"}

# phase2-6
# Component: EGISpawner._update_secret
# Purpose: Check that updating an existing Kubernetes Secret merges old content with new
# values and base64-encodes the new token values before sending a replace request.
# Example pass case: an existing secret contains legacy data, a new access token is
# provided, and replace_namespaced_secret receives both the old entry and the encoded
# new token.
# Example fail case: old data is lost, tokens are stored without base64 encoding, or
# create_namespaced_secret is called even though replace should be enough.
@pytest.mark.asyncio
async def test_update_secret_replaces_existing_data_and_base64_encodes_values(spawner, monkeypatch):
    existing = SimpleNamespace(data={"old": "b2xk", "empty": ""})
    spawner.api.read_namespaced_secret = AsyncMock(return_value=existing)
    spawner.api.replace_namespaced_secret = AsyncMock()
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    await spawner._update_secret({"access_token": "abc", "id_token": None})

    spawner.api.replace_namespaced_secret.assert_awaited_once_with(
        name="access-token-alice",
        namespace="test-ns",
        body={"data": {"old": "b2xk", "access_token": "YWJj"}},
    )
    spawner.api.create_namespaced_secret.assert_not_awaited()

# phase2-7
# Component: EGISpawner._update_secret
# Purpose: Ensure that a Secret whose data field is None is treated like an empty
# dictionary instead of crashing or trying to merge with None.
# Example pass case: read_namespaced_secret returns data=None and the method still
# replaces the secret with just the newly encoded token values.
# Example fail case: code tries to iterate over None, crashes, or produces an invalid
# body because it did not normalize empty secret data.
@pytest.mark.asyncio
async def test_update_secret_reads_empty_secret_data_as_empty_dict(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(return_value=SimpleNamespace(data=None))
    spawner.api.replace_namespaced_secret = AsyncMock()
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    await spawner._update_secret({"access_token": "abc"})

    spawner.api.replace_namespaced_secret.assert_awaited_once_with(
        name="access-token-alice",
        namespace="test-ns",
        body={"data": {"access_token": base64.b64encode(b"abc").decode()}},
    )

# phase2-8
# Component: EGISpawner._update_secret
# Purpose: Verify that empty values are filtered out after merging old and new secret
# data. This prevents stale or blank token entries from remaining in the Secret.
# Example pass case: existing data contains one valid key and one empty key, while the
# new payload contains an empty access token and a non-empty id_token. The final body
# should keep only non-empty values.
# Example fail case: empty strings remain in the secret data, or valid values are
# removed together with the empty ones.
@pytest.mark.asyncio
async def test_update_secret_removes_keys_with_empty_values_after_merge(spawner, monkeypatch):
    existing = SimpleNamespace(data={"old": "b2xk", "remove_me": ""})
    spawner.api.read_namespaced_secret = AsyncMock(return_value=existing)
    spawner.api.replace_namespaced_secret = AsyncMock()
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    await spawner._update_secret({"access_token": "", "id_token": "id-123"})

    encoded_id = base64.b64encode(b"id-123").decode()
    spawner.api.replace_namespaced_secret.assert_awaited_once_with(
        name="access-token-alice",
        namespace="test-ns",
        body={"data": {"old": "b2xk", "id_token": encoded_id}},
    )

# phase2-9
# Component: EGISpawner._update_secret
# Purpose: Document the current behavior when reading the existing Secret fails with a
# non-404 Kubernetes API exception. The implementation still proceeds to replace using
# only the new payload.
# Example pass case: read_namespaced_secret raises ApiException(500), yet the method
# still sends a replace call with freshly encoded token data.
# Example fail case: the method aborts immediately, never attempts replace, or swallows
# the new token payload entirely.
@pytest.mark.asyncio
async def test_update_secret_ignores_read_api_exception_and_continues(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(side_effect=ApiException(status=500))
    spawner.api.replace_namespaced_secret = AsyncMock()
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    await spawner._update_secret({"access_token": "abc"})

    spawner.api.replace_namespaced_secret.assert_awaited_once_with(
        name="access-token-alice",
        namespace="test-ns",
        body={"data": {"access_token": base64.b64encode(b"abc").decode()}},
    )

# phase2-10
# Component: EGISpawner._update_secret
# Purpose: Ensure that a missing Secret is created instead of replaced when the API
# reports 404 during read/replace operations.
# Example pass case: both read and replace report 404 and the code falls back to
# create_namespaced_secret with a correctly encoded payload.
# Example fail case: no create call happens, or the code keeps retrying replace even
# though the Secret does not exist.
@pytest.mark.asyncio
async def test_update_secret_creates_secret_on_404(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.replace_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    await spawner._update_secret({"access_token": "abc"})

    spawner.api.create_namespaced_secret.assert_awaited_once_with(
        namespace="test-ns",
        body={"data": {"access_token": "YWJj"}},
    )

# phase2-11
# Component: EGISpawner._update_secret
# Purpose: Confirm that unexpected replace failures are not silently hidden. Only the
# missing-resource path should be recovered automatically.
# Example pass case: replace_namespaced_secret raises ApiException(500) and the same
# exception is propagated to the caller.
# Example fail case: the method swallows the server error, or incorrectly attempts to
# create the secret for every replace failure.
@pytest.mark.asyncio
async def test_update_secret_reraises_non_404_replace_error(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.replace_namespaced_secret = AsyncMock(side_effect=ApiException(status=500))
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    with pytest.raises(ApiException) as exc:
        await spawner._update_secret({"access_token": "abc"})

    assert exc.value.status == 500
    spawner.api.create_namespaced_secret.assert_not_awaited()

# phase2-12
# Component: EGISpawner._update_secret
# Purpose: Verify that if the fallback create step fails, the error is propagated. This
# helps surface permission or API problems instead of hiding them.
# Example pass case: read and replace both report 404, create reports 403, and the
# caller receives the 403 exception.
# Example fail case: create errors are ignored, converted to the wrong exception type,
# or cause misleading success behavior.
@pytest.mark.asyncio
async def test_update_secret_reraises_create_error_after_404_replace(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.replace_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.create_namespaced_secret = AsyncMock(side_effect=ApiException(status=403))
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    with pytest.raises(ApiException) as exc:
        await spawner._update_secret({"access_token": "abc"})

    assert exc.value.status == 403

# phase2-13
# Component: EGISpawner.set_access_token
# Purpose: Check that the public helper simply forwards the expected token dictionary to
# _update_secret. This keeps the higher-level API thin and predictable.
# Example pass case: calling set_access_token('access-1', 'id-1') results in one call to
# _update_secret with {'access_token': 'access-1', 'id_token': 'id-1'}.
# Example fail case: token keys are renamed, values are swapped, or the helper tries to
# update Kubernetes resources directly instead of delegating.
@pytest.mark.asyncio
async def test_set_access_token_delegates_to_update_secret(spawner):
    spawner._update_secret = AsyncMock()

    await spawner.set_access_token("access-1", "id-1")

    spawner._update_secret.assert_awaited_once_with(
        {"access_token": "access-1", "id_token": "id-1"}
    )

# phase2-14
# Component: EGISpawner.auth_state_hook
# Purpose: Verify that auth_state_hook stores access/id tokens and writes the selected
# primary group into pod annotations while preserving existing annotations.
# Example pass case: auth_state contains access_token, id_token, and primary_group, so
# set_access_token is awaited and extra_annotations gains egi.eu/primary_group.
# Example fail case: tokens are ignored, the primary group annotation is missing, or
# existing annotations are overwritten.
@pytest.mark.asyncio
async def test_auth_state_hook_stores_primary_group_and_tokens(spawner):
    spawner.set_access_token = AsyncMock()

    await spawner.auth_state_hook(
        spawner,
        {
            "access_token": "access",
            "id_token": "id",
            "primary_group": "vo-2",
        },
    )

    spawner.set_access_token.assert_awaited_once_with("access", "id")
    assert spawner.extra_annotations["egi.eu/primary_group"] == "vo-2"
    assert spawner.extra_annotations["existing"] == "annotation"

# phase2-15
# Component: EGISpawner.auth_state_hook
# Purpose: Ensure token propagation still happens even when no primary_group is present.
# This matters because token mounting and group annotation are related but independent.
# Example pass case: auth_state has tokens but no primary_group, and set_access_token is
# still called while no group annotation is added.
# Example fail case: lack of primary_group prevents token storage or writes an empty
# group annotation unnecessarily.
@pytest.mark.asyncio
async def test_auth_state_hook_calls_set_access_token_even_without_primary_group(spawner):
    spawner.set_access_token = AsyncMock()

    await spawner.auth_state_hook(
        spawner,
        {
            "access_token": "access",
            "id_token": None,
        },
    )

    spawner.set_access_token.assert_awaited_once_with("access", None)
    assert "egi.eu/primary_group" not in spawner.extra_annotations

# phase2-16
# Component: EGISpawner.auth_state_hook
# Purpose: Confirm that an empty or missing auth_state produces no side effects.
# Example pass case: auth_state is None, so no token update happens and existing
# annotations remain unchanged.
# Example fail case: the method crashes on None, calls set_access_token anyway, or
# mutates annotations despite having no authentication data.
@pytest.mark.asyncio
async def test_auth_state_hook_ignores_empty_auth_state(spawner):
    spawner.set_access_token = AsyncMock()

    await spawner.auth_state_hook(spawner, None)

    spawner.set_access_token.assert_not_awaited()
    assert spawner.extra_annotations == {"existing": "annotation"}

# phase2-17
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify the branch where user secrets are exposed through an emptyDir volume
# instead of a directly mounted Kubernetes Secret. This is important for setups where a
# sidecar or init logic writes files into a writable directory.
# Example pass case: mount_secrets_volume is False, duplicates are removed, the user
# mount becomes emptyDir-backed, and SECRETS_VOLUME_MOUNTED is set to '0'.
# Example fail case: the method leaves stale duplicate mounts, mounts the wrong volume
# type, or sets the environment flag incorrectly.
@pytest.mark.asyncio
async def test_configure_secret_volumes_uses_emptydir_for_user_mount(spawner):
    spawner._update_secret = AsyncMock()

    await spawner.configure_secret_volumes()

    spawner._update_secret.assert_awaited_once_with({})
    assert spawner.environment["KEEP_ENV"] == "1"
    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "0"
    assert spawner.volume_mounts == [
        {"name": "workspace", "mountPath": "/workspace"},
        {
            "name": "secret-alice-user",
            "mountPath": "/var/run/secrets/egi.eu/",
            "readOnly": False,
        },
    ]
    assert spawner.volumes == [
        {"name": "home", "persistentVolumeClaim": {"claimName": "claim-old"}},
        {"name": "secret-alice", "secret": {"secretName": "access-token-alice"}},
        {"name": "secret-alice-user", "emptyDir": {"medium": "Memory"}},
    ]

# phase2-18
# Component: EGISpawner.configure_secret_volumes
# Purpose: Verify the branch where the actual Kubernetes Secret is mounted directly into
# the user pod.
# Example pass case: mount_secrets_volume is True, the resulting user volume references
# the Secret by name, and SECRETS_VOLUME_MOUNTED is set to '1'.
# Example fail case: the code still creates emptyDir volumes, points to the wrong
# secretName, or forgets to update the environment flag.
@pytest.mark.asyncio
async def test_configure_secret_volumes_uses_secret_when_mount_enabled(spawner):
    spawner.mount_secrets_volume = True
    spawner._update_secret = AsyncMock()

    await spawner.configure_secret_volumes()

    assert spawner.environment["SECRETS_VOLUME_MOUNTED"] == "1"
    assert spawner.volume_mounts[-1] == {
        "name": "secret-alice-user",
        "mountPath": "/var/run/secrets/egi.eu/",
        "readOnly": True,
    }
    assert spawner.volumes[-1] == {
        "name": "secret-alice-user",
        "secret": {"secretName": "access-token-alice"},
    }

# phase2-19
# Component: EGISpawner.configure_secret_volumes
# Purpose: Ensure the method works whether volume_mounts / volumes are stored as dicts or
# lists, and that it still removes outdated duplicate secret entries.
# Example pass case: inputs are plain lists containing old secret mounts and the method
# normalizes them into the expected deduplicated final list.
# Example fail case: code assumes dict-only inputs, crashes on lists, or keeps duplicate
# secret mounts/volumes around.
@pytest.mark.asyncio
async def test_configure_secret_volumes_accepts_list_inputs_and_removes_duplicates(spawner):
    spawner._update_secret = AsyncMock()
    spawner.volume_mounts = [
        {"name": "secret-alice", "mountPath": "/dup-sidecar"},
        {"name": "workspace", "mountPath": "/workspace"},
        {"name": "secret-alice-user", "mountPath": "/dup-user"},
    ]
    spawner.volumes = [
        {"name": "secret-alice-user", "emptyDir": {}},
        {"name": "home", "persistentVolumeClaim": {"claimName": "claim-old"}},
        {"name": "secret-alice", "secret": {"secretName": "dup-secret"}},
    ]

    await spawner.configure_secret_volumes()

    assert [m["name"] for m in spawner.volume_mounts].count("secret-alice-user") == 1
    assert [v["name"] for v in spawner.volumes].count("secret-alice") == 1
    assert [v["name"] for v in spawner.volumes].count("secret-alice-user") == 1

# phase2-20
# Component: EGISpawner.configure_user_volumes
# Purpose: Check that claim-* placeholders are replaced with the real existing PVC name
# discovered from Kubernetes for the current user.
# Example pass case: list_namespaced_persistent_volume_claim returns a matching PVC and
# the claimName inside the user volume is rewritten to that PVC.
# Example fail case: the placeholder claim remains unchanged, the wrong PVC is selected,
# or unrelated volumes are modified.
@pytest.mark.asyncio
async def test_configure_user_volumes_rewrites_claim_name_from_existing_pvc(spawner):
    pvc_items = [
        SimpleNamespace(
            metadata=SimpleNamespace(
                name="claim-other",
                annotations={"hub.jupyter.org/username": "bob"},
            )
        ),
        SimpleNamespace(
            metadata=SimpleNamespace(
                name="claim-alice-real",
                annotations={"hub.jupyter.org/username": "alice"},
            )
        ),
    ]
    spawner.api.list_namespaced_persistent_volume_claim = AsyncMock(
        return_value=SimpleNamespace(items=pvc_items)
    )
    spawner.volumes = {
        "keep": {"name": "data", "persistentVolumeClaim": {"claimName": "claim-123"}},
        "other": {"name": "cache", "persistentVolumeClaim": {"claimName": "real-name"}},
    }

    await spawner.configure_user_volumes()

    assert spawner.pvc_name == "claim-alice-real"
    assert spawner.volumes == [
        {"name": "data", "persistentVolumeClaim": {"claimName": "claim-alice-real"}},
        {"name": "cache", "persistentVolumeClaim": {"claimName": "real-name"}},
    ]

# phase2-21
# Component: EGISpawner.configure_user_volumes
# Purpose: Ensure that when no matching PVC exists, the spawner keeps its currently
# generated pvc_name instead of inventing or clearing it.
# Example pass case: the API returns no matching claims and the resulting claimName uses
# the spawner's current pvc_name.
# Example fail case: claimName becomes None, an unrelated PVC is chosen, or the code
# crashes because it expected at least one match.
@pytest.mark.asyncio
async def test_configure_user_volumes_keeps_existing_pvc_name_when_no_match(spawner):
    spawner.api.list_namespaced_persistent_volume_claim = AsyncMock(
        return_value=SimpleNamespace(
            items=[
                SimpleNamespace(
                    metadata=SimpleNamespace(
                        name="claim-bob",
                        annotations={"hub.jupyter.org/username": "bob"},
                    )
                )
            ]
        )
    )
    spawner.volumes = [
        {"name": "data", "persistentVolumeClaim": {"claimName": "claim-template"}},
        {"name": "logs", "persistentVolumeClaim": {"claimName": "real-name"}},
    ]

    await spawner.configure_user_volumes()

    assert spawner.pvc_name == "generated-pvc"
    assert spawner.volumes == [
        {"name": "data", "persistentVolumeClaim": {"claimName": "generated-pvc"}},
        {"name": "logs", "persistentVolumeClaim": {"claimName": "real-name"}},
    ]

# phase2-22
# Component: EGISpawner.configure_user_volumes
# Purpose: Document that when multiple PVCs could match, the first suitable one is used.
# This gives deterministic behavior and avoids unnecessary later matches overriding the
# first choice.
# Example pass case: two matching PVCs are returned and the claimName is set to the
# first match only.
# Example fail case: the method keeps iterating and overwrites the first match with a
# later PVC, producing non-deterministic results.
@pytest.mark.asyncio
async def test_configure_user_volumes_uses_first_matching_pvc_and_stops(spawner):
    pvc_items = [
        SimpleNamespace(
            metadata=SimpleNamespace(
                name="claim-alice-first",
                annotations={"hub.jupyter.org/username": "alice"},
            )
        ),
        SimpleNamespace(
            metadata=SimpleNamespace(
                name="claim-alice-second",
                annotations={"hub.jupyter.org/username": "alice"},
            )
        ),
    ]
    spawner.api.list_namespaced_persistent_volume_claim = AsyncMock(
        return_value=SimpleNamespace(items=pvc_items)
    )
    spawner.volumes = [
        {"name": "data", "persistentVolumeClaim": {"claimName": "claim-template"}},
    ]

    await spawner.configure_user_volumes()

    assert spawner.pvc_name == "claim-alice-first"
    assert spawner.volumes[0]["persistentVolumeClaim"]["claimName"] == "claim-alice-first"

# phase2-23
# Component: EGISpawner.configure_user_volumes
# Purpose: Make sure only PVC-based volumes are rewritten. Other volume types must stay
# unchanged to avoid breaking unrelated pod configuration.
# Example pass case: config contains both PVC and non-PVC volumes, and only the PVC
# volume gets updated while secret/emptyDir/etc. remain identical.
# Example fail case: non-PVC volumes are mutated accidentally or removed.
@pytest.mark.asyncio
async def test_configure_user_volumes_leaves_non_pvc_volumes_untouched(spawner):
    spawner.api.list_namespaced_persistent_volume_claim = AsyncMock(
        return_value=SimpleNamespace(items=[])
    )
    spawner.volumes = [
        {"name": "config", "configMap": {"name": "cfg"}},
        {"name": "data", "persistentVolumeClaim": {"claimName": "claim-template"}},
    ]

    await spawner.configure_user_volumes()

    assert spawner.volumes == [
        {"name": "config", "configMap": {"name": "cfg"}},
        {"name": "data", "persistentVolumeClaim": {"claimName": "generated-pvc"}},
    ]

# phase2-24
# Component: EGISpawner._profile_filter
# Purpose: Verify that profile filtering keeps unrestricted profiles and profiles whose
# vo_claims intersect with the user's groups.
# Example pass case: the user belongs to vo-1 and vo-2, so unrestricted profiles plus
# profiles requiring vo-1 or vo-2 remain available.
# Example fail case: matching profiles are hidden, or profiles for unrelated groups are
# incorrectly shown.
def test_profile_filter_returns_profiles_matching_user_groups(spawner):
    spawner._profile_config = [
        {"display_name": "Open to all"},
        {"display_name": "VO 2 only", "vo_claims": ["vo-2"]},
        {"display_name": "VO 3 only", "vo_claims": ["vo-3"]},
        {"display_name": "VO 1 or VO 9", "vo_claims": ["vo-1", "vo-9"]},
    ]

    profiles = spawner._profile_filter(spawner)

    assert profiles == [
        {"display_name": "Open to all"},
        {"display_name": "VO 2 only", "vo_claims": ["vo-2"]},
        {"display_name": "VO 1 or VO 9", "vo_claims": ["vo-1", "vo-9"]},
    ]

# phase2-25
# Component: EGISpawner._profile_filter
# Purpose: Ensure that missing profile configuration simply yields no choices rather than
# throwing an exception.
# Example pass case: _profile_config is empty/None and the method returns an empty list.
# Example fail case: code assumes configuration exists and crashes or returns a stale
# cached profile list.
def test_profile_filter_returns_empty_list_when_no_profile_config(spawner):
    spawner._profile_config = []

    assert spawner._profile_filter(spawner) == []

# phase2-26
# Component: EGISpawner._profile_filter
# Purpose: Check behavior for users without any group memberships. They should only see
# profiles that are not restricted by VO claims.
# Example pass case: user.groups is empty and only unrestricted profiles remain.
# Example fail case: group-restricted profiles leak through or unrestricted profiles are
# hidden unnecessarily.
def test_profile_filter_returns_only_unrestricted_profiles_for_user_without_groups(spawner):
    spawner.user = SimpleNamespace(name="alice", groups=[])
    spawner._profile_config = [
        {"display_name": "Open to all"},
        {"display_name": "VO 1 only", "vo_claims": ["vo-1"]},
    ]

    assert spawner._profile_filter(spawner) == [{"display_name": "Open to all"}]

# phase2-27
# Component: EGISpawner._profile_filter
# Purpose: Clarify that an explicit empty vo_claims list should be treated like an
# unrestricted profile rather than a profile matching no one.
# Example pass case: a profile with vo_claims=[] is included for any user.
# Example fail case: empty vo_claims is interpreted as 'deny everyone' and the profile
# disappears.
def test_profile_filter_accepts_empty_vo_claims_as_unrestricted(spawner):
    spawner._profile_config = [
        {"display_name": "Empty vo_claims", "vo_claims": []},
    ]

    assert spawner._profile_filter(spawner) == [
        {"display_name": "Empty vo_claims", "vo_claims": []}
    ]

# phase2-28
# Component: EGISpawner.pre_spawn_hook
# Purpose: Verify the orchestration order of the main preparation steps before spawning:
# load_user_options, configure_user_volumes, then configure_secret_volumes.
# Example pass case: the hook calls those helpers exactly once and in that order.
# Example fail case: a helper is skipped, order is reversed, or secret setup runs before
# user volume selection.
@pytest.mark.asyncio
async def test_pre_spawn_hook_calls_methods_in_expected_order(spawner):
    order = []

    async def fake_load_user_options():
        order.append("load_user_options")

    async def fake_configure_user_volumes():
        order.append("configure_user_volumes")

    async def fake_configure_secret_volumes():
        order.append("configure_secret_volumes")

    spawner.load_user_options = fake_load_user_options
    spawner.configure_user_volumes = fake_configure_user_volumes
    spawner.configure_secret_volumes = fake_configure_secret_volumes

    await spawner.pre_spawn_hook(spawner)

    assert order == [
        "load_user_options",
        "configure_user_volumes",
        "configure_secret_volumes",
    ]

# phase2-29
# Component: EGISpawner.get_args
# Purpose: Ensure the token acquirer mount-path argument is appended when the user pod is
# expected to read secrets from a writable directory rather than a directly mounted
# Secret.
# Example pass case: mount_secrets_volume is False and the returned args include
# TokenAcquirerApp.secrets_mount_path=<token_mount_path>.
# Example fail case: the extra argument is missing, duplicated, or points to the wrong
# path.
def test_get_args_adds_token_acquirer_arg_when_secret_not_mounted(spawner, monkeypatch):
    monkeypatch.setattr(KubeSpawner, "get_args", lambda self: ["--base-arg"])
    spawner.mount_secrets_volume = False

    args = spawner.get_args()

    assert args == [
        "--base-arg",
        "--TokenAcquirerApp.secrets_mount_path=/var/run/secrets/egi.eu/",
    ]

# phase2-30
# Component: EGISpawner.get_args
# Purpose: Verify that no extra token-acquirer path argument is added when the Secret is
# mounted directly, because the application can read the mounted files as-is.
# Example pass case: mount_secrets_volume is True and the args list stays exactly what
# the parent returned.
# Example fail case: the extra argument is still appended even though it is unnecessary.
def test_get_args_does_not_add_token_acquirer_arg_when_secret_is_mounted(spawner, monkeypatch):
    monkeypatch.setattr(KubeSpawner, "get_args", lambda self: ["--base-arg"])
    spawner.mount_secrets_volume = True

    args = spawner.get_args()

    assert args == ["--base-arg"]

# phase2-31
# Component: EGISpawner.get_args
# Purpose: Check that the EGI-specific extra argument is appended without reordering or
# corrupting the base argument list from KubeSpawner.
# Example pass case: parent returns ['a', 'b'] and the final list is ['a', 'b', extra].
# Example fail case: parent arguments are reordered, replaced, or the extra argument is
# inserted in the middle unexpectedly.
def test_get_args_preserves_existing_parent_arguments_order(spawner, monkeypatch):
    monkeypatch.setattr(
        KubeSpawner,
        "get_args",
        lambda self: ["--arg-1", "--arg-2=value", "--arg-3"],
    )
    spawner.mount_secrets_volume = False

    args = spawner.get_args()

    assert args[:-1] == ["--arg-1", "--arg-2=value", "--arg-3"]
    assert args[-1] == "--TokenAcquirerApp.secrets_mount_path=/var/run/secrets/egi.eu/"
