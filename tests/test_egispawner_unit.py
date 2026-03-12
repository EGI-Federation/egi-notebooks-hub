from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from kubernetes_asyncio.client.rest import ApiException

from egi_notebooks_hub.egispawner import EGISpawner
from kubespawner import KubeSpawner


@pytest.fixture
def spawner(monkeypatch):
    s = EGISpawner.__new__(EGISpawner)
    s.namespace = "test-ns"
    s.user = SimpleNamespace(
        name="alice",
        groups=[SimpleNamespace(name="vo-1"), SimpleNamespace(name="vo-2")],
    )
    s.api = SimpleNamespace()
    s.log = MagicMock()
    s.token_secret_name = "access-token-alice"
    s._token_secret_volume_name = "secret-alice"
    s.token_mount_path = "/var/run/secrets/egi.eu/"
    s.mount_secrets_volume = False
    s.environment = {}
    s.extra_annotations = {}
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
    s._sorted_dict_values = lambda value: list(value.values()) if isinstance(value, dict) else list(value)
    s._build_common_annotations = lambda extra: {"anno": "1", **extra}
    return s


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


def test_get_secret_manifest_contains_expected_metadata(spawner, monkeypatch):
    monkeypatch.setattr(spawner, "_build_common_labels", lambda extra: {"label": "1"})

    secret = spawner._get_secret_manifest({"access_token": "YWJj"})

    assert secret.metadata.name == "access-token-alice"
    assert secret.metadata.labels == {"label": "1"}
    assert secret.metadata.annotations == {"anno": "1"}
    assert secret.type == "Opaque"
    assert secret.data == {"access_token": "YWJj"}


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


@pytest.mark.asyncio
async def test_auth_state_hook_ignores_empty_auth_state(spawner):
    spawner.set_access_token = AsyncMock()

    await spawner.auth_state_hook(spawner, None)

    spawner.set_access_token.assert_not_awaited()
    assert spawner.extra_annotations == {}


@pytest.mark.asyncio
async def test_configure_secret_volumes_uses_emptydir_for_user_mount(spawner):
    spawner._update_secret = AsyncMock()

    await spawner.configure_secret_volumes()

    spawner._update_secret.assert_awaited_once_with({})
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


def test_get_args_adds_token_acquirer_arg_when_secret_not_mounted(spawner, monkeypatch):
    monkeypatch.setattr(KubeSpawner, "get_args", lambda self: ["--base-arg"])
    spawner.mount_secrets_volume = False

    args = spawner.get_args()

    assert args == [
        "--base-arg",
        "--TokenAcquirerApp.secrets_mount_path=/var/run/secrets/egi.eu/",
    ]


def test_get_args_does_not_add_token_acquirer_arg_when_secret_is_mounted(spawner, monkeypatch):
    monkeypatch.setattr(KubeSpawner, "get_args", lambda self: ["--base-arg"])
    spawner.mount_secrets_volume = True

    args = spawner.get_args()

    assert args == ["--base-arg"]
