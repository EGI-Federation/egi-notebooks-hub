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


def test_build_common_labels_raises_if_parent_does_not_return_username_label(spawner, monkeypatch):
    monkeypatch.setattr(
        KubeSpawner,
        "_build_common_labels",
        lambda self, extra: {"app": "notebook", **extra},
    )

    with pytest.raises(KeyError):
        spawner._build_common_labels({})


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
async def test_update_secret_reraises_non_404_replace_error(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.replace_namespaced_secret = AsyncMock(side_effect=ApiException(status=500))
    spawner.api.create_namespaced_secret = AsyncMock()
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    with pytest.raises(ApiException) as exc:
        await spawner._update_secret({"access_token": "abc"})

    assert exc.value.status == 500
    spawner.api.create_namespaced_secret.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_secret_reraises_create_error_after_404_replace(spawner, monkeypatch):
    spawner.api.read_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.replace_namespaced_secret = AsyncMock(side_effect=ApiException(status=404))
    spawner.api.create_namespaced_secret = AsyncMock(side_effect=ApiException(status=403))
    monkeypatch.setattr(spawner, "_get_secret_manifest", lambda data: {"data": data})

    with pytest.raises(ApiException) as exc:
        await spawner._update_secret({"access_token": "abc"})

    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_set_access_token_delegates_to_update_secret(spawner):
    spawner._update_secret = AsyncMock()

    await spawner.set_access_token("access-1", "id-1")

    spawner._update_secret.assert_awaited_once_with(
        {"access_token": "access-1", "id_token": "id-1"}
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
    assert spawner.extra_annotations["existing"] == "annotation"


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


@pytest.mark.asyncio
async def test_auth_state_hook_ignores_empty_auth_state(spawner):
    spawner.set_access_token = AsyncMock()

    await spawner.auth_state_hook(spawner, None)

    spawner.set_access_token.assert_not_awaited()
    assert spawner.extra_annotations == {"existing": "annotation"}


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


def test_profile_filter_returns_empty_list_when_no_profile_config(spawner):
    spawner._profile_config = []

    assert spawner._profile_filter(spawner) == []


def test_profile_filter_returns_only_unrestricted_profiles_for_user_without_groups(spawner):
    spawner.user = SimpleNamespace(name="alice", groups=[])
    spawner._profile_config = [
        {"display_name": "Open to all"},
        {"display_name": "VO 1 only", "vo_claims": ["vo-1"]},
    ]

    assert spawner._profile_filter(spawner) == [{"display_name": "Open to all"}]


def test_profile_filter_accepts_empty_vo_claims_as_unrestricted(spawner):
    spawner._profile_config = [
        {"display_name": "Empty vo_claims", "vo_claims": []},
    ]

    assert spawner._profile_filter(spawner) == [
        {"display_name": "Empty vo_claims", "vo_claims": []}
    ]


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
