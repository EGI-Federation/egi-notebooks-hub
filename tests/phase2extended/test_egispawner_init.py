"""
Additional Phase 2 initialization tests for EGISpawner.

These tests verify the initialization contract of EGISpawner: profile filtering
setup, generated Kubernetes object names, template expansion, preserved base
spawner attributes, and configured default values.
"""

import logging
from types import SimpleNamespace
from unittest.mock import Mock

from kubespawner import KubeSpawner

from egi_notebooks_hub.egispawner import EGISpawner

def install_fake_kubespawner_init(
    monkeypatch,
    *,
    profile_list=None,
    username="alice",
    groups=None,
    namespace="test-ns",
    token_secret_name_template=None,
    token_secret_volume_name_template=None,
    token_mount_path=None,
    mount_secrets_volume=None,
):
    """Patch KubeSpawner.__init__ with a lightweight initializer for init tests."""
    if profile_list is None:
        profile_list = []
    if groups is None:
        groups = []

    def fake_super_init(self, *args, **kwargs):
        self.super_init_args = args
        self.super_init_kwargs = kwargs
        self.profile_list = profile_list
        self.namespace = namespace
        self.user = SimpleNamespace(
            name=username,
            groups=[SimpleNamespace(name=group) for group in groups],
        )
        self.log = logging.getLogger("test-egispawner-init-extended")
        self.volumes = []
        self.volume_mounts = []
        self.environment = {}
        self.extra_annotations = {}

        if token_secret_name_template is not None:
            self.token_secret_name_template = token_secret_name_template
        if token_secret_volume_name_template is not None:
            self.token_secret_volume_name_template = token_secret_volume_name_template
        if token_mount_path is not None:
            self.token_mount_path = token_mount_path
        if mount_secrets_volume is not None:
            self.mount_secrets_volume = mount_secrets_volume

    monkeypatch.setattr(KubeSpawner, "__init__", fake_super_init)


# phase2-init-1
# Component: EGISpawner.__init__
# Purpose: Verify constructor arguments are forwarded to KubeSpawner.__init__.
# Example pass: positional and keyword arguments are preserved on the fake base spawner.
# Example fail: EGISpawner swallows or rewrites constructor arguments unexpectedly.
def test_init_forwards_args_and_kwargs_to_kubespawner(monkeypatch):
    install_fake_kubespawner_init(monkeypatch)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner("arg1", test_option=True)

    assert spawner.super_init_args == ("arg1",)
    assert spawner.super_init_kwargs == {"test_option": True}


# phase2-init-2
# Component: EGISpawner.__init__
# Purpose: Verify the original profile list is stored before profile_list becomes a filter method.
# Example pass: _profile_config is the exact original list object.
# Example fail: original profile configuration is lost during initialization.
def test_init_preserves_original_profile_list_object(monkeypatch):
    profiles = [{"display_name": "Default"}, {"display_name": "Large"}]
    install_fake_kubespawner_init(monkeypatch, profile_list=profiles)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner._profile_config == profiles
    assert spawner.profile_list == spawner._profile_filter


# phase2-init-3
# Component: EGISpawner.__init__ + _profile_filter
# Purpose: Verify the installed profile_list filter remains callable after initialization.
# Example pass: calling spawner.profile_list(spawner) returns profiles allowed for the user.
# Example fail: profile_list is not callable or does not use the stored profile configuration.
def test_init_installs_callable_profile_filter(monkeypatch):
    profiles = [
        {"display_name": "Default"},
        {"display_name": "VO2 profile", "vo_claims": ["vo-2"]},
        {"display_name": "VO3 profile", "vo_claims": ["vo-3"]},
    ]
    install_fake_kubespawner_init(monkeypatch, profile_list=profiles, groups=["vo-2"])
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()
    visible_profiles = spawner.profile_list(spawner)

    assert visible_profiles == [
        {"display_name": "Default"},
        {"display_name": "VO2 profile", "vo_claims": ["vo-2"]},
    ]


# phase2-init-4
# Component: EGISpawner.__init__
# Purpose: Verify pvc_name comes from uuid.uuid4().hex.
# Example pass: patched uuid value becomes the initial pvc_name.
# Example fail: pvc_name is missing, constant, or based on the username instead of UUID.
def test_init_uses_uuid_hex_for_initial_pvc_name(monkeypatch):
    install_fake_kubespawner_init(monkeypatch)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="fixed-uuid-hex"),
    )

    spawner = EGISpawner()

    assert spawner.pvc_name == "fixed-uuid-hex"


# phase2-init-5
# Component: EGISpawner.__init__
# Purpose: Verify each instance receives the current UUID-generated pvc_name.
# Example pass: two patched UUID values produce two different pvc_name values.
# Example fail: pvc_name is shared between instances.
def test_init_assigns_independent_pvc_name_per_instance(monkeypatch):
    install_fake_kubespawner_init(monkeypatch)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    values = iter([SimpleNamespace(hex="pvc-one"), SimpleNamespace(hex="pvc-two")])
    monkeypatch.setattr("egi_notebooks_hub.egispawner.uuid.uuid4", lambda: next(values))

    first = EGISpawner()
    second = EGISpawner()

    assert first.pvc_name == "pvc-one"
    assert second.pvc_name == "pvc-two"


# phase2-init-6
# Component: EGISpawner.__init__
# Purpose: Verify default token Secret and volume templates are expanded.
# Example pass: expansion is called for access-token-{userid} and secret-{userid}.
# Example fail: one of the template-based names is not expanded.
def test_init_expands_default_token_name_templates(monkeypatch):
    install_fake_kubespawner_init(monkeypatch)
    expand = Mock(side_effect=lambda template: f"expanded:{template}")
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", expand)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner.token_secret_name == "expanded:access-token-{userid}"
    assert spawner._token_secret_volume_name == "expanded:secret-{userid}"
    assert expand.call_args_list[0].args == ("access-token-{userid}",)
    assert expand.call_args_list[1].args == ("secret-{userid}",)


# phase2-init-7
# Component: EGISpawner.__init__
# Purpose: Verify custom token Secret templates are honored during initialization.
# Example pass: custom templates are expanded into token_secret_name and volume name.
# Example fail: class defaults are used even after custom templates are configured.
def test_init_uses_custom_token_name_templates(monkeypatch):
    install_fake_kubespawner_init(
        monkeypatch,
        token_secret_name_template="custom-token-{username}",
        token_secret_volume_name_template="custom-volume-{username}",
    )
    monkeypatch.setattr(
        EGISpawner,
        "_expand_user_properties",
        lambda self, template: f"expanded:{template}",
    )
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner.token_secret_name == "expanded:custom-token-{username}"
    assert spawner._token_secret_volume_name == "expanded:custom-volume-{username}"


# phase2-init-8
# Component: EGISpawner.__init__
# Purpose: Verify expanded names can include username-specific values.
# Example pass: fake expansion produces access-token-alice and secret-alice.
# Example fail: username-derived expansion is not used for generated names.
def test_init_stores_username_expanded_secret_names(monkeypatch):
    install_fake_kubespawner_init(monkeypatch, username="alice")

    def expand(self, template):
        return template.replace("{userid}", self.user.name).replace(
            "{username}", self.user.name
        )

    monkeypatch.setattr(EGISpawner, "_expand_user_properties", expand)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner.token_secret_name == "access-token-alice"
    assert spawner._token_secret_volume_name == "secret-alice"


# phase2-init-9
# Component: EGISpawner.__init__
# Purpose: Verify default token mount configuration remains available after initialization.
# Example pass: token_mount_path and mount_secrets_volume retain class defaults.
# Example fail: initialization overwrites token mount defaults.
def test_init_preserves_default_token_mount_settings(monkeypatch):
    install_fake_kubespawner_init(monkeypatch)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner.token_mount_path == "/var/run/secrets/egi.eu/"
    assert spawner.mount_secrets_volume is False


# phase2-init-10
# Component: EGISpawner.__init__
# Purpose: Verify configured token mount settings are preserved.
# Example pass: custom token_mount_path and mount_secrets_volume survive initialization.
# Example fail: initialization resets configured mount settings to defaults.
def test_init_preserves_custom_token_mount_settings(monkeypatch):
    install_fake_kubespawner_init(
        monkeypatch,
        token_mount_path="/custom/tokens",
        mount_secrets_volume=True,
    )
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner.token_mount_path == "/custom/tokens"
    assert spawner.mount_secrets_volume is True


# phase2-init-11
# Component: EGISpawner.__init__
# Purpose: Verify base spawner attributes initialized by KubeSpawner are preserved.
# Example pass: namespace, user, log, volumes, mounts, environment, annotations remain usable.
# Example fail: EGISpawner initialization clears base attributes needed by later hooks.
def test_init_preserves_base_spawner_runtime_attributes(monkeypatch):
    install_fake_kubespawner_init(monkeypatch, username="alice", namespace="custom-ns")
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    spawner = EGISpawner()

    assert spawner.namespace == "custom-ns"
    assert spawner.user.name == "alice"
    assert isinstance(spawner.log, logging.Logger)
    assert spawner.volumes == []
    assert spawner.volume_mounts == []
    assert spawner.environment == {}
    assert spawner.extra_annotations == {}


# phase2-init-12
# Component: EGISpawner.__init__ + _build_common_labels
# Purpose: Verify initialized spawner still uses the EGI label override.
# Example pass: hub.jupyter.org/username is removed from generated labels.
# Example fail: long usernames can leak into Kubernetes labels after initialization.
def test_initialized_spawner_uses_egi_common_label_override(monkeypatch):
    install_fake_kubespawner_init(monkeypatch)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )

    def fake_base_labels(self, extra_labels):
        labels = {
            "hub.jupyter.org/username": "very-long-username",
            "app": "jupyterhub",
        }
        labels.update(extra_labels)
        return labels

    monkeypatch.setattr(KubeSpawner, "_build_common_labels", fake_base_labels)

    spawner = EGISpawner()
    labels = spawner._build_common_labels({"component": "singleuser"})

    assert labels == {"app": "jupyterhub", "component": "singleuser"}


# phase2-init-13
# Component: EGISpawner.__init__ + get_args
# Purpose: Verify initialized spawner can still append the token-acquirer argument.
# Example pass: mount_secrets_volume=False adds TokenAcquirerApp.secrets_mount_path.
# Example fail: get_args misses the token-acquirer argument after initialization.
def test_initialized_spawner_get_args_adds_token_acquirer_path(monkeypatch):
    install_fake_kubespawner_init(monkeypatch, token_mount_path="/custom/tokens")
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )
    monkeypatch.setattr(KubeSpawner, "get_args", lambda self: ["--base-arg"])

    spawner = EGISpawner()

    assert spawner.get_args() == [
        "--base-arg",
        "--TokenAcquirerApp.secrets_mount_path=/custom/tokens",
    ]


# phase2-init-14
# Component: EGISpawner.__init__ + get_args
# Purpose: Verify initialized spawner skips token-acquirer argument when real Secret mount is enabled.
# Example pass: mount_secrets_volume=True returns only base args.
# Example fail: token acquirer is still configured even though the real Secret is mounted.
def test_initialized_spawner_get_args_skips_token_acquirer_when_secret_is_mounted(monkeypatch):
    install_fake_kubespawner_init(monkeypatch, mount_secrets_volume=True)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr(
        "egi_notebooks_hub.egispawner.uuid.uuid4",
        lambda: SimpleNamespace(hex="pvc-id"),
    )
    monkeypatch.setattr(KubeSpawner, "get_args", lambda self: ["--base-arg"])

    spawner = EGISpawner()

    assert spawner.get_args() == ["--base-arg"]


# phase2-init-15
# Component: EGISpawner.__init__
# Purpose: Verify that the constructor converts the original static profile list into
# a callable profile filter, preserves the original profile configuration for later use,
# and generates the internal PVC/secret names that later methods depend on.
# Example pass case: parent KubeSpawner initializes profile_list with one profile,
# user/namespace are present, and the helper methods return deterministic values.
# The test should then see _profile_config keep the original list, profile_list become
# the _profile_filter method, and the generated names match the mocked helpers.
# Example fail case: a regression leaves profile_list untouched, forgets to save
# _profile_config, or changes the naming logic so token_secret_name / pvc_name differ
# from the expected deterministic values.
def test_init_converts_profile_list_to_filter_and_generates_names(monkeypatch):
    original_profile_list = [{"display_name": "Profile A"}]

    def fake_super_init(self, *args, **kwargs):
        self.profile_list = original_profile_list
        self.namespace = "test-ns"
        self.user = SimpleNamespace(name="alice", groups=[])
        self.log = logging.getLogger("test-egispawner-init")

    monkeypatch.setattr(KubeSpawner, "__init__", fake_super_init)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: f"expanded:{template}")
    monkeypatch.setattr("egi_notebooks_hub.egispawner.uuid.uuid4", lambda: SimpleNamespace(hex="fixed-pvc-id"))

    spawner = EGISpawner()

    assert spawner._profile_config == original_profile_list
    assert spawner.profile_list == spawner._profile_filter
    assert spawner.pvc_name == "fixed-pvc-id"
    assert spawner.token_secret_name == "expanded:access-token-{userid}"
    assert spawner._token_secret_volume_name == "expanded:secret-{userid}"

# phase2-init-16
# Component: EGISpawner.__init__
# Purpose: Ensure that the constructor behaves correctly even when no profiles are
# configured. This guards against startup failures for minimal deployments.
# Example pass case: parent KubeSpawner sets profile_list to an empty list and the
# constructor still stores that empty list, swaps profile_list to _profile_filter,
# and generates a PVC name.
# Example fail case: code assumes at least one profile exists, crashes on an empty
# list, or stores a wrong value in _profile_config / pvc_name.
def test_init_keeps_empty_profile_list(monkeypatch):
    def fake_super_init(self, *args, **kwargs):
        self.profile_list = []
        self.namespace = "test-ns"
        self.user = SimpleNamespace(name="alice", groups=[])
        self.log = logging.getLogger("test-egispawner-init-empty")

    monkeypatch.setattr(KubeSpawner, "__init__", fake_super_init)
    monkeypatch.setattr(EGISpawner, "_expand_user_properties", lambda self, template: template)
    monkeypatch.setattr("egi_notebooks_hub.egispawner.uuid.uuid4", lambda: SimpleNamespace(hex="abc123"))

    spawner = EGISpawner()

    assert spawner._profile_config == []
    assert spawner.profile_list == spawner._profile_filter
    assert spawner.pvc_name == "abc123"
