import logging
from types import SimpleNamespace

from egi_notebooks_hub.egispawner import EGISpawner
from kubespawner import KubeSpawner


# phase2-1
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

# phase2-2
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
