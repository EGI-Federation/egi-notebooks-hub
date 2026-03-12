import logging
from types import SimpleNamespace

from egi_notebooks_hub.egispawner import EGISpawner
from kubespawner import KubeSpawner


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
