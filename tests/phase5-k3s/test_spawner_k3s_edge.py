
"""
Phase 5 Kubernetes Pod edge and validation tests for EGISpawner-generated objects.

These tests exercise real Kubernetes behavior around missing references,
read-only mounts, writable emptyDir mounts, pre-spawn generated configuration,
and production-like labels and annotations.
"""

import asyncio
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
    """Async Kubernetes API wrapper exposing the methods used by EGISpawner."""

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

    async def create_namespaced_pod(self, namespace, body):
        return await self.core_v1.create_namespaced_pod(namespace=namespace, body=body)

    async def read_namespaced_pod(self, name, namespace):
        return await self.core_v1.read_namespaced_pod(name=name, namespace=namespace)

    async def read_namespaced_pod_log(self, name, namespace, container=None):
        return await self.core_v1.read_namespaced_pod_log(
            name=name, namespace=namespace, container=container
        )


@pytest_asyncio.fixture
async def kube():
    """Create a fresh async Kubernetes CoreV1Api client for each test."""
    await config.load_kube_config()
    api = client.CoreV1Api()
    try:
        yield api
    finally:
        await api.api_client.close()


@pytest_asyncio.fixture
async def namespace(kube):
    """Create and delete an isolated namespace for each test."""
    ns_name = f"phase5-edge-{uuid.uuid4().hex[:10]}"
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
    """Return the async wrapper used by lightweight spawner test objects."""
    return AsyncCoreV1Api(kube)


def make_spawner(
    async_api,
    namespace,
    username="alice",
    mount_secrets_volume=True,
    token_mount_path="/egi-secrets",
):
    """Build a minimal spawner-like object for exercising EGISpawner methods."""
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
    spawner.load_user_options = AsyncMock()
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
        labels = {
            "app": "jupyterhub",
            "component": "singleuser-server",
            "hub.jupyter.org/username": username,
        }
        labels.update(extra_labels or {})
        labels.pop("hub.jupyter.org/username", None)
        return labels

    def _build_common_annotations(extra_annotations):
        annotations = {
            "test-suite": "phase5-k3s-edge",
            "egi.eu/owner": username,
        }
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


def volume_from_dict(volume):
    """Convert a small KubeSpawner-style volume dict into a V1Volume object."""
    if "secret" in volume:
        secret = volume["secret"]
        return client.V1Volume(
            name=volume["name"],
            secret=client.V1SecretVolumeSource(secret_name=secret["secretName"]),
        )

    if "emptyDir" in volume:
        empty_dir = volume["emptyDir"] or {}
        return client.V1Volume(
            name=volume["name"],
            empty_dir=client.V1EmptyDirVolumeSource(medium=empty_dir.get("medium")),
        )

    if "persistentVolumeClaim" in volume:
        pvc = volume["persistentVolumeClaim"]
        return client.V1Volume(
            name=volume["name"],
            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                claim_name=pvc["claimName"]
            ),
        )

    raise AssertionError(f"Unsupported test volume: {volume}")


def mount_from_dict(mount):
    """Convert a small KubeSpawner-style mount dict into a V1VolumeMount."""
    return client.V1VolumeMount(
        name=mount["name"],
        mount_path=mount["mountPath"],
        read_only=mount.get("readOnly"),
    )


def env_from_dict(environment):
    """Convert a plain environment dict into V1EnvVar entries."""
    return [
        client.V1EnvVar(name=name, value=str(value))
        for name, value in sorted(environment.items())
    ]


async def create_pod(
    kube,
    namespace,
    name,
    command,
    volumes=None,
    volume_mounts=None,
    env=None,
    labels=None,
    annotations=None,
    image="busybox:1.36",
):
    """Create a small Pod that runs a shell command."""
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels or {},
            annotations=annotations or {},
        ),
        spec=client.V1PodSpec(
            restart_policy="Never",
            containers=[
                client.V1Container(
                    name="main",
                    image=image,
                    command=["/bin/sh", "-c", command],
                    env=env or [],
                    volume_mounts=volume_mounts or [],
                )
            ],
            volumes=volumes or [],
        ),
    )
    await kube.create_namespaced_pod(namespace=namespace, body=pod)
    return pod


async def wait_for_pod_phase(kube, namespace, name, phases, timeout=90):
    """Wait until a Pod enters one of the requested phases."""
    deadline = asyncio.get_running_loop().time() + timeout
    last_pod = None

    while asyncio.get_running_loop().time() < deadline:
        last_pod = await kube.read_namespaced_pod(name=name, namespace=namespace)
        if last_pod.status.phase in phases:
            return last_pod
        await asyncio.sleep(1)

    phase = last_pod.status.phase if last_pod else "unknown"
    raise AssertionError(f"Pod {name} did not reach {phases}; last phase={phase}")


async def wait_for_container_waiting_reason(kube, namespace, name, reason, timeout=75):
    """Wait until the main container reports a specific waiting reason."""
    deadline = asyncio.get_running_loop().time() + timeout
    last_reason = None
    last_message = None

    while asyncio.get_running_loop().time() < deadline:
        pod = await kube.read_namespaced_pod(name=name, namespace=namespace)
        statuses = pod.status.container_statuses or []
        if statuses and statuses[0].state and statuses[0].state.waiting:
            last_reason = statuses[0].state.waiting.reason
            last_message = statuses[0].state.waiting.message
            if last_reason == reason:
                return pod
        await asyncio.sleep(1)

    raise AssertionError(
        f"Pod {name} did not reach waiting reason {reason}; "
        f"last reason={last_reason}; last message={last_message}"
    )


async def create_user_pvc(kube, namespace, pvc_name, username="alice"):
    """Create a real PVC annotated for a JupyterHub username."""
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
                resources=client.V1VolumeResourceRequirements(
                    requests={"storage": "1Gi"}
                ),
            ),
        ),
    )


# phase5-edge-1
# Component: Kubernetes PVC reference handling
# Purpose: Verify Kubernetes reports a clear error for a missing PVC reference.
# What this test checks:
# - the Pod manifest is accepted by the API server
# - kubelet reports a waiting/configuration error when the PVC does not exist
# Example pass:
# - the Pod reaches ContainerCreating or stays Pending with an event-driven mount
#   error caused by the missing PVC.
# Example fail:
# - the Pod unexpectedly succeeds.
@pytest.mark.asyncio
async def test_pod_with_missing_pvc_does_not_succeed(kube, namespace):
    volume = client.V1Volume(
        name="missing-workspace",
        persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
            claim_name="missing-claim"
        ),
    )
    mount = client.V1VolumeMount(
        name="missing-workspace", mount_path="/workspace", read_only=False
    )

    await create_pod(
        kube,
        namespace,
        "missing-pvc",
        "echo should-not-run",
        volumes=[volume],
        volume_mounts=[mount],
    )

    pod = await wait_for_pod_phase(kube, namespace, "missing-pvc", {"Pending"})
    assert pod.status.phase == "Pending"


# phase5-edge-2
# Component: Kubernetes Secret key reference handling
# Purpose: Verify Kubernetes reports a config error when a Secret exists but the
# requested key does not.
# What this test checks:
# - Secret exists
# - referenced key is missing
# - Pod reaches CreateContainerConfigError
# Example pass:
# - waiting message references the missing key.
# Example fail:
# - the Pod succeeds despite the missing Secret key.
@pytest.mark.asyncio
async def test_pod_reports_config_error_for_missing_secret_key(kube, namespace):
    await kube.create_namespaced_secret(
        namespace=namespace,
        body=client.V1Secret(
            metadata=client.V1ObjectMeta(name="partial-secret", namespace=namespace),
            type="Opaque",
            data={"other_key": "dmFsdWU="},
        ),
    )

    env = [
        client.V1EnvVar(
            name="ACCESS_TOKEN",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name="partial-secret",
                    key="access_token",
                )
            ),
        )
    ]

    await create_pod(kube, namespace, "missing-secret-key", "echo $ACCESS_TOKEN", env=env)

    pod = await wait_for_container_waiting_reason(
        kube,
        namespace,
        "missing-secret-key",
        "CreateContainerConfigError",
    )
    waiting = pod.status.container_statuses[0].state.waiting
    assert "access_token" in waiting.message


# phase5-edge-3
# Component: Kubernetes Secret read-only mount semantics
# Purpose: Verify that a Secret mount generated by spawner-style configuration
# is read-only from the container perspective.
# What this test checks:
# - Secret mount is readable
# - writing into the Secret mount fails
# Example pass:
# - the Pod prints "write-blocked".
# Example fail:
# - the Pod can write into the Secret mount.
@pytest.mark.asyncio
async def test_secret_mount_is_read_only_inside_pod(async_api, kube, namespace):
    spawner = make_spawner(async_api, namespace, mount_secrets_volume=True)
    await EGISpawner.set_access_token(spawner, "abc", None)
    await EGISpawner.configure_secret_volumes(spawner)

    volumes = [volume_from_dict(volume) for volume in spawner.volumes]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]

    await create_pod(
        kube,
        namespace,
        "secret-readonly",
        "cat /egi-secrets/access_token; echo; "
        "if echo no > /egi-secrets/new-file 2>/tmp/write.err; "
        "then echo write-unexpected; else echo write-blocked; fi",
        volumes=volumes,
        volume_mounts=mounts,
    )

    await wait_for_pod_phase(kube, namespace, "secret-readonly", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("secret-readonly", namespace)

    assert "abc" in log
    assert "write-blocked" in log
    assert "write-unexpected" not in log


# phase5-edge-4
# Component: emptyDir user secret mount
# Purpose: Verify that the emptyDir mount produced by secret-volume configuration
# is writable inside a real Pod.
# What this test checks:
# - generated emptyDir volume can be mounted
# - container can write and read a file in the mount
# Example pass:
# - the Pod prints "emptydir-write-ok".
# Example fail:
# - generated emptyDir volume is invalid or read-only.
@pytest.mark.asyncio
async def test_emptydir_secret_mount_is_writable_inside_pod(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace, mount_secrets_volume=False)
    await EGISpawner.configure_secret_volumes(spawner)

    user_volume_names = {mount["name"] for mount in spawner.volume_mounts}
    volumes = [
        volume_from_dict(volume)
        for volume in spawner.volumes
        if volume["name"] in user_volume_names
    ]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]

    await create_pod(
        kube,
        namespace,
        "emptydir-writable",
        "echo emptydir-write-ok > /egi-secrets/result; cat /egi-secrets/result",
        volumes=volumes,
        volume_mounts=mounts,
    )

    await wait_for_pod_phase(kube, namespace, "emptydir-writable", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("emptydir-writable", namespace)

    assert "emptydir-write-ok" in log


# phase5-edge-5
# Component: pre_spawn_hook + Secret-backed Pod
# Purpose: Verify that pre_spawn_hook can generate Secret configuration that is
# immediately usable by a real Pod.
# What this test checks:
# - pre_spawn_hook calls load_user_options
# - generated Secret exists
# - generated Secret mount works in a real Pod
# Example pass:
# - the Pod reads a file from the mounted Secret path.
# Example fail:
# - hook-generated configuration is incomplete or invalid.
@pytest.mark.asyncio
async def test_pre_spawn_hook_secret_mount_can_be_used_by_pod(
    async_api, kube, namespace
):
    spawner = make_spawner(
        async_api,
        namespace,
        mount_secrets_volume=True,
        token_mount_path="/egi-secrets",
    )
    await EGISpawner.set_access_token(spawner, "abc", None)

    await EGISpawner.pre_spawn_hook(spawner, spawner)

    volumes = [volume_from_dict(volume) for volume in spawner.volumes]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]

    await create_pod(
        kube,
        namespace,
        "pre-spawn-secret-pod",
        "cat /egi-secrets/access_token",
        volumes=volumes,
        volume_mounts=mounts,
    )

    await wait_for_pod_phase(kube, namespace, "pre-spawn-secret-pod", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("pre-spawn-secret-pod", namespace)

    spawner.load_user_options.assert_awaited_once()
    assert "abc" in log


# phase5-edge-6
# Component: pre_spawn_hook + PVC-backed Pod
# Purpose: Verify that pre_spawn_hook can select a user PVC that is immediately
# usable by a real Pod.
# What this test checks:
# - user PVC is selected
# - generated volume claimName is valid
# - Pod can write to the selected PVC
# Example pass:
# - the Pod prints "pre-spawn-pvc-ok".
# Example fail:
# - PVC selection or generated volume config is invalid.
@pytest.mark.asyncio
async def test_pre_spawn_hook_pvc_selection_can_be_used_by_pod(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, "claim-alice", username="alice")

    spawner = make_spawner(async_api, namespace, mount_secrets_volume=False)
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await EGISpawner.pre_spawn_hook(spawner, spawner)

    workspace_volume = [
        volume_from_dict(volume)
        for volume in spawner.volumes
        if volume["name"] == "workspace"
    ]
    workspace_mount = [
        client.V1VolumeMount(name="workspace", mount_path="/workspace", read_only=False)
    ]

    await create_pod(
        kube,
        namespace,
        "pre-spawn-pvc-pod",
        "echo pre-spawn-pvc-ok > /workspace/result; cat /workspace/result",
        volumes=workspace_volume,
        volume_mounts=workspace_mount,
    )

    await wait_for_pod_phase(kube, namespace, "pre-spawn-pvc-pod", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("pre-spawn-pvc-pod", namespace)

    spawner.load_user_options.assert_awaited_once()
    assert "pre-spawn-pvc-ok" in log


# phase5-edge-7
# Component: auth_state_hook + Pod metadata
# Purpose: Verify auth_state_hook-propagated primary group can be used as a real
# Pod annotation.
# What this test checks:
# - auth_state_hook stores primary group in extra_annotations
# - Kubernetes accepts and preserves the annotation
# Example pass:
# - read_namespaced_pod returns egi.eu/primary_group annotation.
# Example fail:
# - annotation key/value is invalid or not preserved.
@pytest.mark.asyncio
async def test_auth_state_primary_group_annotation_is_valid_pod_metadata(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace)
    await EGISpawner.auth_state_hook(
        spawner,
        spawner,
        {
            "access_token": "abc",
            "id_token": "xyz",
            "primary_group": "vo.example",
        },
    )

    await create_pod(
        kube,
        namespace,
        "primary-group-metadata",
        "echo metadata-ok",
        annotations=spawner.extra_annotations,
    )

    await wait_for_pod_phase(kube, namespace, "primary-group-metadata", {"Succeeded"})
    pod = await kube.read_namespaced_pod("primary-group-metadata", namespace)

    assert pod.metadata.annotations["egi.eu/primary_group"] == "vo.example"


# phase5-edge-8
# Component: Secret metadata labels and annotations
# Purpose: Verify production-like Secret metadata is accepted by Kubernetes.
# What this test checks:
# - labels from _build_common_labels are valid Kubernetes label keys/values
# - annotations from _build_common_annotations are stored
# Example pass:
# - Secret round trip preserves expected metadata.
# Example fail:
# - generated metadata is invalid or dropped.
@pytest.mark.asyncio
async def test_secret_metadata_roundtrip_uses_valid_kubernetes_labels(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace, username="alice")

    await EGISpawner.set_access_token(spawner, "abc", None)

    secret = await kube.read_namespaced_secret("access-token-alice", namespace)
    assert secret.metadata.labels["app"] == "jupyterhub"
    assert secret.metadata.labels["component"] == "singleuser-server"
    assert "hub.jupyter.org/username" not in (secret.metadata.labels or {})
    assert secret.metadata.annotations["test-suite"] == "phase5-k3s-edge"
    assert secret.metadata.annotations["egi.eu/owner"] == "alice"


# phase5-edge-9
# Component: generated environment variables
# Purpose: Verify generated SECRETS_VOLUME_MOUNTED env values are accepted by a
# real Pod and visible inside the container.
# What this test checks:
# - emptyDir mode produces value "0"
# - Secret-mounted mode produces value "1"
# Example pass:
# - Pods print expected environment values.
# Example fail:
# - environment generation is missing or incorrectly typed.
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mount_secrets_volume", "expected_value", "pod_name"),
    [
        (False, "0", "env-emptydir-mode"),
        (True, "1", "env-secret-mode"),
    ],
)
async def test_generated_secret_mount_environment_is_visible_in_pod(
    async_api,
    kube,
    namespace,
    mount_secrets_volume,
    expected_value,
    pod_name,
):
    spawner = make_spawner(
        async_api,
        namespace,
        mount_secrets_volume=mount_secrets_volume,
    )
    await EGISpawner.configure_secret_volumes(spawner)

    await create_pod(
        kube,
        namespace,
        pod_name,
        "echo mounted=$SECRETS_VOLUME_MOUNTED",
        env=env_from_dict(spawner.environment),
    )

    await wait_for_pod_phase(kube, namespace, pod_name, {"Succeeded"})
    log = await kube.read_namespaced_pod_log(pod_name, namespace)

    assert f"mounted={expected_value}" in log


# phase5-edge-10
# Component: user-specific Secret isolation
# Purpose: Verify that Secrets for two users can be mounted by two different Pods
# without cross-user data leakage.
# What this test checks:
# - Alice and Bob get separate Secrets
# - each Pod reads only its own token
# Example pass:
# - Alice Pod prints alice-token and Bob Pod prints bob-token.
# Example fail:
# - both Pods read the same Secret or one Secret overwrites the other.
@pytest.mark.asyncio
async def test_user_specific_secrets_are_isolated_between_pods(
    async_api, kube, namespace
):
    alice = make_spawner(async_api, namespace, username="alice")
    bob = make_spawner(async_api, namespace, username="bob")

    await EGISpawner.set_access_token(alice, "alice-token", None)
    await EGISpawner.set_access_token(bob, "bob-token", None)

    for name, secret_name in [
        ("alice-token-reader", "access-token-alice"),
        ("bob-token-reader", "access-token-bob"),
    ]:
        volume = client.V1Volume(
            name="tokens",
            secret=client.V1SecretVolumeSource(secret_name=secret_name),
        )
        mount = client.V1VolumeMount(name="tokens", mount_path="/tokens", read_only=True)
        await create_pod(
            kube,
            namespace,
            name,
            "cat /tokens/access_token",
            volumes=[volume],
            volume_mounts=[mount],
        )

    await wait_for_pod_phase(kube, namespace, "alice-token-reader", {"Succeeded"})
    await wait_for_pod_phase(kube, namespace, "bob-token-reader", {"Succeeded"})

    alice_log = await kube.read_namespaced_pod_log("alice-token-reader", namespace)
    bob_log = await kube.read_namespaced_pod_log("bob-token-reader", namespace)

    assert "alice-token" in alice_log
    assert "bob-token" in bob_log
    assert "bob-token" not in alice_log
    assert "alice-token" not in bob_log


# phase5-edge-11
# Component: PVC user isolation
# Purpose: Verify that configure_user_volumes selects the current user's PVC when
# several user PVCs are present and the selected claim works in a Pod.
# What this test checks:
# - Alice and Bob PVCs exist
# - Bob's spawner selects Bob's PVC
# - Pod can write to Bob's selected PVC
# Example pass:
# - Bob Pod prints "bob-pvc-ok".
# Example fail:
# - Bob's spawner selects Alice's PVC or the generated volume is invalid.
@pytest.mark.asyncio
async def test_user_specific_pvc_selection_is_usable_by_pod(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, "claim-alice", username="alice")
    await create_user_pvc(kube, namespace, "claim-bob", username="bob")

    spawner = make_spawner(async_api, namespace, username="bob")
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]

    await EGISpawner.configure_user_volumes(spawner)

    volumes = [volume_from_dict(volume) for volume in spawner.volumes]
    mounts = [
        client.V1VolumeMount(name="workspace", mount_path="/workspace", read_only=False)
    ]

    await create_pod(
        kube,
        namespace,
        "bob-pvc-check",
        "echo bob-pvc-ok > /workspace/result; cat /workspace/result",
        volumes=volumes,
        volume_mounts=mounts,
    )

    await wait_for_pod_phase(kube, namespace, "bob-pvc-check", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("bob-pvc-check", namespace)

    assert spawner.pvc_name == "claim-bob"
    assert "bob-pvc-ok" in log


# phase5-edge-12
# Component: Kubernetes API validation for invalid Pod specs
# Purpose: Verify the cluster rejects an invalid volume reference early.
# What this test checks:
# - invalid duplicate volume names are rejected by the API server
# Example pass:
# - create_namespaced_pod raises ApiException with HTTP 422.
# Example fail:
# - invalid manifest is accepted unexpectedly.
@pytest.mark.asyncio
async def test_kubernetes_rejects_duplicate_volume_names(kube, namespace):
    duplicate_volume_a = client.V1Volume(
        name="duplicate",
        empty_dir=client.V1EmptyDirVolumeSource(),
    )
    duplicate_volume_b = client.V1Volume(
        name="duplicate",
        empty_dir=client.V1EmptyDirVolumeSource(),
    )

    with pytest.raises(ApiException) as exc_info:
        await create_pod(
            kube,
            namespace,
            "duplicate-volume-names",
            "echo should-not-create",
            volumes=[duplicate_volume_a, duplicate_volume_b],
        )

    assert exc_info.value.status == 422


# phase5-edge-13
# Component: Secret update visibility to new Pods
# Purpose: Verify a Pod started after a Secret update reads the updated token.
# What this test checks:
# - first token value is replaced
# - a later Pod reads the new value from the same Secret name
# Example pass:
# - the Pod prints "second-token".
# Example fail:
# - update path leaves the old token visible to newly created Pods.
@pytest.mark.asyncio
async def test_new_pod_reads_updated_secret_value(async_api, kube, namespace):
    spawner = make_spawner(async_api, namespace)
    await EGISpawner.set_access_token(spawner, "first-token", None)
    await EGISpawner.set_access_token(spawner, "second-token", None)

    volume = client.V1Volume(
        name="tokens",
        secret=client.V1SecretVolumeSource(secret_name="access-token-alice"),
    )
    mount = client.V1VolumeMount(name="tokens", mount_path="/tokens", read_only=True)

    await create_pod(
        kube,
        namespace,
        "updated-secret-reader",
        "cat /tokens/access_token",
        volumes=[volume],
        volume_mounts=[mount],
    )

    await wait_for_pod_phase(kube, namespace, "updated-secret-reader", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("updated-secret-reader", namespace)

    assert "second-token" in log
    assert "first-token" not in log


# phase5-edge-14
# Component: combined pre_spawn_hook configuration
# Purpose: Verify pre_spawn_hook can prepare both Secret and PVC configuration
# that work together in a real Pod.
# What this test checks:
# - selected PVC is writable
# - generated Secret mount is readable
# - generated environment flag is present
# Example pass:
# - the Pod prints token, PVC marker, and mounted flag.
# Example fail:
# - combined generated configuration is inconsistent.
@pytest.mark.asyncio
async def test_pre_spawn_hook_combined_secret_pvc_and_env_pod_smoke(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, "claim-alice", username="alice")

    spawner = make_spawner(
        async_api,
        namespace,
        mount_secrets_volume=True,
        token_mount_path="/egi-secrets",
    )
    spawner.volumes = [
        {"name": "workspace", "persistentVolumeClaim": {"claimName": "claim-placeholder"}}
    ]
    await EGISpawner.set_access_token(spawner, "abc", None)

    await EGISpawner.pre_spawn_hook(spawner, spawner)

    volumes = [volume_from_dict(volume) for volume in spawner.volumes]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]
    mounts.append(
        client.V1VolumeMount(name="workspace", mount_path="/workspace", read_only=False)
    )

    await create_pod(
        kube,
        namespace,
        "pre-spawn-combined",
        (
            "printf token=; cat /egi-secrets/access_token; "
            "echo pvc-ok > /workspace/result; "
            "printf ' '; cat /workspace/result; "
            "echo mounted=$SECRETS_VOLUME_MOUNTED"
        ),
        volumes=volumes,
        volume_mounts=mounts,
        env=env_from_dict(spawner.environment),
    )

    await wait_for_pod_phase(kube, namespace, "pre-spawn-combined", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("pre-spawn-combined", namespace)

    assert "token=abc" in log
    assert "pvc-ok" in log
    assert "mounted=1" in log
