
"""
Phase 5 Kubernetes Pod smoke tests for EGISpawner-generated Kubernetes objects.

These tests create small real Pods in the temporary k3s/minikube cluster and
verify that Secrets, PVCs, labels, annotations, environment variables, and
volume mounts are usable by Kubernetes.
"""

import asyncio
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning, module="traitlets")

import types
import uuid
from types import SimpleNamespace

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
    """Create and later delete an isolated namespace for each Pod smoke test."""
    ns_name = f"phase5-pod-{uuid.uuid4().hex[:10]}"
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
    token_mount_path="/var/run/secrets/egi.eu/",
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
        labels = {"app": "jupyterhub", "component": "singleuser-server"}
        labels.update(extra_labels or {})
        labels.pop("hub.jupyter.org/username", None)
        return labels

    def _build_common_annotations(extra_annotations):
        annotations = {"test-suite": "phase5-pod-smoke"}
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

    if "configMap" in volume:
        config_map = volume["configMap"]
        return client.V1Volume(
            name=volume["name"],
            config_map=client.V1ConfigMapVolumeSource(name=config_map["name"]),
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
    restart_policy="Never",
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
            restart_policy=restart_policy,
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


async def wait_for_container_waiting_reason(kube, namespace, name, reason, timeout=60):
    """Wait until the main container reports a specific waiting reason."""
    deadline = asyncio.get_running_loop().time() + timeout
    last_reason = None

    while asyncio.get_running_loop().time() < deadline:
        pod = await kube.read_namespaced_pod(name=name, namespace=namespace)
        statuses = pod.status.container_statuses or []
        if statuses and statuses[0].state and statuses[0].state.waiting:
            last_reason = statuses[0].state.waiting.reason
            if last_reason == reason:
                return pod
        await asyncio.sleep(1)

    raise AssertionError(
        f"Pod {name} did not reach waiting reason {reason}; last reason={last_reason}"
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


# phase5-pod-1
# Component: Kubernetes Pod execution
# Purpose: Verify that the test namespace can run a minimal Pod.
# What this test checks:
# - a Pod can be created
# - the image can be pulled
# - the command exits successfully
# Example pass:
# - busybox prints "pod-ok" and reaches Succeeded.
# Example fail:
# - cluster cannot schedule Pods or pull the image.
@pytest.mark.asyncio
async def test_pod_can_run_simple_command(kube, namespace):
    await create_pod(kube, namespace, "simple-command", "echo pod-ok")

    pod = await wait_for_pod_phase(kube, namespace, "simple-command", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("simple-command", namespace)

    assert pod.status.phase == "Succeeded"
    assert "pod-ok" in log


# phase5-pod-2
# Component: Secret mounted into a real Pod
# Purpose: Verify that a Secret created through EGISpawner.set_access_token can
# be mounted and read as files inside a Pod.
# What this test checks:
# - set_access_token creates the Secret
# - the Pod mounts the Secret
# - access_token and id_token files contain expected values
# Example pass:
# - the Pod prints "abc:xyz" from mounted Secret files.
# Example fail:
# - Secret data is encoded incorrectly or the volume mount is invalid.
@pytest.mark.asyncio
async def test_pod_reads_secret_files_created_by_spawner(async_api, kube, namespace):
    spawner = make_spawner(async_api, namespace, mount_secrets_volume=True)
    await EGISpawner.set_access_token(spawner, "abc", "xyz")

    volume = client.V1Volume(
        name="tokens",
        secret=client.V1SecretVolumeSource(secret_name="access-token-alice"),
    )
    mount = client.V1VolumeMount(name="tokens", mount_path="/tokens", read_only=True)

    await create_pod(
        kube,
        namespace,
        "read-secret-files",
        "cat /tokens/access_token; printf ':'; cat /tokens/id_token",
        volumes=[volume],
        volume_mounts=[mount],
    )

    await wait_for_pod_phase(kube, namespace, "read-secret-files", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("read-secret-files", namespace)

    assert "abc:xyz" in log


# phase5-pod-3
# Component: Secret exposed as environment variable
# Purpose: Verify that a Secret created by the spawner can be consumed through
# valueFrom.secretKeyRef.
# What this test checks:
# - access_token exists in the Secret
# - Kubernetes can inject it into a Pod environment variable
# Example pass:
# - the Pod prints "token=abc".
# Example fail:
# - Secret key is missing or cannot be resolved by Kubernetes.
@pytest.mark.asyncio
async def test_pod_reads_spawner_secret_as_environment_variable(
    async_api, kube, namespace
):
    spawner = make_spawner(async_api, namespace)
    await EGISpawner.set_access_token(spawner, "abc", None)

    env = [
        client.V1EnvVar(
            name="EGI_ACCESS_TOKEN",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name="access-token-alice",
                    key="access_token",
                )
            ),
        )
    ]

    await create_pod(
        kube,
        namespace,
        "secret-env",
        "echo token=$EGI_ACCESS_TOKEN",
        env=env,
    )

    await wait_for_pod_phase(kube, namespace, "secret-env", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("secret-env", namespace)

    assert "token=abc" in log


# phase5-pod-4
# Component: configure_secret_volumes + real Pod mount
# Purpose: Verify that the Secret-backed user-facing mount generated by
# configure_secret_volumes is accepted by Kubernetes and readable by a Pod.
# What this test checks:
# - configure_secret_volumes creates the Secret
# - generated volume/mount dictionaries can become a valid Pod spec
# - Secret file content is readable from the configured mount path
# Example pass:
# - the Pod prints the configured access token from token_mount_path.
# Example fail:
# - generated volume or mount structure is invalid.
@pytest.mark.asyncio
async def test_pod_uses_configure_secret_volumes_secret_mount(
    async_api, kube, namespace
):
    spawner = make_spawner(
        async_api,
        namespace,
        mount_secrets_volume=True,
        token_mount_path="/egi-secrets",
    )
    await EGISpawner.set_access_token(spawner, "abc", None)
    await EGISpawner.configure_secret_volumes(spawner)

    volumes = [volume_from_dict(volume) for volume in spawner.volumes]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]

    await create_pod(
        kube,
        namespace,
        "configured-secret-mount",
        "cat /egi-secrets/access_token",
        volumes=volumes,
        volume_mounts=mounts,
    )

    await wait_for_pod_phase(kube, namespace, "configured-secret-mount", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("configured-secret-mount", namespace)

    assert "abc" in log


# phase5-pod-5
# Component: configure_secret_volumes emptyDir mode + real Pod
# Purpose: Verify that emptyDir user-facing secret mode creates a valid Pod spec.
# What this test checks:
# - generated emptyDir volume is accepted by Kubernetes
# - generated environment variable is available inside the Pod
# - the Pod can write to the emptyDir mount
# Example pass:
# - the Pod prints "mounted=0" and writes a test file.
# Example fail:
# - emptyDir volume or environment generation is invalid.
@pytest.mark.asyncio
async def test_pod_uses_configure_secret_volumes_emptydir_mount(
    async_api, kube, namespace
):
    spawner = make_spawner(
        async_api,
        namespace,
        mount_secrets_volume=False,
        token_mount_path="/egi-empty",
    )
    await EGISpawner.configure_secret_volumes(spawner)

    user_volume_names = {mount["name"] for mount in spawner.volume_mounts}
    volumes = [
        volume_from_dict(volume)
        for volume in spawner.volumes
        if volume["name"] in user_volume_names
    ]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]
    env = env_from_dict(spawner.environment)

    await create_pod(
        kube,
        namespace,
        "configured-emptydir-mount",
        "echo mounted=$SECRETS_VOLUME_MOUNTED; echo ok > /egi-empty/file; cat /egi-empty/file",
        volumes=volumes,
        volume_mounts=mounts,
        env=env,
    )

    await wait_for_pod_phase(kube, namespace, "configured-emptydir-mount", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("configured-emptydir-mount", namespace)

    assert "mounted=0" in log
    assert "ok" in log


# phase5-pod-6
# Component: PVC mounted into a real Pod
# Purpose: Verify that a PVC selected by configure_user_volumes can be mounted
# by Kubernetes.
# What this test checks:
# - a real annotated PVC is discovered
# - the generated PVC claimName is valid
# - a Pod can write to the mounted PVC
# Example pass:
# - the Pod writes and reads "pvc-ok".
# Example fail:
# - PVC discovery picks the wrong claim or the volume cannot mount.
@pytest.mark.asyncio
async def test_pod_mounts_pvc_selected_by_configure_user_volumes(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, pvc_name="claim-alice", username="alice")

    spawner = make_spawner(async_api, namespace)
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
        "pvc-writer",
        "echo pvc-ok > /workspace/result; cat /workspace/result",
        volumes=volumes,
        volume_mounts=mounts,
    )

    await wait_for_pod_phase(kube, namespace, "pvc-writer", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("pvc-writer", namespace)

    assert "pvc-ok" in log


# phase5-pod-7
# Component: PVC persistence across Pods
# Purpose: Verify that a selected PVC can persist data across two sequential Pods.
# What this test checks:
# - one Pod writes into the PVC
# - another Pod reads the same file from the same PVC
# Example pass:
# - second Pod prints "shared-data".
# Example fail:
# - PVC claimName is wrong or data does not persist.
@pytest.mark.asyncio
async def test_pvc_selected_by_configure_user_volumes_persists_between_pods(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, pvc_name="claim-alice", username="alice")

    spawner = make_spawner(async_api, namespace)
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
        "pvc-write-once",
        "echo shared-data > /workspace/shared.txt",
        volumes=volumes,
        volume_mounts=mounts,
    )
    await wait_for_pod_phase(kube, namespace, "pvc-write-once", {"Succeeded"})

    await create_pod(
        kube,
        namespace,
        "pvc-read-back",
        "cat /workspace/shared.txt",
        volumes=volumes,
        volume_mounts=mounts,
    )
    await wait_for_pod_phase(kube, namespace, "pvc-read-back", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("pvc-read-back", namespace)

    assert "shared-data" in log


# phase5-pod-8
# Component: Pod metadata
# Purpose: Verify that labels and annotations used for spawned Pods survive a
# real Kubernetes create/read round trip.
# What this test checks:
# - Kubernetes stores provided labels
# - Kubernetes stores provided annotations
# Example pass:
# - read_namespaced_pod returns the same metadata values.
# Example fail:
# - generated metadata is invalid or unexpectedly dropped.
@pytest.mark.asyncio
async def test_pod_preserves_labels_and_annotations(kube, namespace):
    labels = {"app": "egi-hub-test", "component": "phase5"}
    annotations = {"egi.eu/primary_group": "vo.example"}

    await create_pod(
        kube,
        namespace,
        "metadata-check",
        "echo metadata-ok",
        labels=labels,
        annotations=annotations,
    )

    await wait_for_pod_phase(kube, namespace, "metadata-check", {"Succeeded"})
    pod = await kube.read_namespaced_pod("metadata-check", namespace)

    assert pod.metadata.labels["app"] == "egi-hub-test"
    assert pod.metadata.labels["component"] == "phase5"
    assert pod.metadata.annotations["egi.eu/primary_group"] == "vo.example"


# phase5-pod-9
# Component: Secret reference validation
# Purpose: Verify that Kubernetes reports a clear failure when a Pod references
# a missing Secret.
# What this test checks:
# - the API accepts the Pod manifest
# - kubelet marks the container as CreateContainerConfigError
# Example pass:
# - missing Secret produces CreateContainerConfigError.
# Example fail:
# - the Pod unexpectedly succeeds or fails for an unrelated reason.
@pytest.mark.asyncio
async def test_pod_reports_config_error_for_missing_secret(kube, namespace):
    env = [
        client.V1EnvVar(
            name="MISSING_TOKEN",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name="missing-secret",
                    key="access_token",
                )
            ),
        )
    ]

    await create_pod(kube, namespace, "missing-secret-ref", "echo should-not-run", env=env)

    pod = await wait_for_container_waiting_reason(
        kube,
        namespace,
        "missing-secret-ref",
        "CreateContainerConfigError",
    )

    waiting = pod.status.container_statuses[0].state.waiting
    assert waiting.reason == "CreateContainerConfigError"
    assert "missing-secret" in waiting.message


# phase5-pod-10
# Component: Full generated Secret + PVC Pod spec
# Purpose: Verify a Pod can use both spawner-generated Secret configuration and
# spawner-selected PVC configuration in the same manifest.
# What this test checks:
# - configure_secret_volumes creates valid Secret volumes/mounts/env
# - configure_user_volumes selects a real PVC
# - Kubernetes accepts the combined Pod spec
# - both Secret and PVC are usable inside the container
# Example pass:
# - the Pod prints token and writes/reads the PVC marker.
# Example fail:
# - generated Secret/PVC settings conflict or one of the mounts is invalid.
@pytest.mark.asyncio
async def test_pod_uses_combined_spawner_secret_and_pvc_configuration(
    async_api, kube, namespace
):
    await create_user_pvc(kube, namespace, pvc_name="claim-alice", username="alice")

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
    await EGISpawner.configure_secret_volumes(spawner)
    await EGISpawner.configure_user_volumes(spawner)

    volumes = [volume_from_dict(volume) for volume in spawner.volumes]
    mounts = [mount_from_dict(mount) for mount in spawner.volume_mounts]
    mounts.append(
        client.V1VolumeMount(name="workspace", mount_path="/workspace", read_only=False)
    )
    env = env_from_dict(spawner.environment)

    await create_pod(
        kube,
        namespace,
        "combined-secret-pvc",
        (
            "printf token=; cat /egi-secrets/access_token; "
            "echo combined-ok > /workspace/result; "
            "printf ' '; cat /workspace/result; "
            "echo mounted=$SECRETS_VOLUME_MOUNTED"
        ),
        volumes=volumes,
        volume_mounts=mounts,
        env=env,
    )

    await wait_for_pod_phase(kube, namespace, "combined-secret-pvc", {"Succeeded"})
    log = await kube.read_namespaced_pod_log("combined-secret-pvc", namespace)

    assert "token=abc" in log
    assert "combined-ok" in log
    assert "mounted=1" in log
