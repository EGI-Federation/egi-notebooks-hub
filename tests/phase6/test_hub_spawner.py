"""
Phase 6 spawner lifecycle tests against a running JupyterHub process.
"""

import json
import time
from pathlib import Path

import httpx

from .conftest import HUB_URL, api_delete, api_get, api_post, create_user, delete_user


def _events_path(running_hub):
    return Path(running_hub["log_path"]).parent / "spawner-events.jsonl"


def _read_spawner_events(running_hub):
    path = _events_path(running_hub)
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _events_for_user(running_hub, username):
    return [
        event
        for event in _read_spawner_events(running_hub)
        if event.get("user") == username
    ]


def _wait_for_event(running_hub, username, event_name, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matching = [
            event
            for event in _events_for_user(running_hub, username)
            if event.get("event") == event_name
        ]
        if matching:
            return matching[-1]
        time.sleep(0.5)

    raise AssertionError(f"Missing spawner event {event_name!r} for {username!r}")


def _wait_for_server_ready(username, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = api_get(f"/hub/api/users/{username}")
        if response.status_code == 200:
            user_model = response.json()
            default_server = user_model.get("servers", {}).get("", {})
            if default_server.get("ready") is True:
                return user_model
        time.sleep(0.5)

    raise AssertionError(f"Server for {username!r} did not become ready")


def _start_default_server(username):
    response = api_post(f"/hub/api/users/{username}/server")
    assert response.status_code in {201, 202, 204}
    return response


def _stop_default_server(username):
    response = api_delete(f"/hub/api/users/{username}/server")
    assert response.status_code in {202, 204, 404}
    return response


def _spawn_user(running_hub, username):
    create_user(username)
    _start_default_server(username)
    event = _wait_for_event(running_hub, username, "start")
    user_model = _wait_for_server_ready(username)
    return event, user_model


def _cleanup_user(username):
    _stop_default_server(username)
    delete_user(username)


# phase6-spawner-1
# Component: running Hub + EGISpawner lifecycle.
# Purpose: Verify a Hub spawn request reaches the configured EGISpawner subclass.
# Pass example: POST /hub/api/users/<name>/server records a start event.
# Fail example: Hub does not instantiate the configured spawner class.
def test_running_hub_spawn_request_reaches_egi_spawner(running_hub, unique_name):
    event, _ = _spawn_user(running_hub, unique_name)

    assert event["event"] == "start"
    assert event["user"] == unique_name
    assert event["spawner_class"] == "Phase6RecordingEGISpawner"
    _cleanup_user(unique_name)


# phase6-spawner-2
# Component: running Hub + user server model.
# Purpose: Verify Hub marks the spawned default server as ready.
# Pass example: user model contains servers[""].ready == True.
# Fail example: spawner start returns but Hub never observes the server.
def test_running_hub_spawned_server_becomes_ready(running_hub, unique_name):
    _, user_model = _spawn_user(running_hub, unique_name)

    assert user_model["servers"][""]["ready"] is True
    _cleanup_user(unique_name)


# phase6-spawner-3
# Component: running Hub + proxy routing.
# Purpose: Verify the spawned user route is routed to the test server backend.
# Pass example: the request reaches the backend and does not return proxy 5xx.
# Fail example: Hub starts the server but proxy routing is unavailable.
def test_running_hub_spawned_user_route_is_reachable(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    response = httpx.get(
        f"{HUB_URL}/user/{unique_name}/",
        timeout=5,
        follow_redirects=True,
    )

    # The lightweight http.server backend does not implement JupyterHub base_url
    # path handling, so it may return 404 for /user/<name>/. A 404 response from
    # the backend still proves that Hub proxy routing reached the spawned server.
    assert response.status_code not in {502, 503, 504}
    _cleanup_user(unique_name)


# phase6-spawner-4
# Component: running Hub + EGISpawner configuration.
# Purpose: Verify initialized spawner records generated token Secret name.
# Pass example: start event contains an access-token-* Secret name.
# Fail example: Hub uses a different spawner or skips EGI initialization.
def test_running_hub_spawner_records_token_secret_name(running_hub, unique_name):
    event, _ = _spawn_user(running_hub, unique_name)

    assert event["token_secret_name"].startswith("access-token-")
    _cleanup_user(unique_name)


# phase6-spawner-5
# Component: running Hub + EGISpawner configuration.
# Purpose: Verify initialized spawner records generated token Secret volume name.
# Pass example: start event contains a secret-* volume name.
# Fail example: EGI token volume initialization is skipped.
def test_running_hub_spawner_records_token_secret_volume_name(
    running_hub,
    unique_name,
):
    event, _ = _spawn_user(running_hub, unique_name)

    assert event["token_secret_volume_name"].startswith("secret-")
    _cleanup_user(unique_name)


# phase6-spawner-6
# Component: running Hub + EGISpawner configuration.
# Purpose: Verify initialized spawner records the configured token mount path.
# Pass example: start event contains /var/run/secrets/egi.eu/.
# Fail example: Hub-loaded spawner loses EGI token mount configuration.
def test_running_hub_spawner_records_token_mount_path(running_hub, unique_name):
    event, _ = _spawn_user(running_hub, unique_name)

    assert event["token_mount_path"] == "/var/run/secrets/egi.eu/"
    _cleanup_user(unique_name)


# phase6-spawner-7
# Component: running Hub + EGISpawner PVC initialization.
# Purpose: Verify initialized spawner records a generated pvc_name.
# Pass example: pvc_name is present and non-empty.
# Fail example: EGISpawner initialization did not run in Hub context.
def test_running_hub_spawner_records_generated_pvc_name(running_hub, unique_name):
    event, _ = _spawn_user(running_hub, unique_name)

    assert isinstance(event["pvc_name"], str)
    assert event["pvc_name"]
    _cleanup_user(unique_name)


# phase6-spawner-8
# Component: running Hub + spawner stop lifecycle.
# Purpose: Verify deleting the server reaches the spawner stop method.
# Pass example: DELETE /hub/api/users/<name>/server records a stop event.
# Fail example: Hub removes state without calling spawner cleanup.
def test_running_hub_server_delete_reaches_spawner_stop(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    _stop_default_server(unique_name)
    event = _wait_for_event(running_hub, unique_name, "stop")

    assert event["event"] == "stop"
    delete_user(unique_name)


# phase6-spawner-9
# Component: running Hub + repeated lifecycle.
# Purpose: Verify the same user can spawn again after stopping.
# Pass example: two start events are recorded for the same user.
# Fail example: stale state prevents a second spawn.
def test_running_hub_user_can_spawn_again_after_stop(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)
    _stop_default_server(unique_name)

    _start_default_server(unique_name)
    _wait_for_server_ready(unique_name)

    start_events = [
        event
        for event in _events_for_user(running_hub, unique_name)
        if event["event"] == "start"
    ]

    assert len(start_events) >= 2
    _cleanup_user(unique_name)


# phase6-spawner-10
# Component: running Hub + missing user spawn handling.
# Purpose: Verify spawn request for a missing user is rejected cleanly.
# Pass example: Hub returns 4xx, not 5xx.
# Fail example: missing user spawn crashes Hub.
def test_running_hub_spawn_missing_user_is_rejected_cleanly(
    running_hub,
    unique_name,
):
    response = api_post(f"/hub/api/users/{unique_name}/server")

    assert 400 <= response.status_code < 500


# phase6-spawner-11
# Component: running Hub + multi-user spawner lifecycle.
# Purpose: Verify two users get separate spawner start events.
# Pass example: each user records its own start event and generated Secret name.
# Fail example: spawner state leaks between users.
def test_running_hub_two_users_get_separate_spawner_events(
    running_hub,
    unique_name,
):
    first = f"{unique_name}-a"
    second = f"{unique_name}-b"

    first_event, _ = _spawn_user(running_hub, first)
    second_event, _ = _spawn_user(running_hub, second)

    assert first_event["user"] == first
    assert second_event["user"] == second
    assert first_event["token_secret_name"].startswith("access-token-")
    assert second_event["token_secret_name"].startswith("access-token-")
    assert first_event["token_secret_name"] != second_event["token_secret_name"]

    _cleanup_user(first)
    _cleanup_user(second)


# phase6-spawner-12
# Component: running Hub + process stability.
# Purpose: Verify Hub process survives spawn and stop lifecycle operations.
# Pass example: process.poll() is None after lifecycle operations.
# Fail example: spawner lifecycle crashes the Hub process.
def test_running_hub_process_survives_spawner_lifecycle(
    running_hub,
    unique_name,
):
    _spawn_user(running_hub, unique_name)
    _cleanup_user(unique_name)

    assert running_hub["process"].poll() is None
