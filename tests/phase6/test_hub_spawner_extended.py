"""
Additional Phase 6 spawner lifecycle tests against a running JupyterHub process.
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


def _events_for_user(running_hub, username, server_name=None):
    events = [
        event
        for event in _read_spawner_events(running_hub)
        if event.get("user") == username
    ]
    if server_name is not None:
        events = [
            event for event in events if event.get("server_name", "") == server_name
        ]
    return events


def _wait_for_event_count(
    running_hub,
    username,
    event_name,
    count,
    *,
    server_name=None,
    timeout=45,
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matching = [
            event
            for event in _events_for_user(running_hub, username, server_name)
            if event.get("event") == event_name
        ]
        if len(matching) >= count:
            return matching
        time.sleep(0.5)

    raise AssertionError(f"Expected {count} {event_name!r} events for {username!r}")


def _wait_for_event(running_hub, username, event_name, *, server_name=None, timeout=45):
    return _wait_for_event_count(
        running_hub,
        username,
        event_name,
        1,
        server_name=server_name,
        timeout=timeout,
    )[-1]


def _wait_for_server_ready(username, server_name="", timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = api_get(f"/hub/api/users/{username}")
        if response.status_code == 200:
            user_model = response.json()
            server = user_model.get("servers", {}).get(server_name, {})
            if server.get("ready") is True:
                return user_model
        time.sleep(0.5)

    raise AssertionError(
        f"Server {server_name!r} for {username!r} did not become ready"
    )


def _server_api_path(username, server_name=""):
    if server_name:
        return f"/hub/api/users/{username}/servers/{server_name}"
    return f"/hub/api/users/{username}/server"


def _start_server(username, server_name=""):
    response = api_post(_server_api_path(username, server_name))
    assert response.status_code in {201, 202, 204}
    return response


def _stop_server(username, server_name=""):
    response = api_delete(_server_api_path(username, server_name))
    assert response.status_code in {202, 204, 404}
    return response


def _spawn_user(running_hub, username, server_name=""):
    create_user(username)
    _start_server(username, server_name)
    event = _wait_for_event(
        running_hub,
        username,
        "start",
        server_name=server_name,
    )
    user_model = _wait_for_server_ready(username, server_name)
    return event, user_model


def _cleanup_user(username):
    api_delete(f"/hub/api/users/{username}/servers/named")
    api_delete(f"/hub/api/users/{username}/server")
    delete_user(username)


# phase6-spawner-ext-1
# Component: Hub API authorization.
# Purpose: Verify anonymous clients cannot start a default user server.
# Pass example: POST without token returns 403 or 404.
# Fail example: anonymous clients can spawn servers.
def test_anonymous_client_cannot_start_default_server(running_hub, unique_name):
    create_user(unique_name)

    response = httpx.post(f"{HUB_URL}/hub/api/users/{unique_name}/server", timeout=5)

    assert response.status_code in {403, 404}
    delete_user(unique_name)


# phase6-spawner-ext-2
# Component: Hub API authorization.
# Purpose: Verify anonymous clients cannot stop a default user server.
# Pass example: DELETE without token returns 403 or 404.
# Fail example: anonymous clients can stop servers.
def test_anonymous_client_cannot_stop_default_server(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    response = httpx.delete(f"{HUB_URL}/hub/api/users/{unique_name}/server", timeout=5)

    assert response.status_code in {403, 404}
    _cleanup_user(unique_name)


# phase6-spawner-ext-3
# Component: Hub API authorization.
# Purpose: Verify invalid tokens cannot start a default user server.
# Pass example: invalid token returns 403 or 404.
# Fail example: arbitrary tokens can spawn servers.
def test_invalid_token_cannot_start_default_server(running_hub, unique_name):
    create_user(unique_name)

    response = httpx.post(
        f"{HUB_URL}/hub/api/users/{unique_name}/server",
        headers={"Authorization": "token invalid-token"},
        timeout=5,
    )

    assert response.status_code in {403, 404}
    delete_user(unique_name)


# phase6-spawner-ext-4
# Component: Hub API authorization.
# Purpose: Verify invalid tokens cannot stop a default user server.
# Pass example: invalid token returns 403 or 404.
# Fail example: arbitrary tokens can stop servers.
def test_invalid_token_cannot_stop_default_server(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    response = httpx.delete(
        f"{HUB_URL}/hub/api/users/{unique_name}/server",
        headers={"Authorization": "token invalid-token"},
        timeout=5,
    )

    assert response.status_code in {403, 404}
    _cleanup_user(unique_name)


# phase6-spawner-ext-5
# Component: Hub API authorization.
# Purpose: Verify anonymous clients cannot start a named server.
# Pass example: POST named server without token returns 403 or 404.
# Fail example: anonymous clients can create named servers.
def test_anonymous_client_cannot_start_named_server(running_hub, unique_name):
    create_user(unique_name)

    response = httpx.post(
        f"{HUB_URL}/hub/api/users/{unique_name}/servers/named",
        timeout=5,
    )

    assert response.status_code in {403, 404}
    delete_user(unique_name)


# phase6-spawner-ext-6
# Component: running Hub + named server lifecycle.
# Purpose: Verify a named server spawn reaches the EGI spawner subclass.
# Pass example: POST /servers/named records a start event.
# Fail example: named server requests bypass the configured spawner.
def test_running_hub_named_server_spawn_reaches_spawner(running_hub, unique_name):
    event, user_model = _spawn_user(running_hub, unique_name, "named")

    assert event["event"] == "start"
    assert event["server_name"] == "named"
    assert "named" in user_model["servers"]
    assert user_model["servers"]["named"]["ready"] is True
    _cleanup_user(unique_name)


# phase6-spawner-ext-7
# Component: running Hub + named server model.
# Purpose: Verify named server appears separately from the default server.
# Pass example: servers contains named and does not require default server.
# Fail example: named server state is stored under the default server key.
def test_running_hub_named_server_has_separate_model_key(
    running_hub,
    unique_name,
):
    _, user_model = _spawn_user(running_hub, unique_name, "named")

    assert "named" in user_model["servers"]
    assert "" not in user_model["servers"]
    _cleanup_user(unique_name)


# phase6-spawner-ext-8
# Component: running Hub + named server stop.
# Purpose: Verify named server deletion reaches the spawner stop method.
# Pass example: DELETE /servers/named records a stop event.
# Fail example: named server cleanup skips spawner.stop().
def test_running_hub_named_server_stop_reaches_spawner(running_hub, unique_name):
    _spawn_user(running_hub, unique_name, "named")

    _stop_server(unique_name, "named")
    stop_events = _wait_for_event_count(
        running_hub,
        unique_name,
        "stop",
        1,
        server_name="named",
    )

    assert stop_events[-1]["event"] == "stop"
    assert stop_events[-1]["server_name"] == "named"
    delete_user(unique_name)


# phase6-spawner-ext-9
# Component: running Hub + named server cleanup.
# Purpose: Verify named server model is removed after stop.
# Pass example: servers no longer contains named after DELETE.
# Fail example: stopped named server remains ready in Hub model.
def test_running_hub_named_server_model_updates_after_stop(
    running_hub,
    unique_name,
):
    _spawn_user(running_hub, unique_name, "named")

    _stop_server(unique_name, "named")
    response = api_get(f"/hub/api/users/{unique_name}")
    servers = response.json().get("servers", {})

    assert "named" not in servers or servers["named"].get("ready") is not True
    delete_user(unique_name)


# phase6-spawner-ext-10
# Component: running Hub + named server route.
# Purpose: Verify named server route reaches a backend and avoids proxy 5xx.
# Pass example: /user/<name>/named/ does not return 502, 503, or 504.
# Fail example: named server route is not registered in the proxy.
def test_running_hub_named_server_route_is_not_proxy_failure(
    running_hub,
    unique_name,
):
    _spawn_user(running_hub, unique_name, "named")

    response = httpx.get(
        f"{HUB_URL}/user/{unique_name}/named/",
        timeout=5,
        follow_redirects=True,
    )

    assert response.status_code not in {502, 503, 504}
    _cleanup_user(unique_name)


# phase6-spawner-ext-11
# Component: spawner event payload.
# Purpose: Verify start event contains a process id and port.
# Pass example: pid and port are positive integers.
# Fail example: spawner start did not record backend process metadata.
def test_spawner_start_event_records_pid_and_port(running_hub, unique_name):
    event, _ = _spawn_user(running_hub, unique_name)

    assert isinstance(event["pid"], int)
    assert event["pid"] > 0
    assert isinstance(event["port"], int)
    assert event["port"] > 0
    _cleanup_user(unique_name)


# phase6-spawner-ext-12
# Component: spawner event payload.
# Purpose: Verify start event contains a numeric timestamp.
# Pass example: timestamp is an int or float.
# Fail example: event logging omits ordering metadata.
def test_spawner_start_event_records_timestamp(running_hub, unique_name):
    event, _ = _spawn_user(running_hub, unique_name)

    assert isinstance(event["timestamp"], (int, float))
    assert event["timestamp"] > 0
    _cleanup_user(unique_name)


# phase6-spawner-ext-13
# Component: spawner event payload.
# Purpose: Verify stop event records the stop mode.
# Pass example: stop event contains now=False for normal deletion.
# Fail example: spawner stop metadata is missing.
def test_spawner_stop_event_records_now_flag(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    _stop_server(unique_name)
    event = _wait_for_event(running_hub, unique_name, "stop")

    assert event["now"] is False
    delete_user(unique_name)


# phase6-spawner-ext-14
# Component: spawner event payload.
# Purpose: Verify generated Secret names differ between users.
# Pass example: separate users have different token_secret_name values.
# Fail example: spawner state is shared across users.
def test_spawner_token_secret_names_differ_between_users(
    running_hub,
    unique_name,
):
    first = f"{unique_name}-a"
    second = f"{unique_name}-b"

    first_event, _ = _spawn_user(running_hub, first)
    second_event, _ = _spawn_user(running_hub, second)

    assert first_event["token_secret_name"] != second_event["token_secret_name"]
    _cleanup_user(first)
    _cleanup_user(second)


# phase6-spawner-ext-15
# Component: spawner event payload.
# Purpose: Verify generated Secret volume names differ between users.
# Pass example: separate users have different token_secret_volume_name values.
# Fail example: generated volume names collide across users.
def test_spawner_token_secret_volume_names_differ_between_users(
    running_hub,
    unique_name,
):
    first = f"{unique_name}-a"
    second = f"{unique_name}-b"

    first_event, _ = _spawn_user(running_hub, first)
    second_event, _ = _spawn_user(running_hub, second)

    assert (
        first_event["token_secret_volume_name"]
        != second_event["token_secret_volume_name"]
    )
    _cleanup_user(first)
    _cleanup_user(second)


# phase6-spawner-ext-16
# Component: server stop idempotency.
# Purpose: Verify stopping an already stopped default server is stable.
# Pass example: second DELETE returns a non-5xx status.
# Fail example: repeated stop crashes Hub.
def test_default_server_stop_is_idempotent(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    first = _stop_server(unique_name)
    second = api_delete(f"/hub/api/users/{unique_name}/server")

    assert first.status_code in {202, 204, 404}
    assert second.status_code < 500
    delete_user(unique_name)


# phase6-spawner-ext-17
# Component: server stop idempotency.
# Purpose: Verify stopping an already stopped named server is stable.
# Pass example: second DELETE returns a non-5xx status.
# Fail example: repeated named server stop crashes Hub.
def test_named_server_stop_is_idempotent(running_hub, unique_name):
    _spawn_user(running_hub, unique_name, "named")

    first = _stop_server(unique_name, "named")
    second = api_delete(f"/hub/api/users/{unique_name}/servers/named")

    assert first.status_code in {202, 204, 404}
    assert second.status_code < 500
    delete_user(unique_name)


# phase6-spawner-ext-18
# Component: duplicate spawn handling.
# Purpose: Verify duplicate default server spawn is stable.
# Pass example: second POST returns a non-5xx status.
# Fail example: duplicate spawn crashes Hub.
def test_duplicate_default_server_spawn_is_stable(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    response = api_post(f"/hub/api/users/{unique_name}/server")

    assert response.status_code < 500
    _cleanup_user(unique_name)


# phase6-spawner-ext-19
# Component: duplicate spawn handling.
# Purpose: Verify duplicate named server spawn is stable.
# Pass example: second POST returns a non-5xx status.
# Fail example: duplicate named server spawn crashes Hub.
def test_duplicate_named_server_spawn_is_stable(running_hub, unique_name):
    _spawn_user(running_hub, unique_name, "named")

    response = api_post(f"/hub/api/users/{unique_name}/servers/named")

    assert response.status_code < 500
    _cleanup_user(unique_name)


# phase6-spawner-ext-20
# Component: cleanup behavior.
# Purpose: Verify deleted users disappear from direct lookup after server cleanup.
# Pass example: GET user after cleanup returns HTTP 404.
# Fail example: user remains in Hub database after deletion.
def test_user_disappears_after_server_cleanup_and_delete(
    running_hub,
    unique_name,
):
    _spawn_user(running_hub, unique_name)

    _cleanup_user(unique_name)
    response = api_get(f"/hub/api/users/{unique_name}")

    assert response.status_code == 404


# phase6-spawner-ext-21
# Component: cleanup behavior.
# Purpose: Verify user deletion after a named server cleanup removes the user.
# Pass example: GET user after named server cleanup returns HTTP 404.
# Fail example: named server state prevents user deletion.
def test_user_disappears_after_named_server_cleanup_and_delete(
    running_hub,
    unique_name,
):
    _spawn_user(running_hub, unique_name, "named")

    _cleanup_user(unique_name)
    response = api_get(f"/hub/api/users/{unique_name}")

    assert response.status_code == 404


# phase6-spawner-ext-22
# Component: multi-user lifecycle.
# Purpose: Verify three sequential users receive three distinct backend ports.
# Pass example: each start event has a different port.
# Fail example: backend server allocation reuses live ports incorrectly.
def test_three_sequential_users_receive_distinct_backend_ports(
    running_hub,
    unique_name,
):
    users = [f"{unique_name}-{idx}" for idx in range(3)]

    events = []
    for username in users:
        event, _ = _spawn_user(running_hub, username)
        events.append(event)

    ports = {event["port"] for event in events}
    assert len(ports) == 3

    for username in users:
        _cleanup_user(username)


# phase6-spawner-ext-23
# Component: multi-user lifecycle.
# Purpose: Verify three sequential users all become ready.
# Pass example: every created user has a ready default server.
# Fail example: later spawns fail after earlier users are running.
def test_three_sequential_users_all_become_ready(running_hub, unique_name):
    users = [f"{unique_name}-{idx}" for idx in range(3)]

    models = []
    for username in users:
        _, user_model = _spawn_user(running_hub, username)
        models.append(user_model)

    assert all(model["servers"][""]["ready"] is True for model in models)

    for username in users:
        _cleanup_user(username)


# phase6-spawner-ext-24
# Component: multi-user lifecycle.
# Purpose: Verify cleanup of one user does not stop another user's server.
# Pass example: second user's server remains ready after first user cleanup.
# Fail example: cleanup leaks across users.
def test_cleanup_of_one_user_does_not_stop_another_user(
    running_hub,
    unique_name,
):
    first = f"{unique_name}-a"
    second = f"{unique_name}-b"
    _spawn_user(running_hub, first)
    _spawn_user(running_hub, second)

    _cleanup_user(first)
    response = api_get(f"/hub/api/users/{second}")
    second_model = response.json()

    assert second_model["servers"][""]["ready"] is True
    _cleanup_user(second)


# phase6-spawner-ext-25
# Component: lifecycle event ordering.
# Purpose: Verify repeated lifecycle records start, stop, start ordering.
# Pass example: event sequence contains start, stop, start for same user.
# Fail example: event logging misses repeated lifecycle transitions.
def test_repeated_lifecycle_records_start_stop_start_order(
    running_hub,
    unique_name,
):
    _spawn_user(running_hub, unique_name)
    _stop_server(unique_name)
    _start_server(unique_name)
    _wait_for_server_ready(unique_name)

    events = _events_for_user(running_hub, unique_name)
    event_names = [event["event"] for event in events]

    assert event_names[:3] == ["start", "stop", "start"]
    _cleanup_user(unique_name)


# phase6-spawner-ext-26
# Component: lifecycle event ordering.
# Purpose: Verify final cleanup records a stop event.
# Pass example: the last event after cleanup is stop.
# Fail example: cleanup deletes Hub state without reaching spawner.stop().
def test_final_cleanup_records_stop_event(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)

    _cleanup_user(unique_name)
    events = _events_for_user(running_hub, unique_name)

    assert events[-1]["event"] == "stop"


# phase6-spawner-ext-27
# Component: Hub process stability.
# Purpose: Verify Hub survives multiple sequential spawns and stops.
# Pass example: process.poll() remains None after repeated lifecycle operations.
# Fail example: repeated spawner lifecycle crashes Hub.
def test_hub_process_survives_multiple_spawns_and_stops(
    running_hub,
    unique_name,
):
    users = [f"{unique_name}-{idx}" for idx in range(3)]

    for username in users:
        _spawn_user(running_hub, username)

    for username in users:
        _cleanup_user(username)

    assert running_hub["process"].poll() is None


# phase6-spawner-ext-28
# Component: route behavior after stop.
# Purpose: Verify default user route no longer returns a successful backend route.
# Pass example: route does not return HTTP 200 after stop.
# Fail example: stopped backend remains available through Hub proxy.
def test_default_user_route_changes_after_stop(running_hub, unique_name):
    _spawn_user(running_hub, unique_name)
    _stop_server(unique_name)

    response = httpx.get(
        f"{HUB_URL}/user/{unique_name}/",
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code != 200
    delete_user(unique_name)


# phase6-spawner-ext-29
# Component: route behavior after stop.
# Purpose: Verify named user route no longer returns a successful backend route.
# Pass example: named route does not return HTTP 200 after stop.
# Fail example: stopped named backend remains available through Hub proxy.
def test_named_user_route_changes_after_stop(running_hub, unique_name):
    _spawn_user(running_hub, unique_name, "named")
    _stop_server(unique_name, "named")

    response = httpx.get(
        f"{HUB_URL}/user/{unique_name}/named/",
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code != 200
    delete_user(unique_name)


# phase6-spawner-ext-30
# Component: spawner metadata consistency.
# Purpose: Verify start events contain stable EGI initialization fields.
# Pass example: event has token names, mount path, pvc_name, namespace.
# Fail example: Hub-loaded EGISpawner misses expected initialization data.
def test_spawner_start_event_contains_expected_egi_metadata(
    running_hub,
    unique_name,
):
    event, _ = _spawn_user(running_hub, unique_name)

    assert event["token_secret_name"].startswith("access-token-")
    assert event["token_secret_volume_name"].startswith("secret-")
    assert event["token_mount_path"] == "/var/run/secrets/egi.eu/"
    assert isinstance(event["pvc_name"], str)
    assert event["pvc_name"]
    assert isinstance(event["namespace"], str)
    assert event["namespace"]
    _cleanup_user(unique_name)
