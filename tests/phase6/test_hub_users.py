"""
Phase 6 user and group API tests against a running JupyterHub process.
"""

import httpx

from .conftest import (
    HUB_URL,
    api_get,
    api_post,
    create_group,
    create_user,
    delete_group,
    delete_user,
)


# phase6-users-1
# Component: Hub user API.
# Purpose: Verify that the running Hub can create a user through its API.
# Pass example: POST /hub/api/users/<name> returns HTTP 201 or 409.
# Fail example: service token lacks admin user permissions.
def test_running_hub_can_create_user(running_hub, unique_name):
    response = create_user(unique_name)

    assert response.status_code in {201, 409}
    delete_user(unique_name)


# phase6-users-2
# Component: Hub user API.
# Purpose: Verify that a created user can be read back through the API.
# Pass example: GET /hub/api/users/<name> returns the same user name.
# Fail example: user creation succeeds but read permissions are missing.
def test_running_hub_can_read_created_user(running_hub, unique_name):
    create_user(unique_name)

    response = api_get(f"/hub/api/users/{unique_name}")

    assert response.status_code == 200
    assert response.json()["name"] == unique_name
    delete_user(unique_name)


# phase6-users-3
# Component: Hub user API.
# Purpose: Verify created users appear in the Hub user list.
# Pass example: newly created user is present in /hub/api/users.
# Fail example: list endpoint is not updated or token cannot list users.
def test_running_hub_created_user_appears_in_user_list(
    running_hub,
    unique_name,
):
    create_user(unique_name)

    response = api_get("/hub/api/users")
    names = {user["name"] for user in response.json()}

    assert unique_name in names
    delete_user(unique_name)


# phase6-users-4
# Component: Hub user API.
# Purpose: Verify deleting a user removes the user from direct lookup.
# Pass example: GET after DELETE returns HTTP 404.
# Fail example: delete call does not remove the user.
def test_running_hub_can_delete_created_user(running_hub, unique_name):
    create_user(unique_name)

    delete_response = delete_user(unique_name)
    read_response = api_get(f"/hub/api/users/{unique_name}")

    assert delete_response.status_code in {204, 404}
    assert read_response.status_code == 404


# phase6-users-5
# Component: Hub user API.
# Purpose: Verify duplicate user creation is handled as a stable API response.
# Pass example: second create returns HTTP 409 or compatible success.
# Fail example: duplicate creation crashes Hub or returns a server error.
def test_running_hub_duplicate_user_create_is_stable(running_hub, unique_name):
    first = create_user(unique_name)
    second = create_user(unique_name)

    assert first.status_code in {201, 409}
    assert second.status_code in {201, 409}
    delete_user(unique_name)


# phase6-users-6
# Component: Hub user API.
# Purpose: Verify missing users return a not-found response.
# Pass example: GET for unknown user returns HTTP 404.
# Fail example: Hub returns a server error for missing users.
def test_running_hub_missing_user_returns_404(running_hub, unique_name):
    response = api_get(f"/hub/api/users/{unique_name}")

    assert response.status_code == 404


# phase6-users-7
# Component: Hub group API.
# Purpose: Verify that the running Hub can create a group.
# Pass example: POST /hub/api/groups/<name> returns HTTP 201 or 409.
# Fail example: service token lacks group administration permissions.
def test_running_hub_can_create_group(running_hub, unique_name):
    response = create_group(unique_name)

    assert response.status_code in {201, 409}
    delete_group(unique_name)


# phase6-users-8
# Component: Hub group API.
# Purpose: Verify a created group can be read through the group list.
# Pass example: created group appears in /hub/api/groups.
# Fail example: group creation succeeds but group list does not include it.
def test_running_hub_created_group_appears_in_group_list(
    running_hub,
    unique_name,
):
    create_group(unique_name)

    response = api_get("/hub/api/groups")
    names = {group["name"] for group in response.json()}

    assert unique_name in names
    delete_group(unique_name)


# phase6-users-9
# Component: Hub group API.
# Purpose: Verify deleting a group removes it from the group list.
# Pass example: group name is absent after DELETE.
# Fail example: delete call does not remove the group.
def test_running_hub_can_delete_group(running_hub, unique_name):
    create_group(unique_name)

    delete_response = delete_group(unique_name)
    list_response = api_get("/hub/api/groups")
    names = {group["name"] for group in list_response.json()}

    assert delete_response.status_code in {204, 404}
    assert unique_name not in names


# phase6-users-10
# Component: Hub group API.
# Purpose: Verify adding a user to a group works through the running Hub API.
# Pass example: group model contains the added user's name.
# Fail example: membership update is rejected or not persisted.
def test_running_hub_can_add_user_to_group(running_hub, unique_name):
    user_name = f"{unique_name}-user"
    group_name = f"{unique_name}-group"
    create_user(user_name)
    create_group(group_name)

    response = api_post(
        f"/hub/api/groups/{group_name}/users",
        json={"users": [user_name]},
    )
    assert response.status_code in {200, 201, 204}

    group_response = api_get("/hub/api/groups")
    groups = {group["name"]: group for group in group_response.json()}
    users = groups[group_name].get("users", [])

    assert user_name in users
    delete_group(group_name)
    delete_user(user_name)


# phase6-users-11
# Component: Hub group API.
# Purpose: Verify adding a missing user to a group is rejected cleanly.
# Pass example: Hub returns a 4xx response, not a 5xx server error.
# Fail example: invalid membership update crashes Hub.
def test_running_hub_rejects_missing_user_group_membership(
    running_hub,
    unique_name,
):
    group_name = f"{unique_name}-group"
    missing_user = f"{unique_name}-missing"
    create_group(group_name)

    response = api_post(
        f"/hub/api/groups/{group_name}/users",
        json={"users": [missing_user]},
    )

    assert 400 <= response.status_code < 500
    delete_group(group_name)


# phase6-users-12
# Component: Hub group API.
# Purpose: Verify adding users to a missing group is rejected cleanly.
# Pass example: Hub returns HTTP 404.
# Fail example: invalid group membership update crashes Hub.
def test_running_hub_rejects_membership_update_for_missing_group(
    running_hub,
    unique_name,
):
    user_name = f"{unique_name}-user"
    group_name = f"{unique_name}-missing-group"
    create_user(user_name)

    response = api_post(
        f"/hub/api/groups/{group_name}/users",
        json={"users": [user_name]},
    )

    assert response.status_code == 404
    delete_user(user_name)


# phase6-users-13
# Component: Hub user model.
# Purpose: Verify user models include expected base fields.
# Pass example: user model includes name, admin, groups, and servers keys.
# Fail example: API model shape changes unexpectedly.
def test_running_hub_user_model_contains_expected_fields(
    running_hub,
    unique_name,
):
    create_user(unique_name)

    response = api_get(f"/hub/api/users/{unique_name}")
    payload = response.json()

    assert payload["name"] == unique_name
    assert "admin" in payload
    assert "groups" in payload
    assert "servers" in payload
    delete_user(unique_name)


# phase6-users-14
# Component: Hub group model.
# Purpose: Verify group models include expected base fields.
# Pass example: created group model includes name and users fields.
# Fail example: API model shape changes unexpectedly.
def test_running_hub_group_model_contains_expected_fields(
    running_hub,
    unique_name,
):
    create_group(unique_name)

    response = api_get("/hub/api/groups")
    groups = {group["name"]: group for group in response.json()}
    payload = groups[unique_name]

    assert payload["name"] == unique_name
    assert "users" in payload
    delete_group(unique_name)


# phase6-users-15
# Component: Hub API status handling.
# Purpose: Verify deleting a missing user is stable and non-5xx.
# Pass example: DELETE unknown user returns HTTP 404.
# Fail example: Hub returns a server error.
def test_running_hub_delete_missing_user_is_stable(running_hub, unique_name):
    response = delete_user(unique_name)

    assert response.status_code in {204, 404}


# phase6-users-16
# Component: Hub API status handling.
# Purpose: Verify deleting a missing group is stable and non-5xx.
# Pass example: DELETE unknown group returns HTTP 404.
# Fail example: Hub returns a server error.
def test_running_hub_delete_missing_group_is_stable(running_hub, unique_name):
    response = delete_group(unique_name)

    assert response.status_code in {204, 404}


# phase6-users-17
# Component: Hub API authorization.
# Purpose: Verify user creation rejects missing credentials.
# Pass example: POST /hub/api/users/<name> without token is rejected.
# Fail example: anonymous clients can create users.
def test_running_hub_user_create_requires_authentication(
    running_hub,
    unique_name,
):
    response = api_post(f"/hub/api/users/{unique_name}", token=False)

    assert response.status_code in {403, 404}


# phase6-users-18
# Component: Hub API authorization.
# Purpose: Verify group creation rejects missing credentials.
# Pass example: POST /hub/api/groups/<name> without token is rejected.
# Fail example: anonymous clients can create groups.
def test_running_hub_group_create_requires_authentication(
    running_hub,
    unique_name,
):
    response = api_post(f"/hub/api/groups/{unique_name}", token=False)

    assert response.status_code in {403, 404}


# phase6-users-19
# Component: Hub API authorization.
# Purpose: Verify user deletion rejects missing credentials.
# Pass example: DELETE /hub/api/users/<name> without token is rejected.
# Fail example: anonymous clients can delete users.
def test_running_hub_user_delete_requires_authentication(
    running_hub,
    unique_name,
):
    response = httpx.delete(f"{HUB_URL}/hub/api/users/{unique_name}", timeout=5)

    assert response.status_code in {403, 404}


# phase6-users-20
# Component: Hub API authorization.
# Purpose: Verify group deletion rejects missing credentials.
# Pass example: DELETE /hub/api/groups/<name> without token is rejected.
# Fail example: anonymous clients can delete groups.
def test_running_hub_group_delete_requires_authentication(
    running_hub,
    unique_name,
):
    response = httpx.delete(f"{HUB_URL}/hub/api/groups/{unique_name}", timeout=5)

    assert response.status_code in {403, 404}
