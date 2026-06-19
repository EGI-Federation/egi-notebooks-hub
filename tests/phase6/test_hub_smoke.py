"""
Phase 6 smoke tests for a running JupyterHub process.
"""

import httpx

from .conftest import HUB_URL, api_get, auth_headers, read_log


# phase6-smoke-1
# Component: running JupyterHub API.
# Purpose: Verify that JupyterHub starts and returns version information.
# Pass example: GET /hub/api returns HTTP 200 and contains a version field.
# Fail example: Hub startup or proxy routing is broken.
def test_running_hub_api_returns_version(running_hub):
    response = api_get("/hub/api")

    assert response.status_code == 200
    assert "version" in response.json()


# phase6-smoke-2
# Component: public Hub API root.
# Purpose: Document that /hub/api is an informational endpoint.
# Pass example: GET /hub/api without token returns HTTP 200.
# Fail example: Hub behavior changes and the endpoint becomes protected.
def test_running_hub_api_root_is_public(running_hub):
    response = api_get("/hub/api", token=False)

    assert response.status_code == 200
    assert "version" in response.json()


# phase6-smoke-3
# Component: protected Hub users API.
# Purpose: Verify protected API endpoints reject missing credentials.
# Pass example: GET /hub/api/users without token is forbidden or hidden.
# Fail example: user list can be read anonymously.
def test_running_hub_users_api_requires_authentication(running_hub):
    response = api_get("/hub/api/users", token=False)

    assert response.status_code in {403, 404}


# phase6-smoke-4
# Component: protected Hub services API.
# Purpose: Verify service registry access rejects missing credentials.
# Pass example: GET /hub/api/services without token is forbidden or hidden.
# Fail example: service registry can be read anonymously.
def test_running_hub_services_api_requires_authentication(running_hub):
    response = api_get("/hub/api/services", token=False)

    assert response.status_code in {403, 404}


# phase6-smoke-5
# Component: configured test service token.
# Purpose: Verify the service token has enough access to list users.
# Pass example: GET /hub/api/users with token returns HTTP 200.
# Fail example: the configured service role is too weak.
def test_running_hub_service_token_can_list_users(running_hub):
    response = api_get("/hub/api/users")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


# phase6-smoke-6
# Component: configured test service token.
# Purpose: Verify the service token has enough access to list services.
# Pass example: GET /hub/api/services with token returns HTTP 200.
# Fail example: service role lacks service-read permissions.
def test_running_hub_service_token_can_list_services(running_hub):
    response = api_get("/hub/api/services")

    assert response.status_code == 200


# phase6-smoke-7
# Component: Hub login route.
# Purpose: Verify that the web-facing Hub route is reachable.
# Pass example: /hub/login returns a successful page or redirect.
# Fail example: proxy cannot route ordinary Hub web requests.
def test_running_hub_login_route_is_reachable(running_hub):
    response = httpx.get(
        f"{HUB_URL}/hub/login",
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code in {200, 302, 303}


# phase6-smoke-8
# Component: Hub root routing.
# Purpose: Verify that the proxy can route requests to the Hub base path.
# Pass example: /hub/ returns a normal page or redirect.
# Fail example: proxy routing to Hub base path is broken.
def test_running_hub_base_route_is_reachable(running_hub):
    response = httpx.get(
        f"{HUB_URL}/hub/",
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code in {200, 302, 303}


# phase6-smoke-9
# Component: Hub API token rejection.
# Purpose: Verify that invalid tokens do not get API access.
# Pass example: invalid token does not return HTTP 200 for /hub/api/users.
# Fail example: Hub accepts arbitrary bearer tokens.
def test_running_hub_rejects_invalid_service_token(running_hub):
    response = httpx.get(
        f"{HUB_URL}/hub/api/users",
        headers={"Authorization": "token invalid-token"},
        timeout=5,
    )

    assert response.status_code in {403, 404}


# phase6-smoke-10
# Component: Hub startup quality.
# Purpose: Verify that Hub startup log does not contain Python tracebacks.
# Pass example: Hub and managed services start without tracebacks.
# Fail example: Hub config or service startup raises an exception.
def test_running_hub_log_has_no_traceback(running_hub):
    log_text = read_log(running_hub["log_path"])

    assert "Traceback (most recent call last)" not in log_text


# phase6-smoke-11
# Component: Hub process management.
# Purpose: Verify the fixture keeps Hub running during the test session.
# Pass example: process.poll() is None while tests are running.
# Fail example: Hub exits after startup.
def test_running_hub_process_is_alive(running_hub):
    assert running_hub["process"].poll() is None


# phase6-smoke-12
# Component: Hub API response content.
# Purpose: Verify Hub API returns JSON for the root API endpoint.
# Pass example: content-type contains application/json.
# Fail example: proxy returns an HTML error page.
def test_running_hub_api_returns_json_content_type(running_hub):
    response = api_get("/hub/api")

    assert "application/json" in response.headers["content-type"]


# phase6-smoke-13
# Component: Hub API authorization header handling.
# Purpose: Verify the configured token works with the expected header.
# Pass example: Authorization: token phase6-test-admin-token returns 200.
# Fail example: token format no longer matches Hub expectations.
def test_running_hub_accepts_expected_authorization_header(running_hub):
    response = httpx.get(
        f"{HUB_URL}/hub/api/users",
        headers=auth_headers(),
        timeout=5,
    )

    assert response.status_code == 200


# phase6-smoke-14
# Component: Hub API path protection.
# Purpose: Verify a non-root protected endpoint is protected without token.
# Pass example: GET /hub/api/groups without token is forbidden or hidden.
# Fail example: group list can be read anonymously.
def test_running_hub_groups_api_requires_authentication(running_hub):
    response = api_get("/hub/api/groups", token=False)

    assert response.status_code in {403, 404}


# phase6-smoke-15
# Component: Hub API group listing.
# Purpose: Verify the configured token can access the group API.
# Pass example: GET /hub/api/groups returns HTTP 200.
# Fail example: service token lacks group-read permissions.
def test_running_hub_service_token_can_list_groups(running_hub):
    response = api_get("/hub/api/groups")

    assert response.status_code == 200
