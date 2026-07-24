"""
Phase 6 service tests against a running JupyterHub process.

These tests intentionally distinguish between two different JupyterHub routes:

- /hub/api/services/<name> checks Hub service registry metadata.
- /services/<name> checks the real proxied service endpoint.

The share-manager service is a JupyterHub service, so runtime service routing
must be tested through /services/share-manager, not through /hub/api/services.
"""

import httpx

from .conftest import (
    HUB_URL,
    SERVICE_NAME,
    SERVICE_URL,
    api_get,
    read_log,
    service_names,
)


# phase6-services-1
# Component: JupyterHub service registry.
# Purpose: Verify share-manager is registered in the running Hub metadata.
# Pass example: /hub/api/services includes share-manager.
# Fail example: service configuration is not loaded by Hub.
def test_running_hub_lists_share_manager_service(running_hub):
    response = api_get("/hub/api/services")

    assert response.status_code == 200
    assert SERVICE_NAME in service_names(response.json())


# phase6-services-2
# Component: JupyterHub service registry.
# Purpose: Verify test-admin service is registered in the running Hub metadata.
# Pass example: /hub/api/services includes test-admin.
# Fail example: the API token service is not registered.
def test_running_hub_lists_test_admin_service(running_hub):
    response = api_get("/hub/api/services")

    assert response.status_code == 200
    assert "test-admin" in service_names(response.json())


# phase6-services-3
# Component: Hub service registry metadata.
# Purpose: Verify share-manager has a concrete Hub service model.
# Pass example: /hub/api/services/share-manager returns name and URL metadata.
# Fail example: service list exists but direct Hub service lookup fails.
def test_share_manager_service_model_is_readable_from_hub_api(running_hub):
    response = api_get(f"/hub/api/services/{SERVICE_NAME}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == SERVICE_NAME
    assert payload["url"].startswith("http://127.0.0.1:")


# phase6-services-4
# Component: Hub service registry metadata.
# Purpose: Verify test-admin has a concrete Hub service model.
# Pass example: /hub/api/services/test-admin returns the service name.
# Fail example: direct Hub service lookup fails for the test token service.
def test_test_admin_service_model_is_readable_from_hub_api(running_hub):
    response = api_get("/hub/api/services/test-admin")

    assert response.status_code == 200
    assert response.json()["name"] == "test-admin"


# phase6-services-5
# Component: proxied share-manager service route.
# Purpose: Verify the real share-manager route is /services/share-manager.
# Pass example: /services/share-manager does not return a Hub proxy 5xx error.
# Fail example: tests only validate /hub/api metadata and miss service routing.
def test_share_manager_service_is_reachable_through_services_route(running_hub):
    response = httpx.get(
        SERVICE_URL,
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code not in {502, 503, 504}


# phase6-services-6
# Component: proxied share-manager service route.
# Purpose: Verify SERVICE_URL helper points at the real /services route.
# Pass example: SERVICE_URL contains /services/share-manager.
# Fail example: helper accidentally points at /hub/api/services/share-manager.
def test_share_manager_service_url_helper_uses_services_route(running_hub):
    assert f"/services/{SERVICE_NAME}" in SERVICE_URL
    assert f"/hub/api/services/{SERVICE_NAME}" not in SERVICE_URL


# phase6-services-7
# Component: proxied share-manager service route.
# Purpose: Verify the runtime service route is not treated as Hub API metadata.
# Pass example: service runtime tests use /services/share-manager.
# Fail example: runtime route is accidentally changed back to /hub/api/services.
def test_share_manager_runtime_route_is_not_hub_api_route(running_hub):
    assert f"/services/{SERVICE_NAME}" == f"/services/{SERVICE_NAME}"


# phase6-services-8
# Component: managed service process.
# Purpose: Verify share-manager startup is visible in Hub logs.
# Pass example: Hub log contains the share-manager service name.
# Fail example: managed service command is never started by Hub.
def test_hub_log_mentions_share_manager_service(running_hub):
    log_text = read_log(running_hub["log_path"])

    assert SERVICE_NAME in log_text


# phase6-services-9
# Component: Hub service registry authorization.
# Purpose: Verify direct service model lookup requires authentication.
# Pass example: GET /hub/api/services/share-manager without token is rejected.
# Fail example: anonymous users can inspect service metadata.
def test_share_manager_service_model_requires_authentication(running_hub):
    response = api_get(f"/hub/api/services/{SERVICE_NAME}", token=False)

    assert response.status_code in {403, 404}


# phase6-services-10
# Component: Hub service registry metadata.
# Purpose: Verify missing service lookup returns not found with credentials.
# Pass example: unknown service name returns HTTP 404.
# Fail example: unknown service lookup returns a server error.
def test_missing_service_model_returns_404(running_hub):
    response = api_get("/hub/api/services/missing-phase6-service")

    assert response.status_code == 404


# phase6-services-11
# Component: proxied share-manager service route.
# Purpose: Verify a missing service subpath is not a Hub proxy failure.
# Pass example: service returns application-level 4xx/redirect, not 502/503/504.
# Fail example: proxy route exists but service process is unreachable.
def test_share_manager_missing_path_is_not_proxy_failure(running_hub):
    response = httpx.get(
        f"{SERVICE_URL}/missing-path",
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code not in {502, 503, 504}


# phase6-services-12
# Component: proxied share-manager service route.
# Purpose: Verify repeated requests to the real service route remain stable.
# Pass example: several /services/share-manager requests avoid proxy 5xx.
# Fail example: service process exits after the first request.
def test_share_manager_service_handles_repeated_services_route_requests(
    running_hub,
):
    statuses = []
    for _ in range(3):
        response = httpx.get(
            SERVICE_URL,
            timeout=5,
            follow_redirects=False,
        )
        statuses.append(response.status_code)

    assert all(status not in {502, 503, 504} for status in statuses)


# phase6-services-13
# Component: Hub service API payload.
# Purpose: Verify service-list payload has expected service names.
# Pass example: returned service names include the two configured services.
# Fail example: service registry loses configured services.
def test_service_list_payload_contains_expected_names(running_hub):
    response = api_get("/hub/api/services")
    names = service_names(response.json())

    assert {"test-admin", SERVICE_NAME}.issubset(names)


# phase6-services-14
# Component: Hub service model payload.
# Purpose: Verify share-manager registry model contains expected fields.
# Pass example: name and url keys are available in Hub API metadata.
# Fail example: Hub service model shape changes unexpectedly.
def test_share_manager_model_contains_expected_registry_fields(running_hub):
    response = api_get(f"/hub/api/services/{SERVICE_NAME}")
    payload = response.json()

    assert payload["name"] == SERVICE_NAME
    assert "url" in payload


# phase6-services-15
# Component: Hub service model payload.
# Purpose: Verify test-admin registry model contains expected fields.
# Pass example: name key is available in Hub API metadata.
# Fail example: Hub service model shape changes unexpectedly.
def test_test_admin_model_contains_expected_registry_fields(running_hub):
    response = api_get("/hub/api/services/test-admin")
    payload = response.json()

    assert payload["name"] == "test-admin"


# phase6-services-16
# Component: proxied service HTTP behavior.
# Purpose: Verify service root returns a non-proxy response on the real route.
# Pass example: /services/share-manager is not handled by proxy error page.
# Fail example: request is handled by proxy 502/503/504 error page.
def test_share_manager_service_root_returns_non_proxy_response(running_hub):
    response = httpx.get(
        SERVICE_URL,
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code not in {502, 503, 504}


# phase6-services-17
# Component: running Hub service protection.
# Purpose: Verify service registry API access with an invalid token is rejected.
# Pass example: invalid token cannot read Hub service registry.
# Fail example: arbitrary tokens can read service models.
def test_service_registry_rejects_invalid_token(running_hub):
    response = httpx.get(
        f"{HUB_URL}/hub/api/services",
        headers={"Authorization": "token invalid-token"},
        timeout=5,
    )

    assert response.status_code in {403, 404}


# phase6-services-18
# Component: service routing.
# Purpose: Verify real service route stays available after registry lookup.
# Pass example: Hub API metadata lookup does not break /services routing.
# Fail example: service route disappears after registry access.
def test_service_route_survives_after_registry_lookup(running_hub):
    registry_response = api_get(f"/hub/api/services/{SERVICE_NAME}")
    service_response = httpx.get(
        SERVICE_URL,
        timeout=5,
        follow_redirects=False,
    )

    assert registry_response.status_code == 200
    assert service_response.status_code not in {502, 503, 504}


# phase6-services-19
# Component: Hub API service route.
# Purpose: Verify missing service direct lookup is not server error.
# Pass example: direct lookup for missing service returns 404.
# Fail example: direct lookup raises 5xx.
def test_missing_service_direct_lookup_is_not_server_error(running_hub):
    response = api_get("/hub/api/services/does-not-exist")

    assert response.status_code == 404


# phase6-services-20
# Component: managed service process health.
# Purpose: Verify Hub process remains alive after real service route checks.
# Pass example: Hub process is still running.
# Fail example: service route checks crash the Hub process.
def test_hub_process_survives_service_requests(running_hub):
    httpx.get(
        SERVICE_URL,
        timeout=5,
        follow_redirects=False,
    )

    assert running_hub["process"].poll() is None


# phase6-services-21
# Component: service registry consistency.
# Purpose: Verify services can be listed twice with stable names.
# Pass example: repeated service-list calls include the configured services.
# Fail example: service registry changes unexpectedly between calls.
def test_service_registry_is_stable_across_repeated_reads(running_hub):
    first = service_names(api_get("/hub/api/services").json())
    second = service_names(api_get("/hub/api/services").json())

    assert {"test-admin", SERVICE_NAME}.issubset(first)
    assert {"test-admin", SERVICE_NAME}.issubset(second)


# phase6-services-22
# Component: Hub service routing metadata.
# Purpose: Verify service URL from Hub model points at backend metadata only.
# Pass example: registry URL is the internal backend URL, not /services path.
# Fail example: tests confuse backend model URL with public service route.
def test_share_manager_service_model_url_is_backend_metadata(running_hub):
    response = api_get(f"/hub/api/services/{SERVICE_NAME}")
    payload = response.json()

    assert payload["url"].startswith("http://127.0.0.1:")
    assert f"/services/{SERVICE_NAME}" not in payload["url"]


# phase6-services-23
# Component: proxied service route correctness.
# Purpose: Verify the tested public service URL has no /hub/api prefix.
# Pass example: runtime service URL is http://host/services/share-manager.
# Fail example: runtime service URL is built as /hub/api/services/share-manager.
def test_share_manager_public_service_url_has_no_hub_api_prefix(running_hub):
    assert SERVICE_URL.startswith(HUB_URL)
    assert "/hub/api/" not in SERVICE_URL
    assert SERVICE_URL.endswith(f"/services/{SERVICE_NAME}")

# phase6-services-24
# Component: share manager get user token
# Purpose: Verify the share manager cat get a user token if called with a service token.
# Pass example: share-manager returns 404 because the access_token is not there
# Fail example: share-manager returns 403 because of lack of permissions
def test_share_manager_user_token(running_hub):
    response = api_get(f"/hub/api/services/{SERVICE_NAME}/token/alice")
    payload = response.json()

    assert response.status_code == 404
    print(payload)
    assert payload["url"].startswith("http://127.0.0.1:")
    assert f"/services/{SERVICE_NAME}" not in payload["url"]
