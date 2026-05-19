"""
Phase 6 service tests against a running JupyterHub process.
"""

import httpx

from .conftest import HUB_URL, SERVICE_URL, api_get, read_log, service_names


# phase6-services-1
# Component: JupyterHub service registry.
# Purpose: Verify token-acquirer service is registered in the running Hub.
# Pass example: /hub/api/services includes token-acquirer.
# Fail example: service configuration is not loaded by Hub.
def test_running_hub_lists_token_acquirer_service(running_hub):
    response = api_get("/hub/api/services")

    assert response.status_code == 200
    assert "token-acquirer" in service_names(response.json())


# phase6-services-2
# Component: JupyterHub service registry.
# Purpose: Verify test-admin service is registered in the running Hub.
# Pass example: /hub/api/services includes test-admin.
# Fail example: the API token service is not registered.
def test_running_hub_lists_test_admin_service(running_hub):
    response = api_get("/hub/api/services")

    assert response.status_code == 200
    assert "test-admin" in service_names(response.json())


# phase6-services-3
# Component: service model.
# Purpose: Verify token-acquirer has a concrete service model.
# Pass example: /hub/api/services/token-acquirer returns name and URL.
# Fail example: service list exists but direct service lookup fails.
def test_token_acquirer_service_model_is_readable(running_hub):
    response = api_get("/hub/api/services/token-acquirer")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "token-acquirer"
    assert payload["url"].startswith("http://127.0.0.1:")


# phase6-services-4
# Component: service model.
# Purpose: Verify test-admin has a concrete service model.
# Pass example: /hub/api/services/test-admin returns the service name.
# Fail example: direct service lookup fails for the test token service.
def test_test_admin_service_model_is_readable(running_hub):
    response = api_get("/hub/api/services/test-admin")

    assert response.status_code == 200
    assert response.json()["name"] == "test-admin"


# phase6-services-5
# Component: managed Hub service routing.
# Purpose: Verify token-acquirer is reachable through the Hub proxy.
# Pass example: the proxied service endpoint does not return a proxy 5xx.
# Fail example: Hub proxy cannot connect to the managed service process.
def test_token_acquirer_service_is_reachable_through_hub_proxy(running_hub):
    response = httpx.get(SERVICE_URL, timeout=5, follow_redirects=False)

    assert response.status_code not in {502, 503, 504}


# phase6-services-6
# Component: managed service process.
# Purpose: Verify token-acquirer startup is visible in Hub logs.
# Pass example: Hub log contains the token-acquirer service name.
# Fail example: managed service command is never started by Hub.
def test_hub_log_mentions_token_acquirer_service(running_hub):
    log_text = read_log(running_hub["log_path"])

    assert "token-acquirer" in log_text


# phase6-services-7
# Component: service registry authorization.
# Purpose: Verify direct service model lookup requires authentication.
# Pass example: GET service model without token is rejected.
# Fail example: anonymous users can inspect service configuration.
def test_token_acquirer_service_model_requires_authentication(running_hub):
    response = api_get("/hub/api/services/token-acquirer", token=False)

    assert response.status_code in {403, 404}


# phase6-services-8
# Component: service registry authorization.
# Purpose: Verify missing service lookup returns not found with credentials.
# Pass example: unknown service name returns HTTP 404.
# Fail example: unknown service lookup returns a server error.
def test_missing_service_model_returns_404(running_hub):
    response = api_get("/hub/api/services/missing-phase6-service")

    assert response.status_code == 404


# phase6-services-9
# Component: proxied service routing.
# Purpose: Verify a missing path under the service is not proxy failure.
# Pass example: service returns app-level 4xx or redirect, not 502.
# Fail example: proxy route exists but service process is unreachable.
def test_token_acquirer_missing_path_is_not_proxy_failure(running_hub):
    response = httpx.get(
        f"{SERVICE_URL}missing-path",
        timeout=5,
        follow_redirects=False,
    )

    assert response.status_code not in {502, 503, 504}


# phase6-services-10
# Component: proxied service routing.
# Purpose: Verify repeated requests to the service remain stable.
# Pass example: several proxied requests avoid proxy 5xx responses.
# Fail example: service process exits after the first request.
def test_token_acquirer_service_handles_repeated_requests(running_hub):
    statuses = []
    for _ in range(3):
        response = httpx.get(SERVICE_URL, timeout=5, follow_redirects=False)
        statuses.append(response.status_code)

    assert all(status not in {502, 503, 504} for status in statuses)


# phase6-services-11
# Component: Hub service API payload.
# Purpose: Verify service-list payload has expected service names.
# Pass example: returned service names include the configured services.
# Fail example: service registry loses configured services.
def test_service_list_payload_contains_expected_names(running_hub):
    response = api_get("/hub/api/services")
    names = service_names(response.json())

    assert {"test-admin", "token-acquirer"}.issubset(names)


# phase6-services-12
# Component: Hub service model payload.
# Purpose: Verify token-acquirer model contains expected common fields.
# Pass example: name and url keys are available.
# Fail example: Hub service model shape changes unexpectedly.
def test_token_acquirer_model_contains_expected_fields(running_hub):
    response = api_get("/hub/api/services/token-acquirer")
    payload = response.json()

    assert payload["name"] == "token-acquirer"
    assert "url" in payload


# phase6-services-13
# Component: Hub service model payload.
# Purpose: Verify test-admin model contains expected common fields.
# Pass example: name key is available.
# Fail example: Hub service model shape changes unexpectedly.
def test_test_admin_model_contains_expected_fields(running_hub):
    response = api_get("/hub/api/services/test-admin")
    payload = response.json()

    assert payload["name"] == "test-admin"


# phase6-services-14
# Component: proxied service HTTP behavior.
# Purpose: Verify service root returns a deterministic non-proxy response.
# Pass example: response is not in proxy error range.
# Fail example: request is handled by proxy error page.
def test_token_acquirer_service_root_returns_non_proxy_response(running_hub):
    response = httpx.get(SERVICE_URL, timeout=5, follow_redirects=False)

    assert response.status_code not in {502, 503, 504}


# phase6-services-15
# Component: running Hub service protection.
# Purpose: Verify service API access with an invalid token is rejected.
# Pass example: invalid token cannot read service registry.
# Fail example: arbitrary tokens can read service models.
def test_service_registry_rejects_invalid_token(running_hub):
    response = httpx.get(
        f"{HUB_URL}/hub/api/services",
        headers={"Authorization": "token invalid-token"},
        timeout=5,
    )

    assert response.status_code in {403, 404}


# phase6-services-16
# Component: service routing.
# Purpose: Verify Hub route to token-acquirer stays available after API calls.
# Pass example: API registry calls do not break proxied service route.
# Fail example: service route disappears after registry access.
def test_service_route_survives_after_registry_lookup(running_hub):
    registry_response = api_get("/hub/api/services/token-acquirer")
    service_response = httpx.get(SERVICE_URL, timeout=5, follow_redirects=False)

    assert registry_response.status_code == 200
    assert service_response.status_code not in {502, 503, 504}


# phase6-services-17
# Component: Hub API service route.
# Purpose: Verify missing service direct lookup is not server error.
# Pass example: direct lookup for missing service returns 404.
# Fail example: direct lookup raises 5xx.
def test_missing_service_direct_lookup_is_not_server_error(running_hub):
    response = api_get("/hub/api/services/does-not-exist")

    assert response.status_code == 404


# phase6-services-18
# Component: managed service process health.
# Purpose: Verify Hub process remains alive after service route checks.
# Pass example: Hub process is still running.
# Fail example: service route checks crash the Hub process.
def test_hub_process_survives_service_requests(running_hub):
    httpx.get(SERVICE_URL, timeout=5, follow_redirects=False)

    assert running_hub["process"].poll() is None


# phase6-services-19
# Component: service registry consistency.
# Purpose: Verify services can be listed twice with stable names.
# Pass example: repeated service-list calls include the configured services.
# Fail example: service registry changes unexpectedly between calls.
def test_service_registry_is_stable_across_repeated_reads(running_hub):
    first = service_names(api_get("/hub/api/services").json())
    second = service_names(api_get("/hub/api/services").json())

    assert {"test-admin", "token-acquirer"}.issubset(first)
    assert {"test-admin", "token-acquirer"}.issubset(second)


# phase6-services-20
# Component: Hub service routing.
# Purpose: Verify service URL from Hub model is internally consistent.
# Pass example: token-acquirer URL points at localhost test backend.
# Fail example: service model points at an unexpected backend.
def test_token_acquirer_service_url_matches_configured_backend(running_hub):
    response = api_get("/hub/api/services/token-acquirer")
    payload = response.json()

    assert payload["url"].startswith("http://127.0.0.1:")
