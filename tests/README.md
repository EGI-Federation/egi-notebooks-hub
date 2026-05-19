# Test suite for egi-notebooks-hub

This directory contains a comprehensive test suite for the egi-notebooks-hub repository.

The tests cover both:

- source code validation (unit and integration-style tests)
- execution in a real k3s Kubernetes cluster

All tests can be run locally and are also executed automatically via GitHub Actions.

## Running /tests from scratch

### Preparation

```bash
git clone https://github.com/nikl11/egi-notebooks-hub.git
cd egi-notebooks-hub
git switch tests #for now
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pip install -r requirements-test.txt
pip install -e .
```

---

## Running tests

### Direct pytest usage (optional)

You can still run tests manually using pytest:

```bash
pytest -q tests/phase1extended/test_egiauthenticator.py
```

---

## EGI Hub test runner

We provide a helper script to simplify running tests:

```bash
python tests/run_tests.py
```

This script wraps pytest and provides structured execution of test phases.

---

### Basic usage

Run all test phases:

```bash
python tests/run_tests.py all
```

Run a single phase:

```bash
python tests/run_tests.py phase1
python tests/run_tests.py phase2
python tests/run_tests.py phase3
python tests/run_tests.py phase4
python tests/run_tests.py phase5
```

---

### List all phases and files

```bash
python tests/run_tests.py --list
```

This shows:

- which files belong to each phase
- any unassigned test files

---

### Include new (unmapped) tests

```bash
python tests/run_tests.py all --include-new
```

This will include any test\_\*.py files not yet assigned to a phase.

---

## Useful options

These options are passed through to pytest:

Quiet output:

```bash
python tests/run_tests.py all --quiet
```

Stop on first failure:

```bash
python tests/run_tests.py all --fail-fast
```

Show print() output:

```bash
python tests/run_tests.py all --show-print
```

---

### Combining options

```bash
python tests/run_tests.py phase1 --quiet --show-print
```

---

## Important differences from older version

The CLI flags were renamed:

```bash
- -q → --quiet
- -x → --fail-fast
- -s → --show-print
- --future → --include-new
```

---

## Test phase structure

Defined in run_tests.py:

```bash
PHASES = {
    "phase1": [...],
    "phase2": [...],
    "phase3": [...],
    "phase4": [...],
    "phase5": [...],
}
```

To add a new phase:

```bash
PHASES["phase999"] = ["phase999/test_new_feature.py"]
```

---

## Notes

- The script runs pytest with `cwd=tests/`, so paths are relative to `tests/`
- Always recommended to use: `python tests/run_tests.py all --show-print`

## Test phase overview

The test suite is organized into layers so that fast Python tests catch logic
regressions early, while Kubernetes-backed tests verify real cluster behavior.

### Phase 1: Authenticator unit tests

Files:

- `phase1extended/test_egiauthenticator.py`
- `phase1extended/test_egiauthenticator_handlers.py`

This phase tests `EGICheckinAuthenticator`, `JWTHandler`, and related
authentication behavior in isolation. It covers URL configuration, username
resolution, primary group selection, auth model construction, JWT decoding,
refresh-token exchange, reusable Hub token handling, login failure handling, and
custom handler routes. External OAuth/EGI responses are represented by prepared
test data and mocks.

### Phase 2: Spawner unit and configuration tests

Files:

- `phase2extended/test_egispawner_init.py`
- `phase2extended/test_egispawner_unit.py`
- `phase2extended/test_egispawner_manifest_config.py`

This phase tests `EGISpawner` Python-side behavior without a live cluster. It
covers initialization, token Secret update logic, base64 encoding, Secret
manifest generation, volume and volume mount configuration, `emptyDir` versus
Secret-backed token mounts, environment variables, profile filtering by VO
groups, `auth_state_hook`, `set_access_token`, and `pre_spawn_hook` sequencing.

### Phase 3: Service tests

Files:

- `phase3extended/test_api_wrapper.py`
- `phase3extended/test_token_acquirer.py`

This phase tests Hub service code such as the API wrapper and token acquirer. It
covers bearer-token exchange, forwarded Hub API requests, response handling,
authorization checks, token metadata validation, user auth_state retrieval, and
error paths for missing or unauthorized tokens.

### Phase 4: Integration tests without Kubernetes

Files:

- `phase4/test_auth_integration.py`
- `phase4/test_services_integration.py`
- `phase4/test_spawner_integration_config.py`

This phase combines multiple components while keeping the test environment fast
and deterministic. It covers JWT login flows, reusable API token flows,
refresh-token handling, wrapper/token-acquirer service flows, and integrated
Spawner configuration flows using an in-memory Kubernetes API replacement.

### Phase 5: Kubernetes/k3s tests

Files:

- `phase5-k3s/test_spawner_k3s.py`
- `phase5-k3s/test_spawner_k3s_additional.py`
- `phase5-k3s/test_spawner_k3s_pods.py`
- `phase5-k3s/test_spawner_k3s_edge.py`

This phase runs against a real Kubernetes API, either a local cluster such as
minikube or the temporary k3s cluster created by GitHub Actions. It covers real
Secret creation and update, PVC discovery, generated Secret/PVC volume
configuration, `auth_state_hook`, `pre_spawn_hook`, Pod smoke tests, Secret and
PVC mounts inside containers, environment variable injection, metadata
round-trips, missing Secret/PVC failure behavior, and multi-user isolation.

## Phase 6: running JupyterHub tests

Files:

- `phase6/jupyterhub_config.py`
- `phase6/conftest.py`
- `phase6/test_hub_smoke.py`
- `phase6/test_hub_users.py`
- `phase6/test_hub_services.py`
- `phase6/test_hub_spawner.py`
- `phase6/test_hub_spawner_extended.py`

Phase 6 starts a real JupyterHub process with a dedicated test configuration and
runs tests against the live Hub through HTTP/API calls. The goal is to verify the
parts of the EGI Hub integration that only exist when JupyterHub is actually
running: Hub API access, service registration, managed service routing, user and
group API behavior, authorization checks, proxy routing, and Hub runtime
stability.

The same Hub configuration also uses a lightweight `EGISpawner` subclass for
spawner lifecycle tests. This subclass still inherits from the real
`EGISpawner`, so JupyterHub initializes the EGI spawner in a real Hub context.
Only the actual single-user backend is replaced with a small local HTTP server,
which makes the tests fast and stable while still verifying that Hub spawn and
stop requests reach the spawner lifecycle.

The spawner tests cover default servers, named servers, repeated start/stop
operations, event metadata, generated EGI spawner attributes, multi-user
isolation, cleanup behavior, route behavior after stop, and protection against
unauthorized or invalid API calls.
