=== Running /tests from scratch ===

# Preparation

```bash
git clone https://github.com/nikl11/egi-notebooks-hub.git
cd egi-notebooks-hub
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pip install pytest pytest-asyncio
pip install -e .
```

# Running individual set of tests

```bash
pytest -q tests/test_egiauthenticator.py
```

# EGI Hub test runner

This small helper script provides one stable command for running the whole  test suite or its individual parts.

## Basic usage

Run all currently mapped phases:

```bash
./run_tests.py all -q
```

Run a single phase:

```bash
./run_tests.py phase1 -q
./run_tests.py phase2 -q
./run_tests.py phase3 -q
```

Run a specific test file:

```bash
./run_tests.py tests/test_egiauthenticator.py -q
```

Show known phase mapping:

```bash
./run_tests.py --list
```

Also include any future files matching `tests/test_*.py`:

```bash
./run_tests.py all --future -q
```

## Useful pytest passthrough options

Show print output:

```bash
./run_tests.py phase1 -s
```

Stop after first failure:

```bash
./run_tests.py all -x
```

Hide warnings:

```bash
./run_tests.py all -q --disable-warnings
```

Filter by keyword:

```bash
./run_tests.py all -k primary_group -q
```

## How to extend in the future

Edit `run_tests.py` and add a new phase entry to the `PHASES` mapping, for example:

```python
PHASES["phase4"] = ["tests/test_something_new.py"]
```

If you do not want to maintain the mapping immediately, you can still place a new file into `tests/` with the name pattern `test_*.py` and run:

```bash
./run_tests.py all --future -q
```

That will automatically include it.
