# Running /tests from scratch

## Preparation

```bash
git clone https://github.com/nikl11/egi-notebooks-hub.git  
cd egi-notebooks-hub  
git switch tests #for now
python3 -m venv .venv  
source .venv/bin/activate  
pip install -U pip  
pip install -r requirements.txt  
pip install pytest pytest-asyncio  
pip install -e .  
```

---

# Running tests

## Direct pytest usage (optional)

You can still run tests manually using pytest:

```bash
pytest -q tests/phase1extended/test_egiauthenticator.py
```

---

# EGI Hub test runner

We provide a helper script to simplify running tests:

```bash
python tests/run_tests.py
```

This script wraps pytest and provides structured execution of test phases.

---

## Basic usage

Run all test phases:

```bash
python tests/run_tests.py all
```

Run a single phase:

```bash
python tests/run_tests.py phase1  
python tests/run_tests.py phase2  
python tests/run_tests.py phase3  
```

---

## List all phases and files

```bash
python tests/run_tests.py --list
```

This shows:
- which files belong to each phase
- any unassigned test files

---

## Include new (unmapped) tests

```bash
python tests/run_tests.py all --include-new
```

This will include any test_*.py files not yet assigned to a phase.

---

# Useful options

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

## Combining options

```bash
python tests/run_tests.py phase1 --quiet --show-print
```

---

# Important differences from older version

The CLI flags were renamed:

```bash
- -q → --quiet  
- -x → --fail-fast  
- -s → --show-print  
- --future → --include-new  
```

---

# Test phase structure

Defined in run_tests.py:

```bash
PHASES = {  
    "phase1": [...],  
    "phase2": [...],  
    "phase3": [...],  
}
```

To add a new phase:

```bash
PHASES["phase4"] = ["phase4extended/test_new_feature.py"]
```

---

# Notes

- The script runs pytest with cwd=tests/, so paths are relative to tests/  
- Always use: python tests/run_tests.py  
