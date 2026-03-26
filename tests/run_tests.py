#!/usr/bin/env python3
"""
Simple unified test runner for egi-notebooks-hub.

Usage:
    python tests/run_tests.py --list
    python tests/run_tests.py phase1
    python tests/run_tests.py phase2
    python tests/run_tests.py phase3
    python tests/run_tests.py all

Optional flags:
    --quiet         reduce output
    --fail-fast     stop on first failure
    --show-print    show print() output
    --include-new   include unassigned test files
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


# Paths
TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent


# Test phases
PHASES = {
    "phase1": [
        "phase1extended/test_egiauthenticator.py",
        "phase1extended/test_egiauthenticator_handlers.py",
    ],
    "phase2": [
        "phase2extended/test_egispawner_init.py",
        "phase2extended/test_egispawner_unit.py",
    ],
    "phase3": [
        "phase3extended/test_api_wrapper.py",
        "phase3extended/test_token_acquirer.py",
#        "phase3extended/test_share_manager.py",
    ],
}


# -------------------------
# Helpers
# -------------------------

def all_tests():
    seen = set()
    result = []
    for files in PHASES.values():
        for f in files:
            if f not in seen:
                seen.add(f)
                result.append(f)
    return result


def find_new_tests():
    known = set(all_tests())
    new = []
    for path in TESTS_DIR.rglob("test_*.py"):
        rel = path.relative_to(TESTS_DIR).as_posix()
        if rel not in known:
            new.append(rel)
    return sorted(new)


def list_phases():
    print("\nTest phases:\n")
    for name, files in PHASES.items():
        print(name + ":")
        for f in files:
            print("  -", f)
        print()

    new = find_new_tests()
    if new:
        print("Unassigned tests:")
        for f in new:
            print("  -", f)
    else:
        print("No unassigned tests.")


# -------------------------
# CLI
# -------------------------

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=["phase1", "phase2", "phase3", "all"],
    )

    parser.add_argument("--list", action="store_true")
    parser.add_argument("--include-new", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--show-print", action="store_true")

    return parser.parse_args()


# -------------------------
# Main
# -------------------------

def main():
    args = parse_args()

    if args.list:
        list_phases()
        return

    # select tests
    if args.target == "all":
        selected = all_tests()
    else:
        selected = PHASES[args.target][:]

    if args.include_new:
        selected += find_new_tests()

    if not selected:
        print("No tests selected")
        sys.exit(1)

    # build pytest command
    cmd = ["pytest"] + selected

    if args.quiet:
        cmd.append("-q")

    if args.fail_fast:
        cmd.append("-x")

    if args.show_print:
        cmd.append("-s")

    print("\nRunning:")
    print(" ", " ".join(cmd))
    print()

    result = subprocess.run(cmd, cwd=TESTS_DIR)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
