#!/usr/bin/env python3
"""
Unified test runner for egi-notebooks-hub.

Usage examples:
    ./run_tests.py --list
    ./run_tests.py phase1 -q
    ./run_tests.py phase2 -q
    ./run_tests.py phase3 -q
    ./run_tests.py all -q
    ./run_tests.py all --future -q
    ./run_tests.py phase1 -s
    ./run_tests.py all -x --disable-warnings

This script is intentionally simple:
- it groups test files into phases
- it forwards extra arguments directly to pytest
- it can optionally include additional future tests discovered in tests/
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
TESTS_DIR = REPO_ROOT / "tests"

PHASES: dict[str, list[str]] = {
    "phase1": [
        "tests/test_egiauthenticator.py",
        "tests/test_egiauthenticator_handlers.py",
    ],
    "phase2": [
        "tests/test_egispawner_init.py",
        "tests/test_egispawner_unit.py",
    ],
    "phase3": [
        "tests/test_share_manager.py",
        "tests/test_api_wrapper.py",
    ],
}


def flatten_phases(phases: dict[str, list[str]]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for file_list in phases.values():
        for item in file_list:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return result


KNOWN_TESTS = set(flatten_phases(PHASES))


def discover_future_tests() -> list[str]:
    """
    Discover test files in tests/ that are not yet explicitly assigned to a phase.
    """
    if not TESTS_DIR.exists():
        return []

    discovered: list[str] = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel not in KNOWN_TESTS:
            discovered.append(rel)
    return discovered


def build_test_selection(target: str, include_future: bool) -> list[str]:
    if target == "all":
        selected = flatten_phases(PHASES)
    else:
        selected = PHASES[target][:]

    if include_future:
        selected.extend(discover_future_tests())

    # Deduplicate while preserving order
    deduped: list[str] = []
    seen: set[str] = set()
    for item in selected:
        if item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped


def print_phase_listing() -> None:
    print("Configured test phases:\n")
    for phase_name, files in PHASES.items():
        print(f"{phase_name}:")
        for file in files:
            print(f"  - {file}")
        print()

    future = discover_future_tests()
    if future:
        print("Unassigned future test files detected:")
        for file in future:
            print(f"  - {file}")
    else:
        print("No unassigned future test files detected.")


def ensure_pytest_available() -> None:
    if shutil.which("pytest") is None:
        print("Error: pytest was not found in PATH.", file=sys.stderr)
        print(
            "Activate your virtual environment and install pytest first.",
            file=sys.stderr,
        )
        sys.exit(2)


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Run grouped pytest suites for egi-notebooks-hub."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="all",
        choices=["phase1", "phase2", "phase3", "all"],
        help="Which phase to run.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List configured phases and known test files.",
    )
    parser.add_argument(
        "--future",
        action="store_true",
        help="Also include unassigned test_*.py files found in tests/.",
    )

    args, pytest_args = parser.parse_known_args()
    return args, pytest_args


def main() -> int:
    args, pytest_args = parse_args()

    if args.list:
        print_phase_listing()
        return 0

    ensure_pytest_available()

    selected_tests = build_test_selection(args.target, args.future)

    if not selected_tests:
        print("No test files selected.", file=sys.stderr)
        return 1

    cmd = ["pytest", *selected_tests, *pytest_args]

    print("Running command:")
    print(" ", " ".join(cmd))
    print()

    completed = subprocess.run(cmd, cwd=REPO_ROOT)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
