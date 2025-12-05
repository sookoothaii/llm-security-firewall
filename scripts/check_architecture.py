#!/usr/bin/env python3
"""
Architecture Dependency Rule Checker

Runs import-linter to verify Domain layer doesn't import Infrastructure.
This is a CI/CD gate that prevents Architecture Drift.

Usage:
    python scripts/check_architecture.py

Exit Codes:
    0: Dependency Rule enforced (all checks passed)
    1: Dependency Rule violated (domain imports infrastructure)
"""

import sys
import os
from pathlib import Path


def main():
    """Run import-linter check and exit with appropriate code."""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Check if import-linter is installed
    try:
        from importlinter.cli import main as importlinter_main
    except ImportError:
        print("ERROR: import-linter not installed.")
        print("Install with: pip install import-linter")
        return 1

    # Run import-linter
    config_file = project_root / ".importlinter"
    if not config_file.exists():
        print(f"ERROR: .importlinter config file not found at {config_file}")
        return 1

    # Call import-linter CLI directly
    # Save original argv and cwd, then set up for import-linter
    old_argv = sys.argv.copy()
    old_cwd = os.getcwd()

    try:
        os.chdir(project_root)
        sys.argv = ["import-linter", "--config", str(config_file)]
        exit_code = importlinter_main()
    except SystemExit as e:
        exit_code = e.code if e.code is not None else 0
    finally:
        sys.argv = old_argv
        os.chdir(old_cwd)

    if exit_code != 0:
        print("\n" + "=" * 80)
        print("DEPENDENCY RULE VIOLATION DETECTED")
        print("=" * 80)
        print("\nThe Domain layer is importing from Infrastructure.")
        print("This violates the architectural Dependency Rule.")
        print("\nSee ARCHITECTURE.md for how to fix this:")
        print("  1. Create an adapter implementing the Protocol")
        print("  2. Wire it in Composition Root (app/composition_root.py)")
        print("  3. Inject it into domain via constructor")
        print("\nDomain modules MUST NOT import:")
        print("  - llm_firewall.cache.*")
        print("  - llm_firewall.ui.*")
        print("  - redis, requests, flask, fastapi, etc.")
        print("\nFix the violation and re-run this check.")
        print("=" * 80)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
