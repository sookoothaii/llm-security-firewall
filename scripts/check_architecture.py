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
import subprocess
from pathlib import Path


def main():
    """Run import-linter check and exit with appropriate code."""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Check if import-linter is installed
    try:
        import importlinter  # noqa: F401
    except ImportError:
        print("ERROR: import-linter not installed.")
        print("Install with: pip install import-linter")
        return 1

    # Run import-linter
    config_file = project_root / ".importlinter"
    if not config_file.exists():
        print(f"ERROR: .importlinter config file not found at {config_file}")
        return 1

    # Use python -m importlinter instead of import-linter CLI
    result = subprocess.run(
        [sys.executable, "-m", "importlinter", "--config", str(config_file)],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    # Print output
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if result.returncode != 0:
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

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
