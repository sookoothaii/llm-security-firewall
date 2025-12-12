"""
HarmBench Setup Script
======================

Downloads and sets up HarmBench dataset for firewall evaluation.

Usage:
    python scripts/setup_harmbench.py

This will:
1. Create tests/benchmarks/harmbench directory
2. Clone HarmBench repository (if not exists)
3. Download behaviors.json dataset
4. Verify setup
"""

import sys
import subprocess
from pathlib import Path
import json

# Add parent directory to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir))

HARMBENCH_DIR = base_dir / "tests" / "benchmarks" / "harmbench"
HARMBENCH_REPO = "https://github.com/centerforaisafety/HarmBench.git"
BEHAVIORS_URL = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behaviors.json"


def check_git_available() -> bool:
    """Check if git is available."""
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def clone_harmbench():
    """Clone HarmBench repository."""
    if not check_git_available():
        print("[ERROR] git not found. Please install git first.")
        return False

    if (HARMBENCH_DIR / ".git").exists():
        print(f"[OK] HarmBench repository already exists at {HARMBENCH_DIR}")
        return True

    print(f"[1] Cloning HarmBench repository to {HARMBENCH_DIR}...")
    HARMBENCH_DIR.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            ["git", "clone", HARMBENCH_REPO, str(HARMBENCH_DIR)],
            check=True,
            capture_output=True,
        )
        print("[OK] HarmBench repository cloned successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to clone HarmBench: {e}")
        print(
            f"[INFO] You can manually clone: git clone {HARMBENCH_REPO} {HARMBENCH_DIR}"
        )
        return False


def download_behaviors():
    """Check for behaviors.json dataset (may be in repository)."""
    # Try multiple possible locations
    possible_paths = [
        HARMBENCH_DIR / "data" / "behaviors.json",
        HARMBENCH_DIR / "behaviors.json",
        HARMBENCH_DIR / "harmbench" / "data" / "behaviors.json",
    ]

    for behaviors_path in possible_paths:
        if behaviors_path.exists():
            print(f"[OK] behaviors.json found at {behaviors_path}")
            return True

    print("[2] Checking for behaviors.json in repository...")
    print("[INFO] behaviors.json not found in standard locations")
    print("[INFO] HarmBench may require manual dataset download")
    print("[INFO] Check HarmBench documentation for dataset setup")
    return False


def verify_setup():
    """Verify HarmBench setup is complete."""
    print("[3] Verifying setup...")

    checks = []

    # Check repository
    if (HARMBENCH_DIR / ".git").exists():
        checks.append(("Repository", True))
    else:
        checks.append(("Repository", False))

    # Check behaviors.json
    behaviors_path = HARMBENCH_DIR / "data" / "behaviors.json"
    if behaviors_path.exists():
        try:
            with open(behaviors_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                behavior_count = (
                    len(data)
                    if isinstance(data, list)
                    else len(data.get("behaviors", []))
                )
                checks.append(("behaviors.json", True, f"{behavior_count} behaviors"))
        except Exception as e:
            checks.append(("behaviors.json", False, f"Error: {e}"))
    else:
        checks.append(("behaviors.json", False, "File not found"))

    # Print results
    print("\n" + "=" * 60)
    print("VERIFICATION RESULTS")
    print("=" * 60)
    all_ok = True
    for check in checks:
        status = "[OK]" if check[1] else "[FAIL]"
        info = f" - {check[2]}" if len(check) > 2 else ""
        print(f"{status} {check[0]}{info}")
        if not check[1]:
            all_ok = False

    return all_ok


def main():
    """Main setup function."""
    print("=" * 60)
    print("HARMBENCH SETUP")
    print("=" * 60)
    print()

    # Step 1: Clone repository
    if not clone_harmbench():
        print("\n[WARNING] Repository clone failed. Continuing with manual setup...")

    # Step 2: Download behaviors
    if not download_behaviors():
        print("\n[WARNING] behaviors.json download failed. Continuing...")

    # Step 3: Verify
    if verify_setup():
        print("\n[SUCCESS] HarmBench setup complete!")
        print("\nNext steps:")
        print("  1. Run evaluation: python scripts/run_harmbench_eval.py")
        print(
            "  2. Or integrate into test suite: python scripts/run_phase2_suite.py --harmbench"
        )
    else:
        print("\n[WARNING] Setup incomplete. Please check errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
