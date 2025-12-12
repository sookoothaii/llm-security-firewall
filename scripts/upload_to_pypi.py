#!/usr/bin/env python3
"""
Iterative PyPI Upload Script for llm-security-firewall v2.5.0

Sorgsames, schrittweises Vorgehen:
1. Test-PyPI Upload
2. Warte auf Indexing (60 Sekunden)
3. Installation Test
4. Production PyPI Upload (nach erfolgreichem Test)
"""

import os
import sys
import time
import subprocess
from pathlib import Path

# Colors for output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def print_step(step_num: int, description: str):
    """Print formatted step header."""
    print(f"\n{GREEN}[STEP {step_num}]{RESET} {description}")
    print("-" * 70)


def print_success(message: str):
    """Print success message."""
    print(f"{GREEN}[OK]{RESET} {message}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{YELLOW}[WARN]{RESET} {message}")


def print_error(message: str):
    """Print error message."""
    print(f"{RED}[ERROR]{RESET} {message}")


def check_prerequisites():
    """Check if all prerequisites are met."""
    print_step(0, "Prerequisites Check")

    # Check twine
    try:
        result = subprocess.run(
            ["python", "-m", "twine", "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        print_success(f"Twine installed: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error("Twine not found. Install with: pip install twine")
        return False

    # Check build artifacts
    dist_dir = Path(__file__).parent.parent / "dist"
    wheel_file = dist_dir / "llm_security_firewall-2.5.0-py3-none-any.whl"
    sdist_file = dist_dir / "llm_security_firewall-2.5.0.tar.gz"

    if not wheel_file.exists():
        print_error(f"Wheel not found: {wheel_file}")
        return False
    print_success(
        f"Wheel found: {wheel_file.name} ({wheel_file.stat().st_size / 1024 / 1024:.2f} MB)"
    )

    if not sdist_file.exists():
        print_error(f"Source distribution not found: {sdist_file}")
        return False
    print_success(
        f"Source distribution found: {sdist_file.name} ({sdist_file.stat().st_size / 1024 / 1024:.2f} MB)"
    )

    # Check credentials
    token = os.getenv("TWINE_PASSWORD")
    if not token:
        print_warning("TWINE_PASSWORD not set in environment")
        print("Set with: $env:TWINE_PASSWORD = 'pypi-<your-token>'")
        return False
    print_success(f"Token found (length: {len(token)})")

    return True


def upload_to_test_pypi():
    """Upload to Test-PyPI."""
    print_step(1, "Upload to Test-PyPI")

    dist_dir = Path(__file__).parent.parent / "dist"
    files = [
        dist_dir / "llm_security_firewall-2.5.0-py3-none-any.whl",
        dist_dir / "llm_security_firewall-2.5.0.tar.gz",
    ]

    # Verify files exist
    for f in files:
        if not f.exists():
            print_error(f"File not found: {f}")
            return False

    print(f"Uploading {len(files)} files to Test-PyPI...")

    try:
        result = subprocess.run(
            [
                "python",
                "-m",
                "twine",
                "upload",
                "--repository-url",
                "https://test.pypi.org/legacy/",
                *[str(f) for f in files],
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        print_success("Upload to Test-PyPI completed")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Upload failed: {e.stderr}")
        return False


def wait_for_indexing(seconds: int = 60):
    """Wait for Test-PyPI indexing."""
    print_step(2, f"Waiting for Test-PyPI indexing ({seconds} seconds)")

    for i in range(seconds, 0, -10):
        print(f"  Waiting... {i} seconds remaining", end="\r")
        time.sleep(min(10, i))
    print("  Waiting... 0 seconds remaining")
    print_success("Indexing wait complete")


def test_installation():
    """Test installation from Test-PyPI."""
    print_step(3, "Test Installation from Test-PyPI")

    print("Creating temporary virtual environment...")
    venv_dir = Path(__file__).parent.parent / ".venv_test_pypi"

    # Create venv
    try:
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
            capture_output=True,
        )
        print_success("Virtual environment created")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create venv: {e}")
        return False

    # Determine pip path
    if sys.platform == "win32":
        pip_path = venv_dir / "Scripts" / "pip.exe"
        python_path = venv_dir / "Scripts" / "python.exe"
    else:
        pip_path = venv_dir / "bin" / "pip"
        python_path = venv_dir / "bin" / "python"

    # Install from Test-PyPI
    print("Installing from Test-PyPI...")
    try:
        subprocess.run(
            [
                str(pip_path),
                "install",
                "--index-url",
                "https://test.pypi.org/simple/",
                "llm-security-firewall==2.5.0",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        print_success("Installation successful")
    except subprocess.CalledProcessError as e:
        print_error(f"Installation failed: {e.stderr}")
        print_warning(
            "This might be due to indexing delay. Try again in a few minutes."
        )
        return False

    # Test import
    print("Testing import...")
    try:
        result = subprocess.run(
            [
                str(python_path),
                "-c",
                "from llm_firewall import guard; print('Import successful')",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        print_success("Import test passed")
        print(f"  Output: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print_error(f"Import test failed: {e}")
        return False
    finally:
        # Cleanup
        print("Cleaning up test environment...")
        import shutil

        if venv_dir.exists():
            shutil.rmtree(venv_dir)
            print_success("Test environment cleaned up")


def upload_to_production():
    """Upload to Production PyPI."""
    print_step(4, "Upload to Production PyPI")

    dist_dir = Path(__file__).parent.parent / "dist"
    files = [
        dist_dir / "llm_security_firewall-2.5.0-py3-none-any.whl",
        dist_dir / "llm_security_firewall-2.5.0.tar.gz",
    ]

    print(f"Uploading {len(files)} files to Production PyPI...")
    print_warning("This will make the package publicly available!")

    response = input("Continue with production upload? (yes/no): ")
    if response.lower() != "yes":
        print_warning("Production upload cancelled")
        return False

    try:
        result = subprocess.run(
            ["python", "-m", "twine", "upload", *[str(f) for f in files]],
            check=True,
            capture_output=True,
            text=True,
        )
        print_success("Upload to Production PyPI completed")
        print(result.stdout)
        print(
            f"\n{GREEN}Package available at: https://pypi.org/project/llm-security-firewall/2.5.0/{RESET}"
        )
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Upload failed: {e.stderr}")
        return False


def main():
    """Main execution flow."""
    print(f"{GREEN}{'=' * 70}{RESET}")
    print(f"{GREEN}PyPI Upload Script - llm-security-firewall v2.5.0{RESET}")
    print(f"{GREEN}{'=' * 70}{RESET}")

    # Step 0: Prerequisites
    if not check_prerequisites():
        print_error("Prerequisites check failed. Aborting.")
        sys.exit(1)

    # Step 1: Test-PyPI Upload
    if not upload_to_test_pypi():
        print_error("Test-PyPI upload failed. Aborting.")
        sys.exit(1)

    # Step 2: Wait for indexing
    wait_for_indexing(60)

    # Step 3: Test installation
    if not test_installation():
        print_warning("Installation test failed. Review errors above.")
        print_warning("You may need to wait longer for Test-PyPI indexing.")
        response = input("Continue with production upload anyway? (yes/no): ")
        if response.lower() != "yes":
            print_warning("Aborting. Fix Test-PyPI issues before production upload.")
            sys.exit(1)

    # Step 4: Production Upload
    if not upload_to_production():
        print_error("Production upload failed or cancelled.")
        sys.exit(1)

    print(f"\n{GREEN}{'=' * 70}{RESET}")
    print(f"{GREEN}[SUCCESS] All steps completed successfully!{RESET}")
    print(f"{GREEN}{'=' * 70}{RESET}")


if __name__ == "__main__":
    main()
