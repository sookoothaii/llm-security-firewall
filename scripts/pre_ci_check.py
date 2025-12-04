#!/usr/bin/env python3
"""
Pre-CI Dependency Validation Script

Validates that all packages in requirements-dev.txt are available on PyPI
before pushing to CI/CD. This prevents CI failures due to invalid version requirements.

Usage:
    python scripts/pre_ci_check.py
"""

import sys
import re
import urllib.request
import json
from pathlib import Path
from typing import List, Tuple, Optional


def get_package_versions(package_name: str) -> Optional[List[str]]:
    """Get available versions for a package from PyPI."""
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read())
            return sorted(data["releases"].keys(), reverse=True)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception as e:
        print(f"  [WARN] Error checking {package_name}: {e}")
        return None


def parse_requirement(line: str) -> Optional[Tuple[str, str]]:
    """Parse a requirement line into (package_name, version_spec)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Remove inline comments
    if "#" in line:
        line = line.split("#")[0].strip()

    # Match package name and version spec
    match = re.match(r"^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)(.*)$", line)
    if not match:
        return None

    package_name = match.group(1)
    version_spec = match.group(2).strip()

    # Remove extras (e.g., package[extra] -> package)
    package_name = re.sub(r"\[.*\]", "", package_name)

    return (package_name, version_spec)


def check_version_compatibility(
    package_name: str, version_spec: str, available_versions: List[str]
) -> Tuple[bool, Optional[str]]:
    """Check if version_spec is compatible with available versions."""
    if not version_spec:
        return True, None

    # Extract version requirement (e.g., ">=2.7.0" -> "2.7.0")
    version_match = re.search(r">=([0-9.]+)", version_spec)
    if version_match:
        required_version = version_match.group(1)
        # Check if any available version satisfies >= requirement
        for version in available_versions:
            # Normalize versions for comparison (remove non-numeric suffixes)
            v_clean = re.sub(r"[^0-9.].*$", "", version)
            req_clean = re.sub(r"[^0-9.].*$", "", required_version)
            if compare_versions(v_clean, req_clean) >= 0:
                return True, None
        return False, available_versions[0] if available_versions else None

    # Try == operator
    version_match = re.search(r"==([0-9.]+)", version_spec)
    if version_match:
        required_version = version_match.group(1)
        if required_version in available_versions:
            return True, None
        return False, available_versions[0] if available_versions else None

    # Try ~= operator (compatible release)
    version_match = re.search(r"~=([0-9.]+)", version_spec)
    if version_match:
        required_version = version_match.group(1)
        # ~=X.Y means >=X.Y,<X.(Y+1)
        req_parts = required_version.split(".")
        if len(req_parts) >= 2:
            major, minor = req_parts[0], req_parts[1]
            next_minor = str(int(minor) + 1)
            for version in available_versions:
                v_clean = re.sub(r"[^0-9.].*$", "", version)
                if compare_versions(v_clean, required_version) >= 0:
                    # Check upper bound
                    if not v_clean.startswith(f"{major}.{next_minor}"):
                        return True, None
        return False, available_versions[0] if available_versions else None

    # No specific version requirement, assume compatible
    return True, None


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""

    def version_tuple(v: str):
        # Remove non-numeric suffixes for comparison
        v_clean = re.sub(r"[^0-9.].*$", "", v)
        parts = v_clean.split(".")
        # Normalize to at least 3 parts (major.minor.patch)
        while len(parts) < 3:
            parts.append("0")
        return tuple(map(int, parts[:3]))

    try:
        t1 = version_tuple(v1)
        t2 = version_tuple(v2)
        if t1 > t2:
            return 1
        elif t1 < t2:
            return -1
        return 0
    except (ValueError, IndexError):
        # Fallback: string comparison
        if v1 > v2:
            return 1
        elif v1 < v2:
            return -1
        return 0


def validate_requirements_file(file_path: Path) -> Tuple[bool, List[str]]:
    """Validate all requirements in a file."""
    errors = []
    warnings = []

    print(f"Validating {file_path.name}...")

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines, 1):
        req = parse_requirement(line)
        if not req:
            continue

        package_name, version_spec = req
        print(f"  Checking {package_name}{version_spec}...", end=" ")

        available_versions = get_package_versions(package_name)

        if available_versions is None:
            errors.append(
                f"Line {line_num}: Package '{package_name}' not found on PyPI"
            )
            print("[ERROR] Not found on PyPI")
            continue

        compatible, latest = check_version_compatibility(
            package_name, version_spec, available_versions
        )

        if not compatible:
            errors.append(
                f"Line {line_num}: '{package_name}{version_spec}' - "
                f"No compatible version found. Latest available: {latest}"
            )
            print(f"[ERROR] No compatible version (latest: {latest})")
        else:
            if latest and compare_versions(latest, available_versions[0]) < 0:
                warnings.append(
                    f"Line {line_num}: '{package_name}' - "
                    f"Newer version available: {available_versions[0]}"
                )
            print(f"[OK] Latest: {available_versions[0]}")

    return len(errors) == 0, errors + warnings


def main():
    """Main execution."""
    print("=" * 70)
    print("Pre-CI Dependency Validation")
    print("=" * 70)
    print()

    repo_root = Path(__file__).parent.parent
    requirements_files = [
        repo_root / "requirements.txt",
        repo_root / "requirements-dev.txt",
    ]

    all_valid = True
    all_issues = []

    for req_file in requirements_files:
        if not req_file.exists():
            print(f"[SKIP] {req_file.name} not found")
            continue

        valid, issues = validate_requirements_file(req_file)
        all_valid = all_valid and valid
        all_issues.extend(issues)
        print()

    if all_issues:
        print("=" * 70)
        if any("ERROR" in issue for issue in all_issues):
            print("VALIDATION FAILED")
            print("=" * 70)
            for issue in all_issues:
                if "ERROR" in issue:
                    print(f"ERROR: {issue}")
            sys.exit(1)
        else:
            print("VALIDATION PASSED (with warnings)")
            print("=" * 70)
            for issue in all_issues:
                print(f"WARNING: {issue}")
    else:
        print("=" * 70)
        print("VALIDATION PASSED")
        print("=" * 70)

    sys.exit(0 if all_valid else 1)


if __name__ == "__main__":
    main()
