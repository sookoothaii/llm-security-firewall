#!/usr/bin/env python3
"""
DIAGNOSE_DEPENDENCY_MEMORY.py
===========================================================
Isolates memory footprint of each major dependency to find the ~700MB culprit.
"""

import sys
import os
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List
import tempfile


@dataclass
class DependencyProfile:
    name: str
    import_memory_mb: float
    transitive_deps: List[str]
    is_critical: bool = False


def measure_dependency_memory(dependency_name: str) -> DependencyProfile:
    """
    Measure memory impact of importing a single dependency in clean subprocess.
    """
    test_code = f'''
import sys, psutil, gc, json, os
process = psutil.Process(os.getpid())
gc.collect()
before = process.memory_info().rss

try:
    import {dependency_name}
    import_success = True
    # Capture loaded modules related to this import
    loaded_modules = [m for m in sys.modules if m.startswith(("{dependency_name}", "torch", "tensorflow", "transformers", "numpy", "scipy"))]
except ImportError as e:
    import_success = False
    loaded_modules = []

gc.collect()
after = process.memory_info().rss

result = {{
    "dependency": "{dependency_name}",
    "memory_mb": (after - before) / 1024 / 1024,
    "loaded_modules": loaded_modules,
    "success": import_success
}}
print(json.dumps(result))
'''

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(test_code)
        temp_file = f.name

    try:
        result = subprocess.run(
            [sys.executable, temp_file], capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            return DependencyProfile(
                name=dependency_name,
                import_memory_mb=data["memory_mb"],
                transitive_deps=data["loaded_modules"],
            )
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"Error measuring {dependency_name}: {e}")
    finally:
        os.unlink(temp_file)

    return DependencyProfile(
        name=dependency_name, import_memory_mb=0.0, transitive_deps=[]
    )


def find_dependency_in_codebase(dep_name: str, search_paths: List[str]) -> List[str]:
    """Find files importing a dependency."""
    import_patterns = [f"import {dep_name}", f"from {dep_name} import"]

    files_found = []
    for search_path in search_paths:
        path = Path(search_path)
        if not path.exists():
            continue

        for py_file in path.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                for pattern in import_patterns:
                    if pattern in content:
                        files_found.append(str(py_file.relative_to(Path.cwd())))
                        break
            except:
                continue

    return files_found[:10]  # Limit output


def main():
    print("=" * 70)
    print("DEPENDENCY MEMORY FOOTPRINT ANALYSIS")
    print("=" * 70)
    print("\nMeasuring each major dependency in isolation...\n")

    # Test in order of suspicion
    dependencies_to_test = [
        "torch",
        "tensorflow",
        "transformers",
        "sentence_transformers",
        "numpy",
        "scipy",
        "sklearn",
        "pandas",
        "onnxruntime",
        "tokenizers",
    ]

    profiles = []
    project_root = Path(__file__).parent.parent.parent
    search_paths = [
        str(project_root / "src"),
        str(project_root / "kids_policy"),
        str(project_root / "scripts"),
    ]

    for dep in dependencies_to_test:
        print(f"Measuring {dep}...", end=" ", flush=True)
        profile = measure_dependency_memory(dep)
        profiles.append(profile)

        if profile.import_memory_mb > 50:  # Significant footprint
            print(f"{profile.import_memory_mb:.1f} MB")
            if profile.transitive_deps:
                print(f"  -> Loads modules: {', '.join(profile.transitive_deps[:3])}")

            # Find where it's imported
            import_locations = find_dependency_in_codebase(dep, search_paths)
            if import_locations:
                print(f"  -> Imported in: {import_locations[0]}")
                if len(import_locations) > 1:
                    print(f"    and {len(import_locations) - 1} more files")
            print()
        else:
            print(f"{profile.import_memory_mb:.1f} MB")

    # Generate report
    print("\n" + "=" * 70)
    print("PRIORITIZED DEPENDENCY FOOTPRINT")
    print("=" * 70)

    # Sort by memory impact
    profiles.sort(key=lambda x: x.import_memory_mb, reverse=True)

    total_measured = sum(p.import_memory_mb for p in profiles)
    print(f"\nTotal measured footprint: {total_measured:.1f} MB")
    print("Target reduction: ~400 MB (to reach ~300 MB total)\n")

    print("Rank | Dependency | Memory (MB) | Action Required")
    print("-" * 65)

    action_plan = []

    for i, profile in enumerate(profiles):
        if profile.import_memory_mb == 0:
            continue

        action = "KEEP"
        if profile.import_memory_mb > 200:
            action = "ELIMINATE OR REPLACE"
            action_plan.append(
                f"1. {profile.name}: {profile.import_memory_mb:.1f} MB - Find and remove imports"
            )
        elif profile.import_memory_mb > 100:
            action = "MAKE OPTIONAL"
            action_plan.append(
                f"2. {profile.name}: {profile.import_memory_mb:.1f} MB - Make lazy or optional"
            )
        elif profile.import_memory_mb > 50:
            action = "OPTIMIZE"
            action_plan.append(
                f"3. {profile.name}: {profile.import_memory_mb:.1f} MB - Check if truly needed"
            )

        print(
            f"{i + 1:4} | {profile.name:20} | {profile.import_memory_mb:10.1f} | {action}"
        )

    print("\n" + "=" * 70)
    print("IMMEDIATE ACTION PLAN")
    print("=" * 70)

    if action_plan:
        for action in action_plan[:5]:  # Top 5 actions
            print(f"• {action}")

        print("\nNext steps:")
        print("1. Run: grep -r 'import torch' src/ kids_policy/ --include='*.py'")
        print("2. Check if tensorflow is actually used or legacy dependency")
        print("3. Ensure transformers only imported in ONNX fallback path")
    else:
        print("No major dependencies found - memory must be elsewhere")
        print("\nCheck:")
        print("1. Python interpreter baseline")
        print("2. C extensions in dependencies")
        print("3. Memory fragmentation or measurement artifacts")

    # Save detailed results
    output_file = project_root / "DEPENDENCY_MEMORY_ANALYSIS.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Dependency Memory Analysis\n\n")
        for profile in profiles:
            if profile.import_memory_mb > 0:
                f.write(f"## {profile.name}: {profile.import_memory_mb:.1f} MB\n\n")
                f.write(f"Transitive deps: {', '.join(profile.transitive_deps[:5])}\n")
                locations = find_dependency_in_codebase(profile.name, search_paths)
                if locations:
                    f.write(f"Imported in: {locations[0]}\n")
                f.write("\n")

    print(f"\nDetailed report saved to: {output_file}")


if __name__ == "__main__":
    main()
