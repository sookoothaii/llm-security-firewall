"""
Wrapper to run blocking threshold tuning and capture output.
"""

import subprocess
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
script_path = project_root / "scripts" / "tune_blocking_threshold.py"

print("Starting blocking threshold tuning...")
print("This will test 9 different threshold values (0.20 - 0.60)")
print()

try:
    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=600,  # 10 minutes max
    )

    # Filter output (remove verbose logs)
    lines = result.stdout.split("\n")
    filtered_lines = []
    skip_patterns = [
        "Semantic risk",
        "Device set",
        "UserWarning",
        "warnings.warn",
        "KeywordLayer",
        "NormalizationLayer",
    ]

    for line in lines:
        if not any(pattern in line for pattern in skip_patterns):
            filtered_lines.append(line)

    output = "\n".join(filtered_lines)
    print(output)

    if result.returncode != 0:
        print("\n[ERROR] Script failed:")
        print(result.stderr)
        sys.exit(1)

except subprocess.TimeoutExpired:
    print("\n[ERROR] Tuning timed out after 10 minutes")
    sys.exit(1)
except Exception as e:
    print(f"\n[ERROR] Failed to run tuning: {e}")
    sys.exit(1)
