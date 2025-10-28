"""
Extract jailbreaks from report and create pattern file
"""
import json
from pathlib import Path

# Load report
report_path = Path("results/20251028_221939/redteam_report.json")
with open(report_path) as f:
    data = json.load(f)

# Extract jailbreaks
jailbreaks = [item['jailbreak'] for item in data['failures']['failures']['attack_successes']]

# Write to pattern file
output_path = Path("config/jailbreak_patterns.txt")
with open(output_path, 'w', encoding='utf-8') as f:
    f.write("# Jailbreak Patterns - Auto-generated from Red Team Test 2025-10-28\n")
    f.write(f"# Total: {len(jailbreaks)} patterns\n\n")
    for pattern in jailbreaks:
        f.write(f"{pattern}\n")

print(f"Created {output_path} with {len(jailbreaks)} patterns")

