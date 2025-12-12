"""
Analyze Copyright Prompts
==========================

Direkte Analyse der Copyright-Prompts aus HarmBench CSV.
"""

import csv
import sys
from pathlib import Path

base_dir = Path(__file__).parent.parent
csv_path = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"

if not csv_path.exists():
    print(f"[ERROR] CSV not found: {csv_path}")
    sys.exit(1)

print("\n" + "="*80)
print("COPYRIGHT PROMPTS ANALYSIS")
print("="*80)

prompts = []
with open(csv_path, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get('FunctionalCategory') == 'copyright':
            prompts.append(row.get('Behavior', ''))

print(f"[INFO] Found {len(prompts)} copyright prompts\n")

# Analyze patterns
print("="*80)
print("PATTERN ANALYSIS")
print("="*80)

# Check for common patterns
patterns_to_check = [
    'generate', 'reproduce', 'copy', 'duplicate', 'download', 
    'passage', 'excerpt', 'quote', 'lyrics', 'text from'
]

for pattern in patterns_to_check:
    matches = [p for p in prompts if pattern.lower() in p.lower()]
    print(f"'{pattern}': {len(matches)} prompts")

# Find prompts that might not match
print("\n" + "="*80)
print("POTENTIAL BYPASSES (Prompts without common patterns):")
print("="*80)

common_patterns = ['generate', 'reproduce', 'copy', 'duplicate', 'download', 'lyrics', 'passage', 'excerpt']
potential_bypasses = []

for prompt in prompts:
    prompt_lower = prompt.lower()
    has_pattern = any(pattern in prompt_lower for pattern in common_patterns)
    if not has_pattern:
        potential_bypasses.append(prompt)

print(f"\nFound {len(potential_bypasses)} prompts without common patterns:\n")

for i, prompt in enumerate(potential_bypasses[:20], 1):
    print(f"{i}. {prompt}")
    # Suggest pattern
    if 'text' in prompt.lower() and 'from' in prompt.lower():
        print(f"   💡 Potential pattern: 'text from' or 'text of'")
    elif 'quote' in prompt.lower():
        print(f"   💡 Potential pattern: 'quote' or 'quote from'")
    elif 'extract' in prompt.lower():
        print(f"   💡 Potential pattern: 'extract' or 'extract from'")
    print()

if len(potential_bypasses) > 20:
    print(f"... and {len(potential_bypasses) - 20} more")

# Save to file
output_file = base_dir / "copyright_prompts_analysis.txt"
with open(output_file, 'w', encoding='utf-8') as f:
    f.write("COPYRIGHT PROMPTS ANALYSIS\n")
    f.write("="*80 + "\n\n")
    f.write(f"Total prompts: {len(prompts)}\n")
    f.write(f"Potential bypasses (no common patterns): {len(potential_bypasses)}\n\n")
    f.write("POTENTIAL BYPASSES:\n")
    f.write("-"*80 + "\n")
    for prompt in potential_bypasses:
        f.write(f"{prompt}\n")
        f.write("-"*80 + "\n")

print(f"\n[INFO] Analysis saved to: {output_file}")
