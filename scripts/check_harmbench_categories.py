"""Check HarmBench CSV structure and categories."""

import csv
from pathlib import Path

base_dir = Path(__file__).parent.parent
csv_path = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"

if not csv_path.exists():
    print(f"[ERROR] CSV not found: {csv_path}")
    exit(1)

print(f"Reading: {csv_path}")

with open(csv_path, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    
    # Get column names
    print(f"\nColumns: {reader.fieldnames}")
    
    # Count categories (both FunctionalCategory and SemanticCategory)
    functional_categories = {}
    semantic_categories = {}
    for row in reader:
        func_cat = row.get('FunctionalCategory', '')
        sem_cat = row.get('SemanticCategory', '')
        functional_categories[func_cat] = functional_categories.get(func_cat, 0) + 1
        if sem_cat:
            semantic_categories[sem_cat] = semantic_categories.get(sem_cat, 0) + 1
    
    print(f"\nFunctionalCategory counts:")
    for cat, count in sorted(functional_categories.items()):
        print(f"  '{cat}': {count}")
    
    print(f"\nSemanticCategory counts:")
    for cat, count in sorted(semantic_categories.items()):
        print(f"  '{cat}': {count}")
