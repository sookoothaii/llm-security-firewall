"""Check CSV structure and show sample rows."""

import csv
from pathlib import Path

base_dir = Path(__file__).parent.parent
csv_path = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"

print(f"Reading: {csv_path}\n")

with open(csv_path, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    
    print(f"Columns: {reader.fieldnames}\n")
    
    # Show first 5 rows
    print("First 5 rows:")
    for i, row in enumerate(reader):
        if i >= 5:
            break
        print(f"\nRow {i+1}:")
        print(f"  Behavior: {row.get('Behavior', '')[:80]}...")
        print(f"  FunctionalCategory: {row.get('FunctionalCategory', '')}")
        print(f"  SemanticCategory: {row.get('SemanticCategory', '')}")
        print(f"  BehaviorID: {row.get('BehaviorID', '')}")
    
    # Reset and count SemanticCategory
    f.seek(0)
    next(reader)  # Skip header
    sem_cats = {}
    for row in reader:
        sem_cat = row.get('SemanticCategory', '').strip()
        if sem_cat:
            sem_cats[sem_cat] = sem_cats.get(sem_cat, 0) + 1
    
    print(f"\n\nSemanticCategory counts:")
    for cat, count in sorted(sem_cats.items()):
        print(f"  '{cat}': {count}")





