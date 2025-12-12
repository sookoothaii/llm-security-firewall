#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test PostgreSQL Repository Query direkt
"""

import os
import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "detectors" / "orchestrator"))

from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository

print("="*80)
print("POSTGRES REPOSITORY DIRECT QUERY TEST")
print("="*80)

# Create repository
print("\n1. Erstelle PostgreSQL Repository...")
try:
    repo = PostgresFeedbackRepository(
        connection_string="postgresql://hakgal:admin@127.0.0.1:5172/hakgal"
    )
    print("   ✅ Repository erstellt")
except Exception as e:
    print(f"   ❌ Fehler: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test get_samples
print("\n2. Teste get_samples() ohne Limit...")
try:
    samples = repo.get_samples(limit=100)
    print(f"   ✅ Query erfolgreich: {len(samples)} Samples")
    
    if len(samples) > 0:
        print(f"   ✅✅✅ {len(samples)} SAMPLES GEFUNDEN!")
        print(f"\n   Erste 3 Samples:")
        for i, s in enumerate(samples[:3], 1):
            print(f"     {i}. ID: {s.get('id', 'N/A')[:20]}...")
            print(f"        Text: {s.get('text', 'N/A')[:50]}...")
            print(f"        is_false_negative: {s.get('is_false_negative')}")
            print(f"        created_at: {s.get('created_at')}")
    else:
        print(f"   ⚠️  Keine Samples gefunden")
except Exception as e:
    print(f"   ❌ Query fehlgeschlagen: {e}")
    import traceback
    traceback.print_exc()

# Test direkt SQL
print("\n3. Teste direkte SQL-Abfrage...")
try:
    from sqlalchemy import text
    session = repo.Session()
    result = session.execute(text("SELECT COUNT(*) as count FROM feedback_samples"))
    count = result.fetchone()[0]
    print(f"   ✅ Total Samples in DB: {count}")
    
    result = session.execute(text("SELECT COUNT(*) as count FROM feedback_samples WHERE is_false_negative = true"))
    fn_count = result.fetchone()[0]
    print(f"   ✅ False Negatives in DB: {fn_count}")
    
    session.close()
except Exception as e:
    print(f"   ❌ SQL Query fehlgeschlagen: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)

