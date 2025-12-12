#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diagnose Repository Issue - Prüft warum Orchestrator keine False Negatives erkennt
"""

import os
import sys
from pathlib import Path

# Add detectors directory to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "detectors"))

print("="*80)
print("REPOSITORY DIAGNOSE")
print("="*80)

# 1. Prüfe Environment Variables
print("\n1. Environment Variables:")
feeback_repo_type = os.getenv("FEEDBACK_REPOSITORY_TYPE", "NOT SET")
postgres_conn = os.getenv("POSTGRES_CONNECTION_STRING", "NOT SET")
print(f"   FEEDBACK_REPOSITORY_TYPE: {feeback_repo_type}")
print(f"   POSTGRES_CONNECTION_STRING: {'SET' if postgres_conn != 'NOT SET' else 'NOT SET'}")

# 2. Prüfe ob PostgreSQL Repository importierbar ist
print("\n2. PostgreSQL Repository Import Test:")
try:
    sys.path.insert(0, str(project_root / "detectors" / "orchestrator"))
    from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
    print("   ✅ PostgreSQL Repository importierbar")
except Exception as e:
    print(f"   ❌ PostgreSQL Repository Import fehlgeschlagen: {e}")

# 3. Teste Repository-Erstellung
print("\n3. Teste Repository-Erstellung:")
try:
    from infrastructure.app.composition_root import OrchestratorCompositionRoot
    
    # Test mit postgres
    print("   Teste mit FEEDBACK_REPOSITORY_TYPE=postgres...")
    settings = {"FEEDBACK_REPOSITORY_TYPE": "postgres"}
    root = OrchestratorCompositionRoot(settings=settings, enable_adaptive_learning=True)
    repo = root.create_feedback_repository()
    repo_type = type(repo).__name__
    print(f"   ✅ Repository erstellt: {repo_type}")
    
    # Prüfe ob Repository Samples abrufen kann
    print("\n4. Teste Repository Query:")
    try:
        samples = repo.get_samples(limit=10)
        print(f"   ✅ Repository Query erfolgreich: {len(samples)} Samples")
        
        # Prüfe False Negatives
        fn_samples = [s for s in samples if s.get('is_false_negative', False)]
        print(f"   ✅ False Negatives gefunden: {len(fn_samples)}")
        
        if len(fn_samples) > 0:
            print(f"   ✅ Repository funktioniert! False Negatives verfügbar!")
        else:
            print(f"   ⚠️  Repository funktioniert, aber keine False Negatives in den letzten 10 Samples")
    except Exception as e:
        print(f"   ❌ Repository Query fehlgeschlagen: {e}")
        import traceback
        traceback.print_exc()
        
except Exception as e:
    print(f"   ❌ Repository-Erstellung fehlgeschlagen: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("EMPFOHLENE LÖSUNG:")
print("="*80)
print("1. Setze Environment Variable: $env:FEEDBACK_REPOSITORY_TYPE='postgres'")
print("2. Stelle sicher, dass POSTGRES_CONNECTION_STRING gesetzt ist")
print("3. Restart Orchestrator Service (Port 8001)")
print("="*80)

