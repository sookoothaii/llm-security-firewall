#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Repository direkt - Prüft welches Repository tatsächlich verwendet wird
"""

import os
import sys
from pathlib import Path

# Setze Environment Variables (wie beim Start)
os.environ["FEEDBACK_REPOSITORY_TYPE"] = "postgres"
os.environ["POSTGRES_CONNECTION_STRING"] = "postgresql://hakgal:admin@127.0.0.1:5172/hakgal"
os.environ["ENABLE_ADAPTIVE_LEARNING"] = "true"

# Add paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "detectors"))

print("="*80)
print("DIRECT REPOSITORY TEST")
print("="*80)

print("\n1. Environment Variables:")
print(f"   FEEDBACK_REPOSITORY_TYPE: {os.getenv('FEEDBACK_REPOSITORY_TYPE')}")
print(f"   POSTGRES_CONNECTION_STRING: {'SET' if os.getenv('POSTGRES_CONNECTION_STRING') else 'NOT SET'}")

print("\n2. Teste Composition Root Repository-Erstellung:")
try:
    sys.path.insert(0, str(project_root / "detectors" / "orchestrator"))
    from infrastructure.app.composition_root import OrchestratorCompositionRoot
    
    # Erstelle Composition Root (wie in learning.py)
    settings = {
        "FEEDBACK_REPOSITORY_TYPE": os.getenv("FEEDBACK_REPOSITORY_TYPE", "postgres"),
        "POSTGRES_CONNECTION_STRING": os.getenv("POSTGRES_CONNECTION_STRING"),
        "ENABLE_ADAPTIVE_LEARNING": os.getenv("ENABLE_ADAPTIVE_LEARNING", "true").lower() == "true"
    }
    
    print(f"   Settings: {settings}")
    
    root = OrchestratorCompositionRoot(
        settings=settings,
        enable_adaptive_learning=True
    )
    
    print("   ✅ Composition Root erstellt")
    
    # Erstelle Repository
    repo = root.create_feedback_repository()
    repo_type = type(repo).__name__
    print(f"   ✅ Repository erstellt: {repo_type}")
    
    # Teste Repository Query
    print("\n3. Teste Repository Query:")
    try:
        samples = repo.get_samples(limit=100)
        print(f"   ✅ Repository Query erfolgreich: {len(samples)} Samples abgerufen")
        
        # Prüfe False Negatives
        fn_samples = [s for s in samples if s.get('is_false_negative', False) or s.get('is_false_negative')]
        print(f"   ✅ False Negatives gefunden: {len(fn_samples)}")
        
        if len(fn_samples) > 0:
            print(f"   ✅✅✅ REPOSITORY FUNKTIONIERT! {len(fn_samples)} False Negatives verfügbar!")
            print(f"   Beispiel: {fn_samples[0].get('text', '')[:60]}...")
        else:
            print(f"   ⚠️  Repository funktioniert, aber keine False Negatives in den letzten {len(samples)} Samples")
            if len(samples) > 0:
                print(f"   Erste 3 Samples:")
                for i, s in enumerate(samples[:3], 1):
                    print(f"     {i}. is_false_negative: {s.get('is_false_negative')}, text: {s.get('text', '')[:40]}...")
    except Exception as e:
        print(f"   ❌ Repository Query fehlgeschlagen: {e}")
        import traceback
        traceback.print_exc()
        
except Exception as e:
    print(f"   ❌ Composition Root Erstellung fehlgeschlagen: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)

