#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Repository Access - Prüft welches Repository verwendet wird
"""

import requests
import json

print("="*80)
print("REPOSITORY ACCESS TEST")
print("="*80)

# 1. Prüfe Code Intent Repository
print("\n1. Code Intent Service (8000) - Repository Status:")
try:
    r = requests.get('http://localhost:8000/api/v1/feedback/stats', timeout=5)
    if r.status_code == 200:
        stats = r.json()
        print(f"   ✅ Total Samples: {stats.get('total_samples', 0)}")
        print(f"   ✅ False Negatives: {stats.get('false_negatives', 0)}")
        print(f"   ✅ False Positives: {stats.get('false_positives', 0)}")
        
        # Prüfe False Negatives direkt
        r2 = requests.get('http://localhost:8000/api/v1/feedback/false-negatives?limit=5', timeout=5)
        if r2.status_code == 200:
            fn_data = r2.json()
            print(f"   ✅ False Negatives Count: {fn_data.get('count', 0)}")
            if fn_data.get('count', 0) > 0:
                sample = fn_data.get('samples', [{}])[0]
                print(f"   ✅ Letztes Sample Timestamp: {sample.get('created_at', 'N/A')}")
    else:
        print(f"   ❌ Fehler: {r.status_code}")
except Exception as e:
    print(f"   ❌ Fehler: {e}")

# 2. Prüfe Orchestrator Learning Metrics
print("\n2. Orchestrator Service (8001) - Learning Metrics:")
try:
    r = requests.get('http://localhost:8001/api/v1/learning/metrics', timeout=5)
    if r.status_code == 200:
        metrics = r.json()
        total_fn = metrics.get('total_false_negatives', 0)
        feedback_24h = metrics.get('feedback_last_24h', {})
        fn_24h = feedback_24h.get('false_negative', 0)
        
        print(f"   Total False Negatives: {total_fn}")
        print(f"   False Negatives (24h): {fn_24h}")
        print(f"   Feedback last 24h: {json.dumps(feedback_24h, indent=2)}")
        
        if total_fn > 0 or fn_24h > 0:
            print(f"   ✅ Orchestrator erkennt False Negatives!")
        else:
            print(f"   ⚠️  Orchestrator erkennt KEINE False Negatives")
    else:
        print(f"   ❌ Fehler: {r.status_code}")
except Exception as e:
    print(f"   ❌ Fehler: {e}")

# 3. Prüfe Orchestrator Monitoring (zeigt Repository-Typ)
print("\n3. Orchestrator Service (8001) - Repository Konfiguration:")
try:
    r = requests.get('http://localhost:8001/api/v1/monitoring/config', timeout=5)
    if r.status_code == 200:
        config = r.json()
        repo_type = config.get('FEEDBACK_REPOSITORY_TYPE', 'unknown')
        print(f"   Repository Type: {repo_type}")
        print(f"   ⚠️  Wenn 'memory': Orchestrator nutzt Memory-Repository (Problem!)")
        print(f"   ✅ Wenn 'postgres' oder 'hybrid': Sollte funktionieren")
    else:
        print(f"   ⚠️  Monitoring Config nicht verfügbar: {r.status_code}")
except Exception as e:
    print(f"   ⚠️  Konfiguration nicht abrufbar: {e}")

print("\n" + "="*80)
print("DIAGNOSE:")
print("="*80)
print("Wenn Orchestrator 'memory' verwendet, aber Code Intent PostgreSQL:")
print("  1. Prüfe Environment Variable: $env:FEEDBACK_REPOSITORY_TYPE='postgres'")
print("  2. Prüfe ob POSTGRES_CONNECTION_STRING gesetzt ist")
print("  3. Restart Orchestrator Service (Port 8001)")
print("="*80)
