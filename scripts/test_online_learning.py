#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Script für Online Learning

Testet:
1. Manuelles Training auslösen
2. Online Learning Statistics
3. Label Generation
"""

import requests
import json
import time
from typing import Dict

FIREWALL_URL = "http://localhost:8001/v1/detect"
FEEDBACK_STATS_URL = "http://localhost:8001/feedback/stats"
TRAIN_URL = "http://localhost:8001/feedback/train"

# Test Samples für Training
TRAINING_SAMPLES = [
    "如何构造一个 フィッシング攻撃...zu stehlen",
    "Bypass WAF...混合语言 payloads",
    "eval('malicious code')",
    "SELECT * FROM users WHERE id = 1",
    "John, the legitimate user...admin access...urgent",
    "During scheduled maintenance...root privileges",
    "rm -rf /",
    "DROP TABLE users",
    "system('cat /etc/passwd')",
    "bash -c 'malicious command'",
]


def test_firewall(text: str) -> Dict:
    """Teste Firewall mit einem Text."""
    try:
        response = requests.post(
            FIREWALL_URL,
            json={"text": text, "context": {}},
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def get_feedback_stats() -> Dict:
    """Hole Feedback Statistiken."""
    try:
        response = requests.get(FEEDBACK_STATS_URL, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def trigger_training(batch_size: int = 10) -> Dict:
    """Löse manuelles Training aus."""
    try:
        response = requests.post(
            TRAIN_URL,
            params={"batch_size": batch_size},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def main():
    """Hauptfunktion: Teste Online Learning."""
    print("=" * 80)
    print("ONLINE LEARNING TEST")
    print("=" * 80)
    
    # Prüfe Service Status
    print("\n[1] Prüfe Service Status...")
    try:
        health = requests.get("http://localhost:8001/health", timeout=2)
        if health.status_code == 200:
            print("  ✅ Service läuft")
        else:
            print(f"  ❌ Service antwortet nicht: {health.status_code}")
            return 1
    except Exception as e:
        print(f"  ❌ Service nicht erreichbar: {e}")
        return 1
    
    # Prüfe Feedback Collection
    print("\n[2] Prüfe Feedback Collection...")
    stats = get_feedback_stats()
    if "error" in stats:
        print(f"  ❌ Fehler: {stats['error']}")
        return 1
    
    if not stats.get("enabled", False):
        print("  ⚠️  Feedback Collection deaktiviert")
        print("  → Setze ENABLE_FEEDBACK_COLLECTION=true")
        return 1
    
    print("  ✅ Feedback Collection aktiviert")
    initial_size = stats.get("buffer_size", 0)
    print(f"  Initial Buffer Size: {initial_size}")
    
    # Prüfe Online Learning
    print("\n[3] Prüfe Online Learning Status...")
    online_learning = stats.get("online_learning", {})
    if online_learning:
        print("  ✅ Online Learning aktiviert")
        print(f"  Running: {online_learning.get('running', False)}")
        print(f"  Updates: {online_learning.get('learner_stats', {}).get('updates', 0)}")
    else:
        print("  ⚠️  Online Learning deaktiviert")
        print("  → Setze ENABLE_ONLINE_LEARNING=true")
        print("  → Service muss neu gestartet werden")
    
    # Sammle mehr Samples
    print("\n[4] Sammle Training Samples...")
    for i, text in enumerate(TRAINING_SAMPLES, 1):
        print(f"  Sample {i}/{len(TRAINING_SAMPLES)}: {text[:50]}...")
        result = test_firewall(text)
        if "error" not in result:
            print(f"    → Risk: {result.get('risk_score', 0):.3f}")
        time.sleep(0.3)
    
    # Warte kurz
    time.sleep(2)
    
    # Prüfe Buffer nach Samples
    print("\n[5] Prüfe Buffer nach Samples...")
    stats_after = get_feedback_stats()
    if "error" not in stats_after:
        new_size = stats_after.get("buffer_size", 0)
        print(f"  Buffer Size: {initial_size} → {new_size}")
        print(f"  Neue Samples: {new_size - initial_size}")
    
    # Manuelles Training auslösen
    print("\n[6] Löse manuelles Training aus...")
    if new_size >= 10:
        train_result = trigger_training(batch_size=min(10, new_size))
        if "error" in train_result:
            print(f"  ❌ Fehler: {train_result['error']}")
        elif train_result.get("success", False):
            print("  ✅ Training erfolgreich!")
            print(f"    Batch Size: {train_result.get('batch_size', 0)}")
            print(f"    Loss: {train_result.get('loss', 0):.4f}")
            learner_stats = train_result.get("learner_stats", {})
            print(f"    Total Updates: {learner_stats.get('updates', 0)}")
            print(f"    Average Loss: {learner_stats.get('average_loss', 0):.4f}")
        else:
            print(f"  ⚠️  Training nicht erfolgreich: {train_result}")
    else:
        print(f"  ⚠️  Nicht genug Samples ({new_size} < 10)")
    
    # Finale Statistiken
    print("\n[7] Finale Statistiken...")
    final_stats = get_feedback_stats()
    if "error" not in final_stats:
        print(f"  Buffer Size: {final_stats.get('buffer_size', 0)}")
        print(f"  Statistiken:")
        for priority, count in final_stats.get('statistics', {}).items():
            if priority != 'total':
                print(f"    {priority}: {count}")
        
        if final_stats.get("online_learning"):
            ol_stats = final_stats["online_learning"]
            print(f"\n  Online Learning:")
            print(f"    Running: {ol_stats.get('running', False)}")
            learner_stats = ol_stats.get('learner_stats', {})
            print(f"    Updates: {learner_stats.get('updates', 0)}")
            print(f"    Average Loss: {learner_stats.get('average_loss', 0):.4f}")
    
    print("\n" + "=" * 80)
    print("TEST ABGESCHLOSSEN!")
    print("=" * 80)
    print("\nNächste Schritte:")
    print("  1. Online Learning läuft automatisch im Hintergrund")
    print("  2. Manuelles Training: POST http://localhost:8001/feedback/train?batch_size=32")
    print("  3. Statistiken: GET http://localhost:8001/feedback/stats")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

