#!/usr/bin/env python3
"""
Trigger Learning - Löst manuelles Training aus und zeigt Learning Progress
================================================================================

Löst manuelles Training aus wenn genug Samples im Buffer sind,
und zeigt danach die aktualisierten Learning-Metriken.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-09
"""

import requests
import json
import time
from datetime import datetime

FIREWALL_URL = "http://localhost:8001"
FEEDBACK_STATS_URL = f"{FIREWALL_URL}/feedback/stats"
FEEDBACK_TRAIN_URL = f"{FIREWALL_URL}/feedback/train"


def get_feedback_stats():
    """Hole Feedback-Statistiken."""
    try:
        response = requests.get(FEEDBACK_STATS_URL, timeout=5)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def trigger_training(batch_size: int = 32):
    """Löse manuelles Training aus."""
    try:
        response = requests.post(
            f"{FEEDBACK_TRAIN_URL}?batch_size={batch_size}",
            timeout=120
        )
        return response.json()
    except Exception as e:
        return {"error": str(e), "success": False}


def main():
    print("=" * 80)
    print("TRIGGER LEARNING - Manuelles Training auslösen")
    print("=" * 80)
    print(f"Zeitpunkt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Hole aktuelle Stats
    print("[1] Aktuelle Feedback-Statistiken")
    print("-" * 80)
    stats = get_feedback_stats()
    
    if "error" in stats:
        print(f"❌ Fehler: {stats['error']}")
        return 1
    
    if not stats.get("enabled"):
        print("❌ Feedback Collection ist deaktiviert")
        return 1
    
    buffer_size = stats.get("buffer_size", 0)
    max_size = stats.get("max_size", 10000)
    
    print(f"✅ Feedback Collection: AKTIV")
    print(f"   Buffer: {buffer_size}/{max_size} ({buffer_size/max_size*100:.1f}%)")
    
    online_learning = stats.get("online_learning", {})
    if online_learning.get("running"):
        learner_stats = online_learning.get("learner_stats", {})
        updates = learner_stats.get("updates", 0)
        avg_loss = learner_stats.get("average_loss", 0.0)
        print(f"   Online Learning: ✅ AKTIV")
        print(f"   Updates bisher: {updates}")
        print(f"   Average Loss: {avg_loss:.4f}")
    else:
        print(f"   Online Learning: ❌ DEAKTIVIERT")
    
    print()
    
    # Prüfe ob genug Samples vorhanden
    if buffer_size < 10:
        print(f"⚠️  Nicht genug Samples für Training (benötigt: 10, vorhanden: {buffer_size})")
        return 1
    
    # Bestimme Batch Size
    batch_size = min(32, buffer_size)
    print(f"[2] Starte Training mit {batch_size} Samples")
    print("-" * 80)
    
    # Löse Training aus
    result = trigger_training(batch_size=batch_size)
    
    if result.get("success"):
        print("✅ Training erfolgreich!")
        print(f"   Samples verwendet: {result.get('samples_used', 0)}")
        print(f"   Loss: {result.get('loss', 0):.4f}")
        print(f"   Training Dauer: {result.get('training_time', 0):.2f}s")
        
        learner_stats = result.get("learner_stats", {})
        if learner_stats:
            print(f"\n   📊 Learner Statistiken:")
            print(f"      Total Updates: {learner_stats.get('updates', 0)}")
            print(f"      Total Loss: {learner_stats.get('total_loss', 0):.4f}")
            print(f"      Average Loss: {learner_stats.get('average_loss', 0):.4f}")
    else:
        error = result.get("error", "Unknown error")
        print(f"❌ Training fehlgeschlagen: {error}")
        return 1
    
    print()
    
    # Warte kurz und hole aktualisierte Stats
    print("[3] Aktualisierte Statistiken")
    print("-" * 80)
    time.sleep(2)
    updated_stats = get_feedback_stats()
    
    if "error" not in updated_stats:
        updated_learning = updated_stats.get("online_learning", {})
        if updated_learning.get("running"):
            updated_learner = updated_learning.get("learner_stats", {})
            print(f"✅ Online Learning: AKTIV")
            print(f"   Total Updates: {updated_learner.get('updates', 0)}")
            print(f"   Average Loss: {updated_learner.get('average_loss', 0):.4f}")
            print(f"   Total Loss: {updated_learner.get('total_loss', 0):.4f}")
            
            # Quantifizierung
            updates = updated_learner.get('updates', 0)
            avg_loss = updated_learner.get('average_loss', 0.0)
            
            if updates > 0:
                print(f"\n   🎓 Learning Progress:")
                if avg_loss < 0.01:
                    knowledge_level = "Sehr hoch (>95%)"
                elif avg_loss < 0.05:
                    knowledge_level = "Hoch (80-95%)"
                elif avg_loss < 0.10:
                    knowledge_level = "Moderat (60-80%)"
                else:
                    knowledge_level = "Niedrig (<60%)"
                
                print(f"      Wissens-Level: {knowledge_level}")
                print(f"      Basierend auf: {updates} Updates")
                print(f"      Loss-Trend: {'✅ Verbesserung' if avg_loss < 0.1 else '⚠️  Noch hoch'}")
    
    print()
    print("=" * 80)
    print("✅ TRAINING ABGESCHLOSSEN")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

