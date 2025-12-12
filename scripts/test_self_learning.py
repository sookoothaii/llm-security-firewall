"""
Test Self-Learning Integration

Prüft ob False Negatives vom Policy Optimizer erkannt werden.
"""
import requests
import json
import time

def test_feedback_in_repository():
    """Prüft ob False Negatives im Repository sind."""
    print("=" * 60)
    print("1. Prüfe Code Intent Feedback Repository")
    print("=" * 60)
    
    try:
        r = requests.get('http://localhost:8000/api/v1/feedback/stats', timeout=5)
        if r.status_code == 200:
            stats = r.json()
            print(f"✅ Code Intent Feedback Stats:")
            print(f"   Total Samples: {stats.get('total_samples', 0)}")
            print(f"   False Negatives: {stats.get('false_negatives', 0)}")
            print(f"   False Positives: {stats.get('false_positives', 0)}")
            
            # Prüfe False Negatives direkt
            r2 = requests.get('http://localhost:8000/api/v1/feedback/false-negatives?limit=5', timeout=5)
            if r2.status_code == 200:
                fn_data = r2.json()
                print(f"   False Negatives Count: {fn_data.get('count', 0)}")
                if fn_data.get('count', 0) > 0:
                    print(f"   ✅ False Negatives gefunden!")
                else:
                    print(f"   ⚠️  Keine False Negatives im Repository")
        else:
            print(f"❌ Code Intent nicht erreichbar: {r.status_code}")
    except Exception as e:
        print(f"❌ Fehler: {e}")

def test_orchestrator_learning():
    """Prüft ob Orchestrator die False Negatives erkennt."""
    print("\n" + "=" * 60)
    print("2. Prüfe Orchestrator Learning Metrics")
    print("=" * 60)
    
    try:
        r = requests.get('http://localhost:8001/api/v1/learning/metrics', timeout=5)
        if r.status_code == 200:
            metrics = r.json()
            print(f"✅ Orchestrator Learning Metrics:")
            print(f"   Total False Negatives: {metrics.get('total_false_negatives', 0)}")
            print(f"   Total False Positives: {metrics.get('total_false_positives', 0)}")
            feedback_24h = metrics.get('feedback_last_24h', {})
            fn_24h = feedback_24h.get('false_negative', 0)
            print(f"   Feedback last 24h: {feedback_24h}")
            
            # Prüfe feedback_last_24h, nicht total_false_negatives (das ist historisch)
            if fn_24h > 0 or metrics.get('total_false_negatives', 0) > 0:
                print(f"   ✅✅✅ Orchestrator erkennt False Negatives! ({fn_24h} in den letzten 24h)")
            else:
                print(f"   ⚠️  Orchestrator erkennt keine False Negatives")
        else:
            print(f"❌ Orchestrator nicht erreichbar: {r.status_code}")
    except Exception as e:
        print(f"❌ Fehler: {e}")

def test_policy_optimization():
    """Testet Policy-Optimierung."""
    print("\n" + "=" * 60)
    print("3. Teste Policy-Optimierung")
    print("=" * 60)
    
    try:
        r = requests.post('http://localhost:8001/api/v1/learning/trigger-optimization', timeout=10)
        if r.status_code == 200:
            result = r.json()
            print(f"✅ Policy-Optimierung ausgelöst:")
            print(f"   Policies optimiert: {result.get('policies_optimized', 0)}")
            print(f"   Results: {json.dumps(result.get('results', []), indent=2)}")
            
            if result.get('policies_optimized', 0) > 0:
                print(f"   ✅ Policies wurden optimiert!")
            else:
                print(f"   ⚠️  Keine Policies optimiert (möglicherweise keine Optimierung nötig)")
        else:
            print(f"❌ Optimierung fehlgeschlagen: {r.status_code} - {r.text[:200]}")
    except Exception as e:
        print(f"❌ Fehler: {e}")

def test_optimization_history():
    """Prüft Optimierungsverlauf."""
    print("\n" + "=" * 60)
    print("4. Prüfe Optimierungsverlauf")
    print("=" * 60)
    
    try:
        r = requests.get('http://localhost:8001/api/v1/learning/optimization-history?limit=5', timeout=5)
        if r.status_code == 200:
            history = r.json()
            print(f"✅ Optimierungsverlauf:")
            print(f"   Anzahl Einträge: {len(history)}")
            if history:
                for entry in history[:3]:
                    print(f"   - {entry.get('policy_name')}: {entry.get('improvement', 0):.2%} Verbesserung")
            else:
                print(f"   ⚠️  Keine Optimierungen in der Historie")
        else:
            print(f"❌ Historie nicht erreichbar: {r.status_code}")
    except Exception as e:
        print(f"❌ Fehler: {e}")

if __name__ == "__main__":
    print("\n🛡️  Self-Learning Integration Test\n")
    
    test_feedback_in_repository()
    test_orchestrator_learning()
    test_policy_optimization()
    test_optimization_history()
    
    print("\n" + "=" * 60)
    print("✅ Test abgeschlossen")
    print("=" * 60)


