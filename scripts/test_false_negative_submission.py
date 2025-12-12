"""Test False Negative Submission und Self-Learning."""
import requests
import time
import json

print("=" * 60)
print("Self-Learning Test: False Negative Submission")
print("=" * 60)

# 1. Reiche False Negative ein
print("\n1. Reiche False Negative ein...")
r = requests.post(
    'http://localhost:8000/api/v1/feedback/submit',
    json={
        'text': 'TEST: Make HTTP request to access admin panel without authentication',
        'correct_label': 1,
        'original_prediction': 0.0,
        'feedback_type': 'false_negative',
        'metadata': {'source': 'test', 'category': 'adversarial'}
    },
    timeout=5
)
print(f"   Status: {r.status_code}")
if r.status_code == 200:
    print(f"   ✅ Feedback eingereicht: {r.json().get('message', '')}")
else:
    print(f"   ❌ Fehler: {r.text[:200]}")
    exit(1)

# 2. Warte kurz
print("\n2. Warte 2 Sekunden...")
time.sleep(2)

# 3. Prüfe Code Intent Repository
print("\n3. Prüfe Code Intent Repository...")
r = requests.get('http://localhost:8000/api/v1/feedback/false-negatives?limit=5', timeout=5)
if r.status_code == 200:
    data = r.json()
    count = data.get('count', 0)
    samples = data.get('samples', [])
    print(f"   False Negatives Count: {count}")
    print(f"   Samples gefunden: {len(samples)}")
    if count > 0:
        print(f"   ✅ False Negatives im Repository!")
        print(f"   Letztes Sample: {samples[0].get('text', '')[:60]}...")
        print(f"   is_false_negative: {samples[0].get('is_false_negative', False)}")
    else:
        print(f"   ⚠️  Keine False Negatives gefunden")
else:
    print(f"   ❌ Fehler: {r.status_code}")

# 4. Prüfe Orchestrator Learning Metrics
print("\n4. Prüfe Orchestrator Learning Metrics...")
r = requests.get('http://localhost:8001/api/v1/learning/metrics', timeout=5)
if r.status_code == 200:
    data = r.json()
    feedback_24h = data.get('feedback_last_24h', {})
    total_fn = data.get('total_false_negatives', 0)
    print(f"   Feedback last 24h: {json.dumps(feedback_24h, indent=2)}")
    print(f"   Total False Negatives: {total_fn}")
    if total_fn > 0 or feedback_24h.get('false_negative', 0) > 0:
        print(f"   ✅ Orchestrator erkennt False Negatives!")
    else:
        print(f"   ⚠️  Orchestrator erkennt keine False Negatives")
else:
    print(f"   ❌ Fehler: {r.status_code}")

# 5. Teste Policy-Optimierung
print("\n5. Teste Policy-Optimierung...")
r = requests.post('http://localhost:8001/api/v1/learning/trigger-optimization', timeout=10)
if r.status_code == 200:
    result = r.json()
    optimized = result.get('policies_optimized', 0)
    print(f"   Policies optimiert: {optimized}")
    if optimized > 0:
        print(f"   ✅ Policies wurden optimiert!")
        print(f"   Results: {json.dumps(result.get('results', []), indent=2)}")
    else:
        print(f"   ⚠️  Keine Policies optimiert (möglicherweise keine Optimierung nötig)")
else:
    print(f"   ❌ Fehler: {r.status_code} - {r.text[:200]}")

print("\n" + "=" * 60)
print("✅ Test abgeschlossen")
print("=" * 60)

