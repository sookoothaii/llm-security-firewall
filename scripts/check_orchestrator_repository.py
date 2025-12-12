"""Prüft welches Repository der Orchestrator nutzt."""
import requests
import json

print("=" * 60)
print("Orchestrator Repository Check")
print("=" * 60)

# Prüfe Learning Metrics
r = requests.get('http://localhost:8001/api/v1/learning/metrics', timeout=5)
if r.status_code == 200:
    data = r.json()
    print("\n✅ Orchestrator Learning Metrics:")
    print(f"   Feedback last 24h: {json.dumps(data.get('feedback_last_24h', {}), indent=2)}")
    print(f"   Total False Negatives: {data.get('total_false_negatives', 0)}")
    print(f"   Total False Positives: {data.get('total_false_positives', 0)}")
    
    if data.get('total_false_negatives', 0) > 0 or data.get('feedback_last_24h', {}).get('false_negative', 0) > 0:
        print("\n   ✅ SUCCESS: Orchestrator erkennt False Negatives!")
    else:
        print("\n   ⚠️  Orchestrator erkennt noch keine False Negatives")
        print("   Mögliche Ursachen:")
        print("   - Orchestrator nutzt Memory-Repository (leer)")
        print("   - Timestamp-Parsing schlägt fehl")
        print("   - Repository-Zugriff funktioniert nicht")
else:
    print(f"\n❌ Fehler: {r.status_code} - {r.text[:200]}")

