"""Prüft ob False Negatives im Repository sind."""
import requests
import json

# Prüfe Code Intent
print("=" * 60)
print("Code Intent Feedback Repository")
print("=" * 60)

r = requests.get('http://localhost:8000/api/v1/feedback/samples?limit=100', timeout=5)
if r.status_code == 200:
    data = r.json()
    samples = data.get('samples', [])
    print(f"Total Samples: {len(samples)}")
    
    # Prüfe False Negatives
    fn_samples = [s for s in samples if s.get('is_false_negative', False)]
    fp_samples = [s for s in samples if s.get('is_false_positive', False)]
    
    print(f"False Negatives: {len(fn_samples)}")
    print(f"False Positives: {len(fp_samples)}")
    
    # Zeige letzte 5 Samples
    print("\nLetzte 5 Samples:")
    for s in samples[-5:]:
        print(f"  - Text: {s.get('text', '')[:60]}...")
        print(f"    is_false_negative: {s.get('is_false_negative', False)}")
        print(f"    is_false_positive: {s.get('is_false_positive', False)}")
        print(f"    feedback_type: {s.get('feedback_type', 'N/A')}")
        print(f"    blocked: {s.get('blocked', False)}")
        print()
else:
    print(f"Error: {r.status_code} - {r.text[:200]}")
