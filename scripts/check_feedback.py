#!/usr/bin/env python3
"""Quick script to check feedback statistics."""
import requests
import json

# Check stats
r = requests.get('http://localhost:8000/api/v1/feedback/stats', timeout=10)
stats = r.json()
print("Feedback Statistics:")
print(json.dumps(stats, indent=2))

# Check false negatives
r = requests.get('http://localhost:8000/api/v1/feedback/false-negatives?limit=10', timeout=10)
fn_data = r.json()
print(f"\nFalse Negatives Count: {fn_data.get('count', 0)}")
samples = fn_data.get('samples', [])[:5]
print(f"Recent False Negatives ({len(samples)}):")
for i, s in enumerate(samples, 1):
    print(f"  {i}. {s.get('text', '')[:70]}...")

