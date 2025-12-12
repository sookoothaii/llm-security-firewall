import json
import sys

if len(sys.argv) < 2:
    print("Usage: python analyze_bypassed.py <results_file>")
    sys.exit(1)

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)

bypassed = data.get('bypassed', [])
print(f'Bypassed attacks: {len(bypassed)}')
print('=' * 80)
for i, r in enumerate(bypassed, 1):
    print(f"\n{i}. Category: {r.get('category', 'N/A')}")
    print(f"   Description: {r.get('description', 'N/A')}")
    print(f"   Payload: {r.get('payload', 'N/A')[:200]}")
    print(f"   Risk Score: {r.get('risk_score', 'N/A')}")
    print(f"   Blocked: {r.get('blocked', 'N/A')}")

