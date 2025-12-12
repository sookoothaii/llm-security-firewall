import json
import sys

if len(sys.argv) < 2:
    print("Usage: python check_comparisons.py <results_file>")
    sys.exit(1)

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)

comparisons = [r for r in data['results'] if r.get('category') == 'Comparisons' and r.get('blocked')]
print(f'Comparisons FPs: {len(comparisons)}')
print('\nSample False Positives:')
for i, r in enumerate(comparisons[:15]):
    print(f"  {i+1}. {r['text'][:100]}")

