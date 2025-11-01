#!/usr/bin/env python3
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.detectors.homoglyph_spoof import latin_spoof_score
from llm_firewall.normalizers.unescape_u import has_json_u_escapes, unescape_json_u

# Test JSON-U
payload1 = r'{"key":"\u005b\u005bSECRET\u005d\u005d"}'
print(f'JSON-U payload: {repr(payload1)}')
print(f'has_json_u_escapes: {has_json_u_escapes(payload1)}')
changed, decoded, meta = unescape_json_u(payload1)
print(f'changed: {changed}, decoded: {repr(decoded[:50])}')
print(f'meta: {meta}')

# Test Homoglyph Cyrillic
payload2 = 'АBСDЕ[[SECRET]]'  # Cyrillic A, C, E
print(f'\nHomoglyph Cyrillic: {repr(payload2)}')
ratio, counts = latin_spoof_score(payload2)
print(f'ratio: {ratio:.2f}, changed: {counts["changed"]}')
print(f'counts: {counts}')

# Test Homoglyph Greek
payload3 = 'ΑΒΓΔΕ[[SECRET]]'
print(f'\nHomoglyph Greek: {repr(payload3)}')
ratio2, counts2 = latin_spoof_score(payload3)
print(f'ratio: {ratio2:.2f}, changed: {counts2["changed"]}')

