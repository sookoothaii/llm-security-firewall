#!/usr/bin/env python3
import sys
from pathlib import Path
repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.detectors.idna_punycode import detect_idna_punycode

payload = 'https://аррӏе.com/api/token'
result = detect_idna_punycode(payload)
print(f'Punycode found: {result["punycode_found"]}')
print(f'Hosts: {result["hosts"]}')
print(f'Homoglyph in URL: {result["homoglyph_in_url"]}')

# Check chars
for char in 'аррӏе':
    cp = ord(char)
    is_cyrillic = 0x0400 <= cp <= 0x04FF
    print(f'  Char {repr(char)}: U+{cp:04X} Cyrillic={is_cyrillic}')

