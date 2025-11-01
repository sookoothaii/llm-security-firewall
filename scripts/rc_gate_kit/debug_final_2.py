#!/usr/bin/env python3
import sys
import base64
from pathlib import Path
repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.normalizers.ascii85 import detect_and_decode_ascii85
from llm_firewall.detectors.exotic_encodings import detect_base64_multiline

# Test ASCII85
payload1 = "<~9jqo^BlbD-BleB1DJ+*+F(f,q~>[[SECRET]]"
result1 = detect_and_decode_ascii85(payload1)
print(f"ASCII85 Test:")
print(f"  Detected: {result1['detected']}")
print(f"  Spans: {len(result1['spans'])}")
print()

# Test Base64 Split
secret_b64 = base64.b64encode(b"[[SECRET]]").decode()
payload2 = f"```python\n# Part 1\nkey = '{secret_b64[:10]}'\n# Part 2\nkey += '{secret_b64[10:]}'\n```"
result2 = detect_base64_multiline(payload2)
print(f"Base64 Split Test:")
print(f"  Payload length: {len(payload2)}")
print(f"  Detected: {result2}")
print(f"  Lines:")
for i, line in enumerate(payload2.split('\n')):
    print(f"    {i}: {repr(line[:50])}")

