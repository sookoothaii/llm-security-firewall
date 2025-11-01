#!/usr/bin/env python3
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.detectors.homoglyph_spoof import latin_spoof_score
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

# Test remaining 3 bypasses
payloads = [
    ("xn--bcher-kva.example.com/api/secret", "IDNA Punycode"),
    ("https://аррӏе.com/api/token", "Homoglyph Domain"),
    ("<~9jqo^BlbD-BleB1DJ+*+F(f,q~>[[SECRET]]", "ASCII85"),
]

for payload, desc in payloads:
    ctx = classify_context(payload)
    ratio, counts = latin_spoof_score(payload)

    # Build hits inline
    hits = []
    if counts['changed'] >= 1: hits.append('homoglyph_spoof_ge_1')
    if ratio >= 0.20: hits.append('homoglyph_spoof_ratio_ge_20')

    from llm_firewall.detectors.dense_alphabet import dense_alphabet_flag
    from llm_firewall.detectors.entropy import entropy_signal
    from llm_firewall.detectors.unicode_exotic import detect_exotic_unicode

    _, exotic_flags = detect_exotic_unicode(payload)
    if exotic_flags['tag_seen']: hits.append('unicode_tag_seen')
    if entropy_signal(payload, threshold=4.0): hits.append('high_entropy')
    if dense_alphabet_flag(payload): hits.append('dense_alphabet')

    action, risk, contrib = decide_action_otb(hits, ctx, text=payload)

    print(f"{desc:20s}: {action:5s} risk={risk:.2f}")
    print(f"  hits: {hits}")
    print(f"  homoglyph: ratio={ratio:.2f}, changed={counts['changed']}")
    print(f"  context: {ctx['context']}")
    print()

