#!/usr/bin/env python3
"""
IMMEDIATE Performance Benchmark - REAL METRICS NOW
Keine Ausreden, echte Zahlen!
"""

import importlib.util
import os
import statistics
import time

# Direct module loading
base_path = os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'llm_firewall')

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Load detectors
unicode_mod = load_module('unicode_hardening', os.path.join(base_path, 'detectors', 'unicode_hardening.py'))
encoding_mod = load_module('encoding_chain', os.path.join(base_path, 'normalizers', 'encoding_chain.py'))
entropy_mod = load_module('entropy', os.path.join(base_path, 'detectors', 'entropy.py'))
dense_mod = load_module('dense_alphabet', os.path.join(base_path, 'detectors', 'dense_alphabet.py'))
transport_mod = load_module('transport_indicators', os.path.join(base_path, 'detectors', 'transport_indicators.py'))
identifiers_mod = load_module('identifiers', os.path.join(base_path, 'detectors', 'identifiers.py'))
homoglyph_mod = load_module('homoglyph_spoof', os.path.join(base_path, 'detectors', 'homoglyph_spoof.py'))
exotic_mod = load_module('unicode_exotic', os.path.join(base_path, 'detectors', 'unicode_exotic.py'))
policy_mod = load_module('risk_weights_v2_otb', os.path.join(base_path, 'policy', 'risk_weights_v2_otb.py'))
context_mod = load_module('context', os.path.join(base_path, 'preprocess', 'context.py'))

strip_bidi_zw = unicode_mod.strip_bidi_zw
try_decode_chain = encoding_mod.try_decode_chain
entropy_signal = entropy_mod.entropy_signal
dense_alphabet_flag = dense_mod.dense_alphabet_flag
scan_transport_indicators = transport_mod.scan_transport_indicators
scan_identifiers = identifiers_mod.scan_identifiers
detect_homoglyph_spoof = homoglyph_mod.detect_homoglyph_spoof
detect_exotic_unicode = exotic_mod.detect_exotic_unicode
decide_action_otb = policy_mod.decide_action_otb
classify_context = context_mod.classify_context

def run_full_pipeline(text: str):
    """Full pipeline wie in Tests"""
    hits = []

    text_clean = strip_bidi_zw(text)
    decoded_text, stages, decode_bytes, buffer = try_decode_chain(text_clean)

    if stages > 0:
        hits.append(f'chain_decoded_{stages}_stages')

    hits.extend(entropy_signal(text_clean))
    hits.extend(dense_alphabet_flag(text_clean))
    hits.extend(scan_transport_indicators(text_clean))
    hits.extend(scan_identifiers(text_clean))
    if detect_homoglyph_spoof(text_clean):
        hits.append('homoglyph_spoof')
    exotic_sig, exotic_dict = detect_exotic_unicode(text_clean)
    if exotic_sig:
        hits.append(exotic_sig)

    ctx = classify_context(text_clean)
    action, risk, contrib = decide_action_otb(text_clean, hits, ctx)

    return action, risk, hits

# Test Corpus
test_texts = [
    "Hello, can you help me with my password reset?",
    "def calculate_sum(a, b):\n    return a + b",
    "SELECT * FROM users WHERE active = true;",
    "import numpy as np\nx = np.array([1,2,3])",
    "Die API erfordert Authentifizierung via JWT Token.",
    "javascript:alert('xss')",
    "SGVsbG8gV29ybGQ=",  # Base64
    "\u202e\u200b\u200c hidden text",  # Bidi + ZW
    "../../etc/passwd",
    "const test = 'hello world';",
] * 10  # 100 texts total

print("=== PERFORMANCE BENCHMARK - ECHTE METRIKEN ===\n")

# Warmup
for text in test_texts[:5]:
    run_full_pipeline(text)

# Actual benchmark
times = []
for i, text in enumerate(test_texts):
    start = time.perf_counter()
    action, risk, hits = run_full_pipeline(text)
    end = time.perf_counter()

    latency_ms = (end - start) * 1000
    times.append(latency_ms)

    if i % 20 == 0:
        print(f"Progress: {i}/{len(test_texts)}")

# METRIKEN
times_sorted = sorted(times)
p50 = times_sorted[len(times) // 2]
p95 = times_sorted[int(len(times) * 0.95)]
p99 = times_sorted[int(len(times) * 0.99)]
mean = statistics.mean(times)
max_lat = max(times)

print("\n" + "="*50)
print("ECHTE METRIKEN (100 Texte):")
print("="*50)
print(f"Mean:  {mean:.2f} ms")
print(f"p50:   {p50:.2f} ms")
print(f"p95:   {p95:.2f} ms")
print(f"p99:   {p99:.2f} ms")
print(f"Max:   {max_lat:.2f} ms")
print("\nRC3 Target: p95 <= 12ms")
print(f"Status: {'PASS' if p95 <= 12 else 'FAIL'} (p95 = {p95:.2f}ms)")

