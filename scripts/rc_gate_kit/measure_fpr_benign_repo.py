#!/usr/bin/env python3
"""
FPR Measurement on Benign Corpus (Repo files)
Extracts code/docs/configs from repo, tests firewall FPR
RC2 P4.1: TLSH Whitelist integration
"""

import glob
import json
import re
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

# RC2 P4.1: TLSH Whitelist
try:
    from llm_firewall.whitelist.tlsh_db import TLSHDB

    tlsh_db = TLSHDB(
        str(repo_root / "var" / "whitelist" / "benign_decoded.tlsh"), dist_threshold=85
    )
    tlsh_db.load()
    TLSH_ENABLED = True
except Exception:
    TLSH_ENABLED = False
    tlsh_db = None


def run_detectors_inline(text: str, context: str = "natural") -> list:
    """Inline detector runner - no test imports + RC2 P4 (Tri-Key)"""
    from llm_firewall.detectors.dense_alphabet import dense_alphabet_flag
    from llm_firewall.detectors.entropy import entropy_signal
    from llm_firewall.detectors.exotic_encodings import (
        detect_base64_multiline,
        detect_json_depth,
    )
    from llm_firewall.detectors.homoglyph_spoof import latin_spoof_score

    # RC2 P4.4: Identifiers Detector
    from llm_firewall.detectors.identifiers import scan_identifiers
    from llm_firewall.detectors.idna_punycode import detect_idna_punycode

    # RC2 P4.2: Transport-Indicators Complete
    from llm_firewall.detectors.transport_indicators import scan_transport_indicators
    from llm_firewall.detectors.unicode_exotic import detect_exotic_unicode
    from llm_firewall.detectors.unicode_hardening import strip_bidi_zw
    from llm_firewall.normalizers.ascii85 import detect_and_decode_ascii85
    from llm_firewall.normalizers.decoded_risk import classify_decoded  # RC2 P3.1
    from llm_firewall.normalizers.encoding_chain import try_decode_chain
    from llm_firewall.normalizers.unescape_u import has_json_u_escapes, unescape_json_u

    hits = []

    # RC2 P4: New detectors FIRST
    hits.extend(scan_transport_indicators(text))
    hits.extend(scan_identifiers(text))

    ascii85_info = detect_and_decode_ascii85(text)
    if ascii85_info["detected"]:
        hits.append("ascii85_detected")

    idna_info = detect_idna_punycode(text)
    if idna_info["punycode_found"]:
        hits.append("punycode_detected")
    if idna_info["homoglyph_in_url"]:
        hits.append("url_homoglyph_detected")

    json_depth_info = detect_json_depth(text, max_depth=20)
    if json_depth_info["deep"]:
        hits.append("json_depth_excessive")

    if detect_base64_multiline(text, context=context):
        hits.append("base64_multiline_detected")

    if has_json_u_escapes(text):
        hits.append("json_u_escape_seen")
        changed, decoded_u, _ = unescape_json_u(text)
        if changed:
            hits.append("json_u_escape_decoded")
            text = decoded_u

    ratio, counts = latin_spoof_score(text)
    if counts["changed"] >= 1:
        hits.append("homoglyph_spoof_ge_1")
    if ratio >= 0.20:
        hits.append("homoglyph_spoof_ratio_ge_20")

    cleaned_exotic, exotic_flags = detect_exotic_unicode(text)
    if exotic_flags["tag_seen"]:
        hits.append("unicode_tag_seen")
    if exotic_flags["vs_seen"]:
        hits.append("unicode_vs_seen")
    if exotic_flags["invisible_space_seen"]:
        hits.append("unicode_invisible_space")
    if exotic_flags["combining_seen"]:
        hits.append("unicode_combining_seen")
    if exotic_flags["ligature_seen"]:
        hits.append("unicode_ligature_seen")
    if exotic_flags["math_alpha_seen"]:
        hits.append("unicode_math_alpha_seen")
    if exotic_flags["enclosed_seen"]:
        hits.append("unicode_enclosed_seen")

    # RC2 P3.1: Proof-of-Risk classification
    decoded, stages, _, buf = try_decode_chain(text)
    if stages >= 1:
        hits.append(f"chain_decoded_{stages}_stages")
        hits.append("base64_secret")
        # Classify decoded buffer
        if buf:
            risk_class = classify_decoded(buf)

            # RC2 P4.1: TLSH Whitelist check (before adding risk_class)
            if risk_class == "decoded_unspecified" and TLSH_ENABLED and tlsh_db:
                if tlsh_db.is_benign(buf):
                    # Whitelist match - upgrade to benign
                    risk_class = "decoded_benign_media"

            hits.append(risk_class)

            # RC2 P3.2c: Context hints for benign media (data-URI, sourceMaps, fonts)
            # Upgrade decoded_unspecified to decoded_benign_media if context clearly benign
            if risk_class == "decoded_unspecified":
                text.lower()
                if (
                    b"data:image/" in text.encode("utf-8", errors="ignore")
                    or b"data:font/" in text.encode("utf-8", errors="ignore")
                    or b"sourcemappingurl" in text.encode("utf-8", errors="ignore")
                    or b"base64," in text.encode("utf-8", errors="ignore")
                ):
                    # Context strongly suggests benign asset, upgrade classification
                    hits.remove("decoded_unspecified")
                    hits.append("decoded_benign_media")

    _, flags = strip_bidi_zw(text)
    if flags.get("bidi_seen"):
        hits.append("bidi_controls")
    if flags.get("zw_seen"):
        hits.append("zero_width_chars")
    if flags.get("fullwidth_seen"):
        hits.append("fullwidth_forms")
    if flags.get("mixed_scripts"):
        hits.append("mixed_scripts")

    if entropy_signal(text, threshold=4.0):
        hits.append("high_entropy")
    if dense_alphabet_flag(text):
        hits.append("dense_alphabet")

    return hits


def run_firewall_simple(text: str) -> str:
    """Simplified firewall call for FPR measurement"""
    ctx = classify_context(text)
    hits = run_detectors_inline(text, context=ctx["context"])
    action, _, _ = decide_action_otb(hits, ctx, text=text)

    return action


def collect_benign_corpus(max_chunks: int = 10000) -> list:
    """Extract benign chunks from repo"""
    patterns = ["**/*.py", "**/*.md", "**/*.yaml", "**/*.yml", "**/*.txt", "**/*.json"]
    exclude = ["tests_firewall/", "venv/", "site-packages/", ".venv", "__pycache__"]

    chunks = []

    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            # Skip excluded paths
            if any(excl in path for excl in exclude):
                continue

            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except:
                continue

            # Extract 400-1200 char chunks
            for match in re.finditer(r"(.{400,1200})", text, flags=re.DOTALL):
                chunks.append(match.group(1))
                if len(chunks) >= max_chunks:
                    break

            if len(chunks) >= max_chunks:
                break

        if len(chunks) >= max_chunks:
            break

    return chunks[:max_chunks]


if __name__ == "__main__":
    print("Collecting benign corpus from repo...")
    benign = collect_benign_corpus(max_chunks=1000)

    print(f"Testing {len(benign)} benign chunks...")

    warnings = 0
    blocks = 0
    passes = 0
    block_details = []  # Store details of BLOCK false positives

    for i, chunk in enumerate(benign):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{len(benign)}")

        try:
            # Get full details for BLOCK cases
            ctx = classify_context(chunk)
            hits = run_detectors_inline(chunk, ctx["context"])
            action, risk, contrib = decide_action_otb(hits, ctx, text=chunk)

            if action == "WARN":
                warnings += 1
            elif action == "BLOCK":
                blocks += 1
                # Store details
                block_details.append(
                    {
                        "index": i,
                        "chunk_preview": chunk[:200].replace("\n", "\\n"),
                        "risk_score": risk,
                        "hits": hits,
                        "context": ctx["context"],
                        "top_signals": list(contrib.keys())[:5] if contrib else [],
                    }
                )
            else:
                passes += 1
        except Exception as e:
            print(f"  ERROR on chunk {i}: {e}")
            blocks += 1  # Count errors as FP

    total_fp = warnings + blocks
    fpr = 100 * total_fp / len(benign) if len(benign) > 0 else 0

    print("\n=== FPR RESULTS ===")
    print(f"Total benign: {len(benign)}")
    print(f"PASS: {passes}")
    print(f"WARN: {warnings}")
    print(f"BLOCK: {blocks}")
    print(f"FPR: {fpr:.2f}%")
    print("Target: <=2.0%")
    status = "[OK] PASS" if fpr <= 2.0 else "[X] FAIL"
    print(f"Status: {status}")

    result = {
        "N": len(benign),
        "PASS": passes,
        "WARN": warnings,
        "BLOCK": blocks,
        "FPR": round(fpr, 2),
        "block_details": block_details,
    }

    with open("fpr_benign_repo.json", "w") as f:
        json.dump(result, f, indent=2)

    print("\nSaved to fpr_benign_repo.json")

    # Print BLOCK details
    if block_details:
        print(f"\n=== BLOCK FALSE POSITIVES ({len(block_details)}) ===")
        for bd in block_details:
            print(
                f"\nIndex {bd['index']}: risk={bd['risk_score']:.2f} context={bd['context']}"
            )
            print(f"  Signals: {bd['hits'][:5]}")
            print(f"  Preview: {bd['chunk_preview'][:150]}...")

    sys.exit(0 if fpr <= 2.0 else 1)
