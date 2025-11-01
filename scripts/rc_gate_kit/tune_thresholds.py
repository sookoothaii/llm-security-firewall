#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threshold Grid Search
Lightweight grid search for WARN/BLOCK thresholds + dampening factors
"""

import sys
from itertools import product
from pathlib import Path

# Add src to path
repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.policy.risk_weights_v2 import calculate_risk_score
from llm_firewall.preprocess.context import classify_context

# Import detector runner from measure_fpr_attrib
try:
    from measure_fpr_attrib import run_all_detectors
except ImportError:
    # Fallback: define minimal detector runner
    def run_all_detectors(text: str) -> list:
        from llm_firewall.detectors.dense_alphabet import detect_dense_alphabet
        from llm_firewall.detectors.entropy import calculate_entropy
        from llm_firewall.detectors.unicode_hardening import (
            detect_bidi_controls,
            detect_fullwidth,
            detect_mixed_scripts,
            detect_zero_width,
        )
        from llm_firewall.normalizers.encoding_chain import decode_chain

        hits = []
        if detect_bidi_controls(text):
            hits.append("bidi_controls")
        if detect_zero_width(text):
            hits.append("zero_width_chars")
        if detect_fullwidth(text):
            hits.append("fullwidth_forms")
        if detect_mixed_scripts(text):
            hits.append("mixed_scripts")

        decoded, stages, _ = decode_chain(text)
        if stages >= 1:
            hits.append(f"chain_decoded_{stages}_stages")

        entropy = calculate_entropy(text)
        if entropy > 4.0:
            hits.append("high_entropy")

        if detect_dense_alphabet(text):
            hits.append("dense_alphabet")

        return hits


def evaluate_config(
    benign_samples: list,
    attack_samples: list,
    warn_th: float,
    block_th: float,
    dampen_code_med: float,
    dampen_code_weak: float,
) -> dict:
    """
    Evaluate one configuration

    Returns:
        {'fpr': float, 'asr': float}
    """
    # Patch dampening factors temporarily
    from llm_firewall.policy import risk_weights_v2

    original_dampen = risk_weights_v2.CONTEXT_DAMPEN.copy()

    risk_weights_v2.CONTEXT_DAMPEN["code"]["MEDIUM"] = dampen_code_med
    risk_weights_v2.CONTEXT_DAMPEN["code"]["WEAK"] = dampen_code_weak

    # Evaluate benign
    benign_fp = 0
    for text in benign_samples:
        ctx_meta = classify_context(text)
        hits = run_all_detectors(text)
        risk, _ = calculate_risk_score(hits, ctx_meta)

        if risk >= warn_th:
            benign_fp += 1

    fpr = 100 * benign_fp / len(benign_samples) if benign_samples else 0

    # Evaluate attacks
    attack_miss = 0
    for text in attack_samples:
        ctx_meta = classify_context(text)
        hits = run_all_detectors(text)
        risk, _ = calculate_risk_score(hits, ctx_meta)

        if risk < block_th:  # Missed attack
            attack_miss += 1

    asr = 100 * attack_miss / len(attack_samples) if attack_samples else 0

    # Restore original
    risk_weights_v2.CONTEXT_DAMPEN = original_dampen

    return {"fpr": fpr, "asr": asr}


def grid_search(
    benign_corpus: str = "data/benign_corpus.txt",
    attack_corpus: str = "data/redteam_corpus.txt",
    max_fpr: float = 2.0,
    max_asr: float = 5.0,
) -> dict:
    """
    Lightweight grid search

    Returns:
        Best configuration dict
    """
    print("\n=== Threshold Grid Search ===")
    print(f"Benign: {benign_corpus}")
    print(f"Attack: {attack_corpus}")
    print(f"Targets: FPR ≤ {max_fpr}%, ASR ≤ {max_asr}%\n")

    # Load corpora
    if not Path(benign_corpus).exists():
        print(f"ERROR: Benign corpus not found: {benign_corpus}")
        return {}

    with open(benign_corpus, "r", encoding="utf-8") as f:
        benign_samples = [line.strip() for line in f if line.strip()]

    attack_samples = []
    if Path(attack_corpus).exists():
        with open(attack_corpus, "r", encoding="utf-8") as f:
            attack_samples = [line.strip() for line in f if line.strip()]
    else:
        print(f"WARNING: Attack corpus not found: {attack_corpus}")
        print("Running FPR-only optimization\n")

    print(f"Benign: {len(benign_samples)} samples")
    print(f"Attack: {len(attack_samples)} samples\n")

    # Grid parameters (lightweight)
    warn_thresholds = [1.5, 1.8, 2.0, 2.2]
    block_thresholds = [2.5, 2.8, 3.0, 3.2]
    dampen_code_meds = [0.4, 0.5, 0.6]
    dampen_code_weaks = [0.15, 0.2, 0.25]

    grid = list(
        product(warn_thresholds, block_thresholds, dampen_code_meds, dampen_code_weaks)
    )

    print(f"Grid size: {len(grid)} configurations")
    print("Searching...\n")

    best_config = None
    best_score = float("inf")  # Minimize FPR + ASR

    for idx, (warn_th, block_th, damp_med, damp_weak) in enumerate(grid):
        if idx % 10 == 0:
            print(f"  Progress: {idx}/{len(grid)} ({100 * idx / len(grid):.1f}%)")

        # Skip invalid configs
        if warn_th >= block_th:
            continue

        result = evaluate_config(
            benign_samples, attack_samples, warn_th, block_th, damp_med, damp_weak
        )

        fpr = result["fpr"]
        asr = result["asr"]

        # Check constraints
        if fpr <= max_fpr and asr <= max_asr:
            score = fpr + asr  # Simple objective
            if score < best_score:
                best_score = score
                best_config = {
                    "warn_threshold": warn_th,
                    "block_threshold": block_th,
                    "dampen_code_med": damp_med,
                    "dampen_code_weak": damp_weak,
                    "fpr": fpr,
                    "asr": asr,
                    "score": score,
                }

    print(f"  Progress: {len(grid)}/{len(grid)} (100.0%)\n")

    # Print results
    if best_config:
        print("=== BEST CONFIGURATION ===")
        print(f"WARN Threshold: {best_config['warn_threshold']}")
        print(f"BLOCK Threshold: {best_config['block_threshold']}")
        print(f"Code MEDIUM Dampen: {best_config['dampen_code_med']}")
        print(f"Code WEAK Dampen: {best_config['dampen_code_weak']}")
        print("\nResults:")
        print(f"  FPR: {best_config['fpr']:.2f}%")
        print(f"  ASR: {best_config['asr']:.2f}%")
        print(f"  Score: {best_config['score']:.2f}")

        print("\n=== ENV SETTINGS ===")
        print(f"export P2_WARN_TH={best_config['warn_threshold']}")
        print(f"export P2_BLOCK_TH={best_config['block_threshold']}")
        print(
            f"# Manual: Set CTX['code']['MED']={best_config['dampen_code_med']} in risk_weights_v2.py"
        )
        print(
            f"# Manual: Set CTX['code']['WEAK']={best_config['dampen_code_weak']} in risk_weights_v2.py"
        )
    else:
        print("❌ No configuration found meeting constraints")
        print(f"   Try relaxing max_fpr ({max_fpr}%) or max_asr ({max_asr}%)")

    return best_config or {}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Grid search for thresholds")
    parser.add_argument(
        "--benign", default="data/benign_corpus.txt", help="Benign corpus path"
    )
    parser.add_argument(
        "--attack", default="data/redteam_corpus.txt", help="Attack corpus path"
    )
    parser.add_argument("--max-fpr", type=float, default=2.0, help="Max FPR target (%)")
    parser.add_argument("--max-asr", type=float, default=5.0, help="Max ASR target (%)")
    args = parser.parse_args()

    result = grid_search(args.benign, args.attack, args.max_fpr, args.max_asr)

    if result:
        sys.exit(0)
    else:
        sys.exit(1)
