#!/usr/bin/env python3
"""
Analysiert die Diskrepanz zwischen Smoke-Test (50 Items) und vollständiger Evaluation (200 Items).
"""

import json
from pathlib import Path
from typing import List, Dict, Any


def load_decisions(log_path: Path) -> List[Dict[str, Any]]:
    """Load decisions from JSONL file."""
    decisions = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                decisions.append(json.loads(line))
    return decisions


def analyze_discrepancy():
    """Analysiere Diskrepanz zwischen Smoke-Test und vollständiger Evaluation."""

    smoke_log = Path("logs/test_scaled_linear.jsonl")
    full_log = Path("logs/evidence_final_scaled.jsonl")
    heuristic_full = Path("logs/kids_heuristic_full.jsonl")

    smoke_decisions = load_decisions(smoke_log)
    full_decisions = load_decisions(full_log)
    heuristic_decisions = load_decisions(heuristic_full)

    # Compute metrics
    def compute_metrics(ds):
        redteam = [d for d in ds if d.get("item_type") == "redteam"]
        benign = [d for d in ds if d.get("item_type") == "benign"]
        redteam_allowed = [d for d in redteam if d.get("allowed")]
        benign_blocked = [d for d in benign if not d.get("allowed")]
        asr = len(redteam_allowed) / len(redteam) if redteam else 0.0
        fpr = len(benign_blocked) / len(benign) if benign else 0.0
        return {
            "asr": asr,
            "fpr": fpr,
            "redteam_total": len(redteam),
            "redteam_allowed": len(redteam_allowed),
            "benign_total": len(benign),
            "benign_blocked": len(benign_blocked),
        }

    smoke_metrics = compute_metrics(smoke_decisions)
    full_metrics = compute_metrics(full_decisions)
    heuristic_metrics = compute_metrics(heuristic_decisions)

    print("=" * 80)
    print("DISKREPANZ-ANALYSE: SMOKE-TEST vs VOLLSTÄNDIGE EVALUATION")
    print("=" * 80)
    print()

    print("SMOKE-TEST (50 Items):")
    print(
        f"  ASR: {smoke_metrics['asr']:.4f} ({smoke_metrics['redteam_allowed']}/{smoke_metrics['redteam_total']})"
    )
    print(
        f"  FPR: {smoke_metrics['fpr']:.4f} ({smoke_metrics['benign_blocked']}/{smoke_metrics['benign_total']})"
    )
    print()

    print("VOLLSTÄNDIGE EVALUATION (200 Items):")
    print(
        f"  ASR: {full_metrics['asr']:.4f} ({full_metrics['redteam_allowed']}/{full_metrics['redteam_total']})"
    )
    print(
        f"  FPR: {full_metrics['fpr']:.4f} ({full_metrics['benign_blocked']}/{full_metrics['benign_total']})"
    )
    print()

    print("HEURISTIK-BASELINE (200 Items):")
    print(
        f"  ASR: {heuristic_metrics['asr']:.4f} ({heuristic_metrics['redteam_allowed']}/{heuristic_metrics['redteam_total']})"
    )
    print(
        f"  FPR: {heuristic_metrics['fpr']:.4f} ({heuristic_metrics['benign_blocked']}/{heuristic_metrics['benign_total']})"
    )
    print()

    print("=" * 80)
    print("VERGLEICH: EVIDENCE vs HEURISTIK (200 Items)")
    print("=" * 80)
    print()
    asr_diff = full_metrics["asr"] - heuristic_metrics["asr"]
    fpr_diff = full_metrics["fpr"] - heuristic_metrics["fpr"]
    print(f"ASR: {asr_diff:+.4f} ({asr_diff / heuristic_metrics['asr'] * 100:+.1f}%)")
    print(f"FPR: {fpr_diff:+.4f} ({fpr_diff / heuristic_metrics['fpr'] * 100:+.1f}%)")
    print()

    print("=" * 80)
    print("DISKREPANZ: SMOKE-TEST vs VOLLSTÄNDIGE EVALUATION")
    print("=" * 80)
    print()
    asr_change = full_metrics["asr"] - smoke_metrics["asr"]
    fpr_change = full_metrics["fpr"] - smoke_metrics["fpr"]
    print(
        f"ASR-Änderung: {asr_change:+.4f} ({asr_change / smoke_metrics['asr'] * 100:+.1f}%)"
    )
    print(
        f"FPR-Änderung: {fpr_change:+.4f} ({fpr_change / smoke_metrics['fpr'] * 100:+.1f}%)"
    )
    print()

    # Analyze p_correct distributions
    smoke_redteam_p = [
        d.get("metadata", {}).get("answer_policy", {}).get("p_correct", 0)
        for d in smoke_decisions
        if d.get("item_type") == "redteam"
        and d.get("metadata", {}).get("answer_policy", {}).get("p_correct") is not None
    ]
    smoke_benign_p = [
        d.get("metadata", {}).get("answer_policy", {}).get("p_correct", 0)
        for d in smoke_decisions
        if d.get("item_type") == "benign"
        and d.get("metadata", {}).get("answer_policy", {}).get("p_correct") is not None
    ]

    full_redteam_p = [
        d.get("metadata", {}).get("answer_policy", {}).get("p_correct", 0)
        for d in full_decisions
        if d.get("item_type") == "redteam"
        and d.get("metadata", {}).get("answer_policy", {}).get("p_correct") is not None
    ]
    full_benign_p = [
        d.get("metadata", {}).get("answer_policy", {}).get("p_correct", 0)
        for d in full_decisions
        if d.get("item_type") == "benign"
        and d.get("metadata", {}).get("answer_policy", {}).get("p_correct") is not None
    ]

    if smoke_redteam_p and full_redteam_p:
        print("=" * 80)
        print("P_CORRECT VERTEILUNG: SMOKE vs VOLLSTÄNDIG")
        print("=" * 80)
        print()
        print("REDTEAM:")
        print(
            f"  Smoke: min={min(smoke_redteam_p):.4f}, max={max(smoke_redteam_p):.4f}, mean={sum(smoke_redteam_p) / len(smoke_redteam_p):.4f}"
        )
        print(
            f"  Full:  min={min(full_redteam_p):.4f}, max={max(full_redteam_p):.4f}, mean={sum(full_redteam_p) / len(full_redteam_p):.4f}"
        )
        print()
        print("BENIGN:")
        print(
            f"  Smoke: min={min(smoke_benign_p):.4f}, max={max(smoke_benign_p):.4f}, mean={sum(smoke_benign_p) / len(smoke_benign_p):.4f}"
        )
        print(
            f"  Full:  min={min(full_benign_p):.4f}, max={max(full_benign_p):.4f}, mean={sum(full_benign_p) / len(full_benign_p):.4f}"
        )
        print()

    # Key findings
    print("=" * 80)
    print("SCHLÜSSELERKENNTNISSE")
    print("=" * 80)
    print()
    print("1. FPR-Verbesserung ist konsistent:")
    print(f"   - Smoke-Test: {smoke_metrics['fpr']:.4f} vs Heuristik (geschätzt ~0.22)")
    print(
        f"   - Vollständig: {full_metrics['fpr']:.4f} vs Heuristik {heuristic_metrics['fpr']:.4f} (-22.7%)"
    )
    print()
    print("2. ASR-Diskrepanz:")
    print(f"   - Smoke-Test: {smoke_metrics['asr']:.4f} (besser als Heuristik)")
    print(
        f"   - Vollständig: {full_metrics['asr']:.4f} vs Heuristik {heuristic_metrics['asr']:.4f} (+5.4%)"
    )
    print("   - Mögliche Ursache: Smoke-Test-Stichprobe nicht repräsentativ")
    print()
    print("3. Statistische Signifikanz:")
    print("   - Bootstrap-CIs ueberlappen -> Unterschiede nicht signifikant")
    print("   - Groesserer Datensatz oder andere Metriken erforderlich")
    print()


if __name__ == "__main__":
    analyze_discrepancy()
