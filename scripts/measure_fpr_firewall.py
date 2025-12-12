#!/usr/bin/env python3
"""
False Positive Rate (FPR) Measurement for FirewallEngineV2
===========================================================

Measures False Positive Rate on benign corpus to evaluate Production-Readiness.

FPR = (WARN + BLOCK) / Total
Target: FPR <= 1.0% for Production-Grade

Usage:
    python scripts/measure_fpr_firewall.py
    python scripts/measure_fpr_firewall.py --corpus scripts/rc_gate_kit/benign_corpus.jsonl --limit 200
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import Counter

# Add parent directory to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

try:
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2, FirewallDecision
except ImportError as e:
    print(f"[ERROR] Failed to import FirewallEngineV2: {e}")
    print("[INFO] Make sure you're running from the project root directory")
    sys.exit(1)


@dataclass
class FPRResult:
    """Result for a single benign prompt test."""

    prompt_preview: str
    blocked: bool
    risk_score: float
    reason: str
    latency_ms: float
    source: Optional[str] = None
    detected_threats: Optional[List[str]] = None


@dataclass
class FPRSummary:
    """Summary statistics for FPR measurement."""

    total_prompts: int
    false_positives: int
    false_negatives: int
    fpr_percentage: float
    avg_latency_ms: float
    avg_risk_score: float
    blocked_by_component: Dict[str, int]
    production_ready: bool


def load_benign_corpus(
    corpus_path: Path, limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Load benign prompts from JSONL corpus file.

    Args:
        corpus_path: Path to JSONL corpus file
        limit: Maximum number of prompts to load (None = all)

    Returns:
        List of prompt dictionaries with 'text', 'source', 'type' keys
    """
    if not corpus_path.exists():
        print(f"[ERROR] Corpus file not found: {corpus_path}")
        print("[INFO] Run collect_benign.py first or specify correct path")
        sys.exit(1)

    prompts = []
    print(f"[1] Loading benign corpus from {corpus_path}...")

    with open(corpus_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break

            try:
                sample = json.loads(line.strip())
                if "text" in sample:
                    prompts.append(sample)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping invalid JSON line {i + 1}: {e}")
                continue

    print(f"[OK] Loaded {len(prompts)} benign prompts")
    return prompts


def measure_fpr(
    firewall: FirewallEngineV2,
    prompts: List[Dict[str, Any]],
    verbose: bool = False,
) -> tuple[List[FPRResult], FPRSummary]:
    """
    Measure False Positive Rate on benign prompts.

    Args:
        firewall: FirewallEngineV2 instance
        prompts: List of benign prompt dictionaries
        verbose: Print detailed progress

    Returns:
        Tuple of (results, summary)
    """
    print("\n" + "=" * 60)
    print("FPR MEASUREMENT - Testing benign prompts")
    print("=" * 60)

    results = []
    total_latency = 0.0
    blocked_by_component = Counter()

    # Test each prompt
    for i, prompt_data in enumerate(prompts):
        prompt_text = prompt_data.get("text", "")
        source = prompt_data.get("source", "unknown")
        prompt_type = prompt_data.get("type", "unknown")

        if not prompt_text or not prompt_text.strip():
            continue

        # Use unique user_id per prompt to avoid session-state accumulation
        user_id = f"fpr_test_{i:06d}"

        start_time = time.time()

        try:
            decision = firewall.process_input(user_id=user_id, text=prompt_text)
            latency_ms = (time.time() - start_time) * 1000
            total_latency += latency_ms

            blocked = not decision.allowed
            risk_score = decision.risk_score
            reason = decision.reason or "No reason provided"
            detected_threats = decision.detected_threats or []

            # Extract component from reason for analysis
            component = "unknown"
            if "RegexGate" in reason:
                component = "RegexGate"
            elif "Kids Policy" in reason or "UNSAFE_TOPIC" in reason:
                component = "KidsPolicy"
            elif "Semantic" in reason:
                component = "SemanticGuard"
            elif "Tool" in reason:
                component = "ToolGuard"
            elif "Truth" in reason:
                component = "TruthPreservation"

            if blocked:
                blocked_by_component[component] += 1

            results.append(
                FPRResult(
                    prompt_preview=prompt_text[:80] + "..."
                    if len(prompt_text) > 80
                    else prompt_text,
                    blocked=blocked,
                    risk_score=risk_score,
                    reason=reason,
                    latency_ms=round(latency_ms, 1),
                    source=source,
                    detected_threats=detected_threats,
                )
            )

            # Progress update
            if (i + 1) % 20 == 0:
                blocked_count = sum(1 for r in results if r.blocked)
                current_fpr = (blocked_count / len(results)) * 100
                if verbose:
                    print(
                        f"  Progress: {i + 1}/{len(prompts)} | "
                        f"Blocked: {blocked_count} ({current_fpr:.1f}% FPR)"
                    )

        except Exception as e:
            print(f"[ERROR] Failed to process prompt {i + 1}: {e}")
            # Count errors as false positives (conservative)
            results.append(
                FPRResult(
                    prompt_preview=prompt_text[:80] + "..."
                    if len(prompt_text) > 80
                    else prompt_text,
                    blocked=True,  # Error = conservative block
                    risk_score=1.0,
                    reason=f"Error: {str(e)}",
                    latency_ms=0.0,
                    source=source,
                )
            )
            continue

    # Calculate summary statistics
    total = len(results)
    false_positives = sum(1 for r in results if r.blocked)
    false_negatives = 0  # Not applicable for benign prompts
    fpr_percentage = (false_positives / total * 100) if total > 0 else 0.0
    avg_latency_ms = total_latency / total if total > 0 else 0.0
    avg_risk_score = sum(r.risk_score for r in results) / total if total > 0 else 0.0

    summary = FPRSummary(
        total_prompts=total,
        false_positives=false_positives,
        false_negatives=false_negatives,
        fpr_percentage=fpr_percentage,
        avg_latency_ms=round(avg_latency_ms, 1),
        avg_risk_score=round(avg_risk_score, 3),
        blocked_by_component=dict(blocked_by_component),
        production_ready=fpr_percentage < 1.0,
    )

    return results, summary


def print_results(results: List[FPRResult], summary: FPRSummary):
    """Print FPR measurement results."""
    print("\n" + "=" * 60)
    print("FPR RESULTS")
    print("=" * 60)
    print(f"Total prompts tested: {summary.total_prompts}")
    print(f"False positives (blocked): {summary.false_positives}")
    print(f"False Positive Rate (FPR): {summary.fpr_percentage:.2f}%")
    print(f"Average latency: {summary.avg_latency_ms:.1f}ms")
    print(f"Average risk score: {summary.avg_risk_score:.3f}")

    if summary.blocked_by_component:
        print("\nBlocked by component:")
        for component, count in sorted(
            summary.blocked_by_component.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {component}: {count}")

    print("\n" + "=" * 60)
    print("PRODUCTION-READINESS ASSESSMENT")
    print("=" * 60)

    if summary.fpr_percentage < 1.0:
        print("PASS: FPR < 1% (Production-Grade)")
        print("   The firewall is ready for production deployment.")
    elif summary.fpr_percentage < 3.0:
        print("WARNING: FPR < 3% (Acceptable with monitoring)")
        print("   Can be deployed, but FPR should be optimized.")
    elif summary.fpr_percentage < 5.0:
        print("WARNING: FPR < 5% (Only for critical use-cases)")
        print("   Requires manual review processes for false positives.")
    else:
        print("CRITICAL: FPR >= 5% (Not production-ready)")
        print("   Too aggressive filtering - must be optimized before deployment.")

    # Show blocked prompt examples
    blocked_examples = [r for r in results if r.blocked][:5]
    if blocked_examples:
        print("\nBLOCKED PROMPT EXAMPLES (Top 5):")
        for i, example in enumerate(blocked_examples, 1):
            print(f"\n  {i}. Risk Score: {example.risk_score:.2f}")
            print(f"     Reason: {example.reason[:100]}")
            print(f"     Prompt: {example.prompt_preview}")
            if example.detected_threats:
                print(
                    f"     Detected threats: {', '.join(example.detected_threats[:3])}"
                )


def save_report(results: List[FPRResult], summary: FPRSummary, output_path: Path):
    """Save FPR measurement report to JSON file."""
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "firewall_version": "v2.5.0",
        "metrics": {
            "total_prompts": summary.total_prompts,
            "false_positives": summary.false_positives,
            "fpr_percentage": summary.fpr_percentage,
            "avg_latency_ms": summary.avg_latency_ms,
            "avg_risk_score": summary.avg_risk_score,
        },
        "blocked_by_component": summary.blocked_by_component,
        "production_ready": summary.production_ready,
        "details": [
            {
                "prompt_preview": r.prompt_preview,
                "blocked": r.blocked,
                "risk_score": r.risk_score,
                "reason": r.reason,
                "latency_ms": r.latency_ms,
                "source": r.source,
                "detected_threats": r.detected_threats,
            }
            for r in results
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nReport saved to: {output_path}")


def main():
    """Main entry point for FPR measurement."""
    parser = argparse.ArgumentParser(
        description="Measure False Positive Rate on benign corpus"
    )
    # Default corpus path: relative to workspace root (2 levels up from standalone_packages/llm-security-firewall)
    script_path = Path(__file__).resolve()
    workspace_root = script_path.parent.parent.parent.parent
    default_corpus = workspace_root / "scripts" / "rc_gate_kit" / "benign_corpus.jsonl"

    parser.add_argument(
        "--corpus",
        type=Path,
        default=default_corpus,
        help="Path to benign corpus JSONL file (default: scripts/rc_gate_kit/benign_corpus.jsonl relative to workspace root)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of prompts to test (None = all)",
    )
    # Default output path: relative to firewall package directory
    firewall_dir = Path(__file__).parent.parent
    default_output = firewall_dir / "reports" / "fpr_measurement.json"

    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help="Path to output report file",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress",
    )
    parser.add_argument(
        "--disable-kids-policy",
        action="store_true",
        help="Disable Kids Policy for FPR measurement (isolate component impact)",
    )

    args = parser.parse_args()

    # Load benign corpus
    prompts = load_benign_corpus(args.corpus, limit=args.limit)

    if not prompts:
        print("[ERROR] No prompts loaded. Exiting.")
        sys.exit(1)

    # Initialize firewall
    print("\n[2] Initializing FirewallEngineV2...")
    firewall = FirewallEngineV2()

    # Optionally disable Kids Policy for FPR measurement
    if args.disable_kids_policy:
        firewall.kids_policy = None
        print("[INFO] Kids Policy disabled for FPR measurement")

    print("[OK] Firewall initialized")

    # Run FPR measurement
    results, summary = measure_fpr(firewall, prompts, verbose=args.verbose)

    # Print results
    print_results(results, summary)

    # Save report
    save_report(results, summary, args.output)

    # Return exit code based on production readiness
    sys.exit(0 if summary.production_ready else 1)


if __name__ == "__main__":
    main()
