#!/usr/bin/env python3
"""
Stratified FPR Evaluation for External Benign Corpus

Measures FPR per class (pure_doc, doc_with_codefence) against production API.
Uses Wilson 95% CI for statistical confidence.

Usage:
    python tools/eval_external_benign_fpr.py \
      --root external_benign \
      --csv indexes/metadata_enriched.csv \
      --json-out external_benign/indexes/fpr_external_stratified.json
"""

import csv
import argparse
import json
import time
import math
import sys
from pathlib import Path
from collections import defaultdict

# Import production API
try:
    from src.llm_firewall import SecurityFirewall, FirewallConfig
except ImportError:
    # Try alternate path
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from llm_firewall import SecurityFirewall, FirewallConfig


def wilson_ci(k: int, n: int, z: float = 1.96):
    """
    Wilson score confidence interval
    
    Args:
        k: Number of successes (FPs)
        n: Number of trials (total samples)
        z: Z-score for confidence level (1.96 for 95%)
    
    Returns:
        (lower_bound, upper_bound)
    """
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    margin = z * math.sqrt((p*(1-p)/n) + (z*z/(4*n*n))) / denom
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    return (lo, hi)


def fmt_pct(x: float) -> str:
    """Format as percentage"""
    return f"{100.0*x:.2f}%"


def main():
    ap = argparse.ArgumentParser(description="Evaluate external benign FPR (stratified)")
    ap.add_argument("--root", default="external_benign", help="External benign root")
    ap.add_argument("--csv", default="indexes/metadata_enriched.csv", help="Enriched metadata CSV")
    ap.add_argument("--max-n", type=int, default=0, help="Cap samples per class (0=no cap)")
    ap.add_argument("--json-out", default="", help="Output JSON path")
    args = ap.parse_args()
    
    root = Path(args.root)
    meta_csv = root / args.csv
    
    if not meta_csv.exists():
        print(f"ERROR: {meta_csv} not found", file=sys.stderr)
        return 2
    
    print("Initializing SecurityFirewall...")
    fw = SecurityFirewall(FirewallConfig())
    
    # Load metadata
    print(f"Loading metadata from: {meta_csv}")
    rows = []
    with meta_csv.open("r", encoding="utf-8", newline="") as f:
        rdr = csv.DictReader(f)
        for r in rdr:
            # Keep only benign classes
            if r.get("class_label") not in ("pure_doc", "doc_with_codefence"):
                continue
            rows.append(r)
    
    print(f"Loaded {len(rows)} benign samples")
    
    # Evaluation
    per_class = defaultdict(lambda: {"n": 0, "fp": 0})
    details = []
    
    print("\nEvaluating samples...")
    
    for i, r in enumerate(rows):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(rows)}")
        
        cls = r["class_label"]
        if args.max_n and per_class[cls]["n"] >= args.max_n:
            continue
        
        path = root / r["path"]
        if not path.exists():
            continue
        
        text = path.read_text(encoding="utf-8", errors="ignore")
        
        # Validate against production API
        is_safe, reason = fw.validate_input(text)
        
        # False positive: benign text SHOULD pass; if blocked → FP
        is_fp = (not is_safe)
        
        per_class[cls]["n"] += 1
        per_class[cls]["fp"] += int(is_fp)
        
        if is_fp:
            details.append({
                "id": r["id"],
                "class": cls,
                "fp": int(is_fp),
                "reason": str(reason)[:300] if reason else ""
            })
    
    # Summary
    overall_n = sum(v["n"] for v in per_class.values())
    overall_fp = sum(v["fp"] for v in per_class.values())
    o_lo, o_hi = wilson_ci(overall_fp, overall_n)
    
    print("\n" + "="*80)
    print("EXTERNAL BENIGN FPR (STRATIFIED)")
    print("="*80)
    print(f"TOTAL: N={overall_n}  FP={overall_fp}  FPR={fmt_pct(overall_fp/overall_n if overall_n else 0)}  Wilson95=[{fmt_pct(o_lo)}, {fmt_pct(o_hi)}]")
    print("-"*80)
    
    for cls in ("doc_with_codefence", "pure_doc"):
        n = per_class[cls]["n"]
        fp = per_class[cls]["fp"]
        lo, hi = wilson_ci(fp, n)
        fpr = (fp/n) if n else 0.0
        print(f"{cls:20s} N={n:5d}  FP={fp:4d}  FPR={fmt_pct(fpr):>7s}  Wilson95=[{fmt_pct(lo)}, {fmt_pct(hi)}]")
    
    # JSON output
    if args.json_out:
        outp = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "overall": {
                "n": overall_n,
                "fp": overall_fp,
                "fpr": (overall_fp/overall_n if overall_n else 0.0),
                "wilson95": [o_lo, o_hi]
            },
            "classes": {
                cls: {
                    "n": per_class[cls]["n"],
                    "fp": per_class[cls]["fp"],
                    "fpr": (per_class[cls]["fp"]/per_class[cls]["n"] if per_class[cls]["n"] else 0.0),
                    "wilson95": list(wilson_ci(per_class[cls]["fp"], per_class[cls]["n"]))
                } for cls in ("doc_with_codefence", "pure_doc")
            },
            "sample_details": details[:200]  # cap for size
        }
        
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(outp, indent=2), encoding="utf-8")
        print(f"\nJSON written -> {out_path}")
    
    print("="*80)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

