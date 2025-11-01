#!/usr/bin/env python3
"""
CI Gate for External Benign FPR (Stratified)

Enforces Wilson upper bounds per class. Breaks build on violation.

Usage:
    python tools/ci_gate_external_fpr.py \
      --json external_benign/indexes/fpr_external_stratified.json \
      --upper-codefence 0.015 \
      --upper-pure 0.020 \
      --min-n 300
"""

import argparse
import json
import sys
from pathlib import Path


def pct(x: float) -> str:
    """Format as percentage"""
    return f"{100.0*x:.2f}%"


def main():
    ap = argparse.ArgumentParser(description="CI gate for external FPR")
    ap.add_argument("--json", required=True, help="FPR JSON file")
    ap.add_argument("--upper-codefence", type=float, default=0.015,
                    help="doc_with_codefence Wilson upper limit (decimal, default 1.5%%)")
    ap.add_argument("--upper-pure", type=float, default=0.020,
                    help="pure_doc Wilson upper limit (decimal, default 2.0%%)")
    ap.add_argument("--min-n", type=int, default=300,
                    help="Minimum N per class")
    ap.add_argument("--soft", action="store_true",
                    help="Warn-only mode (no hard failure)")
    args = ap.parse_args()
    
    # Load JSON
    p = Path(args.json)
    if not p.exists():
        print(f"[CI-GATE] ERROR: JSON not found: {p}", file=sys.stderr)
        return 2
    
    data = json.loads(p.read_text(encoding="utf-8"))
    classes = data.get("classes", {})
    
    ok = True
    msgs = []
    
    def check(cls: str, upper_limit: float):
        """Check class against limit"""
        nonlocal ok
        d = classes.get(cls, {})
        n = int(d.get("n", 0))
        lo, hi = d.get("wilson95", [0.0, 0.0])
        
        if n < args.min_n:
            msgs.append(f"[{cls}] N={n} < min_n={args.min_n} -> INSUFFICIENT DATA (hi={pct(hi)})")
            return False
        
        if hi > upper_limit:
            msgs.append(f"[{cls}] Wilson-Upper {pct(hi)} > limit {pct(upper_limit)} -> FAIL")
            return False
        
        msgs.append(f"[{cls}] PASS: N={n}, FPR={pct(d.get('fpr',0))}, Wilson95=[{pct(lo)},{pct(hi)}] <= {pct(upper_limit)}")
        return True
    
    # Check both classes
    ok &= check("doc_with_codefence", args.upper_codefence)
    ok &= check("pure_doc", args.upper_pure)
    
    # Print results
    print("\n[CI-GATE] External Benign FPR (stratified) summary")
    for m in msgs:
        print(" - " + m)
    
    # Final verdict
    if not ok and not args.soft:
        print("\n[CI-GATE] Gate FAILED.", file=sys.stderr)
        return 1
    if not ok and args.soft:
        print("\n[CI-GATE] Gate SOFT-FAIL (warning only).")
    else:
        print("\n[CI-GATE] Gate PASSED.")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

