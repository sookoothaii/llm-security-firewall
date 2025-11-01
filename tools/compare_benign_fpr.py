#!/usr/bin/env python3
"""
Side-by-Side Comparison: External vs HAK_GAL Benign FPR

Compares stratified FPR results and generates:
- JSON comparison report
- Markdown table for PR comments

Usage:
    python tools/compare_benign_fpr.py \
      --external-json external_benign/indexes/fpr_external_stratified.json \
      --hakgal-json   hak_gal_benign/indexes/fpr_hakgal_stratified.json \
      --upper-codefence 0.015 \
      --upper-pure 0.020 \
      --min-n 300 \
      --md-out external_benign/indexes/fpr_compare.md \
      --json-out external_benign/indexes/fpr_compare.json
"""

import argparse
import json
import sys
from pathlib import Path


def pct(x: float) -> str:
    """Format as percentage"""
    return f"{100.0*x:.2f}%"


def load(path: str) -> dict:
    """Load JSON file"""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Missing JSON: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def gate_status(n: int, upper: float, limit: float, min_n: int) -> str:
    """Determine gate status"""
    if n < min_n:
        return "INSUFFICIENT"
    return "PASS" if upper <= limit else "FAIL"


def main():
    ap = argparse.ArgumentParser(description="Compare External vs HAK_GAL benign FPR")
    ap.add_argument("--external-json", required=True, help="External FPR JSON")
    ap.add_argument("--hakgal-json", required=True, help="HAK_GAL FPR JSON")
    ap.add_argument("--upper-codefence", type=float, default=0.015,
                    help="doc_with_codefence upper limit (decimal)")
    ap.add_argument("--upper-pure", type=float, default=0.020,
                    help="pure_doc upper limit (decimal)")
    ap.add_argument("--min-n", type=int, default=300,
                    help="Minimum N per class")
    ap.add_argument("--md-out", required=True, help="Markdown output path")
    ap.add_argument("--json-out", required=True, help="JSON output path")
    args = ap.parse_args()
    
    # Load both JSONs
    ext = load(args.external_json)
    hak = load(args.hakgal_json)
    
    classes = ["doc_with_codefence", "pure_doc"]
    limits = {
        "doc_with_codefence": args.upper_codefence,
        "pure_doc": args.upper_pure
    }
    
    # Build comparison rows
    rows = []
    for cls in classes:
        e = ext["classes"].get(cls, {})
        h = hak["classes"].get(cls, {})
        
        erow = {
            "class": cls,
            "ext_n": int(e.get("n", 0)),
            "ext_fpr": float(e.get("fpr", 0.0)),
            "ext_lo": float(e.get("wilson95", [0.0, 0.0])[0]),
            "ext_hi": float(e.get("wilson95", [0.0, 0.0])[1]),
        }
        
        hrow = {
            "hak_n": int(h.get("n", 0)),
            "hak_fpr": float(h.get("fpr", 0.0)),
            "hak_lo": float(h.get("wilson95", [0.0, 0.0])[0]),
            "hak_hi": float(h.get("wilson95", [0.0, 0.0])[1]),
        }
        
        limit = limits[cls]
        erow["ext_gate"] = gate_status(erow["ext_n"], erow["ext_hi"], limit, args.min_n)
        hrow["hak_gate"] = gate_status(hrow["hak_n"], hrow["hak_hi"], limit, args.min_n)
        
        rows.append({**erow, **hrow, "limit": limit})
    
    # Combined JSON output
    out = {
        "compare": rows,
        "limits": limits,
        "min_n": args.min_n,
        "timestamp": ext.get("timestamp", ""),
    }
    Path(args.json_out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"JSON comparison written: {args.json_out}")
    
    # Markdown report for PR comment
    lines = []
    lines.append("## External vs HAK_GAL – Stratified FPR (Wilson 95%)")
    lines.append("")
    lines.append(f"Gate limits: codefence ≤ {pct(limits['doc_with_codefence'])}, pure_doc ≤ {pct(limits['pure_doc'])}; min_n={args.min_n}")
    lines.append("")
    lines.append("| Class | Ext N | Ext FPR | Ext Upper | Ext Gate | HAK_GAL N | HAK_GAL FPR | HAK_GAL Upper | HAK_GAL Gate | Limit |")
    lines.append("|---|---:|---:|---:|---|---:|---:|---:|---|---:|")
    
    for r in rows:
        lines.append(
            f"| {r['class']} | {r['ext_n']} | {pct(r['ext_fpr'])} | {pct(r['ext_hi'])} | {r['ext_gate']} | "
            f"{r['hak_n']} | {pct(r['hak_fpr'])} | {pct(r['hak_hi'])} | {r['hak_gate']} | {pct(r['limit'])} |"
        )
    
    lines.append("")
    lines.append("_Note:_ 'INSUFFICIENT' means N < min_n and does not count as PASS.")
    lines.append("")
    lines.append("---")
    lines.append(f"Generated: {ext.get('timestamp', 'N/A')}")
    
    md_content = "\n".join(lines)
    Path(args.md_out).write_text(md_content, encoding="utf-8")
    print(f"Markdown report written: {args.md_out}")
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[compare_benign_fpr] ERROR: {e}", file=sys.stderr)
        sys.exit(2)

