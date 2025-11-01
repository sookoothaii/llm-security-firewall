#!/usr/bin/env python3
"""
Generate Shields.io Badges for FPR/ASR Quality Metrics

Creates colored badges showing Wilson upper bounds per class.
Used in PR comments for at-a-glance quality assessment.

Usage:
    python tools/make_shields_md.py \
      --compare-json external_benign/indexes/fpr_compare.json \
      --asr-upper 0.0359 \
      --asr-limit 0.0500 \
      --out-md external_benign/indexes/badges.md
"""

import argparse
import json
import urllib.parse
from pathlib import Path


def pct(x: float) -> str:
    """Format as percentage"""
    return f"{100.0*float(x):.2f}%"


def color_for(upper: float, limit: float) -> str:
    """
    Determine badge color based on upper bound vs limit
    
    - Green: upper <= limit (PASS)
    - Yellow: upper <= 1.5 * limit (WATCH)
    - Red: upper > 1.5 * limit (FAIL)
    """
    if upper <= limit:
        return "brightgreen"
    if upper <= 1.5 * limit:
        return "yellow"
    return "red"


def shield(label: str, value: str, color: str) -> str:
    """Generate shields.io badge markdown"""
    lab = urllib.parse.quote(label)
    val = urllib.parse.quote(value)
    col = urllib.parse.quote(color)
    return f"![](https://img.shields.io/badge/{lab}-{val}-{col})"


def read_json(p: str) -> dict:
    """Load JSON file"""
    return json.loads(Path(p).read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser(description="Generate shields badges for FPR/ASR metrics")
    ap.add_argument("--compare-json", required=True,
                    help="Comparison JSON from compare_benign_fpr.py")
    ap.add_argument("--asr-upper", required=True,
                    help="ASR upper bound (decimal, e.g. 0.0359)")
    ap.add_argument("--asr-limit", default="0.0500",
                    help="ASR limit (decimal, default 5%)")
    ap.add_argument("--out-md", required=True,
                    help="Output markdown file")
    args = ap.parse_args()
    
    # Load comparison data
    data = read_json(args.compare_json)
    rows = data["compare"]
    limits = data["limits"]
    
    # Build markdown
    lines = []
    lines.append("### Quality Badges (Upper Bounds, Wilson 95%)")
    lines.append("")
    
    # Per class (External + HAK_GAL)
    for r in rows:
        cls = r["class"]
        lim = float(limits[cls])
        
        # External badge
        e_up = float(r["ext_hi"])
        e_col = color_for(e_up, lim)
        e_badge = shield(f"external {cls} upper", pct(e_up), e_col)
        
        # HAK_GAL badge
        h_up = float(r["hak_hi"])
        h_col = color_for(h_up, lim)
        h_badge = shield(f"hak_gal {cls} upper", pct(h_up), h_col)
        
        lines.append(f"- {cls}: {e_badge} {h_badge} (limit {pct(lim)})")
    
    # ASR badge
    asr_up = float(args.asr_upper)
    asr_lim = float(args.asr_limit)
    asr_col = color_for(asr_up, asr_lim)
    asr_badge = shield("asr upper", pct(asr_up), asr_col)
    
    lines.append("")
    lines.append(f"- overall: {asr_badge} (limit {pct(asr_lim)})")
    
    # Write output
    md_content = "\n".join(lines) + "\n"
    Path(args.out_md).write_text(md_content, encoding="utf-8")
    print(f"Shields badges written: {args.out_md}")
    
    return 0


if __name__ == "__main__":
    import sys
    try:
        sys.exit(main())
    except Exception as e:
        print(f"[make_shields_md] ERROR: {e}", file=sys.stderr)
        sys.exit(2)

