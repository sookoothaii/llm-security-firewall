"""Benign Corpus FPR Evaluation"""
import argparse
import json
import math
import os
import glob
from datetime import datetime
from src.llm_firewall import SecurityFirewall, FirewallConfig


def wilson(b, n, z=1.96):
    """Wilson score confidence interval"""
    if n == 0:
        return (0, 0)
    p = b / n
    den = 1 + z * z / n
    cen = (p + z * z / (2 * n)) / den
    mar = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return max(0, cen - mar), min(1, cen + mar)


ap = argparse.ArgumentParser()
ap.add_argument("--paths", nargs="+", required=True, help="Paths to benign files/dirs")
ap.add_argument("--exts", nargs="+", default=[".md", ".txt", ".rst", ".py"], help="File extensions")
ap.add_argument("--maxlen", type=int, default=4000, help="Max text length per file")
ap.add_argument("--save", action="store_true", help="Save JSON report")
args = ap.parse_args()

cfg = FirewallConfig()
fw = SecurityFirewall(cfg)


def texts():
    """Generator for text samples from paths"""
    for p in args.paths:
        if os.path.isdir(p):
            for e in args.exts:
                pattern = os.path.join(p, f"**/*{e}")
                for f in glob.glob(pattern, recursive=True):
                    try:
                        content = open(f, "r", encoding="utf-8", errors="ignore").read()[:args.maxlen]
                        yield f, content
                    except Exception as ex:
                        print(f"[SKIP] {f}: {ex}")
        else:
            try:
                content = open(p, "r", encoding="utf-8", errors="ignore").read()[:args.maxlen]
                yield p, content
            except Exception as ex:
                print(f"[SKIP] {p}: {ex}")


print("=" * 80)
print("BENIGN CORPUS FPR EVALUATION")
print("=" * 80)
print(f"Paths: {args.paths}")
print(f"Extensions: {args.exts}")
print(f"Max length: {args.maxlen} chars")
print("=" * 80)
print()

N = 0
B = 0
misses = []

print("Processing files...\n")
for fn, tx in texts():
    N += 1
    safe, reason = fw.validate_input(tx)
    if not safe:
        B += 1
        if len(misses) < 15:
            misses.append({"file": fn, "reason": str(reason)[:200]})
        print(f"[{N:4d}] [FP] {fn[:70]:70s} | {str(reason)[:50]}")
    elif N % 100 == 0:
        print(f"[{N:4d}] Processing... ({B} false positives so far)")

print()
print("=" * 80)
print("RESULTS")
print("=" * 80)

fpr = (100.0 * B / N) if N > 0 else 0.0
L, U = wilson(B, N)

print(f"Total Samples: {N}")
print(f"False Positives (Blocks): {B}")
print(f"FPR: {fpr:.2f}%")
print(f"Wilson 95% CI: [{L*100:.2f}%, {U*100:.2f}%]")
print(f"Upper Bound: {U*100:.2f}%")
print()

gate = "PASS" if (U * 100.0) <= 1.5 else "FAIL"
print(f"GATE STATUS: {gate} (Upper {U*100:.2f}% {'<=' if gate=='PASS' else '>'} 1.50%)")
print("=" * 80)

if misses:
    print("\nTOP FALSE POSITIVES (first 15):")
    for i, m in enumerate(misses, 1):
        print(f"{i:2d}. {m['file'][:60]:60s} | {m['reason'][:80]}")

# Save
if args.save:
    out = {
        "timestamp": datetime.now().isoformat(),
        "total": N,
        "blocks": B,
        "fpr": fpr,
        "wilson_ci_lower": L * 100,
        "wilson_ci_upper": U * 100,
        "gate_status": gate,
        "misses": misses,
        "config": {
            "paths": args.paths,
            "exts": args.exts,
            "maxlen": args.maxlen
        }
    }
    out_file = f"benign_fpr_report_{N}samples_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w", encoding="utf-8", errors="replace") as f:
        json.dump(out, f, indent=2)
    print(f"\nReport saved to: {out_file}")

