"""
Benign Corpus Collector
Collects diverse benign samples for FPR validation at scale
"""

import os
import glob
import random
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("--roots", nargs="+", required=True, help="Root directories to search")
ap.add_argument(
    "--exts",
    nargs="+",
    default=[
        ".md",
        ".txt",
        ".rst",
        ".py",
        ".cfg",
        ".ini",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
    ],
    help="File extensions",
)
ap.add_argument("--maxlen", type=int, default=4000, help="Max chars per file")
ap.add_argument("--limit", type=int, default=1500, help="Target sample count")
ap.add_argument("--outdir", default="benign_samples", help="Output directory")
args = ap.parse_args()

print("=" * 80)
print("BENIGN CORPUS COLLECTOR")
print("=" * 80)
print(f"Roots: {args.roots}")
print(f"Extensions: {args.exts}")
print(f"Max length: {args.maxlen}")
print(f"Target: {args.limit} samples")
print(f"Output: {args.outdir}")
print("=" * 80)
print()

# Collect candidates
candidates = []
for root in args.roots:
    for ext in args.exts:
        pattern = os.path.join(root, f"**/*{ext}")
        found = glob.glob(pattern, recursive=True)
        candidates.extend(found)
        print(f"Found {len(found)} {ext} files in {root}")

print(f"\nTotal candidates: {len(candidates)}")

# Shuffle for diversity
random.shuffle(candidates)

# Create output directory
os.makedirs(args.outdir, exist_ok=True)

# Collect samples
picked = 0
skipped_empty = 0
skipped_error = 0

for f in candidates:
    if picked >= args.limit:
        break

    try:
        with open(f, "r", encoding="utf-8", errors="ignore") as h:
            content = h.read()[: args.maxlen]

        # Skip very short/empty files
        if len(content.strip()) < 20:
            skipped_empty += 1
            continue

        # Save sample
        basename = os.path.basename(f).replace("/", "_").replace("\\", "_")
        outpath = os.path.join(args.outdir, f"{picked:04d}_{basename}")

        with open(outpath, "w", encoding="utf-8") as w:
            w.write(content)

        picked += 1

        if picked % 100 == 0:
            print(f"Progress: {picked}/{args.limit} samples collected...")

    except Exception as e:
        skipped_error += 1
        continue

print()
print("=" * 80)
print("COLLECTION COMPLETE")
print("=" * 80)
print(f"Collected: {picked} samples")
print(f"Skipped (empty): {skipped_empty}")
print(f"Skipped (errors): {skipped_error}")
print(f"Output directory: {args.outdir}")
print("=" * 80)
print()
print("Next steps:")
print(f"  python eval_benign_fpr.py --paths {args.outdir}")
