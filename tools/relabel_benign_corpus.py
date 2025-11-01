"""
Re-label benign corpus into pure_benign vs educational_with_exec
Separates true benign (should PASS) from teaching materials (may WARN)
"""
import os
import shutil
import argparse
from llm_firewall.pipeline.context import (
    detect_documentation_context,
    is_exec_context,
    is_exploit_context
)

ap = argparse.ArgumentParser()
ap.add_argument("--indir", default="benign_samples", help="Input directory")
ap.add_argument("--pure-out", default="benign_pure", help="Pure benign output")
ap.add_argument("--edu-out", default="benign_educational", help="Educational output")
args = ap.parse_args()

print("=" * 80)
print("BENIGN CORPUS RE-LABELING")
print("=" * 80)
print(f"Input: {args.indir}")
print(f"Pure benign -> {args.pure_out}")
print(f"Educational -> {args.edu_out}")
print("=" * 80)
print()

# Create output dirs
os.makedirs(args.pure_out, exist_ok=True)
os.makedirs(args.edu_out, exist_ok=True)

# Process files
pure_count = 0
edu_count = 0

files = [f for f in os.listdir(args.indir) if os.path.isfile(os.path.join(args.indir, f))]

for idx, fname in enumerate(files):
    fpath = os.path.join(args.indir, fname)
    
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as h:
            text = h.read()
        
        # Classify
        ctx_meta = detect_documentation_context(text, filename=fname)
        context = ctx_meta["ctx"]
        exec_ctx = is_exec_context(text, context)
        exploit_ctx = is_exploit_context(text, context)
        
        # Route
        if exec_ctx or exploit_ctx:
            # Educational/research content with executable examples
            shutil.copy2(fpath, os.path.join(args.edu_out, fname))
            edu_count += 1
        else:
            # Pure benign
            shutil.copy2(fpath, os.path.join(args.pure_out, fname))
            pure_count += 1
        
        if (idx + 1) % 100 == 0:
            print(f"[{idx+1:4d}] Pure: {pure_count}, Educational: {edu_count}")
    
    except Exception:
        continue

print()
print("=" * 80)
print("RE-LABELING COMPLETE")
print("=" * 80)
print(f"Pure benign: {pure_count} files -> {args.pure_out}/")
print(f"Educational: {edu_count} files -> {args.edu_out}/")
print(f"Total: {pure_count + edu_count}")
print("=" * 80)
print()
print("Next steps:")
print(f"  python eval_benign_fpr.py --paths {args.pure_out}")
print(f"  # Use ONLY pure_benign for FPR gate validation")

