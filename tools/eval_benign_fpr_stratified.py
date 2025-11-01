"""
Stratified Benign FPR Evaluation
Measures FPR across different content classes for precise targeting
"""
import argparse
import json
import os
import glob
from datetime import datetime
from collections import defaultdict

from llm_firewall import SecurityFirewall, FirewallConfig
from llm_firewall.pipeline.context import (
    detect_documentation_context,
    is_exec_context,
    is_network_context,
    is_exploit_context
)

def wilson(b, n, z=1.96):
    """Wilson score interval"""
    if n == 0:
        return 0.0, 0.0
    p = b / n
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    margin = z * ((p*(1-p)/n + z*z/(4*n*n))**0.5) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


ap = argparse.ArgumentParser()
ap.add_argument("--paths", nargs="+", required=True)
ap.add_argument("--exts", nargs="+", default=[".md", ".txt", ".rst"])
ap.add_argument("--maxlen", type=int, default=4000)
ap.add_argument("--save", action="store_true")
args = ap.parse_args()

print("=" * 80)
print("STRATIFIED BENIGN FPR EVALUATION")
print("=" * 80)
print(f"Paths: {args.paths}")
print(f"Extensions: {args.exts}")
print(f"Max length: {args.maxlen}")
print("=" * 80)
print()

# Collect files
files = []
for p in args.paths:
    for e in args.exts:
        files.extend(glob.glob(os.path.join(p, f"**/*{e}"), recursive=True))

print(f"Found {len(files)} files")
print()

# Initialize firewall
fw = SecurityFirewall(FirewallConfig())

# Stratified counters
strata = defaultdict(lambda: {"total": 0, "fps": []})

print("Processing files...")
for idx, fpath in enumerate(files):
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as h:
            text = h.read()[:args.maxlen]
        
        if len(text.strip()) < 20:
            continue
        
        # Classify
        ctx_meta = detect_documentation_context(text, filename=fpath)
        context = ctx_meta["ctx"]
        exec_ctx = is_exec_context(text, context)
        net_ctx = is_network_context(text)
        exploit_ctx = is_exploit_context(text, context)
        
        # Detect code fences
        has_codefence = "```" in text
        
        # Determine stratum
        if context == "documentation":
            if exec_ctx or exploit_ctx:
                stratum = "doc_with_exec"
            elif has_codefence:
                stratum = "doc_with_codefence"
            else:
                stratum = "pure_doc"
        elif context == "generic":
            if ".py" in fpath or ".cfg" in fpath or ".ini" in fpath or ".toml" in fpath or ".yaml" in fpath:
                stratum = "code_cfg"
            else:
                stratum = "generic_text"
        else:
            stratum = "unknown"
        
        # Validate
        safe, reason = fw.validate_input(text)
        
        strata[stratum]["total"] += 1
        
        if not safe:
            strata[stratum]["fps"].append({
                "file": fpath,
                "reason": reason,
                "exec_ctx": exec_ctx,
                "net_ctx": net_ctx,
                "exploit_ctx": exploit_ctx,
                "has_codefence": has_codefence
            })
        
        if (idx + 1) % 100 == 0:
            total_fps = sum(len(s["fps"]) for s in strata.values())
            print(f"[{idx + 1:4d}] Processing... ({total_fps} false positives so far)")
    
    except Exception:
        continue

print()
print("=" * 80)
print("STRATIFIED RESULTS")
print("=" * 80)
print()

overall_total = sum(s["total"] for s in strata.values())
overall_fps = sum(len(s["fps"]) for s in strata.values())
overall_fpr = 100.0 * overall_fps / overall_total if overall_total > 0 else 0.0
ol, ou = wilson(overall_fps, overall_total)

print(f"OVERALL:")
print(f"  Total: {overall_total}")
print(f"  FPs: {overall_fps}")
print(f"  FPR: {overall_fpr:.2f}%")
print(f"  Wilson 95% CI: [{ol*100:.2f}%, {ou*100:.2f}%]")
print(f"  Upper: {ou*100:.2f}%")
print()

for stratum in sorted(strata.keys()):
    s = strata[stratum]
    total = s["total"]
    fps = len(s["fps"])
    fpr = 100.0 * fps / total if total > 0 else 0.0
    lower, upper = wilson(fps, total)
    
    gate = ""
    if stratum == "pure_doc":
        gate = "PASS" if upper*100 <= 1.50 else "FAIL"
    elif stratum == "code_cfg":
        gate = "PASS" if upper*100 <= 1.00 else "FAIL"
    else:
        gate = "Advisory"
    
    print(f"{stratum:20s} | N={total:4d} | FPs={fps:3d} | FPR={fpr:5.2f}% | Upper={upper*100:5.2f}% | {gate}")

print()
print("=" * 80)
print("GATE STATUS")
print("=" * 80)

pure_doc = strata.get("pure_doc", {"total": 0, "fps": []})
if pure_doc["total"] > 0:
    pd_fps = len(pure_doc["fps"])
    pd_total = pure_doc["total"]
    pd_lower, pd_upper = wilson(pd_fps, pd_total)
    pd_fpr = 100.0 * pd_fps / pd_total
    
    print(f"PRIMARY GATE (pure_doc FPR):")
    print(f"  N: {pd_total}")
    print(f"  FPR: {pd_fpr:.2f}%")
    print(f"  Wilson Upper: {pd_upper*100:.2f}%")
    print(f"  Target: <=1.50%")
    print(f"  Status: {'PASS' if pd_upper*100 <= 1.50 else 'FAIL'}")
else:
    print("PRIMARY GATE: No pure_doc samples")

print()

# Save results
if args.save:
    outfile = f"benign_fpr_stratified_{overall_total}samples_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "overall": {
            "total": overall_total,
            "fps": overall_fps,
            "fpr": overall_fpr,
            "wilson_lower": ol * 100,
            "wilson_upper": ou * 100
        },
        "strata": {}
    }
    
    for stratum, s in strata.items():
        total = s["total"]
        fps_list = s["fps"]
        fps = len(fps_list)
        fpr = 100.0 * fps / total if total > 0 else 0.0
        lower, upper = wilson(fps, total)
        
        results["strata"][stratum] = {
            "total": total,
            "fps": fps,
            "fpr": fpr,
            "wilson_lower": lower * 100,
            "wilson_upper": upper * 100,
            "false_positives": fps_list
        }
    
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved: {outfile}")

print()
print("=" * 80)

