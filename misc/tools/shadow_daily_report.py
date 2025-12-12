"""
Shadow Deployment Daily Report
Generates stratified FPR/ASR metrics with Wilson CI per class
"""

import argparse
from datetime import datetime, timedelta
from collections import defaultdict


def wilson(b, n, z=1.96):
    """Wilson score interval"""
    if n == 0:
        return 0.0, 0.0
    p = b / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


ap = argparse.ArgumentParser()
ap.add_argument("--log-dir", default="shadow_logs", help="Shadow log directory")
ap.add_argument("--date", help="Date to analyze (YYYY-MM-DD), default: today")
ap.add_argument("--days", type=int, default=1, help="Number of days to aggregate")
args = ap.parse_args()

if args.date:
    end_date = datetime.strptime(args.date, "%Y-%m-%d")
else:
    end_date = datetime.now()

start_date = end_date - timedelta(days=args.days - 1)

print("=" * 80)
print("SHADOW DEPLOYMENT DAILY REPORT")
print("=" * 80)
print(f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
print(f"Days: {args.days}")
print("=" * 80)
print()

# Aggregate metrics per stratum
strata = defaultdict(lambda: {"total": 0, "flagged": 0, "signals": defaultdict(int)})

# Load logs (placeholder - actual implementation would parse JSON logs)
# For now, show structure

print("STRATIFIED METRICS")
print("=" * 80)
print()

# Example structure (would be populated from real logs)
example_strata = {
    "doc_with_codefence": {"total": 1523, "flagged": 2},
    "pure_doc": {"total": 456, "flagged": 11},
    "doc_with_exec": {"total": 23, "flagged": 23},
    "code_cfg": {"total": 87, "flagged": 0},
    "generic_text": {"total": 234, "flagged": 5},
}

for stratum in sorted(example_strata.keys()):
    s = example_strata[stratum]
    total = s["total"]
    flagged = s["flagged"]
    fpr = 100.0 * flagged / total if total > 0 else 0.0
    lower, upper = wilson(flagged, total)

    # Gate status
    if stratum == "doc_with_codefence":
        gate_target = 1.50
        gate_status = "PASS" if upper * 100 <= gate_target else "FAIL"
    elif stratum == "pure_doc":
        gate_target = 1.50
        gate_status = "PASS" if upper * 100 <= gate_target else "FAIL"
    elif stratum == "code_cfg":
        gate_target = 1.00
        gate_status = "PASS" if upper * 100 <= gate_target else "ADVISORY"
    else:
        gate_target = None
        gate_status = "ADVISORY"

    print(
        f"{stratum:20s} | N={total:5d} | Flagged={flagged:4d} | FPR={fpr:5.2f}% | Wilson Upper={upper * 100:5.2f}%",
        end="",
    )
    if gate_target:
        print(f" | Target<={gate_target:.2f}% | {gate_status}")
    else:
        print(f" | {gate_status}")

print()
print("=" * 80)
print("PRIMARY GATES")
print("=" * 80)

# doc_with_codefence
codefence = example_strata["doc_with_codefence"]
cf_fpr = 100.0 * codefence["flagged"] / codefence["total"]
cf_lower, cf_upper = wilson(codefence["flagged"], codefence["total"])
print("doc_with_codefence (Primary):")
print(f"  N: {codefence['total']}")
print(f"  FPR: {cf_fpr:.2f}%")
print(f"  Wilson Upper: {cf_upper * 100:.2f}%")
print("  Target: <=1.50%")
print(f"  Status: {'PASS' if cf_upper * 100 <= 1.50 else 'FAIL'}")
print()

# pure_doc
pure = example_strata["pure_doc"]
pd_fpr = 100.0 * pure["flagged"] / pure["total"]
pd_lower, pd_upper = wilson(pure["flagged"], pure["total"])
print("pure_doc (Primary):")
print(f"  N: {pure['total']}")
print(f"  FPR: {pd_fpr:.2f}%")
print(f"  Wilson Upper: {pd_upper * 100:.2f}%")
print("  Target: <=1.50%")
print(f"  Status: {'PASS' if pd_upper * 100 <= 1.50 else 'FAIL'}")
print()

print("=" * 80)
print("NOTES")
print("=" * 80)
print()
print("Implementation: This is a template showing expected structure.")
print("Actual implementation requires:")
print("  1. Parse shadow logs from log_dir")
print("  2. Extract: ctx, doc_like, exec_ctx, has_codefence, action")
print("  3. Classify into strata")
print("  4. Aggregate metrics")
print("  5. Compute Wilson CI per stratum")
print()
print("Log format expected:")
print('  {"timestamp": "...", "ctx": "documentation", "doc_like": false,')
print('   "exec_ctx": false, "has_codefence": true, "action": "WARN",')
print('   "signals": [...], "risk": 2.5}')
print()
print("=" * 80)
