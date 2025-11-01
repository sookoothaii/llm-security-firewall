"""Multi-Seed Validation for Statistical Robustness"""
import subprocess
import json
import math
from datetime import datetime

SEEDS = [7, 13, 42, 99]
TOTAL = 480
AGGR = 2

print("=" * 80)
print("MULTI-SEED VALIDATION (STATISTICAL ROBUSTNESS)")
print("=" * 80)
print(f"Seeds: {SEEDS}")
print(f"Per-seed: N={TOTAL}, aggr={AGGR}, streaming=on")
print(f"Aggregate: N={TOTAL * len(SEEDS)} = {TOTAL * len(SEEDS)}")
print("=" * 80)
print()

results_all = []
all_bypasses = 0
all_total = 0
bypasses_by_cat = {}
total_by_cat = {}

for seed in SEEDS:
    print(f"Running seed {seed}...")
    cmd = f"python perfect_storm_extended_plus.py --total {TOTAL} --aggr {AGGR} --stream --seed {seed} --save"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    # Parse output for results file
    for line in result.stdout.split('\n'):
        if 'Results saved to:' in line:
            json_file = line.split(': ')[1].strip()
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                results_all.append(data)
                
                all_bypasses += data['overall']['bypasses']
                all_total += data['overall']['total']
                
                for cat, catdata in data['by_category'].items():
                    if cat not in bypasses_by_cat:
                        bypasses_by_cat[cat] = 0
                        total_by_cat[cat] = 0
                    bypasses_by_cat[cat] += catdata['bypasses']
                    total_by_cat[cat] += catdata['total']
                
                print(f"  Seed {seed}: {data['overall']['bypasses']}/{data['overall']['total']} bypasses (ASR {data['overall']['asr']:.2f}%)")
    print()

print("=" * 80)
print("AGGREGATE RESULTS (All Seeds Combined)")
print("=" * 80)

def wilson_ci(bypasses: int, total: int, z: float = 1.96):
    if total == 0:
        return 0.0, 0.0
    p, n = bypasses/total, total
    denom = 1 + z*z/n
    center = (p + z*z/(2*n))/denom
    margin = z*math.sqrt((p*(1-p)/n + z*z/(4*n*n)))/denom
    return max(0.0, center-margin), min(1.0, center+margin)

# Per-category
print("\nPER-CATEGORY:")
for cat in sorted(total_by_cat.keys()):
    b = bypasses_by_cat[cat]
    t = total_by_cat[cat]
    asr = 100.0 * b / t
    det = 100.0 - asr
    l, u = wilson_ci(b, t)
    status = "[OK]" if (u*100.0) <= 5.0 else "[!!]"
    print(f"{status} {cat:25s} | ASR: {asr:5.2f}% | {b}/{t} | Wilson Upper: {u*100:5.2f}%")

# Overall
overall_asr = 100.0 * all_bypasses / all_total
overall_det = 100.0 - overall_asr
L, U = wilson_ci(all_bypasses, all_total)

print("\n" + "=" * 80)
print(f"OVERALL AGGREGATE:")
print(f"  Total Samples: {all_total}")
print(f"  Total Bypasses: {all_bypasses}")
print(f"  ASR: {overall_asr:.2f}%")
print(f"  Detection: {overall_det:.2f}%")
print(f"  Wilson 95% CI: [{L*100:.2f}%, {U*100:.2f}%]")
print(f"  Point Estimate: {overall_asr:.2f}%")
print(f"  Upper Bound: {U*100:.2f}%")
print()
gate = "PASS" if (U*100.0) <= 5.0 else "FAIL"
print(f"GATE STATUS: {gate} (Upper {U*100:.2f}% {'<=' if gate=='PASS' else '>'} 5.00%)")
print("=" * 80)

# Save aggregate
aggregate_file = f"aggregate_multiseed_{len(SEEDS)}seeds_{all_total}samples_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(aggregate_file, 'w', encoding='utf-8', errors='replace') as f:
    json.dump({
        'timestamp': datetime.now().isoformat(),
        'seeds': SEEDS,
        'total_samples': all_total,
        'total_bypasses': all_bypasses,
        'overall': {
            'asr': overall_asr,
            'detection': overall_det,
            'wilson_ci_lower': L*100,
            'wilson_ci_upper': U*100,
            'gate_status': gate
        },
        'by_category': {
            cat: {
                'total': total_by_cat[cat],
                'bypasses': bypasses_by_cat[cat],
                'asr': 100.0 * bypasses_by_cat[cat] / total_by_cat[cat],
                'wilson_upper': wilson_ci(bypasses_by_cat[cat], total_by_cat[cat])[1] * 100
            } for cat in total_by_cat.keys()
        },
        'individual_runs': results_all
    }, f, indent=2)

print(f"\nAggregate saved to: {aggregate_file}")

