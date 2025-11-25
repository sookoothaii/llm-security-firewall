# DeepSeek RC3 Collaboration Scripts
**Date:** 2025-10-31
**Partner:** DeepSeek
**Purpose:** MSG Attack Testing, Performance Benchmarking, E-Values Design

---

## Phase 1: MSG Hill-Climbing Attack (CRITICAL)

**File:** `msg_hill_climb_attack.py`
**Status:** Ready for integration
**Timeline:** 48h

### Integration Steps

**1. Import Real Firewall:**
```python
# Replace MockFirewall with real system
import sys
sys.path.insert(0, '../../src')
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.detectors import run_detectors  # From test files
from llm_firewall.preprocess.context import classify_context
```

**2. Adapt Analyzer:**
```python
class RealFirewallAdapter:
    def analyze(self, text: str) -> Dict:
        # Run full pipeline like in tests
        hits = []
        # Add all detector calls here (copy from test files)

        ctx = classify_context(text)
        action, risk, contrib = decide_action_otb(text, hits, ctx)

        return {
            'risk_score': risk,
            'blocked': action == 'BLOCK',
            'warn': action == 'WARN',
            'hits': hits
        }
```

**3. Run Attack:**
```python
from msg_hill_climb_attack import MSGHillClimbAttacker

firewall = RealFirewallAdapter()
attacker = MSGHillClimbAttacker(firewall)
results = attacker.hill_climbing_attack(max_iterations=200)

# Save results
import json
with open('msg_attack_results.json', 'w') as f:
    json.dump(results, f, indent=2)
```

### Expected Results

**If MSG defeated (80% probability):**
- SUCCESS after 50-100 iterations
- Bypass payload identified
- Vulnerability documented

**If MSG holds (20% probability):**
- No bypass after 200 iterations
- MSG robustness confirmed
- Continue with 500+ iterations to validate

### Deliverables

- [ ] Iteration log (JSON)
- [ ] Bypass payload (if successful)
- [ ] Vulnerability analysis report
- [ ] Mitigation recommendations

---

## Phase 2: Performance Benchmark (HIGH)

**File:** `performance_benchmark.py`
**Status:** Ready for adaptation
**Timeline:** 24h parallel

### Integration Notes

**Corpus Sources:**
- Benign: `../../data/benign_repo/`
- Adversarial: Extract from `../../tests_firewall/test_ultra_break_*.py`

**Metrics to track:**
- p50, p95, p99 latency (ms)
- Memory usage (MB)
- Layer-by-layer breakdown
- With/without MSG comparison

### Deliverables

- [ ] Performance dashboard (CSV + JSON)
- [ ] Latency distribution plots
- [ ] Bottleneck analysis
- [ ] Comparison vs RC3 targets (p95 <=12ms)

---

## Phase 3: E-Values Design (MEDIUM→HIGH if MSG defeated)

**File:** `evalues_design.py`
**Status:** Conceptual prototype
**Timeline:** Day 3-5 (48h)

### Integration Strategy

**Where to integrate:**
- New module: `src/llm_firewall/session/evalues_guard.py`
- Hook into: `decide_action_otb` or wrapper layer
- Session management: Track turns, alpha spending

**Design decisions:**
- Alpha=0.05 (session-level)
- Risk→p-value calibration (use validation set)
- Performance overhead target: <10%

### Deliverables

- [ ] Algorithm specification
- [ ] Python prototype (production-ready)
- [ ] Integration plan
- [ ] Test suite
- [ ] Performance estimates

---

## Communication

**Daily Updates:** End-of-day summary (progress, blockers, findings)
**Critical Findings:** Immediate notification
**Final Reports:**
- Phase 1: 48h (MSG Attack Analysis)
- Phase 2: 24h (Performance Baseline)
- Phase 3: 48h (E-Values Design)

---

## Status

**Phase 1:** READY TO START
**Phase 2:** READY TO START (parallel)
**Phase 3:** WAITING FOR PHASE 1 RESULTS

**Next Action:** DeepSeek integrates RealFirewallAdapter and starts Phase 1
