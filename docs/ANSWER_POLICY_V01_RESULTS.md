# AnswerPolicy v0.1 – Mixed Small Dataset Results
**Date:** [To be filled after experiments]
**Status:** Experimental Results
**Author:** Joerg Bollwahn

---

## Overview

This document captures empirical results from the v0.1 AnswerPolicy evaluation on a small mixed dataset (50 prompts: 25 red-team, 25 benign).

**Goal:** Verify that AnswerPolicy (especially `kids` policy) behaves sensibly:
- Blocks more malicious content than baseline
- Without completely blocking everything

---

## Dataset

**File:** `datasets/mixed_small.jsonl`

**Composition:**
- 25 red-team prompts (malicious/heavy)
- 25 benign prompts (normal/harmless)
- Total: 50 prompts

---

## Experiment A: Baseline (no AnswerPolicy / default)

**Configuration:**
- `use_answer_policy=False`
- Policy: `default` (if AnswerPolicy were enabled)

**Results:**
- Total decisions: [To be filled]
- Block rate: [To be filled]%
- Epistemic blocks (mode == "silence"): [To be filled] (should be 0 or very low)
- p_correct (allowed): mean=[To be filled], std=[To be filled]

**Per-Policy Statistics:**
- Policy: [To be filled]
- Answer count: [To be filled]
- Silence count: [To be filled]
- Blocked by AnswerPolicy: [To be filled]
- Blocked by other reasons: [To be filled]

**Histogram (p_correct × mode):**
```
Bucket          Answer          Silence
[0.0-0.2]       [To be filled]  [To be filled]
(0.2-0.4]       [To be filled]  [To be filled]
(0.4-0.6]       [To be filled]  [To be filled]
(0.6-0.8]       [To be filled]  [To be filled]
(0.8-1.0]       [To be filled]  [To be filled]
```

---

## Experiment B: Kids Policy

**Configuration:**
- `use_answer_policy=True`
- Policy: `kids` (threshold ≈ 0.98)

**Results:**
- Total decisions: [To be filled]
- Block rate: [To be filled]%
- Epistemic blocks (mode == "silence"): [To be filled]
- p_correct (allowed): mean=[To be filled], std=[To be filled]

**Per-Policy Statistics:**
- Policy: `kids`
- Answer count: [To be filled]
- Silence count: [To be filled]
- Blocked by AnswerPolicy: [To be filled]
- Blocked by other reasons: [To be filled]

**Histogram (p_correct × mode):**
```
Bucket          Answer          Silence
[0.0-0.2]       [To be filled]  [To be filled]
(0.2-0.4]       [To be filled]  [To be filled]
(0.4-0.6]       [To be filled]  [To be filled]
(0.6-0.8]       [To be filled]  [To be filled]
(0.8-1.0]       [To be filled]  [To be filled]
```

---

## Comparison

**Block Rate Difference:**
- Baseline block rate: [To be filled]%
- Kids block rate: [To be filled]%
- Difference: +[To be filled]%

**AnswerPolicy Impact:**
- Additional blocks by AnswerPolicy: [To be filled]
- Percentage of total decisions: [To be filled]%

**Red-Team Prompts:**
- Baseline: [To be filled] blocked / 25 total
- Kids: [To be filled] blocked / 25 total
- Improvement: [To be filled]

**Benign Prompts:**
- Baseline: [To be filled] blocked / 25 total
- Kids: [To be filled] blocked / 25 total
- False positive impact: [To be filled]

---

## Observations

### Expected Behavior (Heuristic Rules for v0.1)

**Kids Policy:**
- Red-team prompts: Should block most or all (close to 100%)
- Benign prompts: Should not block everything, but noticeably stricter than baseline
- Low p_correct bins should be dominated by `silence` decisions

**Baseline:**
- Should have clearly fewer blocks than kids policy
- Epistemic blocks should be 0 or very low

### Actual Observations

[To be filled after running experiments]

**Key Findings:**
1. [Observation 1]
2. [Observation 2]
3. [Observation 3]

**Issues/Anomalies:**
- [If any]

**Next Steps:**
- [If kids and baseline look almost identical → check parameters/integration]
- [If p_correct values cluster in one bin → investigate risk scoring]
- [If policies show no separation → review policy parameters]

---

## Execution Log

**Date:** [To be filled]

**Commands:**
```bash
# Run experiments
python scripts/run_simple_experiment.py

# Analyze baseline
python scripts/analyze_answer_policy_metrics.py --input logs/baseline_mixed_small.jsonl

# Analyze kids policy
python scripts/analyze_answer_policy_metrics.py --input logs/kids_mixed_small.jsonl

# Optional: CSV export
python scripts/analyze_answer_policy_metrics.py --input logs/baseline_mixed_small.jsonl --output-csv metrics/baseline_mixed_small.csv
python scripts/analyze_answer_policy_metrics.py --input logs/kids_mixed_small.jsonl --output-csv metrics/kids_mixed_small.csv
```

**Environment:**
- Python version: [To be filled]
- Package version: [To be filled]
- Platform: [To be filled]

---

## References

- Experiment Plan: `docs/ANSWER_POLICY_EXPERIMENTS.md`
- Metrics Analysis: `docs/ANSWER_POLICY_METRICS.md`
- Integration Guide: `docs/ANSWER_POLICY_INTEGRATION.md`
