# AnswerPolicy v0.1 Quick Start
**Date:** 2025-12-02
**Status:** Practical Guide
**Author:** Joerg Bollwahn

---

## Overview

This is a **minimal, laptop-friendly** evaluation of AnswerPolicy. Goal: Verify that AnswerPolicy (especially `kids` policy) behaves sensibly on a small dataset.

**Time estimate:** 1-2 hours on a single laptop.

---

## Prerequisites

- Python environment with `llm-security-firewall` installed
- No external dependencies beyond what's already in the repo

---

## Step 1: Run Experiments

Execute the simple experiment runner:

```bash
python scripts/run_simple_experiment.py
```

This will:
1. Read prompts from `datasets/mixed_small.jsonl` (50 prompts: 25 red-team, 25 benign)
2. Run baseline (no AnswerPolicy)
3. Run kids policy (AnswerPolicy enabled)
4. Generate two JSONL files:
   - `logs/baseline_mixed_small.jsonl`
   - `logs/kids_mixed_small.jsonl`

**Expected output:**
```
======================================================================
Experiment A: Baseline
======================================================================
Running experiment: policy=default, use_answer_policy=False
  Processed 50 items...
Completed: 50 decisions written to logs/baseline_mixed_small.jsonl

======================================================================
Experiment B: Kids Policy
======================================================================
Running experiment: policy=kids, use_answer_policy=True
  Processed 50 items...
Completed: 50 decisions written to logs/kids_mixed_small.jsonl

======================================================================
Experiments completed!
======================================================================
```

---

## Step 2: Analyze Results

### Baseline Analysis

```bash
python scripts/analyze_answer_policy_metrics.py --input logs/baseline_mixed_small.jsonl
```

**What to look for:**
- Total decisions: Should be 50
- Block rate: Baseline percentage
- Epistemic blocks: Should be 0 or very low (AnswerPolicy disabled)

### Kids Policy Analysis

```bash
python scripts/analyze_answer_policy_metrics.py --input logs/kids_mixed_small.jsonl
```

**What to look for:**
- Total decisions: Should be 50
- Block rate: Should be higher than baseline
- Epistemic blocks: Should be non-zero (AnswerPolicy actively blocking)
- Mode distribution: Percentage of `answer` vs `silence`
- Histogram: Low `p_correct` bins should show more `silence` decisions

### Optional: CSV Export

```bash
python scripts/analyze_answer_policy_metrics.py \
    --input logs/baseline_mixed_small.jsonl \
    --output-csv metrics/baseline_mixed_small.csv

python scripts/analyze_answer_policy_metrics.py \
    --input logs/kids_mixed_small.jsonl \
    --output-csv metrics/kids_mixed_small.csv
```

---

## Step 3: Document Findings

Fill in `docs/ANSWER_POLICY_V01_RESULTS.md` with your observations.

**Key metrics to document:**
1. Block rate comparison (baseline vs. kids)
2. AnswerPolicy impact (additional blocks)
3. Red-team vs. benign breakdown
4. p_correct distribution patterns

**Heuristic checks:**
- ✅ Kids policy blocks more red-team prompts than baseline
- ✅ Kids policy doesn't block all benign prompts
- ✅ Low p_correct bins show more `silence` decisions
- ✅ Baseline and kids show measurable difference

**If something looks wrong:**
- Kids and baseline almost identical → Check AnswerPolicy integration
- p_correct values cluster in one bin → Investigate risk scoring
- No separation between policies → Review policy parameters

---

## What You Get

After completing these steps, you have:

1. **Two decision logs** (baseline and kids policy)
2. **Metrics summaries** (text output + optional CSV)
3. **Documented findings** (in `ANSWER_POLICY_V01_RESULTS.md`)

This gives you a **reproducible, empirical first measurement** of AnswerPolicy behavior on a practical scale.

---

## Next Steps (Optional)

If v0.1 looks good, you can:

1. **Expand dataset:** Add more prompts to `datasets/mixed_small.jsonl`
2. **Experiment B:** Run default vs. internal_debug comparison
3. **Parameter tuning:** Adjust policy parameters (C, A) and re-run

But for v0.1, the goal is just: **Does AnswerPolicy work as expected on a small, manageable dataset?**

---

## Troubleshooting

**Error: Input file not found**
- Make sure `datasets/mixed_small.jsonl` exists
- Check that you're running from the project root

**Error: FirewallEngine not available**
- Ensure `llm-security-firewall` is installed
- Check Python environment

**No difference between baseline and kids**
- Verify AnswerPolicy is actually enabled (`use_answer_policy=True`)
- Check that policy provider is correctly configured
- Review `firewall_engine_v2.py` integration

---

## References

- Results Template: `docs/ANSWER_POLICY_V01_RESULTS.md`
- Metrics Analysis: `docs/ANSWER_POLICY_METRICS.md`
- Integration Guide: `docs/ANSWER_POLICY_INTEGRATION.md`
