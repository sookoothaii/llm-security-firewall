# AnswerPolicy Experiments
**Date:** 2025-12-02
**Status:** Experimental Plan
**Author:** Joerg Bollwahn

---

## Overview

This document outlines concrete experiments to evaluate AnswerPolicy behavior empirically. The goal is to measure how different policy configurations affect refusal rates, block rates, and decision distributions.

---

## Experiment 1: Kids Policy vs. Default (Red-Team Suite)

### Objective

Verify that AnswerPolicy achieves the intended behavior: **more blocking without completely killing all requests**.

### Setup

**Run A (Baseline):**
- `use_answer_policy=False`
- All other settings unchanged

**Run B (Kids Policy):**
- `use_answer_policy=True`
- `policy=kids` (via tenant mapping or context)
- All other settings unchanged

### Test Suite

Use existing Red-Team/Kids test suites:
- Adversarial test cases
- Kids Policy test cases
- Mixed benign + malicious inputs

### Execution

1. **Run A:**
   ```python
   from llm_firewall.core.firewall_engine_v2 import FirewallEngine
   import json

   engine = FirewallEngine()
   decisions_a = []

   for test_input in test_suite:
       decision = engine.process_input(
           test_input,
           use_answer_policy=False,  # Baseline
           tenant_id="test_tenant",
       )
       decisions_a.append({
           "allowed": decision.allowed,
           "reason": decision.reason,
           "risk_score": decision.risk_score,
           "metadata": decision.metadata,
       })

   with open("logs/runA_baseline.jsonl", "w") as f:
       for d in decisions_a:
           f.write(json.dumps(d) + "\n")
   ```

2. **Run B:**
   ```python
   from llm_firewall.core.policy_provider import PolicyProvider

   provider = PolicyProvider(tenant_policy_map={"test_tenant": "kids"})
   decisions_b = []

   for test_input in test_suite:
       decision = engine.process_input(
           test_input,
           use_answer_policy=True,
           policy_provider=provider,
           tenant_id="test_tenant",
       )
       decisions_b.append({
           "allowed": decision.allowed,
           "reason": decision.reason,
           "risk_score": decision.risk_score,
           "metadata": decision.metadata,
       })

   with open("logs/runB_kids_policy.jsonl", "w") as f:
       for d in decisions_b:
           f.write(json.dumps(d) + "\n")
   ```

3. **Analysis:**
   ```bash
   python scripts/analyze_answer_policy_metrics.py --input logs/runA_baseline.jsonl
   python scripts/analyze_answer_policy_metrics.py --input logs/runB_kids_policy.jsonl
   ```

### Key Metrics to Compare

1. **Refusal/Block Rate:**
   - How much does `allowed == False` increase in Run B?
   - Expected: Moderate increase (not 100% blocking)

2. **Mode Distribution:**
   - Percentage of `mode == "silence"` in Run B
   - Expected: Significant portion (e.g., 20-40% depending on test suite)

3. **p_correct Distribution:**
   - Are low `p_correct` bins (e.g., `[0.0-0.2]`, `(0.2-0.4]`) dominated by `mode == "silence"`?
   - Expected: Yes - AnswerPolicy should block low-confidence cases

4. **AnswerPolicy Block Rate:**
   - How often does AnswerPolicy add additional blocking beyond existing safety layers?
   - Expected: Non-zero, measurable impact

### Success Criteria

- Kids Policy shows higher block rate than baseline
- Low `p_correct` bins show more `silence` decisions
- Not all requests are blocked (AnswerPolicy is not overly aggressive)
- Block attribution is clear (AnswerPolicy blocks vs. other safety layers)

---

## Experiment 2: Default vs. Internal Debug (Epistemic Distance)

### Objective

Demonstrate that policies have measurably different "epistemic tolerance" (how much uncertainty they accept).

### Setup

**Mixed Test Suite:**
- Normal queries (low risk)
- Borderline queries (moderate risk)
- No hard attacks (focus on epistemic behavior, not security)

**Two Tenants:**
- `tenant_default` → Policy `default`
- `tenant_research` → Policy `internal_debug`

### Execution

```python
from llm_firewall.core.firewall_engine_v2 import FirewallEngine
from llm_firewall.core.policy_provider import PolicyProvider
import json

engine = FirewallEngine()
provider = PolicyProvider(
    tenant_policy_map={
        "tenant_default": "default",
        "tenant_research": "internal_debug",
    }
)

decisions_default = []
decisions_research = []

for test_input in mixed_test_suite:
    # Default policy
    decision = engine.process_input(
        test_input,
        use_answer_policy=True,
        policy_provider=provider,
        tenant_id="tenant_default",
    )
    decisions_default.append({
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "metadata": decision.metadata,
    })

    # Internal debug policy
    decision = engine.process_input(
        test_input,
        use_answer_policy=True,
        policy_provider=provider,
        tenant_id="tenant_research",
    )
    decisions_research.append({
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "metadata": decision.metadata,
    })

with open("logs/run_default_policy.jsonl", "w") as f:
    for d in decisions_default:
        f.write(json.dumps(d) + "\n")

with open("logs/run_internal_debug_policy.jsonl", "w") as f:
    for d in decisions_research:
        f.write(json.dumps(d) + "\n")
```

### Analysis

```bash
python scripts/analyze_answer_policy_metrics.py --input logs/run_default_policy.jsonl
python scripts/analyze_answer_policy_metrics.py --input logs/run_internal_debug_policy.jsonl
```

### Expected Results

**Internal Debug Policy:**
- High rate of `mode == "answer"` even at low `p_correct` values
- Low refusal rate (threshold = 0.0, always answers)
- More permissive behavior overall

**Default Policy:**
- More `mode == "silence"` at low `p_correct` bins
- Higher refusal rate (threshold ≈ 0.75)
- More conservative behavior

### Success Criteria

- Histograms show clear separation: `internal_debug` has more `answer` decisions in low `p_correct` bins
- Refusal rates differ measurably (e.g., `internal_debug` < 10%, `default` > 20%)
- If separation is not visible, investigate:
  - Risk scoring too coarse/constant
  - Policy parameters too similar

---

## Experiment 3: Policy Parameter Sensitivity

### Objective

Measure how changing policy parameters (C, A) affects behavior.

### Setup

Test with different cost configurations:
- `kids`: C=50, A=0 (very high cost for wrong answers)
- `strict`: C=20, A=0 (high cost)
- `default`: C=5, A=0.5 (moderate cost)
- `permissive`: C=2, A=1.0 (low cost)

### Execution

Run same test suite with each policy, compare metrics.

### Expected Results

- Higher C → Higher threshold → More `silence` decisions
- Higher A → Lower threshold → More `answer` decisions (silence becomes expensive)

---

## Sample Results Template

After running experiments, document results here:

### Experiment 1: Kids Policy vs. Baseline

**Run A (Baseline):**
- Total decisions: XXX
- Block rate: XX.X%
- (Other metrics...)

**Run B (Kids Policy):**
- Total decisions: XXX
- Block rate: XX.X%
- AnswerPolicy block rate: XX.X%
- Mode distribution:
  - `answer`: XX.X%
  - `silence`: XX.X%
- p_correct histogram: (fill in)

**Comparison:**
- Block rate increase: +X.X%
- AnswerPolicy additional blocks: XX

### Experiment 2: Default vs. Internal Debug

**Default Policy:**
- Refusal rate: XX.X%
- (Other metrics...)

**Internal Debug Policy:**
- Refusal rate: XX.X%
- (Other metrics...)

**Epistemic Distance:**
- Clear separation: Yes/No
- If no, potential causes: (list)

---

## Next Steps After Experiments

1. **If p_correct values cluster in one bin:**
   - Investigate risk scoring granularity
   - Consider calibrated probability model

2. **If policies show no separation:**
   - Review policy parameter differences
   - Check if thresholds are actually different

3. **If AnswerPolicy blocks too much/too little:**
   - Adjust policy parameters (C, A)
   - Consider per-route policy selection

4. **Document findings:**
   - Add sample results to this document
   - Update `ANSWER_POLICY_METRICS.md` with empirical observations
   - Note any limitations or unexpected behavior

---

## References

- Metrics Analysis: `docs/ANSWER_POLICY_METRICS.md`
- Integration Guide: `docs/ANSWER_POLICY_INTEGRATION.md`
- Design Decisions: `docs/ANSWER_POLICY_DESIGN_DECISIONS.md`
