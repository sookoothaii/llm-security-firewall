# AnswerPolicy Design Decisions
**Date:** 2025-12-02
**Status:** Design Documentation
**Author:** Joerg Bollwahn

---

## Overview

This document captures critical design decisions for the AnswerPolicy (Epistemic Decision Layer) implementation, addressing the two key questions raised in the review.

---

## Design Decision 1: AnswerPolicy as "Additional Brake" vs. "Pure Utility Optimization"

### Current Implementation: "Additional Brake" (Conservative)

**Behavior:**
- AnswerPolicy can **only block** (when `decision_mode == "silence"`).
- If AnswerPolicy says "answer", the decision **still goes through** the existing risk threshold logic (`base_risk_score < 0.7`).
- AnswerPolicy acts as an **extra safety layer**, not a replacement for existing heuristics.

**Rationale:**
1. **Security-First Principle**: This is a security product, not a utility optimization demo. Multiple independent checks reduce false negatives.
2. **Backward Compatibility**: Existing behavior is preserved when AnswerPolicy is disabled or says "answer".
3. **Defense-in-Depth**: AnswerPolicy adds another layer of protection without removing existing safeguards.

**Mathematical Implication:**
- The pure utility model (`E[U(answer)] > E[U(silence)]`) is **not** the final decision criterion.
- Instead, AnswerPolicy implements: "If utility model says silence, block immediately. Otherwise, continue to existing threshold logic."

**Documentation:**
This behavior is explicitly documented in:
- `docs/ANSWER_POLICY_INTEGRATION.md` (Integration Guide)
- Code comments in `firewall_engine_v2.py` (line ~456)

### Alternative: "Pure Utility Optimization" (Not Implemented)

**Hypothetical Behavior:**
- Final `allowed` decision would be **solely** based on utility comparison.
- Existing risk threshold (`base_risk_score < 0.7`) would be removed or ignored when AnswerPolicy is enabled.

**Why Not Chosen:**
- Removes defense-in-depth (single point of failure).
- Breaks backward compatibility.
- Requires extensive re-validation of all existing test cases.

**Future Consideration:**
If empirical evidence shows that AnswerPolicy alone is sufficient (e.g., in research/development mode), a configuration flag could enable "pure utility mode" as an opt-in feature.

---

## Design Decision 2: `p_correct = 1 - base_risk_score` as Heuristic

### Current Implementation: Monotonic Heuristic

**Mapping:**
```python
p_correct = max(0.0, min(1.0, 1.0 - base_risk_score))
```

**Properties:**
- Monotonic: Higher risk → Lower p_correct
- Bounded: Always in [0, 1]
- Simple: No additional model training required

**Limitations:**
1. **Not Calibrated**: `p_correct` is not an empirically validated probability estimate.
2. **No Uncertainty Modeling**: Does not account for epistemic uncertainty (e.g., "I don't know if this is safe").
3. **No Multi-Feature Fusion**: Does not incorporate Dempster-Shafer masses, CUSUM status, or other signals.

**Documentation:**
This is explicitly labeled as a **heuristic** in:
- `docs/ANSWER_POLICY_INTEGRATION.md` (Section: "Connection to Dempster-Shafer")
- Code comments in `firewall_engine_v2.py` (line ~467)

### Future Enhancement: Calibrated Probability Model

**Proposed Approach:**
1. **Training Data**: Collect labeled examples (Red-Team attacks, benign queries) with ground truth labels.
2. **Features**: Combine multiple signals:
   - `base_risk_score` (current heuristic)
   - Dempster-Shafer mass assignments (`m_safe`, `m_unsafe`, `m_unknown`)
   - CUSUM oscillation status
   - Embedding-based anomaly scores (if available)
   - Vendor-specific signals (if available)
3. **Calibration**: Train a probabilistic model (e.g., Platt scaling, isotonic regression, or neural calibration) to output calibrated `p_correct`.
4. **Validation**: Measure calibration error (ECE, Brier score) on held-out test set.

**Benefits:**
- Empirically grounded probability estimates
- Citable in papers: "AnswerPolicy operates on calibrated p(correct) estimates trained on Red-Team and benign datasets"
- Better uncertainty quantification

**Implementation Note:**
This would be a separate module (e.g., `src/llm_firewall/core/probability_calibrator.py`) that AnswerPolicy can use instead of the heuristic.

---

## Metrics Collection

### Always-Logging Strategy

**Implementation:**
AnswerPolicy metadata is **always** logged in `FirewallDecision.metadata["answer_policy"]`, even when AnswerPolicy is disabled.

**Metadata Structure:**
```python
{
    "enabled": bool,           # Whether AnswerPolicy was active
    "policy_name": str | None, # Policy name if enabled
    "p_correct": float | None, # Estimated p_correct if enabled
    "threshold": float | None, # Policy threshold if enabled
    "mode": str | None,        # "answer" or "silence" if enabled
}
```

**Rationale:**
- Enables offline analysis: Compare ASR/FPR with vs. without AnswerPolicy
- Histogram analysis: Distribution of `p_correct` in live traffic
- A/B testing: Compare different policy configurations

**Usage:**
Scripts in `scripts/` or `monitoring/` can aggregate this metadata to compute:
- Attack Success Rate (ASR) per policy
- False Positive Rate (FPR) per policy
- Refusal/Block Rate (how often AnswerPolicy blocks vs. threshold)
- `p_correct` distribution histograms

---

## Summary

1. **AnswerPolicy is an "additional brake"**, not a pure utility optimizer. This is a conscious security-first design choice.
2. **`p_correct = 1 - base_risk_score` is a heuristic placeholder**. Future work should implement a calibrated probability model.
3. **Metrics are always logged** to enable empirical evaluation and policy comparison.

These decisions are documented and can be revisited based on empirical evidence from production use or research experiments.
