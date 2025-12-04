# AnswerPolicy Review Checkpoints
**Date:** 2025-12-02
**Status:** Implementation Complete - Ready for Testing
**Author:** Joerg Bollwahn

---

## Overview

This document tracks the review checkpoints and test plan for AnswerPolicy implementation.

---

## 1. Architecture Check ✅

**Status:** PASSED

**Verification:**
- Core modules in `src/llm_firewall/core/` (decision_policy.py, policy_provider.py)
- Configuration in `config/answer_policy.yaml`
- Integration in `firewall_engine_v2.py` (optional, via `use_answer_policy` flag)
- Tests in `tests/core/test_answer_policy*.py`
- Documentation in `docs/ANSWER_POLICY_*.md`
- Examples in `examples/answer_policy_example.py`

**Result:** Architecture is coherent with existing repo layout. AnswerPolicy is a clearly bounded new decision layer.

---

## 2. Test Plan

### 2.1. Logic Verification (Unit Tests) ✅

**Location:** `tests/core/test_answer_policy.py`

**Coverage:**

#### ✅ 2.1.1. Threshold Basics
- [x] B=1, C=9, A=0 → threshold = 0.9
- [x] B=1, C=50, A=0 → threshold ≈ 0.98
- [x] B=1, C=1, A=0 → threshold = 0.5

**Test:** `test_threshold_basics()`

#### ✅ 2.1.2. Edge Cases
- [x] A > C (silence "more expensive" than wrong) → threshold < 0 → clamped to 0
- [x] C very large (Kids Policy) → threshold near 1, but < 1

**Test:** `test_edge_cases()`

#### ✅ 2.1.3. Monotonicity
- [x] For fixed policy: if `p_correct` increases, `decide()` never flips from "answer" back to "silence"

**Test:** `test_monotonicity()`

**Status:** All unit tests implemented and passing.

---

### 2.2. Integration Tests ✅

**Location:** `tests/core/test_answer_policy_integration.py`

**Coverage:**

#### ✅ Case 1: AnswerPolicy Blocks, Threshold Would Allow
- [x] `base_risk_score = 0.2` → `p_correct = 0.8`
- [x] Policy `kids` with threshold ≈ 0.98
- [x] Expected: `decision.allowed == False`, `reason` contains "Epistemic gate", metadata contains policy info

**Test:** `test_case_1_answer_policy_blocks_threshold_would_allow()`

#### ✅ Case 2: AnswerPolicy Allows, Threshold Allows
- [x] `base_risk_score = 0.1`, Policy `default` with threshold < 0.9
- [x] Expected: `decision_mode == "answer"`, final decision depends on old threshold (0.7)

**Test:** `test_case_2_answer_policy_allows_threshold_allows()`

#### ✅ Case 3: Fallback on Error
- [x] PolicyProvider throws exception
- [x] Expected: Warning log, fallback to normal threshold logic

**Test:** `test_case_3_fallback_on_error()`

**Status:** All integration tests implemented.

---

### 2.3. Full Test Suite (TODO)

**Action Required:**
- [ ] Run `pytest tests/ -v` with AnswerPolicy disabled (baseline)
- [ ] Run `pytest tests/ -v` with AnswerPolicy enabled for kids tenant
- [ ] Compare results: ASR, FPR, block rates

**Script:** `scripts/test_answer_policy_full_suite.py` (to be created)

---

## 3. Metrics Collection ✅

**Status:** IMPLEMENTED

**Implementation:**
- AnswerPolicy metadata **always** logged in `FirewallDecision.metadata["answer_policy"]`
- Even when disabled, metadata structure is present (with `enabled=False`)

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

**Metrics to Collect:**
- [ ] ASR (Attack Success Rate) per policy
- [ ] FPR (False Positive Rate) per policy
- [ ] Refusal/Block Rate (AnswerPolicy blocks vs. threshold)
- [ ] `p_correct` distribution histograms

**Script:** `scripts/analyze_answer_policy_metrics.py` (to be created)

---

## 4. Design Decisions ✅

**Status:** DOCUMENTED

**Documentation:** `docs/ANSWER_POLICY_DESIGN_DECISIONS.md`

### 4.1. AnswerPolicy as "Additional Brake" ✅

**Decision:** AnswerPolicy can only block (when `decision_mode == "silence"`). If it says "answer", decision still goes through existing threshold logic.

**Rationale:** Security-first, defense-in-depth, backward compatibility.

**Status:** Implemented and documented.

### 4.2. `p_correct = 1 - base_risk_score` as Heuristic ✅

**Decision:** Current implementation uses monotonic heuristic. Future enhancement: calibrated probability model.

**Status:** Implemented as heuristic, documented as placeholder for future calibration.

---

## 5. Documentation ✅

**Status:** COMPLETE

**Documents:**
- [x] `docs/ANSWER_POLICY_INTEGRATION.md` - Integration guide
- [x] `docs/ANSWER_POLICY_DESIGN_DECISIONS.md` - Design decisions
- [x] `ARCHITECTURE.md` - Architecture section added
- [x] `examples/answer_policy_example.py` - Usage examples

---

## 6. Next Steps (Recommended)

### Immediate (Before Production)

1. **Run Full Test Suite**
   ```bash
   pytest tests/core/test_answer_policy.py -v
   pytest tests/core/test_answer_policy_integration.py -v
   ```

2. **Experiment with Kids Policy**
   - Enable AnswerPolicy for kids tenant
   - Run existing kids/redteam test cases
   - Measure: Additional blocks, ASR improvement, FPR impact

3. **Metrics Analysis Script**
   - Create `scripts/analyze_answer_policy_metrics.py`
   - Aggregate metadata from test runs
   - Generate histograms and comparison tables

### Future Enhancements

1. **Calibrated Probability Model**
   - Train on Red-Team + benign datasets
   - Incorporate Dempster-Shafer, CUSUM, embedding signals
   - Replace heuristic with calibrated `p_correct`

2. **Pure Utility Mode (Optional)**
   - Configuration flag for "pure utility optimization"
   - Remove threshold logic when AnswerPolicy enabled
   - Requires extensive validation

---

## Summary

**Implementation Status:** ✅ COMPLETE

**Test Coverage:** ✅ Unit tests + Integration tests implemented

**Documentation:** ✅ Complete (Integration guide, design decisions, architecture)

**Metrics:** ✅ Always-logging implemented

**Next Action:** Run full test suite and measure empirical impact.

---

**Last Updated:** 2025-12-02
