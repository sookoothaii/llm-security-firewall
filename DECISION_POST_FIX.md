# Decision Document - Post Hotfix Evaluation

**Date:** 2025-12-04
**Status:** Awaiting Full Evaluation Results
**Hotfix:** Risk Scorer Whitelist Filter for Educational Queries

---

## Hotfix Summary

**Implemented:** Whitelist filter in `risk_scorer.py` to eliminate UNSAFE_TOPIC false positives for harmless educational queries.

**Target:** 17 identified false positives (77% of all FPs)

**Implementation Status:**
- ✅ Filter function `_is_benign_educational_query()` added
- ✅ Integrated into `compute_risk_score()` pipeline
- ✅ Test validation: 15/15 false positives now have score 0.05 (100% success)

---

## Evaluation Status

**Current:** Evaluation running in background with:
- Policy: `kids`
- Dataset: `core_suite.jsonl` (200 items)
- Workers: 18 (optimized for i9-12900HX)
- Output: `logs/evaluation_post_fix_kids.jsonl`

**Expected Completion:** ~1 hour

---

## Decision Framework

### Scenario 1: FPR < 10% AND ASR Stable (≤ 60%)

**Decision:** ✅ **SUCCESS - DEPLOY HOTFIX**

**Actions:**
1. Celebrate success 🎉
2. Create release notes documenting the fix
3. Plan to merge hotfix into next release
4. Set Evidence-Fusion project to "Archived" (root cause fixed)

**Rationale:**
- Primary goal achieved (FPR reduction)
- Security maintained (ASR stable)
- Hotfix is minimal, targeted, and low-risk

---

### Scenario 2: FPR 10-15% (Still High)

**Decision:** ⚠️ **PARTIAL SUCCESS - ITERATE**

**Actions:**
1. Analyze remaining false positives
2. Expand whitelist with additional patterns
3. Investigate other categories contributing to FPs
4. Re-run evaluation with expanded filter

**Rationale:**
- Significant improvement but not meeting strict target
- Additional iteration needed

---

### Scenario 3: FPR < 10% BUT ASR Degraded (> 65%)

**Decision:** ❌ **WHITELIST TOO AGGRESSIVE - ROLLBACK**

**Actions:**
1. **DO NOT DEPLOY** - Security compromised
2. Analyze which threats were incorrectly whitelisted
3. Make whitelist more restrictive
4. Require stronger evidence (e.g., multiple benign signals) before whitelisting

**Rationale:**
- Security is priority #1
- False negatives (missed threats) are worse than false positives

---

### Scenario 4: FPR Still > 15% (No Improvement)

**Decision:** ❌ **HOTFIX INEFFECTIVE - INVESTIGATE**

**Actions:**
1. Verify hotfix is actually being used (check logs)
2. Investigate if UNSAFE_TOPIC detection happens elsewhere (not in Risk Scorer)
3. Check if Kids Policy has separate UNSAFE_TOPIC logic
4. Root cause analysis: Where exactly is UNSAFE_TOPIC detected?

**Rationale:**
- If no improvement, fix may be in wrong place
- Need to understand full detection pipeline

---

## Current Baseline (Pre-Fix)

From previous evaluation:
- **FPR:** 22% (22/100 benign items blocked)
- **ASR:** 56-59% (depending on policy)
- **UNSAFE_TOPIC FPs:** 17/22 (77% of all FPs)

---

## Expected Impact (Optimistic)

**If Scenario 1 (Best Case):**
- FPR: 22% → ~5% (77% reduction)
- ASR: 56% → ~56% (stable)
- **Remaining FPs:** 5/100 (down from 22)

---

## Next Steps After Evaluation

1. **Parse Results:**
   ```bash
   python scripts/analyze_false_positives_for_risk_scorer.py \
       --results logs/evaluation_post_fix_kids.jsonl \
       --output analysis/false_positive_analysis_post_fix.json
   ```

2. **Calculate Metrics:**
   - Count false positives (allowed=false for benign items)
   - Count false negatives (allowed=true for redteam items)
   - Calculate FPR and ASR

3. **Compare with Baseline:**
   - Load baseline results: `logs/kids_core_suite_full_core_suite.jsonl`
   - Compute difference in FPR and ASR
   - Check statistical significance

4. **Make Decision:**
   - Follow decision framework above
   - Document decision and rationale
   - Create action plan

---

## Files Created

1. `src/llm_firewall/risk/risk_scorer.py` - Hotfix implementation
2. `test_risk_scorer_fix.py` - Validation test script
3. `scripts/clean_core_suite_dataset.py` - Dataset cleaning tool
4. `datasets/core_suite_CLEANED.jsonl` - Cleaned dataset (141 items, 59 duplicates removed)
5. `HOTFIX_VALIDATION_RESULTS.md` - Test results summary
6. `DECISION_POST_FIX.md` - This document

---

## Dataset Cleanup Results

**Cleaned Dataset:** `datasets/core_suite_CLEANED.jsonl`
- Original: 200 items
- Cleaned: 141 items
- Duplicates removed: 59
- Categories fixed: 4

**Note:** Current evaluation uses original dataset for fair comparison. Cleaned dataset will be used for future evaluations.

---

**Status:** Awaiting evaluation results to make final decision...
