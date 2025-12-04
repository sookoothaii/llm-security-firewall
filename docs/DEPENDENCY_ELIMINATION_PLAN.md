# Dependency Elimination Plan

**Date:** 2025-12-05
**Target:** Eliminate ~1039 MB from top 3 dependencies (torch, transformers, tensorflow)

## Critical Findings

| Dependency | Memory (MB) | Status | Action Required |
|------------|-------------|--------|-----------------|
| **transformers** | 362.7 | **CRITICAL** | Eliminate from main path |
| **torch** | 350.9 | **CRITICAL** | Eliminate from main path |
| **tensorflow** | 325.9 | **CRITICAL** | Eliminate (likely transitive) |
| sklearn | 123.2 | HIGH | Make optional/lazy |
| pandas | 61.0 | MEDIUM | Review usage |

**Total Critical:** 1039.5 MB
**Target Reduction:** ~400 MB to reach 300 MB goal

## Import Analysis

### torch (350.9 MB)

**Main Path Imports:**
- `src/llm_firewall/input_protection/topic_fence.py` (lazy import - OK)
- `src/layer15/validators/age_stratified_nli.py` (check if in main path)

**Action:**
1. Verify `topic_fence.py` lazy import is working correctly
2. Check if `age_stratified_nli.py` is used in main firewall path
3. If yes, convert to ONNX or make optional

### transformers (362.7 MB)

**Main Path Imports:**
- `kids_policy/__init__.py` → `TruthPreservationValidatorV2_3` → `transformers`
- `src/layer15/crisis.py` (check if in main path)

**Action:**
1. Make `TruthPreservationValidatorV2_3` import lazy (already done via property)
2. Verify `crisis.py` is not in main path
3. Ensure transformers only loaded when validator is actually used

### tensorflow (325.9 MB)

**No direct imports found** - likely transitive dependency

**Action:**
1. Find transitive import source
2. Likely from `transformers` or `sentence_transformers`
3. Will be eliminated when transformers/torch are removed

## Implementation Plan

### Phase 1: Verify Lazy Loading (P0)

**Goal:** Ensure torch/transformers are NOT loaded at import time

1. **Verify `topic_fence.py`:**
   - Already has lazy import (line 45)
   - Confirm it's not triggered at module import

2. **Verify `kids_policy/__init__.py`:**
   - Currently imports `TruthPreservationValidatorV2_3` at module level
   - **FIX:** Make import conditional or move to lazy property

3. **Test:** Run PoC again after fixes to measure reduction

### Phase 2: Make Critical Dependencies Optional (P0)

**Goal:** Ensure main firewall path doesn't require torch/transformers

1. **Update `kids_policy/__init__.py`:**
   ```python
   # Remove direct import
   # Make TruthPreservationValidatorV2_3 available only via lazy property
   ```

2. **Update `topic_fence.py`:**
   - Already lazy, but verify it's not triggered unnecessarily

3. **Test:** Verify firewall works without torch/transformers in main path

### Phase 3: ONNX Migration for Remaining Components (P1)

**Goal:** Convert remaining torch-dependent components to ONNX

1. **TopicFence:** Convert to ONNX (if used in main path)
2. **AgeStratifiedNLI:** Convert to ONNX (if used in main path)

## Expected Results

After Phase 1 & 2:
- **Baseline reduction:** ~700-800 MB (eliminate torch + transformers from main path)
- **New baseline:** ~200-300 MB (ONNX Runtime + essential libs only)

After Phase 3:
- **Full elimination:** ~1039 MB saved
- **Final baseline:** ~50-100 MB (well under 300 MB target)

## Next Steps

1. **Immediate:** Fix `kids_policy/__init__.py` to remove direct transformers import
2. **Verify:** Run PoC again to measure actual reduction
3. **Document:** Update progress report with findings
