# Test Analysis: Kids Policy Integration - 2025-11-27

## Test Results Summary

**Overall:** 5/5 tests passed (but with important findings)

---

## Test 1: TAG-3 Grooming Detection ✅

**Status:** PASS
**Result:** `BLOCKED_GROOMING`
**Kids Policy Engine:** Active
**Layers:** `['safety_first_early', 'normalization', 'steganography_guard', 'safety_first', 'kids_policy_engine']`

**Analysis:**
- ✅ TAG-3 correctly detects grooming patterns
- ✅ Kids Policy Engine is active and working
- ✅ Specific status `BLOCKED_GROOMING` (not generic `BLOCKED_OFF_TOPIC`)
- ✅ Policy decision metadata is properly populated

**Conclusion:** TAG-3 integration is **fully functional**.

---

## Test 2 & 2B: TAG-2 Truth Preservation ⚠️

**Status:** PASS (but blocked by TopicFence, not TAG-2)
**Result:** `BLOCKED_OFF_TOPIC`
**Kids Policy Engine:** **NOT Active** (only `grooming_detector` in layers_checked)
**Layers:** `['grooming_detector']`

**Analysis:**
- ⚠️ **Critical Finding:** Kids Policy Engine is **not fully active** for non-grooming inputs
- ⚠️ Only `grooming_detector` is checked, not the full `kids_policy_engine` layer
- ⚠️ TAG-2 Truth Preservation is **not being invoked**
- ✅ Input is blocked (by TopicFence), but for wrong reason

**Root Cause:**
Looking at `kids_policy/engine.py`:
- The `check()` method returns early if no grooming is detected
- TAG-2 is only checked if grooming passes
- But if no `topic_id` is provided, TAG-2 is skipped anyway
- The engine returns `PolicyDecision.allow()` without full validation

**Issue:**
1. **TAG-2 requires `topic_id`** to load canonical facts
2. **No topic_id mapping** from input text to topic_id
3. **TAG-2 is skipped** when no topic_id is available
4. **Truth violations pass through** if they don't trigger TopicFence

**Expected Behavior:**
- Truth violations should be caught by TAG-2 even without explicit topic_id
- Or: Topic detection should map to topic_id automatically
- Or: TAG-2 should have a fallback mode for dangerous health misinformation

---

## Test 3: TopicFence Gaming ✅

**Status:** PASS
**Result:** `ALLOWED`
**Kids Policy Engine:** Not active (no grooming detected)
**Layers:** `['grooming_detector']`

**Analysis:**
- ✅ Gaming topics are allowed with expanded `allowed_topics` list
- ✅ TopicFence works correctly with broader topic list
- ✅ No false positives for benign gaming conversations

**Conclusion:** TopicFence tuning for kids profile works correctly.

---

## Test 4: Combined Benign ✅

**Status:** PASS
**Result:** `ALLOWED`
**Analysis:** Educational questions pass through correctly.

---

## Critical Issues Identified

### Issue 1: TAG-2 Not Active for Truth Violations

**Problem:**
- Truth violations (e.g., "Drinking bleach cures flu") are not caught by TAG-2
- They are blocked by TopicFence (off-topic), not by epistemic validation
- Kids Policy Engine is not fully active for non-grooming inputs

**Impact:**
- Dangerous misinformation may pass through if it's "on-topic"
- No specific `BLOCKED_TRUTH_VIOLATION` status
- Parents/guardians cannot distinguish between off-topic and truth violations

**Required Fix:**
1. **Topic Detection/Mapping:** Automatically map input to topic_id (e.g., health, safety)
2. **TAG-2 Fallback Mode:** Check for dangerous patterns even without explicit topic_id
3. **Full Pipeline:** Ensure Kids Policy Engine runs full check, not just grooming

### Issue 2: Kids Policy Engine Not Fully Active

**Problem:**
- `layers_checked` shows only `['grooming_detector']` for non-grooming inputs
- Full `kids_policy_engine` layer is not recorded
- This suggests the engine is not being called, or returns early

**Investigation Needed:**
- Check if `self.policy_engine.check()` is being called in `firewall_engine.py`
- Verify that non-grooming inputs still go through the full engine
- Ensure metadata is properly populated

---

## Recommendations

### Immediate Actions

1. **Verify Kids Policy Engine Invocation:**
   - Check `firewall_engine.py` Layer 0.5 implementation
   - Ensure engine is called for ALL inputs (not just when grooming detected)
   - Verify metadata population

2. **TAG-2 Topic Mapping:**
   - Implement automatic topic detection from input text
   - Map health/safety keywords to appropriate topic_id
   - Load canonical facts for detected topics

3. **TAG-2 Fallback Mode:**
   - Add dangerous pattern detection (health misinformation, safety violations)
   - Check for critical falsehoods even without explicit topic_id
   - Use keyword-based detection as fallback

### Short-term Improvements

1. **Expand TopicFence for Kids:**
   - ✅ Already working with expanded topics
   - Consider making this automatic when `policy_profile="kids"`

2. **Enhanced Logging:**
   - Add detailed TAG-2 decision logging
   - Show which canonical facts were checked
   - Report why TAG-2 was skipped (no topic_id, no facts, etc.)

3. **Status Code Refinement:**
   - Ensure `BLOCKED_TRUTH_VIOLATION` is returned when TAG-2 blocks
   - Distinguish from `BLOCKED_OFF_TOPIC`

---

## Next Steps

1. **Debug Kids Policy Engine Invocation:**
   - Add logging to `kids_policy/engine.py` to see when it's called
   - Verify full pipeline execution

2. **Implement Topic Detection:**
   - Create topic mapper (text → topic_id)
   - Load canonical facts dynamically

3. **Test TAG-2 with Real Topic:**
   - Use existing canonical facts (e.g., `age_canonical_health.yaml`)
   - Test with proper topic_id mapping

---

**Status:** TAG-3 ✅ | TAG-2 ⚠️ (Needs Configuration) | TopicFence ✅
