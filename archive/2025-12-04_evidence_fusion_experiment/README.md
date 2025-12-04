# Evidence Fusion Experiment Archive

**Date:** 2025-12-04
**Status:** Experiment Paused / Superseded by Hotfix v2.4.1

---

## Summary

This archive contains the evidence-based answer policy integration experiment that was paused in favor of a targeted hotfix solution.

**Root Cause:** The evaluation revealed that the false positive problem was in the upstream Risk Scorer (UNSAFE_TOPIC classification), not in the answer policy logic.

**Solution:** A simple whitelist filter (`_is_benign_educational_query()`) in the Kids Policy eliminated all 17 UNSAFE_TOPIC false positives, achieving FPR 5% (down from 22%) without the complexity of Dempster-Shafer evidence fusion.

**Result:** The evidence fusion architecture was not needed. The hotfix (83 lines) outperformed the complex fusion layer.

---

## Lessons Learned

1. **Root Cause Analysis is Critical:** Empirical validation revealed the problem was upstream (Risk Scorer), not in the answer policy logic.

2. **Simple Solutions Can Be Superior:** A targeted whitelist filter outperformed a complex evidence fusion architecture.

3. **Evidence-Based Decision Making:** Comprehensive evaluation (200 items) provided clear direction for the fix.

4. **Iterative Improvement:** The project highlights the importance of empirical validation and root-cause analysis over architectural expansion.

---

## Archived Components

### Scripts
- `test_engine_evidence_integration.py` - Integration test for evidence-based policy
- `test_evidence_based_policy.py` - Evidence-based policy test suite
- `scripts/test_evidence_calibration_fixes.py` - Calibration fixes for evidence fusion
- `scripts/compute_answerpolicy_effectiveness.py` - Effectiveness computation
- `scripts/analyze_answer_policy_metrics.py` - Metrics analysis

### Core Implementation (Still in Production)
- `src/llm_firewall/fusion/dempster_shafer.py` - Dempster-Shafer fusion implementation (kept for future use)
- `tests/test_dempster_shafer_fusion.py` - Unit tests for fusion logic (kept for future use)

### Evaluation Results
- `logs/kids_evidence_*.jsonl` - Evidence-based evaluation logs
- `logs/evidence_final_scaled.jsonl` - Scaled evaluation results
- `results/evidence_full_analysis.md` - Full analysis report
- `results/pcorrect_metrics_comparison_report.md` - Metrics comparison

### Configuration
- Evidence fusion thresholds and calibration parameters
- Answer policy gate configurations

---

## Future Use

The Dempster-Shafer fusion implementation (`src/llm_firewall/fusion/dempster_shafer.py`) remains in the codebase for potential future use cases where evidence fusion is needed. However, for the false positive reduction problem, the simple whitelist filter was the superior solution.

---

## References

- **Hotfix Summary:** `FINAL_HOTFIX_SUMMARY.md`
- **Decision Document:** `FINAL_DECISION_HOTFIX_DEPLOY.md`
- **Handover Document:** `docs/HANDOVER_EVIDENCE_BASED_ANSWERPOLICY.md` (Chapter 9: Resolution & Outcome)

---

**Status:** Archived - Experiment Superseded by Hotfix v2.4.1
