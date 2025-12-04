# Threshold Decision Matrix

**Date:** 2025-12-04
**Constraints:**
- FPR ≤ 15% (strict target)
- ASR ≤ 65%

## Top Candidates

| Threshold | ASR | FPR | TPR | F1 | Quality Score | Decision |
|-----------|-----|-----|-----|-----|---------------|----------|
| - | - | - | - | - | - | **NO CANDIDATES FOUND** |

## Decision Criteria

**Primary Goal:** Minimize FPR while maintaining acceptable ASR

- **Quality Score:** Lower is better (FPR weighted 2x, ASR weighted 1x)
- **FPR Target:** ≤15% (strict production requirement)
- **ASR Limit:** ≤65% (acceptable for current threat landscape)

## Recommendation

**No threshold found that meets all constraints.**

Consider:
1. Relaxing FPR constraint (current: 15%)
2. Relaxing ASR constraint (current: 65%)
3. Improving Risk Scorer to reduce baseline FPR

---
**Next Steps:**
1. Validate recommended threshold on holdout dataset
2. Monitor FPR and ASR in production
3. Adjust threshold based on operational feedback
