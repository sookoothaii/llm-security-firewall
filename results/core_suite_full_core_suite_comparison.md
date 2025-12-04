# Phase-2 Evaluation Suite: Policy Comparison

## Summary

| Policy | ASR | FPR | Redteam Blocked | Benign Blocked | AP Blocks (RT) | AP Blocks (B) |
|--------|-----|-----|-----------------|---------------|----------------|--------------|
| baseline | 0.430 | 0.170 | 57/100 | 17/100 | 0 | 0 |
| default | 0.430 | 0.170 | 57/100 | 17/100 | 0 | 0 |
| internal_debug | 0.430 | 0.170 | 57/100 | 17/100 | 0 | 0 |
| kids | 0.400 | 0.220 | 60/100 | 22/100 | 3 | 5 |

## Detailed Results

### Policy: baseline

**Total items:** 200

**Redteam:**
- Total: 100
- Blocked: 57
- Allowed: 43
- ASR: 0.430
- Blocked by AnswerPolicy: 0

**Benign:**
- Total: 100
- Blocked: 17
- Allowed: 83
- FPR: 0.170
- Blocked by AnswerPolicy: 0

### Policy: default

**Total items:** 200

**Redteam:**
- Total: 100
- Blocked: 57
- Allowed: 43
- ASR: 0.430
- Blocked by AnswerPolicy: 0

**Benign:**
- Total: 100
- Blocked: 17
- Allowed: 83
- FPR: 0.170
- Blocked by AnswerPolicy: 0

### Policy: internal_debug

**Total items:** 200

**Redteam:**
- Total: 100
- Blocked: 57
- Allowed: 43
- ASR: 0.430
- Blocked by AnswerPolicy: 0

**Benign:**
- Total: 100
- Blocked: 17
- Allowed: 83
- FPR: 0.170
- Blocked by AnswerPolicy: 0

### Policy: kids

**Total items:** 200

**Redteam:**
- Total: 100
- Blocked: 60
- Allowed: 40
- ASR: 0.400
- Blocked by AnswerPolicy: 3

**Benign:**
- Total: 100
- Blocked: 22
- Allowed: 78
- FPR: 0.220
- Blocked by AnswerPolicy: 5
