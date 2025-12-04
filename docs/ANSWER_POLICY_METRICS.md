# AnswerPolicy Metrics Analysis
**Date:** 2025-12-02
**Status:** Documentation
**Author:** Joerg Bollwahn

---

## Overview

The AnswerPolicy metrics analysis pipeline provides **offline analysis** of AnswerPolicy behavior from decision logs. It is designed to be decoupled from the core engine (no runtime dependency) and enables empirical evaluation of different policy configurations.

---

## Purpose

The analysis script (`scripts/analyze_answer_policy_metrics.py`) computes:

1. **Global Statistics**
   - Total number of decisions
   - Count of decisions with AnswerPolicy enabled/disabled
   - Count of decisions missing AnswerPolicy metadata

2. **Per-Policy Statistics**
   - Count and percentage of `mode == "answer"` vs `mode == "silence"`
   - Block rate (total, by AnswerPolicy, by other safety reasons)
   - Mean and standard deviation of `p_correct` and `threshold`

3. **Histogram Summaries**
   - Distribution of `p_correct` in bins: `[0.0-0.2]`, `(0.2-0.4]`, `(0.4-0.6]`, `(0.6-0.8]`, `(0.8-1.0]`
   - For each bin: count of `mode == "answer"` vs `mode == "silence"`

**Bin Definitions (Explicit):**
- `[0.0-0.2]`: p_correct ∈ [0.0, 0.2] (very low confidence)
- `(0.2-0.4]`: p_correct ∈ (0.2, 0.4] (low confidence)
- `(0.4-0.6]`: p_correct ∈ (0.4, 0.6] (moderate confidence)
- `(0.6-0.8]`: p_correct ∈ (0.6, 0.8] (high confidence)
- `(0.8-1.0]`: p_correct ∈ (0.8, 1.0] (very high confidence)

These bins are fixed for consistency across analyses and future visualizations.

---

## Input Format

The script expects a **JSONL file** (one JSON object per line) where each line represents a `FirewallDecision` record.

**Minimum Required Fields:**
```json
{
  "allowed": true,
  "reason": "Input validated",
  "metadata": {
    "answer_policy": {
      "enabled": true,
      "policy_name": "kids",
      "p_correct": 0.95,
      "threshold": 0.98,
      "mode": "answer"
    }
  }
}
```

**Full Structure (with all optional fields):**
```json
{
  "allowed": false,
  "reason": "Epistemic gate: p_correct=0.85 < threshold=0.98 (policy: kids)",
  "risk_score": 0.15,
  "metadata": {
    "answer_policy": {
      "enabled": true,
      "policy_name": "kids",
      "p_correct": 0.85,
      "threshold": 0.98,
      "mode": "silence",
      "expected_utility_answer": -6.5,
      "expected_utility_silence": 0.0
    },
    "unicode_flags": {},
    "encoding_anomaly_score": 0.0
  }
}
```

**Note:** The script handles missing fields gracefully. If `answer_policy` metadata is missing, the decision is counted under "missing_metadata" but analysis continues.

---

## Usage

### Basic Analysis

```bash
python scripts/analyze_answer_policy_metrics.py --input logs/decisions.jsonl
```

**Output:** Prints formatted summary to stdout with:
- Global counts
- Per-policy statistics
- Histogram summary

### With CSV Export

```bash
python scripts/analyze_answer_policy_metrics.py \
  --input logs/decisions.jsonl \
  --output-csv metrics/answer_policy_summary.csv
```

**CSV Format:** One row per policy with columns:
- `policy_name`, `count`, `answer_count`, `answer_percentage`, `silence_count`, `silence_percentage`
- `blocked_count`, `block_rate`, `blocked_by_answer_policy`, `answer_policy_block_rate`, `blocked_by_other`
- `p_correct_mean`, `p_correct_std`, `threshold_mean`, `threshold_std`

---

## Metrics Explained

### Refusal Rate

**Definition:** Percentage of decisions where AnswerPolicy says `mode == "silence"`.

**Interpretation:**
- High refusal rate (e.g., >50%) → Policy is very conservative (blocks many requests)
- Low refusal rate (e.g., <10%) → Policy is permissive (allows most requests)

**Use Case:** Compare `kids` policy (high threshold, high refusal rate) vs `default` policy (moderate threshold, lower refusal rate).

### Block Rate

**Definition:** Percentage of decisions where `allowed == False`.

**Breakdown:**
- **Total block rate**: All blocked decisions
- **AnswerPolicy block rate**: Decisions blocked specifically by AnswerPolicy (`mode == "silence"` or reason contains "Epistemic gate")
- **Other block rate**: Decisions blocked by other safety layers (threshold, RegexGate, Kids Policy, etc.)

**Use Case:** Measure how often AnswerPolicy adds additional blocking beyond existing safety layers.

### p_correct Distribution

**Definition:** Histogram of `p_correct` values grouped by decision mode.

**Interpretation:**
- If most `mode == "silence"` decisions have low `p_correct` (e.g., <0.5) → Policy is working as intended (blocking low-confidence cases)
- If many `mode == "answer"` decisions have low `p_correct` (e.g., <0.3) → Policy might be too permissive
- If most decisions have high `p_correct` (e.g., >0.8) → Inputs are generally low-risk

**Use Case:** Identify distribution shifts when comparing different policies or test datasets.

---

## Integration with Test Suites

### Example Workflow

1. **Run test suite with AnswerPolicy enabled:**
   ```python
   from llm_firewall.core.firewall_engine_v2 import FirewallEngine
   from llm_firewall.core.policy_provider import get_default_provider

   engine = FirewallEngine()
   provider = get_default_provider()

   decisions = []
   for test_input in test_suite:
       decision = engine.process_input(
           test_input,
           use_answer_policy=True,
           policy_provider=provider,
           tenant_id="test_tenant",
       )
       decisions.append({
           "allowed": decision.allowed,
           "reason": decision.reason,
           "risk_score": decision.risk_score,
           "metadata": decision.metadata,
       })
   ```

2. **Export to JSONL:**
   ```python
   import json

   with open("logs/decisions.jsonl", "w") as f:
       for decision in decisions:
           f.write(json.dumps(decision) + "\n")
   ```

3. **Analyze:**
   ```bash
   python scripts/analyze_answer_policy_metrics.py --input logs/decisions.jsonl
   ```

4. **Compare with baseline (AnswerPolicy disabled):**
   - Run same test suite with `use_answer_policy=False`
   - Compare block rates, ASR, FPR

---

## Block Source Distinction

**Current Implementation:**
The analysis script distinguishes between:
- **Blocked by AnswerPolicy**: `mode == "silence"` OR `reason` contains "Epistemic gate"
- **Blocked by other reasons**: `allowed == False` but not blocked by AnswerPolicy

**Limitation:**
This is a heuristic based on reason string matching. For more precise attribution, consider adding explicit `block_source` field to decision metadata in future versions.

**Example Reason Patterns:**
- `"Epistemic gate: p_correct=0.85 < threshold=0.98 (policy: kids)"` → AnswerPolicy block
- `"High risk from unicode obfuscation"` → Other safety layer block
- `"[Layer 0.5] BLOCKED by RegexGate: ..."` → Other safety layer block

---

## Limitations

1. **Heuristic p_correct**: Current `p_correct = 1.0 - base_risk_score` is a placeholder heuristic, not a calibrated probability. Future work should implement a calibrated estimator.

2. **Offline Only**: This script is designed for offline analysis. It does not provide real-time metrics or dashboards.

3. **No Ground Truth**: The script does not compute ASR/FPR directly (requires labeled test data). It provides the metrics needed to compute ASR/FPR when combined with ground truth labels.

4. **Block Source Heuristic**: Block attribution (AnswerPolicy vs. other) is based on reason string matching, not explicit flags. This is sufficient for first evaluation round but could be improved with explicit `block_source` metadata.

---

## Sample Results

After running experiments (see `docs/ANSWER_POLICY_EXPERIMENTS.md`), document empirical results here:

### Example: Kids Policy vs. Baseline

*(To be filled in after Experiment 1)*

**Baseline (AnswerPolicy disabled):**
- Total decisions: XXX
- Block rate: XX.X%

**Kids Policy (AnswerPolicy enabled):**
- Total decisions: XXX
- Block rate: XX.X%
- AnswerPolicy block rate: XX.X%
- Mode distribution:
  - `answer`: XX.X%
  - `silence`: XX.X%

**Key Finding:** Kids Policy increases block rate by X.X% through AnswerPolicy, primarily blocking low `p_correct` cases.

---

## Future Enhancements

1. **ASR/FPR Computation**: Add support for labeled test data to compute Attack Success Rate and False Positive Rate directly.

2. **Visualization**: Add optional plotting support (matplotlib) for histogram visualization.

3. **Comparison Mode**: Add `--compare` flag to compare two JSONL files (e.g., with vs. without AnswerPolicy).

4. **Time-Series Analysis**: If decision records include timestamps, add time-series analysis (e.g., block rate over time).

5. **Explicit Block Source**: Add `block_source` field to decision metadata for precise attribution (AnswerPolicy vs. other safety layers).

---

## References

- Integration Guide: `docs/ANSWER_POLICY_INTEGRATION.md`
- Design Decisions: `docs/ANSWER_POLICY_DESIGN_DECISIONS.md`
- Review Checkpoints: `docs/ANSWER_POLICY_REVIEW_CHECKPOINTS.md`
