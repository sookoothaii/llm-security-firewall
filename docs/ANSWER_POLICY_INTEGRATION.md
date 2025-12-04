# AnswerPolicy Integration Guide
**Date:** 2025-12-02
**Status:** Implementation Proposal
**Author:** Joerg Bollwahn

---

## Overview

AnswerPolicy implements an **epistemic decision layer** that replaces/additional to simple threshold-based decisions with explicit cost-benefit trade-offs.

**Mathematical Foundation:**
```
E[U(answer)] = p_correct * B - (1 - p_correct) * C
E[U(silence)] = -A

Answer if: p_correct >= (C - A) / (C + B)
```

Where:
- `p_correct`: Estimated probability that answer is correct (derived from `1.0 - risk_score`)
- `B`: Benefit if answer is correct
- `C`: Cost if answer is wrong
- `A`: Cost of silence (block / no answer)

---

## Files Created

1. **`src/llm_firewall/core/decision_policy.py`**
   - `AnswerPolicy` class with threshold calculation
   - Predefined policies: `default`, `kids`, `strict`, `permissive`, `internal_debug`

2. **`src/llm_firewall/core/policy_provider.py`**
   - `PolicyProvider` class for per-tenant/per-route policy selection
   - YAML configuration support
   - Fallback to default policy

3. **`config/answer_policy.yaml`**
   - Configuration file with policy definitions
   - Can be customized per deployment

---

## Integration Point

**Location:** `src/llm_firewall/core/firewall_engine_v2.py`, line ~448

**Current Code:**
```python
# Line 447-448 (current)
decision = FirewallDecision(
    allowed=True if base_risk_score < 0.7 else False,  # Block if risk too high
    ...
)
```

**Proposed Integration:**
```python
# After line 445 (after risk score calculation, before decision creation)

# AnswerPolicy Integration (optional, can be disabled)
use_answer_policy = kwargs.get("use_answer_policy", False)
policy_provider = kwargs.get("policy_provider", None)

if use_answer_policy and policy_provider is not None:
    try:
        tenant_id = kwargs.get("tenant_id", "default")
        route = kwargs.get("route", None)
        context = kwargs.get("context", {})

        policy = policy_provider.for_tenant(tenant_id, route=route, context=context)
        p_correct = max(0.0, min(1.0, 1.0 - base_risk_score))
        decision_mode = policy.decide(p_correct, risk_score=base_risk_score)

        if decision_mode == "silence":
            decision = FirewallDecision(
                allowed=False,
                reason=f"Epistemic gate: p_correct={p_correct:.3f} < threshold={policy.threshold():.3f} (policy: {policy.policy_name or 'unknown'})",
                sanitized_text=clean_text,
                risk_score=base_risk_score,
                metadata={
                    "unicode_flags": unicode_flags,
                    "encoding_anomaly_score": encoding_anomaly_score,
                    "answer_policy": {
                        "policy_name": policy.policy_name,
                        "p_correct": p_correct,
                        "threshold": policy.threshold(),
                        "expected_utility_answer": policy.expected_utility_answer(p_correct),
                        "expected_utility_silence": policy.expected_utility_silence(),
                    },
                },
            )
            # Cache and return early
            # ... (cache logic same as below)
            return decision
        # If decision_mode == "answer", continue to normal decision logic
    except Exception as e:
        logger.warning(f"[AnswerPolicy] Error in policy evaluation: {e}. Falling back to threshold-based decision.")
        # Fall through to normal threshold logic

# Normal threshold-based decision (existing code, line 447-458)
decision = FirewallDecision(
    allowed=True if base_risk_score < 0.7 else False,
    reason="Input validated" if base_risk_score < 0.7 else "High risk from unicode obfuscation",
    sanitized_text=clean_text,
    risk_score=base_risk_score,
    metadata={
        "unicode_flags": unicode_flags,
        "encoding_anomaly_score": encoding_anomaly_score,
    },
)
```

---

## Usage Examples

### Example 1: Enable AnswerPolicy in FirewallEngine

```python
from llm_firewall.core.firewall_engine_v2 import FirewallEngine
from llm_firewall.core.policy_provider import PolicyProvider, get_default_provider

# Option A: Use default provider (loads from config/answer_policy.yaml)
engine = FirewallEngine()
policy_provider = get_default_provider()

# Option B: Custom provider with tenant mapping
policy_provider = PolicyProvider(
    tenant_policy_map={
        "tenant_kids": "kids",
        "tenant_enterprise": "default",
        "tenant_research": "internal_debug",
    },
    route_policy_map={
        "/api/kids": "kids",
        "/api/public": "strict",
    },
)

# Use in process_input
decision = engine.process_input(
    text="user input",
    tenant_id="tenant_kids",
    route="/api/kids",
    use_answer_policy=True,
    policy_provider=policy_provider,
)
```

### Example 2: Kids Policy (High Cost for Wrong Answers)

```python
from llm_firewall.core.decision_policy import get_policy

kids_policy = get_policy("kids")
# Threshold: (50 - 0) / (50 + 1) ≈ 0.98

p_correct = 0.95  # 95% confidence
decision = kids_policy.decide(p_correct)
# Returns: "silence" (0.95 < 0.98)

p_correct = 0.99  # 99% confidence
decision = kids_policy.decide(p_correct)
# Returns: "answer" (0.99 >= 0.98)
```

### Example 3: Internal Debug Policy (Low Cost for Wrong Answers)

```python
debug_policy = get_policy("internal_debug")
# Threshold: (1 - 2) / (1 + 1) = -0.5 → clamped to 0.0

p_correct = 0.1  # 10% confidence
decision = debug_policy.decide(p_correct)
# Returns: "answer" (0.1 >= 0.0) - always answers for research
```

---

## Configuration

### YAML Configuration (`config/answer_policy.yaml`)

```yaml
kids:
  benefit_correct: 1.0
  cost_wrong: 50.0
  cost_silence: 0.0
  description: "Child safety policy - very high cost for wrong answers"
```

### Programmatic Configuration

```python
from llm_firewall.core.decision_policy import AnswerPolicy
from llm_firewall.core.policy_provider import PolicyProvider

custom_policy = AnswerPolicy(
    benefit_correct=1.0,
    cost_wrong=30.0,
    cost_silence=0.0,
    policy_name="custom_strict",
)

provider = PolicyProvider()
provider.add_policy(custom_policy)
```

---

## Integration with Existing Components

### Connection to Dempster-Shafer

If Dempster-Shafer mass assignments are available:
```python
# Instead of: p_correct = 1.0 - risk_score
# Use: p_correct = m_safe + 0.5 * m_unknown  # Conservative estimate
```

### Connection to CUSUM

If CUSUM detects oscillation/drift:
```python
# Lower p_correct for session if CUSUM alarm
if cusum_alarm:
    p_correct *= 0.5  # Reduce confidence
```

---

## Testing

### Unit Tests

```python
def test_answer_policy_threshold():
    policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)
    assert policy.threshold() == (9.0 - 0.0) / (9.0 + 1.0)  # 0.9

def test_kids_policy():
    kids = get_policy("kids")
    assert kids.decide(0.95) == "silence"  # Below threshold
    assert kids.decide(0.99) == "answer"   # Above threshold

def test_policy_provider():
    provider = PolicyProvider(tenant_policy_map={"tenant1": "kids"})
    policy = provider.for_tenant("tenant1")
    assert policy.policy_name == "kids"
```

### Integration Tests

```python
def test_firewall_with_answer_policy():
    engine = FirewallEngine()
    provider = get_default_provider()

    # High risk input
    decision = engine.process_input(
        text="malicious input with high risk",
        use_answer_policy=True,
        policy_provider=provider,
        tenant_id="tenant_kids",
    )

    # Should be blocked by AnswerPolicy if p_correct < threshold
    assert decision.allowed == False
    assert "Epistemic gate" in decision.reason
```

---

## Benefits

1. **Explicit Cost-Benefit Trade-offs**: No hidden heuristics, all decisions traceable
2. **Per-Tenant/Per-Route Policies**: Different risk tolerances for different use cases
3. **Measurable Policy Comparisons**: Compare ASR/FPR for different cost configurations
4. **Consistent Hallucination Handling**: Formal utility-based approach to "answer vs silence"
5. **Research-Ready**: Can be cited in papers, clear mathematical foundation

---

## Next Steps

1. **Review Integration Point**: Confirm line 448 is correct insertion point
2. **Add Import Statements**: Add AnswerPolicy imports to firewall_engine_v2.py
3. **Test with Existing Test Suite**: Run adversarial tests with AnswerPolicy enabled
4. **Measure Impact**: Compare ASR/FPR with/without AnswerPolicy
5. **Documentation**: Add to README.md under "Advanced Features"

---

**Note:** This is a proposal. No code has been modified in `firewall_engine_v2.py` yet. Review and approve before integration.

---

## Metrics Analysis

### Overview

The AnswerPolicy implementation includes comprehensive metadata logging in every `FirewallDecision`. This enables **offline analysis** of AnswerPolicy behavior without modifying core engine behavior.

### Analysis Script

**Script:** `scripts/analyze_answer_policy_metrics.py`

**Purpose:**
- Analyze AnswerPolicy behavior from decision logs (JSONL format)
- Compute metrics: ASR/FPR-like statistics, refusal rate, policy usage
- Generate histogram summaries of `p_correct` distribution vs. decision mode

**Expected Input:**
JSONL file where each line is a JSON object representing a `FirewallDecision` with at least:
- `allowed` (bool)
- `reason` (string, optional)
- `metadata.answer_policy` (object with `enabled`, `policy_name`, `p_correct`, `threshold`, `mode`)

**Example Invocation:**
```bash
# Basic analysis (prints summary to stdout)
python scripts/analyze_answer_policy_metrics.py --input logs/decisions.jsonl

# With CSV export
python scripts/analyze_answer_policy_metrics.py --input logs/decisions.jsonl --output-csv metrics/summary.csv
```

**Output:**
- Global counts (total, enabled/disabled, missing metadata)
- Per-policy statistics:
  - Count and percentage of `mode == "answer"` vs `mode == "silence"`
  - Block rate (total, by AnswerPolicy, by other reasons)
  - Mean and standard deviation of `p_correct` and `threshold`
- Histogram: Distribution of `p_correct` in bins `[0.0-0.2]`, `(0.2-0.4]`, ..., `(0.8-1.0]` vs. decision mode

**Use Cases:**
- **Offline analysis**: Compare AnswerPolicy behavior across different test runs
- **Policy comparison**: Compare `kids` vs `default` policies in terms of:
  - Refusal rate (how often AnswerPolicy says "silence")
  - Block rate (how often requests are blocked)
  - Distribution of `p_correct` vs. decisions
- **Empirical evaluation**: Measure ASR/FPR impact of AnswerPolicy on existing test suites

**Note:** This script is **purely offline** (no network access, no LLM calls). It uses only standard library (`argparse`, `json`, `collections`, `statistics`).

For more details, see `docs/ANSWER_POLICY_METRICS.md`.
