# Advanced Components: Calibrated Stacking and Band-Judge

**Status:** Optional components for research and advanced deployments  
**Difficulty:** Advanced  
**Requirements:** Python programming, ML knowledge, API access

---

## Overview

The framework includes two advanced components designed for research and high-security deployments:

1. **Calibrated Risk Stacking** - ML-based risk aggregation
2. **Band-Judge** - LLM-as-Judge for uncertainty band

These are **NOT included in the default pipeline** because they require:
- Labeled training data (Stacking)
- API keys and latency tolerance (Band-Judge)

---

## 1. Calibrated Risk Stacking

### What It Does

Aggregates multiple risk signals (pattern scores, semantic scores, toxicity) using calibrated machine learning instead of simple weighted sums.

**Pipeline:**
```
Feature Extraction → LogisticRegression → Platt Scaling → Conformal Prediction → Risk Score
```

### When To Use

- You have labeled training data (n >= 100 examples)
- You need better uncertainty quantification than heuristic thresholds
- You want statistically rigorous confidence intervals

### How To Use

**Step 1: Prepare training data**

```python
import numpy as np
from llm_firewall.risk.stacking import fit_aggregator

# Collect features from your validation pipeline
# Features: [pattern_score, semantic_score, toxicity_score, confidence]
X_train = np.array([
    [0.8, 0.9, 0.7, 0.85],  # Known attack
    [0.1, 0.2, 0.0, 0.90],  # Known safe
    # ... at least 100 examples ...
])

# Labels: 1 = unsafe (should block), 0 = safe
y_train = np.array([1, 0, ...])  # Binary labels
```

**Step 2: Train calibrated stacker**

```python
# Fit on training data
aggregator = fit_aggregator(
    X_dev=X_train,
    y_dev=y_train,
    tau_block=0.85,   # Block threshold
    epsilon=0.05,     # Uncertainty band width
    alpha=0.10        # Conformal coverage (90%)
)
```

**Step 3: Use in production**

```python
# Extract features from new input
features = np.array([[pattern_score, semantic_score, toxicity, confidence]])

# Get calibrated decision
should_block, risk_proba = aggregator.decide(features)

if should_block[0]:
    print(f"BLOCK: Risk = {risk_proba[0]:.3f}")
else:
    print(f"SAFE: Risk = {risk_proba[0]:.3f}")
```

**Step 4: Integrate with SecurityFirewall**

Currently requires manual integration. The component is available for research use via `bench/run_eval.py`.

### Data Requirements

**Minimum viable:**
- n >= 100 labeled examples
- Balanced classes (40-60% unsafe examples)
- Representative of production traffic

**Recommended:**
- n >= 500 for stable calibration
- Hold-out validation set (20%)
- Temporal split (older data = train, recent = test)

### Performance

- Conformal guarantee: (1 - alpha) coverage on calibration set
- Platt scaling: Calibrated probabilities (not raw logistic output)
- Uncertainty quantification: q_alpha floor prevents overconfidence

---

## 2. Band-Judge

### What It Does

Uses external LLM (DeepSeek or GPT-4) as meta-check, but **ONLY** for samples in uncertainty band.

**Trigger condition:**
```python
|p_risk - tau_block| < epsilon
```

If risk score is near decision threshold, invoke LLM judge. Otherwise trust statistical model.

### When To Use

- You have API budget for external calls
- You can tolerate 500-2000ms added latency
- You need highest possible accuracy for edge cases

### How To Use

**Step 1: Set API key**

```bash
export DEEPSEEK_API_KEY="sk-..."
# or
export OPENAI_API_KEY="sk-..."
```

**Step 2: Initialize**

```python
from llm_firewall.safety.band_judge import BandJudge

judge = BandJudge(
    model="deepseek-chat",  # or "gpt-4o-mini"
    api_key=None,           # Reads from env
    cache_enabled=True
)

if not judge.available:
    print("WARNING: BandJudge not available (missing API key or openai package)")
```

**Step 3: Use in uncertainty band**

```python
# After getting risk score from main pipeline
if abs(risk_score - 0.85) < 0.05:  # Near threshold
    result = judge.judge(
        prompt=user_query,
        risk_score=risk_score
    )
    
    if not result.is_safe:
        print(f"BLOCK (LLM Judge): {result.reasoning}")
```

**Step 4: Monitor efficiency**

Band-Judge should trigger on ~10-30% of samples (not all). If triggering on >50%, tune epsilon or tau_block.

### Cost Estimation

**DeepSeek-chat:**
- ~$0.14 per 1M input tokens
- ~$0.28 per 1M output tokens
- Typical call: 200 input + 50 output tokens = $0.00004 per call

**GPT-4o-mini:**
- ~$0.15 per 1M input tokens
- ~$0.60 per 1M output tokens
- Typical call: 200 input + 50 output tokens = $0.00006 per call

If 20% of traffic triggers Band-Judge at 1000 req/day:
- Daily cost: ~$0.80 (DeepSeek) or ~$1.20 (GPT-4o-mini)

### Integration Status

**Current:** Available as standalone component in `src/llm_firewall/safety/band_judge.py`

**Future:** Will be integrated into `SecurityFirewall` when `use_band_judge=True` config option is set.

**Now:** Use directly in custom pipelines or evaluation scripts.

---

## 3. Example: Advanced Pipeline

```python
from llm_firewall import SecurityFirewall, FirewallConfig
from llm_firewall.risk.stacking import fit_aggregator
from llm_firewall.safety.band_judge import BandJudge
import numpy as np

# Initialize standard firewall
config = FirewallConfig()
firewall = SecurityFirewall(config)

# Train stacking model (if you have data)
X_train = load_training_features()  # Your labeled dataset
y_train = load_training_labels()
stacker = fit_aggregator(X_train, y_train)

# Initialize band-judge
judge = BandJudge(model="deepseek-chat")

# Custom validation with advanced components
def advanced_validate(query: str):
    # Standard pipeline first
    is_safe, reason = firewall.validate_input(query)
    
    # Extract features for stacking (if available)
    # This requires access to internal signals - advanced use only
    
    # Use band-judge for uncertain cases
    # Implementation left to advanced users
    
    return is_safe, reason
```

---

## 4. Limitations

**Why Not Default?**

1. **Stacking:** Requires domain-specific training data not included in package
2. **Band-Judge:** Requires API keys, adds latency, costs money
3. **Integration:** Requires custom pipeline code (not yet in `core.py`)

**Current Use Cases:**

- Research evaluation (`bench/run_eval.py`)
- Custom security pipelines
- High-security deployments with resources

---

## 5. Future Integration

Planned for v1.1:

```python
config = FirewallConfig(
    use_calibrated_stacking=True,
    stacking_model_path="models/my_stacker.pkl",
    use_band_judge=True,
    band_judge_model="deepseek-chat"
)
```

Currently: Manual integration required.

---

## Support

For advanced component integration:
- Read source: `src/llm_firewall/risk/stacking.py`
- Read source: `src/llm_firewall/safety/band_judge.py`
- Check tests: `tests/test_stacking.py`
- Check benchmarks: `bench/run_eval.py`

Issues: https://github.com/sookoothaii/llm-security-firewall/issues

