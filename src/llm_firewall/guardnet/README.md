# GuardNet: Proactive Firewall Guard Model

**Version:** 1.0.0-alpha
**Creator:** Joerg Bollwahn
**Date:** 2025-10-30
**Phase:** 3 (Guard Model Implementation)

---

## Overview

GuardNet is a standalone guard model trained on firewall signals for proactive input classification. It provides multi-task outputs suitable for integration with Policy-DSL, Conformal Prediction, and Streaming Guards.

**Key Features:**
- Two-tower fusion architecture (text encoder + engineered features)
- Multi-task outputs: policy, intent, actionability, obfuscation
- ONNX-exportable for production deployment
- Deterministic feature extraction
- Conformal prediction compatible
- Teacher-distillation ready

---

## Architecture

```text
Input Text + Features
       │
       ├─── Text Tower (Transformer Encoder: MiniLM/DeBERTa-Small/bert-tiny)
       │           │
       │      [CLS Token]
       │
       └─── Feature Tower (MLP: engineered features)
                   │
              [Alpha Gate]
                   │
         ┌─────────┴─────────┐
         │   Gated Fusion    │
         └────────┬───────────┘
                  │
       ┌──────────┼──────────┐
       │          │          │
   Policy    Intent    Actionability    Obfuscation
   (3 cls)   (5 cls)      (3 cls)       (6 multi-label)
```

### Components

1. **Text Tower**: Small transformer encoder
   - Recommended: `prajjwal1/bert-tiny` (17MB), `all-MiniLM-L6-v2` (80MB)
   - Extracts CLS token as text representation

2. **Feature Tower**: MLP over engineered features
   - Input: zwc_density, base64_frac, mixed_script_ratio, punct_burst, OOD energy, TTL delta, trust tier, regex hits
   - Output: Hidden representation for fusion

3. **Fusion**: Gated additive
   - Alpha gate learned from features
   - Stable, ONNX-friendly

4. **Heads**: Multi-task classification
   - Policy: {block, allow_high_level, allow}
   - Intent: {jailbreak, injection, dual_use, persuasion, benign}
   - Actionability: {procedural, advisory, descriptive}
   - Obfuscation: {base64, leet, homoglyph, zwc, mixed_script, emoji_burst}

---

## Installation

GuardNet is part of the LLM Security Firewall package. Install dependencies:

```bash
pip install transformers torch onnx onnxruntime
```

For training:
```bash
pip install torch transformers
```

For INT8 quantization:
```bash
pip install onnxruntime
```

---

## Quick Start

### 1. Feature Extraction

```python
from llm_firewall.guardnet.features import extract_features

text_normalized = "Your input text here"
regex_hits = {"intent/jailbreak": 0, "evasion/base64": 0}
lid = "en"
emb_ood_energy = 0.0
ttl_delta_days = 30
trust_tier = 0.8

features = extract_features(
    text_normalized,
    regex_hits,
    lid,
    emb_ood_energy,
    ttl_delta_days,
    trust_tier
)
```

### 2. Training

```python
from llm_firewall.guardnet.train import train_guardnet

model = train_guardnet(
    train_path="data/train.jsonl",
    val_path="data/val.jsonl",
    encoder_name="prajjwal1/bert-tiny",
    feat_dim=64,
    epochs=3,
    batch_size=16,
    lr=3e-4,
    device="cpu",
    save_path="models/guardnet.pt"
)
```

### 3. ONNX Export

```python
from llm_firewall.guardnet.export_onnx import export_onnx

export_onnx(
    model=model,
    onnx_path="models/guardnet.onnx",
    seq_len=256,
    feat_dim=64,
    quantize_int8=True  # Optional: reduce size by ~4x
)
```

### 4. Inference (ONNX)

```python
from llm_firewall.guardnet.export_onnx import load_onnx_session
import numpy as np

session = load_onnx_session("models/guardnet.onnx")

# Prepare inputs
inputs = {
    "input_ids": input_ids_np,  # (1, seq_len)
    "attention_mask": mask_np,  # (1, seq_len)
    "feat_vec": features_np,    # (1, feat_dim)
}

# Run inference
outputs = session.run(None, inputs)
policy_logits, intent_logits, action_logits, obf_logits = outputs
```

### 5. Gate 1 Integration

```python
from llm_firewall.guardnet.gate_integration import (
    map_to_policy_dsl,
    compute_risk_uplift,
    should_early_abort,
)

# Map to Policy-DSL (Guard stricter wins)
final_policy = map_to_policy_dsl(guard_output, policy_dsl_output)

# Compute risk uplift for Conformal Stacker
risk_uplift = compute_risk_uplift(guard_output)

# Check early abort for Streaming Guard
should_abort, reason = should_early_abort(guard_output)
```

---

## Data Format

Training data: JSONL with text, features, labels, meta.

See `data/schema_guardnet.md` for complete specification.

Example:
```json
{
  "text": "User input text",
  "features": {
    "zwc_density": 0.0,
    "base64_frac": 0.0,
    ...
  },
  "labels": {
    "policy": "allow",
    "intent": "benign",
    "actionability": "descriptive",
    "obfuscation": []
  },
  "meta": {
    "seed": 1337,
    "split": "train",
    "ts": "2025-10-30T00:00:00Z"
  }
}
```

---

## Performance Targets

From Phase 3 specification:

- **ASR@FPR=1%**: ≤ 0.25
- **Critical-Leak@20**: ≤ 0.2%
- **ECE**: ≤ 0.05
- **Brier**: ≤ 0.10
- **P99 Latency**: ≤ 350ms (including judges)
- **Model Size**: < 100MB (INT8)

---

## Integration Points

### Gate 1 (Input Protection)
- Replace/augment existing input guards
- Outputs feed Policy-DSL and Conformal Stacker
- Early abort signals to Streaming Guard

### Policy-DSL
- Guard policy overrides DSL if stricter
- Compatible with existing policy rules

### Conformal Stacker
- Risk uplift computed from multi-task outputs
- Category-wise q-hat calibration (LODO)

### Streaming Guard
- Intent/obfuscation flags trigger early abort
- Prevents critical-leak@n

### Fallback to Judges
- Low coverage → use ONNX Judges as fallback
- Teacher-student relationship maintained

---

## Teacher Distillation

GuardNet supports distillation from teacher ensemble:

**Teachers:**
1. Policy-DSL Compiler
2. NLI ONNX Judge
3. Policy ONNX Judge
4. Optional: Band-Judge (LLM-as-Judge)

**Distillation loss:**
```python
# Soft targets from teachers (τ=2-5)
loss_distill = KL_divergence(student_logits / τ, teacher_logits / τ)

# Combined with hard labels
loss_total = loss_hard + α * loss_distill
```

---

## Calibration

GuardNet uses category-wise conformal prediction:

1. **LODO** (Leave-One-Day-Out) for temporal robustness
2. **Weighted Quantile** for covariate shift (Phase 3)
3. **Mondrian** per domain/intent for granular coverage

See Phase 3 specification for Weighted/Mondrian Conformal implementation.

---

## Testing

```bash
# Run shape tests
pytest tests/test_guardnet_shapes.py -v

# Run feature extractor tests
pytest tests/test_feature_extractor.py -v

# Run all GuardNet tests
pytest tests/test_guardnet*.py -v
```

---

## Limitations

**Current Status:** Alpha (Implementation complete, not yet trained)

**Known Limitations:**
1. No pre-trained weights available (requires training data)
2. Teacher distillation not yet validated
3. Calibration integration pending (Phase 3)
4. Red-team validation needed (HarmBench, JailbreakBench)
5. Production latency not measured

**Next Steps:**
1. Generate training data (from Decision Ledger + CGRF + Quarantine)
2. Train baseline model
3. Implement Phase 3 Quick Drops:
   - Online q-hat (Weighted Conformal)
   - Secrets v2 (PASTA-like heuristics)
   - WCG Penalty (PageRank)
4. Red-team evaluation
5. Production deployment with shadow mode

---

## References

- **Llama Guard** (Meta): ai.meta.com/research/publications/llama-guard-llm-based-input-output-safeguard-for-human-ai-conversations/
- **HarmBench**: arxiv.org/abs/2402.04249
- **JailbreakBench**: Standardized evaluation for red-team robustness
- **Phase 3 Specification**: 12 extensions for operational resilience

---

## Contributing

Maintain hexagonal architecture:
- Domain logic pure (no infrastructure dependencies)
- Ports/adapters separation
- All features deterministic and tested

---

## License

MIT License (same as parent framework)

---

## Creator

**Joerg Bollwahn**
HAK/GAL Research Project
2025-10-30

"Heritage is my currency" - Joerg Bollwahn
