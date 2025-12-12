# Adversarial Training Infrastructure

Complete adversarial training pipeline for improving detector robustness.

## Overview

This directory contains the full adversarial training pipeline implemented for Phase 3:

1. **Dataset Generation** - Create adversarial training examples
2. **Model Training** - Fine-tune models with adversarial data
3. **Validation** - Test on new, unseen adversarial examples
4. **Weakness Analysis** - Find model weaknesses for next iteration
5. **Deployment** - Production deployment plan and monitoring

---

## Quick Start

### 1. Generate Adversarial Training Dataset

```bash
python detectors/orchestrator/infrastructure/training/adversarial_training_pipeline.py \
    --detector code_intent \
    --samples 1000
```

### 2. Train Model with Adversarial Examples

```bash
python detectors/orchestrator/infrastructure/training/train_adversarial_code_intent.py \
    --train-data data/adversarial_training/code_intent_train_adversarial.jsonl \
    --val-data data/adversarial_training/code_intent_val_adversarial.jsonl \
    --original-data data/train/quantum_cnn_training.jsonl \
    --base-model models/quantum_cnn_trained/best_model.pt \
    --output-dir models/code_intent_adversarial_v1 \
    --epochs 5 \
    --mix-ratio 0.3 \
    --validate-baseline
```

### 3. Generate True Validation Set

```bash
python detectors/orchestrator/infrastructure/training/generate_true_validation_set.py \
    --output data/adversarial_training/code_intent_true_validation.jsonl \
    --malicious-samples 100 \
    --benign-samples 200 \
    --seed 9999
```

### 4. Validate Model

```bash
python detectors/orchestrator/infrastructure/training/validate_adversarial_model.py \
    --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
    --original-model models/quantum_cnn_trained/best_model.pt \
    --adversarial-model models/code_intent_adversarial_v1/best_model.pt \
    --output results/adversarial_validation_comparison.json
```

### 5. Find Model Weaknesses (Next Iteration)

```bash
python detectors/orchestrator/infrastructure/training/find_adversarial_weaknesses.py \
    --model models/code_intent_adversarial_v1/best_model.pt \
    --output data/adversarial_training/weakness_analysis.json \
    --samples 1000
```

---

## Files

### Core Scripts

- `adversarial_training_pipeline.py` - Generate adversarial training datasets
- `train_adversarial_code_intent.py` - Train model with adversarial examples
- `generate_true_validation_set.py` - Create new validation set (not in training)
- `validate_adversarial_model.py` - Compare original vs adversarial model
- `find_adversarial_weaknesses.py` - Find specific model weaknesses

### Documentation

- `PHASE_3_QUICK_START.md` - Quick start guide
- `TRAINING_RESULTS.md` - Training results and metrics
- `TRUE_VALIDATION_RESULTS.md` - True validation analysis
- `DEPLOYMENT_PLAN.md` - Production deployment strategy
- `README.md` - This file

---

## Results Summary

### Training Results

- **Train Accuracy:** 98.34%
- **Val Accuracy:** 100.00%
- **Baseline Bypass Detection:** 100% (17/17)

### True Validation Results (NEW Samples)

| Metric | Original | Adversarial | Change |
|--------|----------|-------------|--------|
| **Accuracy** | 39.72% | 62.06% | +22.34% ✅ |
| **False Positive Rate** | 86.39% | 53.40% | -32.98% ✅✅ |
| **Bypass Rate** | 5.49% | 5.49% | 0.00% |

**Key Finding:** Massive FPR improvement (-32.98%) addresses critical production issue of over-blocking legitimate requests.

---

## Next Steps

1. **Deploy** - Follow `DEPLOYMENT_PLAN.md` for Canary Release
2. **Monitor** - Track FPR, Bypass Rate, User Feedback
3. **Iterate** - Use weakness analysis tool for next training cycle

---

## Support

For questions or issues, see:
- `HANDOVER_ADVERSARIAL_ROBUSTNESS.md` - Overall project status
- `ADVERSARIAL_ROBUSTNESS_IMPLEMENTATION_PLAN.md` - Full implementation plan

