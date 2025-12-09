# Quick Start Guide
## LLM Security Firewall - Evaluation Framework

**Date:** 2025-12-10

---

## Quick Start

### 1. Start Service

```bash
# Option 1: With script
python scripts/start_service.py

# Option 2: Direct
cd detectors/code_intent_service
python -m uvicorn main:app --host 0.0.0.0 --port 8001
```

### 2. Run Evaluation Suite

```bash
# Single suite
python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml

# All suites
for suite in eval_suites/*.yaml; do
  python scripts/run_eval_suite.py "$suite"
done
```

### 3. Analyze Results

```bash
# All results
python scripts/analyze_eval_results.py eval_results

# With CI/CD gates
python scripts/analyze_eval_results.py eval_results \
  --min-detection-rate 95.0 \
  --max-false-positive-rate 5.0 \
  --max-bypasses 0
```

---

## Available Scripts

### Evaluation

- `scripts/run_eval_suite.py` - Execute evaluation suites
- `scripts/analyze_eval_results.py` - Analyze results with gates

### Adversarial Testing

- `scripts/automated_adversarial_generator.py` - Generate new attacks
- `scripts/adversarial_red_teaming.py` - Red-teaming tests

### Service

- `scripts/start_service.py` - Start firewall service
- `scripts/trigger_learning.py` - Trigger training
- `scripts/monitor_learning.py` - Monitor online learning

---

## Test Suites

### Available

- `eval_suites/jailbreak_poetry.yaml` - Poetic obfuscation & jailbreaks
- `eval_suites/command_injection.yaml` - Command injection attacks

### Create New Suite

1. Create YAML in `eval_suites/`
2. Define attacks with `id`, `category`, `expected_blocked`, `template`
3. Execute: `python scripts/run_eval_suite.py eval_suites/your_suite.yaml`

---

## CI/CD

**Workflow:** `.github/workflows/security-eval.yml`

**Automatically on:**
- Push to `main`/`develop`
- Pull requests
- Daily at 02:00 UTC

**Gates:**
- Detection Rate >= 95%
- False Positive Rate <= 5%
- Bypasses = 0

---

## Current Performance

- Detection Rate: 100%
- Bypasses: 0
- False Positives: 0 (after fixes)

---

## Documentation

- `eval_suites/README.md` - Evaluation framework guide
- `docs/CI_CD_SETUP_2025_12_10.md` - CI/CD setup
- `docs/COMPLETE_IMPLEMENTATION_SUMMARY_2025_12_10.md` - Complete overview

---

**Creator:** HAK_GAL Security Team
