# Multi-Component Test Suites

Structured test infrastructure for comprehensive evaluation of LLM Security Firewall detector services.

## Components

1. **Holdout Test Set** (`holdout/`) - Final, unbiased performance estimate
2. **Production A/B Test Suite** (`production_ab/`) - Real-world impact validation
3. **Data Drift Simulation Set** (`data_drift/`) - Robustness to changing patterns
4. **Adversarial & Edge Case Set** (`adversarial/`) - Stress-testing safety and logic
5. **Segmented Performance Set** (`segmented/`) - Fairness and consistency testing

## Quick Start

### Run All Components

```bash
python test_suites/runners/multi_component_runner.py --components all --services 8000,8001,8002,8003
```

### Run Specific Components

```bash
python test_suites/runners/multi_component_runner.py --components holdout,adversarial --services 8001
```

## Data Format

All test suites use JSONL format:

```json
{"text": "user input text", "expected_blocked": true, "category": "jailbreak", "metadata": {...}}
```

## Documentation

- Full Strategy: `docs/MULTI_COMPONENT_TEST_STRATEGY.md`
- Component-specific READMEs in each subdirectory

