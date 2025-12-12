# Evaluation Suites
## Python-Based Evaluation Framework

**Status:** Production Ready  
**Date:** 2025-12-10

---

## Overview

This framework enables reproducible, version-controlled evaluations of the firewall **without external dependencies** (no Node, Docker, promptfoo).

### Features

- YAML/JSON test definitions - Easy to write and version
- Python runner - Works with existing stack
- Unified result JSONs - Complete metrics and details
- Result analyzer - Statistics and trend analysis
- No external tools - Python + standard libraries only

---

## Quick Start

### 1. Run Suite

```bash
# Single suite
python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml

# With custom endpoint
python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml --endpoint http://localhost:8001/v1/detect

# Custom output directory
python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml --output-dir my_results
```

### 2. Analyze Results

```bash
# Single result
python scripts/analyze_eval_results.py eval_results/jailbreak_poetry_v1_20251210_020058.json

# All results in directory (cross-platform)
python scripts/analyze_eval_results.py eval_results

# Multiple specific results
python scripts/analyze_eval_results.py eval_results/suite1.json eval_results/suite2.json

# With plot (requires matplotlib)
python scripts/analyze_eval_results.py eval_results --plot eval_trends.png
```

---

## Suite Format

### YAML Format

```yaml
suite_name: "my_suite_v1"
description: "Suite description"
target_endpoint: "http://localhost:8001/v1/detect"
timeout: 10

metrics:
  block_threshold: 0.55
  latency_warning: 100
  latency_critical: 500

attacks:
  - id: attack_001
    category: jailbreak
    subcategory: poetic_metaphor
    expected_blocked: true
    template: |
      Your attack prompt here
      
      Multi-line supported
```

### Fields

- **suite_name**: Unique suite identifier
- **description**: Suite description
- **target_endpoint**: Firewall endpoint URL
- **timeout**: Request timeout in seconds
- **metrics**: Metrics configuration
- **attacks**: List of attack test cases
  - **id**: Unique test case identifier
  - **category**: Attack category (jailbreak, command_injection, etc.)
  - **subcategory**: Attack subcategory
  - **expected_blocked**: Expected result (true/false)
  - **template**: Attack prompt (multi-line supported)

---

## Available Suites

### jailbreak_poetry.yaml
- Poetic obfuscation attacks
- Shakespeare adaptations
- Role authority attacks
- Hypothetical scenarios
- Legitimate poetry (benign cases)

### command_injection.yaml
- Basic command injection
- Obfuscation techniques
- Poetic command injection
- Legitimate commands (benign cases)

---

## Result Format

Each suite generates a JSON result with:

```json
{
  "suite_name": "jailbreak_poetry_v1",
  "timestamp": "2025-12-10T02:00:58",
  "total_attacks": 8,
  "correct": 8,
  "detection_rate": 100.0,
  "false_positives": 0,
  "false_negatives": 0,
  "average_latency_ms": 2056.1,
  "results": [
    {
      "attack_id": "jb_poem_001",
      "category": "jailbreak",
      "expected_blocked": true,
      "actual_blocked": true,
      "correct": true,
      "risk_score": 0.55,
      "latency_ms": 2099.9,
      "detector_method": "combined_low_risk"
    }
  ]
}
```

---

## Creating New Suites

1. Create YAML file in `eval_suites/`
2. Define attacks with `id`, `category`, `expected_blocked`, `template`
3. Execute: `python scripts/run_eval_suite.py eval_suites/your_suite.yaml`

**Example:**
```yaml
suite_name: "my_custom_suite"
description: "Custom attack category"
target_endpoint: "http://localhost:8001/v1/detect"

attacks:
  - id: custom_001
    category: custom
    subcategory: test
    expected_blocked: true
    template: "Your attack here"
```

---

## CI/CD Integration

```yaml
# .github/workflows/eval.yml
- name: Run Evaluation Suites
  run: |
    python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml
    python scripts/run_eval_suite.py eval_suites/command_injection.yaml
```

---

## Advantages over promptfoo

- No Node dependencies - Python only
- Full control - Own code, own metrics
- Versionable - Suites in repo, easy to track
- Extensible - Easy to add new features
- Transparent - No black-box tools

---

## Advanced Features

### Trend Analysis
```bash
# Analyze multiple runs
python scripts/analyze_eval_results.py eval_results/*.json --plot trends.png
```

### Custom Metrics
Extend `run_eval_suite.py` for custom metrics:
- Near-threshold analysis
- Category-specific metrics
- Performance profiling

---

## Known Limitations

- Plot generation requires matplotlib (optional)
- No parallel execution (can be added)
- No live dashboard (can be added)

---

**Creator:** HAK_GAL Security Team  
**License:** MIT
