# AnswerPolicy Phase 2 Evaluation Pipeline

This directory contains the Phase 2 evaluation pipeline for AnswerPolicy, an epistemic decision layer within the llm-security-firewall system.

## Quick Start

Run a smoke test evaluation:

```bash
python scripts/run_phase2_suite.py --config smoke_test_core
```

This will:
1. Load the `core_suite_smoke.jsonl` dataset (~50 items)
2. Run experiments for `baseline`, `kids`, and `default` policies
3. Compute ASR (Attack Success Rate) and FPR (False Positive Rate) metrics
4. Generate a comparison report in `results/`

## Available Scripts

### Core Phase 2 Scripts

- **`generate_small_mixed_dataset.py`**: Generate labeled JSONL datasets (redteam/benign)
- **`run_answerpolicy_experiment.py`**: Run experiments through FirewallEngineV2
- **`compute_answerpolicy_effectiveness.py`**: Compute ASR/FPR metrics (with optional bootstrap CIs)
- **`analyze_answer_policy_metrics.py`**: Extract AnswerPolicy and latency statistics

### Phase 2.5 Orchestration & Utilities

- **`run_phase2_suite.py`**: Orchestrator for multi-policy experiments
- **`experiment_configs.py`**: Reusable experiment configurations
- **`eval_utils.py`**: Shared utilities for JSONL parsing and directory setup
- **`validate_dataset.py`**: Dataset schema validation and statistics
- **`tool_guard_types.py`**: Tool-abuse scaffolding (for future evaluation)
- **`demo_tool_guard_logging.py`**: Demo script for tool-abuse context logging

## Experiment Configurations

Predefined configurations available via `--config`:

- `smoke_test_core`: Quick validation (~50 items)
- `core_suite_full`: Full core evaluation (~150-200 items)
- `tool_abuse_focused`: Tool-abuse focused evaluation (~70 items)
- `combined_suite`: Combined core + tool-abuse
- `category_ablation`: Ablation study configuration

## Datasets

Evaluation datasets are located in `datasets/`:

- `core_suite.jsonl`: Core evaluation dataset (~200 items, 10 harm categories)
- `core_suite_smoke.jsonl`: Smoke test subset (~50 items)
- `tool_abuse_suite.jsonl`: Tool-abuse evaluation dataset (~70 items)
- `combined_suite.jsonl`: Combined core + tool-abuse

## Documentation

For complete technical documentation, see:

- **Technical Handover**: [`docs/ANSWER_POLICY_EVALUATION_PHASE2_2_4_0.md`](../docs/ANSWER_POLICY_EVALUATION_PHASE2_2_4_0.md)
- **User Workflow**: [`docs/ANSWER_POLICY_EVALUATION_PHASE2.md`](../docs/ANSWER_POLICY_EVALUATION_PHASE2.md)

## Limitations

- Sample sizes are small (20-100 items in typical runs), limiting statistical significance
- The `p_correct` estimator uses an uncalibrated heuristic (`1.0 - base_risk_score`)
- Datasets use hard-coded templates rather than real-world distributions
- Bootstrap CIs are approximate indicators, not publication-grade statistics

See the technical handover document for detailed limitations and future work.
