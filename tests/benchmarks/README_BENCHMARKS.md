# Benchmark Evaluations - AVI Paper Based

This directory contains evaluation scripts for various security benchmarks recommended by the AVI paper and other research sources.

## Available Benchmarks

### Foundational Benchmarks

| Benchmark | Description | Difficulty | Status |
|-----------|-------------|------------|--------|
| **AdvBench** | Foundational Jailbreak Test - Contains harmful strings and instructions to test if a model's safety can be bypassed | Baseline | ✅ Ready |
| **RealToxicityPrompts** | Toxic Degeneration Test - ~100k sentence beginnings from real web text, scored for toxicity | Baseline | ✅ Ready |
| **DoNotAnswer** | Refusal Capability Test - 900+ harmful queries across 12 categories to test if a model correctly refuses | Medium | ✅ Ready |

### Harder Benchmarks

| Benchmark | Description | Difficulty | Status |
|-----------|-------------|------------|--------|
| **PolygloToxicityPrompts** | Multilingual Toxicity Test - 425K prompts across 17 languages | Hard | ✅ Ready |
| **ToxiGen** | Implicit Hate Speech Test - 274K machine-generated statements targeting 13 minority groups | Hard | ✅ Ready |
| **AnthropicRedTeam** | Sophisticated Adversarial Dialogues - ~39k multi-turn, human-crafted conversations | Very Hard | ⏳ Planned |

## Quick Start

### 1. AdvBench (Jailbreak Evaluation)

**Source:** GitHub: [`arobey1/advbench`](https://github.com/arobey1/advbench)

**Usage:**
```bash
cd standalone_packages/llm-security-firewall
python scripts/run_advbench_eval.py
python scripts/run_advbench_eval.py --limit 100  # Test first 100 prompts
python scripts/run_advbench_eval.py --output results/advbench_results.json
```

**What it tests:**
- Basic safety alignment against direct jailbreak prompts
- Attack Success Rate (ASR) for harmful instructions
- Input scanner effectiveness

**Expected Metrics:**
- ASR < 10%: Excellent (Production-grade)
- ASR 10-30%: Good (Acceptable)
- ASR > 30%: Needs improvement

### 2. RealToxicityPrompts (Toxicity Evaluation)

**Source:** Hugging Face: [`allenai/real-toxicity-prompts`](https://huggingface.co/datasets/allenai/real-toxicity-prompts)

**Usage:**
```bash
python scripts/run_realtoxicity_eval.py
python scripts/run_realtoxicity_eval.py --limit 1000
```

**What it tests:**
- Model tendency to produce toxicity from naturally occurring, often benign prompts
- Requires LLM completion + external toxicity scoring (e.g., Perspective API)

**Expected Metrics:**
- Toxicity reduction compared to raw LLM outputs
- Input blocking rate for toxic prompts

### 3. DoNotAnswer (Refusal Capability)

**Source:** Dataset name: `DoNotAnswer`

**Usage:**
```bash
python scripts/run_donotanswer_eval.py
```

**What it tests:**
- Nuanced understanding of ethical refusal
- Tests if model correctly refuses to answer harmful queries

**Expected Metrics:**
- Refusal rate for harmful queries
- False positive rate (should not refuse benign queries)

## Benchmark Framework

All benchmarks use a common evaluation framework (`benchmark_evaluator_base.py`) that provides:

- **Consistent metrics:** ASR, Risk Scores, Latency
- **Category breakdown:** Results by threat category
- **JSON output:** Standardized result format
- **Progress tracking:** Verbose mode for detailed output

## Dataset Setup

### AdvBench

```bash
# Download AdvBench dataset
cd datasets
git clone https://github.com/arobey1/advbench.git advbench
# Or download manually from: https://github.com/arobey1/advbench
```

### RealToxicityPrompts

**Source:** Hugging Face: [`allenai/real-toxicity-prompts`](https://huggingface.co/datasets/allenai/real-toxicity-prompts)

**Usage:**
```bash
# Downloads automatically from Hugging Face on first run
python scripts/run_realtoxicity_eval.py
python scripts/run_realtoxicity_eval.py --limit 1000  # Default limit for testing
```

**Requirements:**
```bash
pip install datasets  # For Hugging Face dataset loading
```

### DoNotAnswer

**Usage:**
```bash
python scripts/run_donotanswer_eval.py
python scripts/run_donotanswer_eval.py --limit 100
```

**Dataset Setup:**
- Place DoNotAnswer dataset (JSON/JSONL/CSV) in `datasets/donotanswer/`
- Format: Each item should have 'question' or 'prompt' field

### PolygloToxicityPrompts

**Source:** Hugging Face: [`ToxicityPrompts/PolygloToxicityPrompts`](https://huggingface.co/datasets/ToxicityPrompts/PolygloToxicityPrompts)
GitHub: [`kpriyanshu256/polyglo-toxicity-prompts`](https://github.com/kpriyanshu256/polyglo-toxicity-prompts)

**Usage:**
```bash
python scripts/run_polyglotoxicity_eval.py
python scripts/run_polyglotoxicity_eval.py --limit 1000  # Default limit for testing
```

**Requirements:**
```bash
pip install datasets  # For Hugging Face dataset loading
```

**Dataset Setup:**
- Automatically downloads from Hugging Face on first run
- Available configs: `ptp-en` (25K prompts), `ptp-small-en` (5K prompts), `wildchat-en` (1K prompts)
- Or download manually from GitHub and place in `datasets/polyglotoxicityprompts/`

**Dataset Setup:**
- Download from GitHub repository
- Place dataset in `datasets/polyglotoxicityprompts/`
- Format: JSON/JSONL with 'text' or 'prompt' field

### ToxiGen

**Source:** Available on Hugging Face

**Usage:**
```bash
python scripts/run_toxigen_eval.py
python scripts/run_toxigen_eval.py --limit 1000  # Default limit for testing
```

**Dataset Setup:**
- Automatically downloads from Hugging Face on first run
- Or place dataset in `datasets/toxigen/`
- Format: JSON/JSONL with 'text' or 'statement' field

## Results Format

All benchmark results are saved in JSON format:

```json
{
  "benchmark": "AdvBench",
  "summary": {
    "benchmark_name": "AdvBench",
    "total_tests": 520,
    "blocked_tests": 500,
    "allowed_tests": 20,
    "attack_success_rate": 0.038,
    "avg_risk_score": 0.985,
    "avg_latency_ms": 25.3,
    "by_category": {
      "jailbreak": {
        "total": 520,
        "blocked": 500,
        "allowed": 20,
        "asr": 0.038
      }
    }
  },
  "results": [
    {
      "test_id": "advbench_001",
      "prompt": "...",
      "blocked": true,
      "risk_score": 0.99,
      "reason": "...",
      "latency_ms": 23.5
    }
  ]
}
```

## Comparison with HarmBench

| Benchmark | Focus | Dataset Size | Primary Metric |
|-----------|-------|--------------|----------------|
| **HarmBench** | Comprehensive harmful behaviors | ~912 behaviors | ASR (Attack Success Rate) |
| **AdvBench** | Direct jailbreaks | ~520 prompts | ASR |
| **RealToxicityPrompts** | Natural toxicity | ~100k prompts | Toxicity Rate |
| **DoNotAnswer** | Ethical refusal | ~900 queries | Refusal Rate |
| **PolygloToxicityPrompts** | Multilingual toxicity | 425K prompts | Cross-lingual ASR |
| **ToxiGen** | Implicit hate speech | 274K prompts | Implicit toxicity detection |

## Evaluation Best Practices

1. **Baseline First:** Start with AdvBench (foundational) before moving to harder benchmarks
2. **Incremental Testing:** Test with `--limit` flag first before full evaluation
3. **Category Analysis:** Review results by category to identify weak spots
4. **Compare Metrics:** Use consistent metrics (ASR, latency) across benchmarks
5. **Production Threshold:** Aim for ASR < 10% for production deployment

## References

- **AVI Paper:** [Adversarial VLM](https://arxiv.org/abs/...) - Original benchmark recommendations
- **AdvBench:** [GitHub Repository](https://github.com/arobey1/advbench)
- **RealToxicityPrompts:** [Paper](https://arxiv.org/abs/2009.11462) | [Hugging Face](https://huggingface.co/datasets/allenai/real-toxicity-prompts)
- **DoNotAnswer:** [Paper/Dataset Reference]
- **PolygloToxicityPrompts:** [GitHub](https://github.com/kpriyanshu256/polyglo-toxicity-prompts)

## Contributing

To add a new benchmark:

1. Create a new evaluator class inheriting from `BenchmarkEvaluatorBase`
2. Implement `load_dataset()` and `prepare_prompt()` methods
3. Create evaluation script in `scripts/run_{benchmark}_eval.py`
4. Add dataset setup script if needed
5. Update this README

See `benchmark_evaluator_base.py` for the base class interface.
