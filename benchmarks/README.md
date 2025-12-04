# Benchmarks Directory

**Status:** Active

**Purpose:** Benchmark runner scripts for reproducing reported metrics (ASR, FPR, ECE) with fixed seeds.

**Usage:**
```bash
python benchmarks/run_benchmarks.py --model gpt-4o-mini --poison_rates 0.001 0.005 0.01 --seed 1337 --out results/report.json
```

**Contents:**
- `run_benchmarks.py`: Main benchmark runner
- `run_benchmarks_safety.py`: Safety-focused benchmarks
- `phase2_validation.py`: Phase 2 evaluation pipeline
- Dataset generation and redteam evaluation scripts

**Note:** This directory is actively maintained. Benchmark scripts are used for metric validation and regression testing.
