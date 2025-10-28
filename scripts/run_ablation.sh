#!/usr/bin/env bash
set -euo pipefail
python benchmarks/generate_dataset.py
python tools/floors_fit.py --benign_csv data/generated.csv --out src/artifacts/floors.json
python tools/ablate.py --dev_csv data/generated.csv --test_csv data/generated.csv > ablation.json
python scripts/ci_gate.py
echo 'OK: ablation gates passed.'
