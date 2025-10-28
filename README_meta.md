# Meta & Evaluation Toolkit

## Artifacts & Gates
- `src/artifacts/meta/{model_meta.json, platt.json, metrics.json}` — enabled only if **ECE ≤ 0.05** and **Brier ≤ 0.10**.
- `src/artifacts/floors.json` — data-driven category floors from benign corpus (e.g., 99.5% quantile + 0.05).

## Runners
- `python tools/ablate.py --dev_csv DEV.csv [--test_csv TEST.csv]`
- `python tools/floors_fit.py --benign_csv BENIGN.csv`

## Arms (Ablation)
- **A0:** Pattern only.
- **A1:** Pattern + Intent (AC-only).
- **A2:** Pattern + Intent (AC + Gapped Regex).
- **A3:** A2 + Meta-Ensemble (gated).

## Go/No-Go
- ΔASR@50 ≤ −10% vs A0, **ECE ≤ 0.05**, **Brier ≤ 0.10**, ΔP95 ≤ +15 ms, LODO ΔAUC ≤ 0.02.

Notes:
- All inputs are **canonicalized**.
- For very long inputs, use `evaluate_windowed()` (win=512, stride=256).
