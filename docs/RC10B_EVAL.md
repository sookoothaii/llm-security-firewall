# RC10b Extended Evaluation - Usage Guide

**Datum:** 2025-11-18  
**Zweck:** Praktische Anleitung zur Verwendung des erweiterten RC10b-Ablation-Frameworks

---

## Übersicht

Das erweiterte Ablation-Framework (`rc10b_ablation_studies_extended.py`) ermöglicht:

- Standard-Ablations-Studien (Full RC10b vs. Ablationen)
- Boundary-Dataset-Evaluierungen
- Mehrdimensionale Metriken (Margins, Delays, Kalibration)
- Reproduzierbare Experimente mit Seeds

---

## Installation & Voraussetzungen

### Abhängigkeiten

```bash
pip install numpy scipy
```

### Projekt-Struktur

```
standalone_packages/llm-security-firewall/
├── scripts/
│   └── rc10b_ablation_studies_extended.py
├── data/
│   ├── phase2_dataset.json
│   └── boundary_*.jsonl
└── results/
    └── ablation_extended/
```

---

## Verwendung

### 1. Standard Phase-2 Dataset

**Befehl:**
```bash
python scripts/rc10b_ablation_studies_extended.py \
    --dataset data/phase2_dataset.json \
    --output-dir results/eval_phase2 \
    --t-soft 0.35 \
    --t-hard 0.55 \
    --seed 42
```

**Was passiert:**
- Lädt 180 Szenarien (100 Baseline + 80 Hard Cases)
- Führt 4 Konfigurationen aus:
  - Full RC10b (Baseline)
  - No Phase-Floor
  - No Scope-Mismatch
  - No Policy-Layer
- Berechnet alle Metriken (ASR/FPR, Margins, Delays, Kalibration)
- Speichert Ergebnisse als JSON

**Output:**
- `run1_full_rc10b.json`
- `run2_no_phase_floor.json`
- `run3_no_scope_mismatch.json`
- `run4_no_policy_layer.json`

---

### 2. Boundary-Dataset

**Befehl:**
```bash
python scripts/rc10b_ablation_studies_extended.py \
    --boundary-dataset data/boundary_phase_floor_v1.jsonl \
    --output-dir results/eval_boundary \
    --t-soft 0.35 \
    --t-hard 0.55 \
    --seed 42
```

**Was passiert:**
- Lädt Boundary-Dataset (JSONL-Format)
- Führt gleiche 4 Konfigurationen aus
- Ermöglicht gezielte Feature-Kausalitäts-Tests

**Boundary-Dataset-Format:**
Jede Zeile ist ein JSON-Objekt:
```json
{
  "campaign_id": "boundary_phase_floor_phase4_001",
  "label": "malicious",
  "operator_id": "boundary_gen",
  "description": "Phase-Floor Boundary Test",
  "events": [...],
  "difficulty": "hard_fn",
  "scenario_type": "boundary_phase_floor",
  "scope": "internal",
  "authorized": false
}
```

---

### 3. Synthetisches Dataset generieren

**Befehl:**
```bash
python scripts/rc10b_ablation_studies_extended.py \
    --output-dir results/eval_synthetic \
    --t-soft 0.35 \
    --t-hard 0.55 \
    --seed 42
```

**Was passiert:**
- Generiert 180 synthetische Szenarien (100 Baseline + 80 Hard Cases)
- Verwendet Seed für Reproduzierbarkeit
- Führt Ablations-Studien durch

---

## CLI-Parameter

| Parameter | Typ | Default | Beschreibung |
|-----------|-----|---------|--------------|
| `--dataset` | str | - | Pfad zu Phase-2-Dataset (JSON) |
| `--boundary-dataset` | str | - | Pfad zu Boundary-Dataset (JSONL) |
| `--output-dir` | str | `results/ablation_extended` | Ausgabe-Verzeichnis |
| `--t-soft` | float | 0.35 | Soft-Threshold für REQUIRE_APPROVAL |
| `--t-hard` | float | 0.55 | Hard-Threshold für BLOCK |
| `--seed` | int | 42 | Random Seed für Reproduzierbarkeit |

**Hinweis:** Entweder `--dataset`, `--boundary-dataset` oder keines (dann wird generiert).

---

## JSON-Output-Struktur

Jede Run-Datei (`run{1-4}_*.json`) enthält:

### Top-Level-Felder

- `run_name`: Name der Konfiguration
- `flags`: Feature-Flags (`use_phase_floor`, `use_scope_mismatch`, `use_policy_layer`)
- `metrics`: Metriken pro Difficulty-Klasse
- `margin_analyses`: Margin-Analysen pro Difficulty
- `detection_delays`: Detection-Delay-Statistiken
- `calibration`: Kalibrations-Metriken (ECE, Brier)
- `results`: Per-Campaign-Results

### Metrics-Struktur

```json
{
  "metrics": {
    "baseline": {
      "n_benign": 50,
      "n_malicious": 50,
      "asr_block": 0.0,
      "fpr_block": 0.0,
      "avg_risk_malicious": 0.65,
      "avg_risk_benign": 0.15
    },
    "hard_fn": {
      "n_malicious": 20,
      "asr_block": 0.0,
      "avg_risk_malicious": 0.55
    }
  }
}
```

### Margin-Analyses-Struktur

```json
{
  "margin_analyses": {
    "baseline": {
      "mean_margin": -0.092,
      "median_margin": -0.061,
      "std_margin": 0.185,
      "p25_margin": -0.15,
      "p75_margin": 0.05,
      "n_above_threshold": 47,
      "n_below_threshold": 53,
      "decision_flip_count": 0
    }
  }
}
```

### Detection-Delays-Struktur

```json
{
  "detection_delays": {
    "baseline": {
      "mean_events_soft": 5.2,
      "mean_events_hard": 11.9,
      "median_events_soft": 4,
      "median_events_hard": 9
    }
  }
}
```

### Calibration-Struktur

```json
{
  "calibration": {
    "ece": 0.2390,
    "brier": 0.2201,
    "reliability_data": {
      "n_bins": 10,
      "bins": [
        {
          "bin": 0,
          "bin_start": 0.0,
          "bin_end": 0.1,
          "mean_risk": 0.05,
          "mean_label": 0.0,
          "count": 20,
          "calibration_error": 0.05
        }
      ]
    }
  }
}
```

### Per-Campaign-Results

```json
{
  "results": [
    {
      "campaign_id": "benign_dev_1",
      "label": "benign",
      "difficulty": "baseline",
      "scenario_type": "baseline",
      "risk_max": 0.458,
      "margin": -0.092,
      "blocked": false,
      "require_approval": true,
      "delay_events_soft": 2,
      "delay_events_hard": null
    }
  ]
}
```

---

## Metriken-Interpretation

### ASR_block / FPR_block

- **ASR_block**: Attack Success Rate (Anteil nicht geblockter malicious Kampagnen)
  - 0.0 = alle geblockt (gut)
  - 1.0 = keine geblockt (schlecht)

- **FPR_block**: False Positive Rate (Anteil geblockter benign Kampagnen)
  - 0.0 = keine False Positives (gut)
  - >0.0 = False Positives vorhanden

### Margin

- **margin = risk_max - T_hard**
- **Positive Margin**: über Threshold (sollte geblockt werden)
- **Negative Margin**: unter Threshold (sollte nicht geblockt werden)
- **Mean/Median Margin**: Durchschnittlicher Abstand zum Threshold
- **Std Margin**: Variabilität der Margins

**Interpretation:**
- Große positive Margins → robuste Erkennung
- Margins nahe 0 → knappe Entscheidungen
- Negative Margins → nicht geblockt (erwartet bei benign)

### Detection Delay

- **delay_events_soft**: Events bis Soft-Alert (REQUIRE_APPROVAL)
- **delay_events_hard**: Events bis Hard-Block
- **Mean/Median**: Durchschnittliche/Median-Delays

**Interpretation:**
- Niedrige Delays → frühe Erkennung
- Hohe Delays → späte Erkennung (bei HARD_FN erwartet)

### Kalibration

- **ECE (Expected Calibration Error)**: Maß für Kalibrierungsgüte
  - 0.0 = perfekt kalibriert
  - >0.1 = schlecht kalibriert

- **Brier Score**: Mean Squared Error zwischen Risk und Label
  - 0.0 = perfekt
  - 1.0 = maximal schlecht

**Wichtig:** Risk-Scores sind **keine explizit kalibrierten Wahrscheinlichkeiten**. Kalibrations-Metriken dienen diagnostischen Zwecken.

---

## Beispiel-Workflow

### 1. Standard-Evaluierung

```bash
# Phase-2 Dataset evaluieren
python scripts/rc10b_ablation_studies_extended.py \
    --dataset data/phase2_dataset.json \
    --output-dir results/eval_phase2

# Ergebnisse analysieren
python scripts/analyze_results.py results/eval_phase2/
```

### 2. Boundary-Dataset-Evaluierung

```bash
# Boundary-Dataset generieren (falls noch nicht vorhanden)
python data/parametric_campaign_generator.py \
    --boundary-type phase_floor \
    --output data/boundary_phase_floor_v1.jsonl

# Boundary-Dataset evaluieren
python scripts/rc10b_ablation_studies_extended.py \
    --boundary-dataset data/boundary_phase_floor_v1.jsonl \
    --output-dir results/eval_boundary_phase_floor
```

### 3. Threshold-Sweep (manuell)

```bash
# Verschiedene Thresholds testen
for t_hard in 0.50 0.55 0.60; do
    python scripts/rc10b_ablation_studies_extended.py \
        --dataset data/phase2_dataset.json \
        --output-dir results/eval_threshold_${t_hard} \
        --t-hard ${t_hard}
done
```

---

## Troubleshooting

### Problem: "CampaignDetectorConfig not found"

**Lösung:** Stelle sicher, dass `src/llm_firewall/detectors/agentic_campaign.py` im Python-Pfad ist.

### Problem: "Boundary dataset not found"

**Lösung:** Prüfe, ob der Pfad relativ zum Projekt-Root korrekt ist, oder verwende absoluten Pfad.

### Problem: "Empty dataset"

**Lösung:** Prüfe, ob das Dataset korrekt geladen wird:
```python
from campaign_dataset import load_dataset
scenarios = load_dataset("data/phase2_dataset.json")
print(f"Loaded {len(scenarios)} scenarios")
```

---

## Referenzen

- **Status-Dokumentation:** `docs/RC10B_EVALUATION_STATUS.md`
- **Technical Report:** `docs/RC10B_TECH_REPORT.md`
- **Ablation Studies:** `docs/RC10B_ABLATION_STUDIES.md`
- **Evaluation Framework:** `docs/RC10B_EVALUATION_FRAMEWORK.md`

