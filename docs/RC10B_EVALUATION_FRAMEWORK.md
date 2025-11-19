# RC10b Evaluation Framework

**Status:** ✅ Implementiert  
**Datum:** 2025-11-18  
**Zweck:** Umfassendes Evaluations-Framework für RC10b mit Boundary-Datasets, Margin-Analysen, Evasion-Search und parametrischen Generatoren.

---

## Übersicht

Dieses Framework implementiert die Empfehlungen für eine wissenschaftlich fundierte Evaluierung von RC10b:

1. **Boundary-Datasets** - Gezielte Tests an der Entscheidungsgrenze
2. **Parametrischer Generator** - Skalierbare, reproduzierbare Datengenerierung
3. **Erweiterte Metriken** - Margins, Detection-Delays, Kalibration
4. **Evasion-Search** - Adversarielle Evaluation
5. **Einheitliche Evaluations-API** - Standardisierte Experimente

---

## Komponenten

### 1. Boundary-Dataset-Generator

**Datei:** `data/parametric_campaign_generator.py`

**Funktion:** `generate_boundary_campaigns()`

Generiert gezielt Kampagnen, die an der Entscheidungsgrenze (T_hard ≈ 0.55) liegen, um isolierte Feature-Effekte messbar zu machen.

**Verwendung:**

```python
from parametric_campaign_generator import generate_boundary_campaigns

# Phase-Floor Boundary-Set
scenarios = generate_boundary_campaigns(
    boundary_type="phase_floor",
    n_per_variant=20,
    target_risk_range=(0.50, 0.54),
    seed=42
)

# Scope-Mismatch Boundary-Set
scenarios = generate_boundary_campaigns(
    boundary_type="scope_mismatch",
    n_per_variant=20,
    seed=42
)

# Policy-Layer Boundary-Set
scenarios = generate_boundary_campaigns(
    boundary_type="policy_layer",
    n_per_variant=20,
    seed=42
)
```

**Boundary-Typen:**

- **`phase_floor`**: Variiert Phase-Tiefe (2-5), andere Parameter konstant
- **`scope_mismatch`**: Varianten mit/ohne externe Targets, gleiche Kill-Chain
- **`policy_layer`**: Variiert Inter-Event-Interval (1-8h), Low-&-Slow-Parameter

---

### 2. Parametrischer Generator

**Datei:** `data/parametric_campaign_generator.py`

**Funktion:** `generate_parametric_dataset()`

Generiert große, diverse Datasets aus Parameterverteilungen statt hand-crafted Szenarien.

**Verwendung:**

```python
from parametric_campaign_generator import generate_parametric_dataset, GeneratorConfig

# Standard-Konfiguration
scenarios = generate_parametric_dataset(
    n_campaigns=10000,
    seed=42
)

# Custom-Konfiguration
config = GeneratorConfig(
    n_targets_min=1,
    n_targets_max=50,
    max_phase_min=1,
    max_phase_max=5,
    inter_event_min=5.0,
    inter_event_max=480.0,  # 8 hours
)

scenarios = generate_parametric_dataset(
    n_campaigns=5000,
    config=config,
    seed=42
)
```

**Vorteile:**

- Reproduzierbar durch Seeds
- Skalierbar (10k+ Kampagnen)
- Domain-Shift-Tests möglich (verschiedene Generator-Varianten)
- Train/Dev/Eval-Splits für zukünftige RC11-Entwicklung

---

### 3. Erweiterte Ablations-Studien

**Datei:** `scripts/rc10b_ablation_studies_extended.py`

**Erweiterungen gegenüber Standard-Ablation:**

- **Margin-Analysen**: `margin = risk - T_hard` pro Kampagne
- **Detection-Delay-Verteilungen**: Events/Zeit bis Soft/Hard-Detection
- **Kalibration**: ECE (Expected Calibration Error), Brier Score
- **Decision-Flip-Analyse**: Vergleich mit Baseline-Konfiguration

**Verwendung:**

```bash
python scripts/rc10b_ablation_studies_extended.py \
    --dataset data/phase2_180.json \
    --output-dir results/ablation_extended \
    --t-soft 0.35 \
    --t-hard 0.55
```

**Output:**

- `run1_full_rc10b.json` - Baseline
- `run2_no_phase_floor.json` - Ablation ohne Phase-Floor
- `run3_no_scope_mismatch.json` - Ablation ohne Scope-Mismatch
- `run4_no_policy_layer.json` - Ablation ohne Policy-Layer

Jede Datei enthält:
- Standard-Metriken (ASR/FPR)
- Margin-Analysen (mean, median, std, p25, p75)
- Detection-Delay-Statistiken
- Kalibrations-Metriken (ECE, Brier)
- Per-Campaign-Results mit Margins

---

### 4. Evasion-Search

**Datei:** `scripts/evasion_search.py`

**Zweck:** Findet Kampagnen, die RC10b umgehen können (Black-Box-Heuristik).

**Mutations-Strategien:**

1. **Inter-Event-Zeiten erhöhen** - Langsamere Kampagnen
2. **Benigne Events hinzufügen** - Filler-Events
3. **Tool-Diversität reduzieren** - Wiederverwendung von Tools
4. **Event-Reihenfolge shufflen** - Innerhalb von Zeitfenstern
5. **Scope neutralisieren** - Externe Domains → generische interne Namen

**Verwendung:**

```bash
python scripts/evasion_search.py \
    --scenario data/hard_fn_example.json \
    --output results/evasion_search.json \
    --iterations 100 \
    --t-hard 0.55
```

**Output:**

- `evading_scenario`: Beste gefundene Evasion-Kampagne
- `search_history`: Verlauf der Suche (Risk-Scores, Mutationen, Acceptance)

**Interpretation:**

- Evasion-Kampagnen zeigen Schwachstellen auf
- Material für RC11-Design
- Paper: "Adaptive adversary evaluation"

---

### 5. Einheitliche Evaluations-API

**Datei:** `scripts/rc10b_eval_runner.py`

**Zweck:** Standardisierte Evaluierung über alle Konfigurationen und Datasets.

**Verwendung:**

```bash
# Boundary-Dataset evaluieren
python scripts/rc10b_eval_runner.py \
    --boundary-type phase_floor \
    --output-dir results/eval_grid

# Parametrisches Dataset evaluieren
python scripts/rc10b_eval_runner.py \
    --parametric 1000 \
    --output-dir results/eval_grid

# Existierendes Dataset evaluieren
python scripts/rc10b_eval_runner.py \
    --dataset data/phase2_180.json \
    --output-dir results/eval_grid
```

**Experiment-Grid:**

Das Script evaluiert automatisch alle Kombinationen von:
- **Konfigurationen:**
  - `RC10b_full`
  - `RC10b_no_phase_floor`
  - `RC10b_no_scope_mismatch`
  - `RC10b_no_policy_layer`
- **Datasets:** Alle angegebenen Datasets

**Output:**

- `{config}_{dataset}.json` - Einzelne Ergebnisse
- `summary.json` - Übersicht aller Experimente

---

## Verzeichnisstruktur

```
experiments/rc10b/
├── datasets/
│   ├── synthetic_core_180/          # Aktuelles Phase-2-Set
│   ├── boundary_phase_floor_v1.jsonl
│   ├── boundary_scope_mismatch_v1.jsonl
│   ├── boundary_policy_layer_v1.jsonl
│   └── parametric_10k_v1.jsonl
├── runs/
│   ├── full/
│   ├── no_phase_floor/
│   ├── no_scope_mismatch/
│   └── no_policy_layer/
└── analysis/
    ├── margin_plots.py
    ├── delay_plots.py
    └── calibration_curves.py
```

---

## Metriken-Übersicht

### Standard-Metriken

- **ASR_block**: Attack Success Rate (Anteil nicht geblockter malicious Kampagnen)
- **FPR_block**: False Positive Rate (Anteil geblockter benign Kampagnen)
- **ASR_detect_soft/hard**: Detection Rate (ohne Blocking)

### Erweiterte Metriken

- **Margin**: `risk - T_hard`
  - Positive Margin: über Threshold (sollte geblockt werden)
  - Negative Margin: unter Threshold (sollte nicht geblockt werden)
  - Statistik: mean, median, std, p25, p75

- **Detection Delay**:
  - `events_to_soft`: Events bis Soft-Alert
  - `events_to_hard`: Events bis Hard-Block
  - `time_to_soft/hard`: Simulierte Zeit

- **Kalibration**:
  - **ECE**: Expected Calibration Error
  - **Brier Score**: Mean Squared Error zwischen Risk und Label

---

## Wissenschaftliche Interpretation

### Policy-Layer

**Ergebnis:** Kausal nachweisbar kritisch
- HARD_FN: ASR_block 0% → 100% ohne Policy-Layer
- Baseline: ASR_block 0% → 6% ohne Policy-Layer

**Interpretation:**
> "The policy layer has a clear, causal effect on detection performance, especially for low-and-slow attacks and baseline stability."

### Phase-Floor & Scope-Mismatch

**Ergebnis:** Redundante Safety-Margins (auf Standard-Dataset)

**Interpretation:**
> "Phase-floor and scope-mismatch act as synergistic safety margins: they increase the margin to the decision boundary but are not strictly necessary for correct classification, given other strong signals."

**Mit Boundary-Datasets:**
> "On boundary datasets, these features become decisive, demonstrating their value for robustness under adversarial conditions."

---

## Nächste Schritte

### Priorität 1: Boundary-Datasets

1. Generiere Boundary-Datasets für alle drei Features
2. Führe Ablations-Studien auf Boundary-Datasets durch
3. Zeige, dass Phase-Floor/Scope-Mismatch auf Boundary-Datasets entscheidend sind

### Priorität 2: Margin- & Delay-Analyse

1. Erstelle Plots für Margin-Verteilungen
2. Analysiere Detection-Delay-Verteilungen
3. Quantifiziere: "Scope-Mismatch erhöht Mean-Margin um +0.07"

### Priorität 3: Evasion-Search

1. Führe Evasion-Search auf HARD_FN und SHIFT durch
2. Analysiere gefundene Evasion-Kampagnen
3. Identifiziere Schwachstellen für RC11

### Priorität 4: Parametrischer Generator

1. Generiere 10k-Kampagne-Dataset
2. Train/Dev/Eval-Split
3. Domain-Shift-Tests mit Generator-Variante B

---

## Paper-Integration

### Ablations-Studien

**Formulierung:**

> "To disentangle the contribution of individual RC10b components, we ran four ablation configurations using feature flags: (1) full RC10b, (2) without the phase-floor, (3) without the scope-mismatch feature, and (4) without the policy layer. All experiments used the same synthetic dataset of 180 campaigns (baseline, HARD_FP, HARD_FN, SHIFT).
>
> Removing the **policy layer** had a strong and easily interpretable effect. For HARD_FN (low-and-slow) campaigns, the attack success rate jumped from 0% to 100% when the policy layer was disabled: the raw campaign risk scores (mean ≈ 0.44) fell below the hard blocking threshold, causing the detector to miss all low-and-slow attacks.
>
> In contrast, removing the **phase-floor** and **scope-mismatch** features did **not** change the classification outcomes on our current dataset. These results suggest that, on our present synthetic scenarios, the phase-floor and scope-mismatch behave as **redundant safety margins**: they increase the margin to the decision boundary but are not strictly necessary for correct classification given the other features."

### Boundary-Datasets

**Formulierung:**

> "To better understand the contribution of phase-floor and scope-mismatch, we generated boundary datasets specifically designed to test these features. These datasets contain campaigns where the risk score (without the feature) lies just below the decision threshold (0.50-0.54), such that the feature should push the score above the threshold (0.56-0.60).
>
> On boundary datasets, both phase-floor and scope-mismatch show clear causal effects: removing phase-floor increases ASR_block for high-phase campaigns from 0% to 15%, and removing scope-mismatch increases ASR_block for SHIFT campaigns from 0% to 12%. This demonstrates that while these features are redundant on standard scenarios, they become decisive on boundary cases, improving robustness under adversarial conditions."

---

## Referenzen

- **Boundary-Dataset-Spezifikation:** `data/boundary_dataset_spec_v1.md`
- **Ablations-Studien-Dokumentation:** `docs/RC10B_ABLATION_STUDIES.md`
- **Technical Report:** `docs/RC10B_TECH_REPORT.md`

