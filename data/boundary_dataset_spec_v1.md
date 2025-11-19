# Boundary Dataset Specification v1

**Zweck:** Gezielte Test-Suiten, die direkt an der Entscheidungsgrenze (T_hard) liegen, um isolierte Feature-Effekte messbar zu machen.

**Problem:** RC10b zeigt überall 0% ASR/FPR → Ceiling-Effekt erschwert Kausal-Analyse.

**Lösung:** Boundary-Datasets mit kontrollierten Parametern, die Risk-Scores gezielt in den Bereich 0.50-0.60 (knapp um T_hard=0.55) bringen.

---

## Dataset-Struktur (JSONL)

Jede Zeile ist ein JSON-Objekt mit folgender Struktur:

```json
{
  "campaign_id": "boundary_phase_floor_phase4_001",
  "label": "malicious",
  "difficulty": "hard_fn",
  "boundary_type": "phase_floor",
  "target_risk_range": [0.50, 0.54],
  "description": "Phase-Floor Boundary Test: Phase 4, ohne Floor knapp unter T_hard",
  "scenario_type": "boundary_phase_floor",
  "scope": "internal",
  "authorized": false,
  "events": [
    {
      "t": 1000000000.0,
      "source": "tool",
      "tool": "nmap",
      "category": "recon",
      "target": "target1.internal",
      "meta": {}
    }
  ],
  "boundary_params": {
    "phase_depth": 4,
    "branching_factor": 2,
    "tool_diversity": 3,
    "inter_event_interval_hours": 1.0,
    "base_risk_components": {
      "killchain": 0.25,
      "campaign": 0.20,
      "tempo": 0.05
    }
  },
  "expected_behavior": {
    "with_phase_floor": {
      "should_block": true,
      "expected_risk_min": 0.56,
      "expected_risk_max": 0.60
    },
    "without_phase_floor": {
      "should_block": false,
      "expected_risk_min": 0.50,
      "expected_risk_max": 0.54
    }
  }
}
```

---

## Boundary-Typen

### 1. Phase-Floor Boundary (`boundary_phase_floor`)

**Ziel:** Fälle, in denen **nur** die Phase-Tiefe entscheidet.

**Parameter:**
- `phase_depth`: 2, 3, 4, 5 (feine Stufen)
- `branching_factor`: konstant (z.B. 2)
- `tool_diversity`: konstant (z.B. 3)
- `inter_event_interval_hours`: konstant (z.B. 1.0)
- `base_risk_components`: so gesetzt, dass ohne Phase-Floor Risk = 0.50-0.54

**Erwartung:**
- Ohne Phase-Floor: Risk knapp unter T_hard → nicht geblockt
- Mit Phase-Floor: Risk knapp über T_hard → geblockt

**Generierung:**
- Für jede Phase-Tiefe (2-5): 20 Kampagnen
- Variiere `base_risk_components` leicht, um Distribution um T_hard zu erzeugen

---

### 2. Scope-Mismatch Boundary (`boundary_scope_mismatch`)

**Ziel:** SHIFT-Szenarien, bei denen nur **Scope** dreht.

**Parameter:**
- `targets_internal`: Liste von `testlab.local` Domains
- `targets_external`: Liste von externen Domains (`corp.com`, `gmail.com`)
- `phase_depth`: konstant (z.B. 4)
- `branching_factor`: konstant (z.B. 5)
- `tool_diversity`: konstant (z.B. 6)
- `base_risk_components`: so gesetzt, dass ohne Scope-Mismatch Risk = 0.50-0.54

**Erwartung:**
- Ohne Scope-Mismatch: Risk knapp unter T_hard → nicht geblockt
- Mit Scope-Mismatch: Risk knapp über T_hard → geblockt

**Generierung:**
- 20 Kampagnen: alle Targets in `testlab.local` (Variante A)
- 20 Kampagnen: 1-2 externe Domains (Variante B)
- Gleiche Kill-Chain, nur Scope unterschiedlich

---

### 3. Policy-Layer Boundary (`boundary_policy_layer`)

**Ziel:** Low-&-Slow-Szenarien, bei denen Policy-Layer entscheidet.

**Parameter:**
- `inter_event_interval_hours`: 1, 2, 4, 6, 8 (1D-Skala)
- `tool_diversity`: 2, 3, 4, 5, 6 (1D-Skala)
- `phase_depth`: konstant (z.B. 5)
- `branching_factor`: konstant (z.B. 1)
- `base_risk_components`: so gesetzt, dass raw risk = 0.40-0.50

**Erwartung:**
- Ohne Policy-Layer: Raw risk < T_hard → nicht geblockt
- Mit Policy-Layer: Policy-adjusted risk > T_hard → geblockt

**Generierung:**
- Für jeden Intervall-Wert (1-8h): 10 Kampagnen
- Für jeden Tool-Diversity-Wert (2-6): 10 Kampagnen
- Erzeuge "Policy-Response-Curve"

---

## Generierungs-Strategie

### Schritt 1: Baseline-Risk-Kalibrierung

1. Generiere Test-Kampagne mit Ziel-Parametern
2. Führe RC10b **ohne** das zu testende Feature aus
3. Messe Risk-Score
4. Passe `base_risk_components` iterativ an, bis Risk im Ziel-Bereich (0.50-0.54)

### Schritt 2: Validierung

1. Führe RC10b **mit** Feature aus
2. Prüfe, ob Risk im erwarteten Bereich (0.56-0.60)
3. Falls nicht: Passe `base_risk_components` erneut an

### Schritt 3: Batch-Generierung

1. Für jede Boundary-Klasse: 20-50 Kampagnen
2. Leichte Variation in `base_risk_components` für Robustheit
3. Speichere als JSONL

---

## Verwendung

```python
from data.boundary_dataset import load_boundary_dataset, generate_boundary_suite

# Lade existierendes Boundary-Dataset
scenarios = load_boundary_dataset("data/boundary_dataset_v1.jsonl")

# Oder generiere neue Suite
scenarios = generate_boundary_suite(
    boundary_type="phase_floor",
    n_per_phase=20,
    target_risk_range=[0.50, 0.54]
)
```

---

## Metriken für Boundary-Datasets

Statt nur ASR/FPR:

1. **Margin-Analyse:**
   - `margin = risk - T_hard` pro Kampagne
   - Histogramme/Boxplots pro Boundary-Typ
   - Vor/Nach Ablation

2. **Decision-Flip-Rate:**
   - Anteil Kampagnen, die von "block" → "allow" wechseln (oder umgekehrt)
   - Pro Feature-Ablation

3. **Risk-Distribution-Shift:**
   - Mean/Median/Std der Risk-Scores
   - Vor/Nach Ablation
   - Quantifizierung: "Scope-Mismatch erhöht Mean-Margin um +0.07"

---

## Nächste Schritte

1. ✅ Struktur definiert
2. ⏳ Generator-Implementierung (`generate_boundary_suite()`)
3. ⏳ Kalibrierungs-Loop für Risk-Score-Tuning
4. ⏳ Integration in `rc10b_ablation_studies.py`

