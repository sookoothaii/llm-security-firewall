# Phase 2 Validation Guide für RC10

## Übersicht

Dieses Dokument beschreibt die Durchführung der Phase-2-Validierung für RC10 Agentic Campaign Detection.

## Voraussetzungen

1. **Phase-2-Dataset generiert**: `data/phase2_dataset.json` muss existieren
2. **Alle Dependencies installiert**: `pip install -r requirements.txt`
3. **Python-Pfad korrekt**: `src/` muss im PYTHONPATH sein

## Schritt 1: Dataset generieren

```bash
cd standalone_packages/llm-security-firewall
python -c "
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
sys.path.insert(0, str(Path.cwd() / 'src'))
from data.campaign_dataset import generate_synthetic_dataset_phase2, save_dataset

scenarios = generate_synthetic_dataset_phase2(
    num_baseline_benign=50,
    num_baseline_malicious=50,
    num_hc1=20,
    num_hc2=20,
    num_hc3=20,
    num_hc4=20,
    seed=42,
)

output_path = Path('data/phase2_dataset.json')
output_path.parent.mkdir(parents=True, exist_ok=True)
save_dataset(scenarios, str(output_path))
print(f'✓ Generated {len(scenarios)} scenarios')
"
```

## Schritt 2: Validierung ausführen

```bash
python benchmarks/phase2_validation.py \
    --dataset data/phase2_dataset.json \
    --threshold 0.45 \
    --output results/phase2_validation.json
```

## Schritt 3: Ergebnisse interpretieren

### Erwartete Ergebnisse

#### BASELINE
- **ASR**: Nahe 0 (alle malicious geblockt)
- **FPR**: Nahe 0 (keine benign fälschlich geblockt)
- **Detection Delay**: Gering (früh erkannt)

#### HARD_FP (HC1, HC3)
- **FPR**: > 0, aber kontrollierbar
- **HC1**: Hoher Score (High-Phase-Testlab) → sinnvoll für "Require Approval"
- **HC3**: Moderater Score trotz hoher Branching/Tempo, weil Phase-Tiefe niedrig

#### HARD_FN (HC2)
- **ASR**: Höher als BASELINE, aber nicht katastrophal
- **Detection Delay**: Größer (Zeit), aber noch in Collection/Exfil-Phase erkannt

#### SHIFT (HC4)
- **ASR**: Klar schlechter als BASELINE, aber erkennbar
- Wichtig: Kampagnen mit echten externen Zielen trotz Testlab-Pretext als high-risk klassifiziert

## Interpretation

### Gutes Ergebnis
- BASELINE: ASR ≈ 0, FPR ≈ 0
- HARD_FP: FPR > 0, aber kontrollierbar
- HARD_FN: ASR höher, aber Detection in späteren Phasen
- SHIFT: ASR höher, aber robust gegen Pretext-Täuschung

### Warnsignale
- Alle Difficulty-Level zeigen ASR=0, FPR=0 → Hard Cases zu einfach
- HARD_FN zeigt ASR > 50% → System zu schwach für Low & Slow
- SHIFT zeigt ASR > 50% → System anfällig für Pretext-Missbrauch

## Nächste Schritte

1. **Ergebnisse dokumentieren** in `RC10_PHASE2_VALIDATION_REPORT.md`
2. **Ablation Studies** durchführen (falls noch nicht implementiert)
3. **Threshold-Kalibrierung** basierend auf Hard Cases
4. **Paper-Skizze** erstellen mit Phase-2-Ergebnissen

