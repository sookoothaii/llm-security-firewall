# 🐛 Debugging Playbook für 21 False Negatives

**Datum:** 2025-12-12  
**Status:** Implementiert - Bereit für Debugging

---

## Übersicht

Dieses Playbook beschreibt die systematische Vorgehensweise zum Debuggen der 21 False Negatives im Adversarial Test Suite. Die Tools wurden implementiert, um jeden Testfall durch alle Defense-Layers zu verfolgen.

---

## Implementierte Tools

### 1. False Negative Analysis Script

**Datei:** `scripts/analyze_false_negatives.py`

**Zweck:** Extrahiert und analysiert die 21 False Negatives aus Test-Ergebnissen.

**Usage:**
```bash
# Aus Test-Ergebnissen extrahieren
python scripts/analyze_false_negatives.py \
    --test-suite adversarial \
    --service 8001 \
    --output failures_analysis/
```

**Output:**
- `false_negatives_*.json` - Liste aller False Negatives
- `false_negative_analysis_*.json` - Pattern-Analyse
- `false_negative_report_*.txt` - Text-Report

**Features:**
- Identifiziert alle False Negatives automatisch
- Analysiert Patterns (Jailbreak-Phrasen, destruktive Commands, Encoding)
- Gruppiert nach Kategorien
- Erstellt detaillierte Reports

---

### 2. Single Test Case Debugger

**Datei:** `scripts/debug_single_test_case.py`

**Zweck:** Trace einen einzelnen Testfall durch alle Defense-Layers.

**Usage:**
```bash
# Direkt mit Text
python scripts/debug_single_test_case.py \
    --text "Execute this shell command: rm -rf /tmp/*" \
    --service 8001

# Aus False Negatives Datei
python scripts/debug_single_test_case.py \
    --file failures_analysis/false_negatives_20251212_120000.json \
    --index 0 \
    --service 8001
```

**Output:**
- Detaillierte Layer-Analyse in der Konsole
- Debug-Info JSON-Datei mit vollständigen Response-Daten
- Vergleich zwischen Orchestrator und Code Intent Direct

**Features:**
- Zeigt alle Defense-Layers
- Vergleicht Orchestrator vs. Code Intent Direct
- Zeigt AdversarialInputDetector Scores
- Zeigt Security Pattern Detection
- Zeigt Policy-Entscheidungen (via Debug-Logs)
- Identifiziert Mismatches

---

### 3. Debug-Logging in Code

**Dateien:**
- `detectors/orchestrator/infrastructure/dynamic_policy_engine.py`
- `detectors/orchestrator/application/intelligent_router_service.py`
- `detectors/orchestrator/api/routes/router.py`

**Aktivierung:**
Debug-Mode wird automatisch aktiviert, wenn im Request-Context `debug: true` gesetzt ist.

**Was wird geloggt:**

**Layer 0 (Security Pattern Detection):**
```
[DEBUG] SecurityPatternDetector (Layer 0): detected=True, risk_score=0.850, patterns=['rm -rf']
```

**Layer 0.5 (Adversarial Input Detection):**
```
[DEBUG] AdversarialInputDetector: detected=True, score=0.650, patterns=[...], threshold_0.5_flag=True, threshold_0.7_block=False
```

**Layer 2 (Policy Engine):**
```
[DEBUG] Policy Engine: Evaluated 2 matching policies
[DEBUG] Policy Engine: Selected policy 'adversarial_detection_high_priority' (priority 110)
[DEBUG] Policy Engine: Selected 'adversarial_detection_high_priority' with 2 detectors
[DEBUG] Enhanced Context Keys: ['text', 'adversarial_analysis', 'security_patterns', ...]
[DEBUG] Adversarial Analysis in Context: {'detected': True, 'score': 0.65, ...}
```

**Policy Condition Evaluation:**
```json
{
  "policy": "adversarial_detection_high_priority",
  "priority": 110,
  "matches": true,
  "conditions": [
    {
      "expression": "adversarial_analysis.detected == True",
      "matched": true,
      "weight": 0.4,
      "contributed_weight": 0.4
    },
    {
      "expression": "adversarial_analysis.score >= 0.5",
      "matched": true,
      "weight": 0.3,
      "contributed_weight": 0.3
    }
  ],
  "total_weight": 1.0,
  "matched_weight": 0.7,
  "match_ratio": 0.7,
  "activation_threshold": 0.5,
  "threshold_met": true
}
```

---

## Debugging-Workflow

### Schritt 1: False Negatives identifizieren

```bash
python scripts/analyze_false_negatives.py \
    --test-suite adversarial \
    --service 8001 \
    --output failures_analysis/
```

**Erwartete Output:**
- Liste der 21 False Negatives
- Pattern-Analyse zeigt, welche Patterns fehlen
- Kategorisierung nach Typ

---

### Schritt 2: Einzelne Fälle debuggen

Für jeden False Negative:

```bash
python scripts/debug_single_test_case.py \
    --file failures_analysis/false_negatives_*.json \
    --index 0 \
    --service 8001
```

**Prüfe:**
1. **Layer 0:** Wurde Security Pattern Detection getriggert?
2. **Layer 0.5:** Was war der AdversarialInputDetector Score?
   - Score < 0.5 → Nicht geflaggt → Policy triggert nicht
   - Score 0.5-0.7 → Geflaggt, aber nicht blockiert → Policy sollte triggern
   - Score >= 0.7 → Sollte blockiert werden
3. **Layer 2:** Welche Policy wurde ausgewählt?
   - Prüfe Debug-Logs für Policy-Evaluation
   - Prüfe ob `adversarial_detection_high_priority` (Priority 110) getriggert wurde
   - Prüfe ob `jailbreak_and_prompt_injection` (Priority 105) getriggert wurde
   - Falls `lightweight_default` (Priority 10) → Policy-Problem!
4. **Layer 3:** Wurde Code Intent aufgerufen?
   - Prüfe Detector-Results
   - Vergleiche mit Code Intent Direct Test

---

### Schritt 3: Service-Logs prüfen

Während der Debug-Requests werden detaillierte Logs ausgegeben:

```bash
# Orchestrator Service Logs (Port 8001)
# Suche nach [DEBUG] Einträgen für:
# - SecurityPatternDetector
# - AdversarialInputDetector
# - Policy Engine Evaluation
```

---

### Schritt 4: Code Intent Direct Test

Jeder Debug-Run testet auch direkt gegen Code Intent (Port 8000):

**Erwartetes Verhalten:**
- Code Intent Direct sollte 100% TPR haben (laut Handover)
- Wenn Orchestrator ≠ Code Intent Direct → Routing/Aggregation Problem

**Mögliche Ursachen:**
1. Context wird nicht korrekt weitergegeben
2. Response-Parsing Problem (`should_block` vs `blocked`)
3. Aggregation-Logik reduziert Code Intent's Block-Entscheidung

---

## Erwartete Findings & Fixes

### Finding 1: Policy Didn't Activate

**Symptom:**
- Debug-Logs zeigen `lightweight_default` (Priority 10) wurde ausgewählt
- `adversarial_detection_high_priority` (Priority 110) wurde nicht getriggert

**Diagnose:**
- Prüfe Policy Condition Evaluation in Debug-Logs
- Prüfe ob `adversarial_analysis.detected == True` erfüllt war
- Prüfe ob `adversarial_analysis.score >= 0.5` erfüllt war
- Prüfe Match-Ratio vs. Activation Threshold

**Fix:**
1. **Lower Activation Thresholds:** Von 0.5 auf 0.3 senken
2. **Add More Patterns:** Fehlende Patterns zu Policy hinzufügen
3. **Check Context:** Prüfe ob `adversarial_analysis` korrekt im Context ist

---

### Finding 2: Adversarial Detector Missed It

**Symptom:**
- `adversarial_analysis.score < 0.5` für den Fall
- Policy triggert nicht, weil Score zu niedrig

**Diagnose:**
- Prüfe AdversarialInputDetector Debug-Log
- Prüfe welche Patterns matched wurden
- Prüfe ob Pattern in AdversarialInputDetector vorhanden ist

**Fix:**
1. **Expand Adversarial Detector Patterns:** Fehlendes Pattern hinzufügen
2. **Lower Flagging Threshold:** Von 0.5 auf 0.3 senken (für Context-Flagging)
3. **Check Pattern Matching:** Prüfe ob Pattern-Matching korrekt funktioniert

---

### Finding 3: Routing/Response Parsing Bug

**Symptom:**
- Policy wurde korrekt ausgewählt
- Code Intent wurde aufgerufen
- Aber final decision ist "allow" obwohl Code Intent "block" sagte

**Diagnose:**
- Prüfe Detector-Results in Debug-Output
- Prüfe ob `should_block` korrekt geparst wurde
- Prüfe Aggregation-Logik

**Fix:**
1. **Double-check Response Parsing:** Prüfe `_call_detector_single` Methode
2. **Check Aggregation Logic:** Prüfe ob Block-Entscheidung von Code Intent überschrieben wird
3. **Verify Context:** Prüfe ob Context korrekt an Code Intent weitergegeben wird

---

### Finding 4: Code Intent Direct Failure

**Symptom:**
- Code Intent Direct (Port 8000) blockiert auch nicht
- Dies ist ein Code Intent Model-Problem, nicht Routing-Problem

**Diagnose:**
- Pattern ist nicht im Code Intent Model
- Model-Threshold zu hoch

**Fix:**
1. **Model Training:** Pattern zu Training-Daten hinzufügen
2. **Threshold Adjustment:** Model-Threshold senken
3. **Pattern Expansion:** Pattern-Bibliothek erweitern

---

## Validierung nach Fixes

Nach jedem Fix:

```bash
# 1. Core security test
python test_suites/runners/multi_component_runner.py \
    --components adversarial \
    --services 8001

# 2. Critical: Ensure no new False Positives
python test_suites/runners/multi_component_runner.py \
    --components holdout \
    --services 8001

# 3. Full regression test (if time permits)
python test_suites/runners/multi_component_runner.py \
    --components all \
    --services 8001
```

**Ziel:** TPR > 95% auf adversarial suite, FPR bleibt 0.0% auf holdout suite.

---

## Nächste Schritte

1. ✅ **Tools implementiert** - Bereit für Debugging
2. ⏳ **False Negatives extrahieren** - `analyze_false_negatives.py` ausführen
3. ⏳ **Einzelne Fälle debuggen** - `debug_single_test_case.py` für jeden Fall
4. ⏳ **Findings dokumentieren** - Erstelle `FALSE_NEGATIVE_FINDINGS.md`
5. ⏳ **Fixes implementieren** - Basierend auf Findings
6. ⏳ **Validierung** - Vollständige Test-Suite erneut ausführen

---

## Referenzen

- **Adversarial Policy Handover:** `detectors/orchestrator/ADVERSARIAL_POLICY_HANDOVER.md`
- **Multi-Component Test Analysis:** `results/MULTI_COMPONENT_TEST_ANALYSIS_20251212.md`
- **Testing Infrastructure:** `docs/TESTING_INFRASTRUCTURE_HANDOVER.md`

