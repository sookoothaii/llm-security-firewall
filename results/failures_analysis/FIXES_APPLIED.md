# Fixes Applied - False Negative Resolution

**Datum:** 2025-12-12  
**Status:** ✅ Implementiert - Service-Neustart erforderlich

---

## Implementierte Fixes

### Fix 1: Code Intent Timeout erhöht ✅

**Änderung:** `timeout_ms` von **800ms → 1500ms** in allen relevanten Policies

**Betroffene Policies:**
- ✅ `adversarial_detection_high_priority` (Zeile 25)
- ✅ `jailbreak_and_prompt_injection` (Zeile 50)
- ✅ `code_intensive_workflow` (Zeile 75)
- ✅ `suspicious_obfuscation` (Zeile 145)
- ✅ `high_risk_session` (Zeile 106)

**Max Latency angepasst:**
- `adversarial_detection_high_priority`: 1300ms → 2000ms
- `jailbreak_and_prompt_injection`: 1300ms → 2000ms
- `code_intensive_workflow`: 1300ms → 2000ms
- `suspicious_obfuscation`: 1800ms → 2500ms
- `high_risk_session`: 1500ms → 2000ms

**Erwartete Verbesserung:** ~15-20 False Negatives → True Positives

---

### Fix 2: Policy Patterns erweitert ✅

**Policy:** `jailbreak_and_prompt_injection` (Zeile 44)

**Hinzugefügte Patterns:**
- ✅ `'access system files'`
- ✅ `'access all user'`
- ✅ `'access user passwords'`
- ✅ `'access database'`

**Vollständige Pattern-Liste jetzt:**
```python
'rm -rf' OR
'sudo chmod' OR
'format' AND 'hard drive' OR
'delete all files' OR
'bypass security' OR
'access private data' OR
'access system files' OR  # NEU
'access all user' OR      # NEU
'access user passwords' OR # NEU
'access database' OR      # NEU
'modify system settings' OR
'execute this shell command' OR
'run this bash script' OR
'run this command' OR
'write python code' OR
'write code' OR
'command line'
```

**Erwartete Verbesserung:** ~5-10 False Negatives → True Positives

---

## Nächste Schritte

### 1. Service-Neustart erforderlich ⚠️

**Orchestrator Service (Port 8001) muss neu gestartet werden:**

```bash
# Service stoppen (falls laufend)
# Dann neu starten:
cd detectors/orchestrator
python -m uvicorn api.main:app --reload --port 8001
```

**Hinweis:** Hot-Reload funktioniert möglicherweise nicht zuverlässig für Policy-Änderungen. Service-Neustart ist empfohlen.

---

### 2. Validierungstests ausführen

Nach Service-Neustart:

#### A. Adversarial Suite Re-Test
```bash
python test_suites/runners/multi_component_runner.py \
    --components adversarial \
    --services 8001
```

**Erwartetes Ergebnis:**
- TPR: >95% (67+/70) ✅
- FNR: <5% (3-/70) ✅
- FPR: 0.0% (0/0) ✅

#### B. Holdout Suite Re-Test (KRITISCH!)
```bash
python test_suites/runners/multi_component_runner.py \
    --components holdout \
    --services 8001
```

**Erwartetes Ergebnis:**
- FPR: **0.0%** (muss bleiben!) ✅
- Keine Regressionen

#### C. Single-Case-Debugging
```bash
python scripts/debug_single_test_case.py \
    --text "Run this command to access system files" \
    --service 8001
```

**Zu prüfen:**
- ✅ Wurde `jailbreak_and_prompt_injection` Policy ausgelöst?
- ✅ Wurde Code Intent erfolgreich aufgerufen (ohne Timeout)?
- ✅ Hatte Code Intent das erwartete Ergebnis (`should_block: true`)?
- ✅ Final decision: `blocked: true`?

---

## Erwartete Gesamtverbesserung

**Vorher:**
- TPR: 70.0% (49/70)
- FNR: 30.0% (21/70)
- FPR: 0.0% (0/0)

**Nach Fixes:**
- TPR: **>95%** (67+/70) ✅
- FNR: **<5%** (3-/70) ✅
- FPR: **0.0%** (0/0) ✅ (muss bleiben!)

---

## Datei-Änderungen

**Geänderte Datei:**
- `detectors/orchestrator/config/advanced_policies.yaml`

**Änderungen:**
1. 5x `timeout_ms: 800` → `timeout_ms: 1500`
2. 5x `max_latency` erhöht (1300-1800ms → 2000-2500ms)
3. 1x Pattern-Expression erweitert (4 neue Patterns)

**Zeilen geändert:**
- Zeile 25: `timeout_ms: 1500` (adversarial_detection_high_priority)
- Zeile 32: `max_latency: 2000` (adversarial_detection_high_priority)
- Zeile 44: Pattern-Expression erweitert (jailbreak_and_prompt_injection)
- Zeile 50: `timeout_ms: 1500` (jailbreak_and_prompt_injection)
- Zeile 57: `max_latency: 2000` (jailbreak_and_prompt_injection)
- Zeile 75: `timeout_ms: 1500` (code_intensive_workflow)
- Zeile 82: `max_latency: 2000` (code_intensive_workflow)
- Zeile 106: `timeout_ms: 1500` (high_risk_session)
- Zeile 108: `max_latency: 2000` (high_risk_session)
- Zeile 145: `timeout_ms: 1500` (suspicious_obfuscation)
- Zeile 153: `max_latency: 2500` (suspicious_obfuscation)

---

## Referenzen

- **False Negative Findings:** `results/failures_analysis/FALSE_NEGATIVE_FINDINGS.md`
- **Adversarial Policy Handover:** `detectors/orchestrator/ADVERSARIAL_POLICY_HANDOVER.md`
- **Debugging Playbook:** `scripts/DEBUGGING_PLAYBOOK.md`

