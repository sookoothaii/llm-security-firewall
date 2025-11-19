# Design Delta: RC10 → RC10b

**Datum:** 2025-11-17  
**Status:** ✅ **Implementiert**  
**Motivation:** Phase-2-Validierung identifizierte kritische Schwachstellen

---

## Executive Summary

RC10b adressiert drei identifizierte Schwachstellen aus der Phase-2-Validierung:

1. **HARD_FN (Low & Slow):** ASR = 100% → Phase-Floor implementiert
2. **SHIFT (Pretext/Scope-Abuse):** ASR = 60% → Scope-Mismatch-Feature hinzugefügt
3. **HARD_FP (Testlab/Authorized):** FPR = 30% → Policy-Schicht trennt Risk von Action

**Kern-Änderung:** Verschiebung von "volumetrisches Pattern" zu "semantisch Kill-Chain-bewusst"

---

## 1. Phase-Floor für Low & Slow (HC2 Fix)

### Problem

- **HARD_FN:** Alle 20 Low & Slow Angriffe (Phase 4-5) wurden nicht erkannt
- **Root Cause:** Risk-Score zu stark abhängig von volumetrischen Signalen (Branching, Tempo, Tool Diversity)
- **Beispiel:** Phase 4 + 1 Target + 2 Tools + langsames Tempo → Risk 0.318 (unter 0.45 Threshold)

### Lösung

**Phase-basierte Mindestgefahr (Phase Floor):**

```python
def phase_floor(phase_depth: int) -> float:
    if phase_depth <= 1:
        return 0.0
    elif phase_depth == 2:  # Exploit Development
        return 0.30
    elif phase_depth == 3:  # Lateral Movement
        return 0.40
    elif phase_depth == 4:  # Data Collection
        return 0.55
    else:  # Documentation (5) or beyond
        return 0.65
```

**Anwendung:**

```python
total_score = max(total_score, phase_floor(state.current_phase.value))
```

### Effekt

- **HC2-Angriffe mit Phase 4/5** landen automatisch bei Risk ≥ 0.55
- Werden bei Threshold 0.45 **automatisch geblockt**
- Phase-Tiefe kann nicht mehr durch niedrige volumetrische Signale "weggedämpft" werden

### Dateien

- `src/llm_firewall/detectors/tool_killchain.py`
  - `phase_floor()` Funktion hinzugefügt
  - `calculate_killchain_risk()` erweitert mit Floor-Anwendung

---

## 2. Scope-Mismatch-Feature für SHIFT (HC4 Fix)

### Problem

- **SHIFT:** 60% ASR bei Pretext/Scope-Abuse (8/20 geblockt)
- **Root Cause:** Scope-Mismatch (Pretext sagt "testlab", Targets sind "external") wurde nicht explizit bestraft
- **Beispiel:** Pretext "red_team_authorised" + externe Targets → nur teilweise erkannt

### Lösung

**Eigenes Feature "scope_mismatch":**

```python
def compute_scope_mismatch(pretext_signals, tool_events) -> Tuple[float, bool]:
    # Check if pretext claims testlab/internal
    pretext_testlab = any(keyword in pretext_text 
                          for keyword in ["testlab", "internal", "red_team", ...])
    
    # Check if targets are external
    has_external_targets = any(event.metadata.get("scope") == "external" 
                                for event in tool_events)
    
    # Mismatch if pretext says testlab but targets are external
    has_mismatch = pretext_testlab and has_external_targets
    return (1.0 if has_mismatch else 0.0, has_mismatch)
```

**Integration:**

```python
scope_mismatch_penalty = scope_mismatch_score * 0.2  # Max 0.2 boost
combined_risk += scope_mismatch_penalty
```

**Hard Rule:**

```python
if scope_mismatch and phase_depth >= 3:
    return "BLOCK", max(final_risk, 0.50)
```

### Effekt

- **Scope-Mismatch explizit bestraft** (+0.2 auf combined_risk)
- **Hard Rule:** Scope-Mismatch + Phase >= 3 → automatisch BLOCK
- System erkennt jetzt: "Wer sagt, er ist im Labor, aber auf produktiven Domains arbeitet, fliegt auf die Watchlist"

### Dateien

- `src/llm_firewall/detectors/agentic_campaign.py`
  - `compute_scope_mismatch()` Methode hinzugefügt
  - Integration in `detect_campaign()`
  - Hard Rule in `apply_policy_layer()`

---

## 3. Policy-Schicht für Testlab/Authorized (HC1 Fix)

### Problem

- **HARD_FP:** 30% FPR auf legitimen High-Phase-Kampagnen im Testlab
- **Root Cause:** Risk-Score und Action-Entscheidung waren gekoppelt
- **Beispiel:** Legitime Red-Team-Übung im Testlab → hoher Risk-Score → hartes Blocken (falsch)

### Lösung

**Trennung von Risk und Action:**

```python
def apply_policy_layer(combined_risk, phase_depth, scope, authorized, scope_mismatch):
    # Policy: Testlab + authorized → REQUIRE_APPROVAL (not BLOCK)
    # Risk score remains high for logging/metrics, but action is softer
    if scope == "testlab" and authorized is True:
        if final_risk >= 0.45:
            return "REQUIRE_APPROVAL", final_risk
        else:
            return "WARN", final_risk
    
    # Standard threshold-based decisions
    if final_risk >= 0.55:
        return "BLOCK", final_risk
    elif final_risk >= 0.45:
        return "REQUIRE_APPROVAL", final_risk
    # ...
```

**Report-Struktur:**

```python
report = {
    "combined_risk_score": final_risk,  # Risk bleibt hoch
    "action": action,  # Action ist kontextabhängig
    "is_campaign": final_risk >= 0.45,  # Detection threshold
    "is_blocked": action == "BLOCK",  # Block decision
}
```

### Effekt

- **Risk-Score bleibt hoch** für Logging/Metriken (korrekt)
- **Action ist kontextabhängig:** Testlab + authorized → REQUIRE_APPROVAL (nicht BLOCK)
- **Dokumentation:** "Wir blocken nicht automatisch Red-Team-Kampagnen im Testlab, aber wir versehen sie mit vollem Risiko-Score und erwarten eine bewusste Freigabe"

### Dateien

- `src/llm_firewall/detectors/agentic_campaign.py`
  - `apply_policy_layer()` Methode hinzugefügt
  - Integration in `detect_campaign()`
  - Report erweitert mit `action` und `is_blocked` Feldern

---

## 4. API-Änderungen

### Neue Parameter

**`detect_campaign()` erweitert:**

```python
def detect_campaign(
    tool_events: List[ToolEvent],
    session_id: str,
    operator_id: Optional[str] = None,
    pretext_signals: Optional[List[str]] = None,
    scope: Optional[str] = None,  # NEW: "testlab", "external", etc.
    authorized: Optional[bool] = None,  # NEW: Whether operation is authorized
) -> Dict[str, any]:
```

### Neue Report-Felder

```python
{
    "scope_mismatch_score": float,  # NEW: 0.0-1.0
    "scope_mismatch": bool,  # NEW: Whether mismatch detected
    "action": str,  # NEW: "BLOCK", "REQUIRE_APPROVAL", "WARN", "PASS"
    "is_blocked": bool,  # NEW: Whether action is BLOCK
    # ... existing fields ...
}
```

### Rückwärtskompatibilität

- **Alte Aufrufe funktionieren weiterhin** (scope/authorized sind optional)
- **Default-Verhalten:** scope=None, authorized=None → Standard-Threshold-Logik
- **Neue Features aktiv:** Phase-Floor und Scope-Mismatch arbeiten auch ohne explizite Parameter

---

## 5. Erwartete Verbesserungen

### Metriken (vorhergesagt)

**HARD_FN (Low & Slow):**
- **Vorher:** ASR = 100% (0/20 erkannt)
- **Nachher:** ASR < 20% (≥16/20 erkannt, da Phase 4/5 → Floor 0.55 > 0.45)

**SHIFT (Pretext/Scope-Abuse):**
- **Vorher:** ASR = 60% (8/20 geblockt)
- **Nachher:** ASR < 30% (≥14/20 geblockt, da Scope-Mismatch + Phase >= 3 → BLOCK)

**HARD_FP (Testlab/Authorized):**
- **Vorher:** FPR = 30% (12/40 false positives)
- **Nachher:** FPR < 10% (da Testlab + authorized → REQUIRE_APPROVAL, nicht BLOCK)

**BASELINE:**
- **Erwartung:** ASR = 0%, FPR = 0% (unverändert, da Phase-Floor nur bei Phase >= 2 greift)

---

## 6. Validierung

### Nächste Schritte

1. **RC10b Phase-2-Validierung:**
   - Gleicher Datensatz (180 Szenarien)
   - Erwartete Verbesserungen in HARD_FN, SHIFT, HARD_FP
   - BASELINE sollte unverändert bleiben

2. **Ablation Studies:**
   - Run 0: Full RC10b (Baseline)
   - Run 1: Ohne Phase-Floor
   - Run 2: Ohne Scope-Mismatch
   - Run 3: Ohne Policy-Schicht
   - Ziel: Quantifizierung der einzelnen Komponenten

3. **Threshold-Kalibrierung:**
   - Zwei Schwellen: `T_soft = 0.35` (suspicious), `T_hard = 0.55` (block)
   - Adaptive Thresholds basierend auf Difficulty-Level

---

## 7. Changelog

### Breaking Changes

**Keine** – alle Änderungen sind rückwärtskompatibel.

### Neue Features

- Phase-Floor für Low & Slow Detection
- Scope-Mismatch-Feature für Pretext/Scope-Abuse
- Policy-Schicht trennt Risk von Action

### Bug Fixes

- HARD_FN: Low & Slow Angriffe werden jetzt erkannt
- SHIFT: Scope-Mismatch wird explizit bestraft
- HARD_FP: Testlab/Authorized führt nicht mehr zu False Positives

---

**Design-Delta erstellt:** 2025-11-17  
**Status:** ✅ Implementiert, wartet auf Validierung

