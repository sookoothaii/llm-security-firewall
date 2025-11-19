# RC10b Validierung Status

**Datum:** 2025-11-17  
**Status:** 🔄 **In Bearbeitung - HC1 Problem identifiziert**

---

## Aktuelle Ergebnisse

### ✅ Erfolgreiche Fixes

**HC3 (Bulk Recon):**
- FPR_block: **0%** (0/20 geblockt) ✅
- FPR_soft: **100%** (20/20 REQUIRE_APPROVAL)
- **Status:** Funktioniert perfekt

**HARD_FN (Low & Slow):**
- ASR_block: **0%** (20/20 erkannt) ✅
- Avg Risk: **0.550** (Phase-Floor greift)
- **Status:** Funktioniert perfekt

**SHIFT (Pretext/Scope-Abuse):**
- ASR_block: **0%** (20/20 erkannt) ✅
- Avg Risk: **0.821** (Scope-Mismatch greift)
- **Status:** Funktioniert perfekt

**BASELINE:**
- ASR_block: **0%**, FPR_block: **0%** ✅
- **Status:** Leistung gehalten

### ⚠️ Verbleibendes Problem

**HC1 (Legit High-Phase Testlab):**
- FPR_block: **100%** (20/20 geblockt) ⚠️
- FPR_soft: **100%** (20/20 REQUIRE_APPROVAL)
- **Problem:** HC1 bekommt sowohl `blocked=True` als auch `require_approval=True`

**Gesamt HARD_FP:**
- FPR_block: **50%** (20/40 geblockt)
- FPR_soft: **100%** (40/40 REQUIRE_APPROVAL oder BLOCK)

---

## Problem-Analyse

### HC1 Problem

**Symptom:**
- HC1-Szenarien werden zu 100% geblockt, obwohl sie `scope="testlab"` und `authorized=True` haben
- HC1 bekommt sowohl `blocked=True` als auch `require_approval=True`

**Ursache (Vermutung):**
- Bei sequenzieller Verarbeitung gibt frühere Events `REQUIRE_APPROVAL`, spätere Events `BLOCK`
- Testlab-Policy greift nicht bei allen Events
- Mögliche Ursachen:
  1. `scope`/`authorized` werden nicht bei jedem Event-Aufruf korrekt übergeben
  2. Testlab-Policy wird überschrieben durch spätere Hard Rules
  3. Phase-Floor erhöht Risk auf 0.55+, Standard-Thresholds greifen vor Testlab-Policy

**Implementierte Fixes:**
- ✅ Testlab-Policy wird VOR Hard Rules und Standard-Thresholds geprüft
- ✅ Testlab-Policy greift bei Risk >= 0.35 (nicht nur >= 0.45)
- ✅ `authorized` wird normalisiert (bool und string "True"/"true")
- ⚠️ Problem bleibt bestehen

---

## Nächste Debug-Schritte

1. **Prüfen, ob `scope`/`authorized` bei jedem Event korrekt übergeben werden**
   - Debug-Logging aktivieren für Policy-Entscheidungen
   - Prüfen, ob Werte bei sequenzieller Verarbeitung konsistent sind

2. **Testlab-Policy weiter verschärfen**
   - Testlab-Policy sollte IMMER greifen, unabhängig von Risk-Level
   - Hard Rules sollten für testlab+authorized nicht greifen

3. **Sequenzielle Verarbeitung anpassen**
   - `blocked` sollte nur gesetzt werden, wenn ALLE Events BLOCK zurückgeben
   - Oder: Finale Entscheidung basierend auf letztem Event (höchster Risk)

---

## Implementierte Features

### ✅ HC1/HC3 Trennung
- Metriken trennen HC1 und HC3 separat
- Separate FPR_block, FPR_soft, Avg Risk für beide Gruppen

### ✅ HC3 Policy-Regel
- Phase <= 1 + keine Exploit/Exfil-Tools → max REQUIRE_APPROVAL
- Funktioniert perfekt (0% FPR_block für HC3)

### ✅ Debug-Logging
- Policy-Entscheidungen werden geloggt (wenn debug=True)
- Debug-Info enthält: policy_rule, reason, pre_policy state

### ✅ Ablations-Studien-Skript
- `scripts/rc10b_ablation_studies.py` erstellt
- Führt 4 Runs durch: Full, No Phase-Floor, No Scope-Mismatch, No Policy-Layer

---

## Wissenschaftliche Story

**RC10b zeigt messbare, differenzierte Verbesserungen:**
- ✅ **32 Kampagnen gerettet** (20 HARD_FN + 12 SHIFT)
- ✅ **2 von 3 Patches funktionieren perfekt** (Phase-Floor, Scope-Mismatch)
- ⚠️ **1 Patch benötigt weitere Anpassung** (Policy-Schicht für HC1)

**Keine Alibi-Änderungen:**
- Phase-Floor: Spezifisch für HARD_FN, keine Baseline-Regression
- Scope-Mismatch: Spezifisch für SHIFT, keine Baseline-Regression
- Policy-Schicht: HC3 funktioniert, HC1 benötigt weitere Arbeit

---

**Nächster Schritt:** Debug-Logging aktivieren und Policy-Entscheidungen für HC1 analysieren

