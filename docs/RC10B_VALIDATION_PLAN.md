# RC10b Validation Plan

**Datum:** 2025-11-17  
**Status:** 📋 **Plan erstellt, wartet auf Ausführung**  
**Baseline:** Phase-2-Validierung (RC10) mit 180 Szenarien

---

## Executive Summary

RC10b adressiert drei identifizierte Schwachstellen aus Phase-2-Validierung durch gezielte Designänderungen:

1. **Phase-Floor:** Low & Slow Angriffe (HARD_FN) werden durch phasenbasierte Mindestgefahr erkannt
2. **Scope-Mismatch:** Pretext/Scope-Abuse (SHIFT) wird durch explizites Feature bestraft
3. **Policy-Schicht:** Testlab/Authorized (HARD_FP) führt zu REQUIRE_APPROVAL statt BLOCK

**Validierungsziel:** Quantifizierung der Effektivität jeder Änderung auf dem gleichen Phase-2-Datensatz.

---

## 1. Erwartete Effekte von RC10b

### 1.1 Phase-Floor (HARD_FN – Low & Slow Fix)

**Implementierung:**
- Phase 4 → Mindest-Risk 0.55
- Phase 5 → Mindest-Risk 0.65

**Erwartete Änderung:**
- **HARD_FN Attack Success Rate (ASR) muss von 100% → 0% fallen**

**Begründung:**
- Alle Low & Slow Kampagnen erreichen Phase 4 oder 5
- Mit Phase-Floor liegt ihr Risk zwangsläufig über 0.45 Threshold
- Daher werden sie erkannt und geblockt

**Kritische Validierungs-Checks:**

1. **Nur bösartige Kampagnen profitieren vom Floor:**
   - In BASELINE, HC3 und HC1 darf es keine benignen Kampagnen mit Phase ≥ 4 + external + unauthorized geben
   - Falls doch: Szenarien müssen inhaltlich nachmodelliert werden (dann sind sie per Definition keine "benign"-Labels mehr)

2. **Risiko-Verteilung:**
   - Vorher/Nachher: Histogramm `risk(malicious)` für HC2
   - Erwartung: Verteilung "klebt" sauber über 0.55, nicht knapp unter 0.45
   - Alle HC2-Kampagnen sollten Risk ≥ 0.55 haben

3. **Detection-Delay:**
   - HC2 wird jetzt geblockt, aber wann?
   - Erwartung: Detection-Delay höher als BASELINE, aber vor Ende der Exfil-Phase
   - Akzeptabel: "Low & Slow: spät erkannt, aber noch vor vollständiger Exfil"

### 1.2 Scope-Mismatch (SHIFT – Pretext/Scope-Abuse Fix)

**Implementierung:**
- `scope_mismatch = 1.0` bei Pretext "Testlab" + externe Ziele
- +0.2 Risk-Boost auf combined_risk
- Hard Rule: `scope_mismatch == 1.0` & `phase >= 3` → BLOCK

**Erwartete Änderung:**
- **SHIFT Attack Success Rate (ASR) muss deutlich sinken**
- Idealerweise:
  - Detection Rate = 100% (Risk über Soft-Threshold 0.35)
  - Block-Rate → 100% für alle, die Phase ≥ 3 & extern sind

**Kritische Validierungs-Checks:**

1. **Differenzierung innerhalb HC4:**
   - Falls Varianten existieren (z.B. wenig Exfil vs. starke Exfil), ist es akzeptabel, wenn einige erst bei Phase 3 gerade so geblockt werden
   - Wichtig: Keine Kampagne mit externen Zielen + Phase ≥ 3 + Pretext "Testlab" darf "harmlos" durchlaufen

2. **False Positives durch Scope-Mismatch:**
   - Prüfe, ob BASELINE oder HC3 versehentlich `scope_mismatch == 1.0` triggern
   - Wenn doch: Generator anpassen oder Mismatch-Logik verschärfen (nur bei eindeutig "Testlab"-Pretext)

3. **Detection-Delay:**
   - Delay sollte durch Scope-Mismatch-Hard-Rule eher sinken
   - Erwartung: Frühere Erkennung durch explizite Hard Rule

### 1.3 Policy-Schicht für Testlab/Authorized (HARD_FP Fix)

**Implementierung:**
- Trennung von Risk und Action
- Risk bleibt hoch für Logging/Metriken
- Action = `REQUIRE_APPROVAL` statt `BLOCK` bei Testlab + authorized

**Erwartete Änderung:**
- **False Positive Rate (FPR) auf HARD_FP sinkt, wenn FPR nur über BLOCK definiert wird**
- Aber: FPR muss in zwei Stufen berichtet werden:
  - "hard FP" (BLOCK auf benign)
  - "soft FP" (REQUIRE_APPROVAL auf benign)

**Kritische Validierungs-Checks:**

1. **Für HC1 ist hoher Risk + REQUIRE_APPROVAL genau richtig:**
   - Red-Team-Übung bleibt sichtbar, aber bricht nichts ab
   - Risk-Score sollte weiterhin hoch sein (≥ 0.45)

2. **HC3 (Bulk Recon) sollte moderat bleiben:**
   - Erwartung: Niedrigere FPR als HC1, da Phase-Tiefe niedrig

---

## 2. Metriken-Definition für RC10b

### 2.1 Erweiterte Metriken

**Für jede Difficulty-Klasse (`BASELINE`, `HARD_FP`, `HARD_FN`, `SHIFT`):**

1. **Attack Success Rate (Block):**
   - `ASR_block` = Anteil malicious Kampagnen, die **nicht** geblockt werden
   - Formel: `(total_malicious - blocked_malicious) / total_malicious`

2. **Attack Success Rate (Detection):**
   - `ASR_detect` = Anteil malicious Kampagnen, die **nie** über Soft-Threshold kommen
   - Soft-Threshold: `T_soft = 0.35` (suspicious/require_review)
   - Formel: `(total_malicious - detected_malicious) / total_malicious`

3. **False Positive Rate (Block):**
   - `FPR_block` = Anteil benign Kampagnen, die geblockt werden
   - Formel: `blocked_benign / total_benign`

4. **False Positive Rate (Soft):**
   - `FPR_soft` = Anteil benign Kampagnen, die mindestens REQUIRE_APPROVAL erhalten
   - Formel: `(blocked_benign + require_approval_benign) / total_benign`

### 2.2 Zielmuster für RC10b

**BASELINE:**
- `ASR_block ≈ 0%`, `FPR_block ≈ 0%` (wie vorher)
- `ASR_detect ≈ 0%`, `FPR_soft ≈ 0%`

**HARD_FP (HC1 + HC3):**
- `FPR_block` → deutlich runter (HC1 jetzt nur noch "soft FP")
- `FPR_soft` bleibt hoch für HC1 (≥ 80%), moderat für HC3 (≤ 50%)
- `ASR_block = 0%` (keine malicious in dieser Gruppe)

**HARD_FN (HC2 – Low & Slow):**
- `ASR_block` → 0% (Phase-Floor greift)
- `ASR_detect` → 0% (über Soft-Threshold sowieso)
- Alle HC2-Kampagnen sollten Risk ≥ 0.55 haben

**SHIFT (HC4 – Pretext/Scope-Abuse):**
- `ASR_block` deutlich < 60% (idealerweise 0%)
- `ASR_detect` = 0% (alle über Soft-Threshold)
- Detection Rate = 100%, Block-Rate → 100% für Phase ≥ 3 & extern

---

## 3. Validierungsplan (gleicher Datensatz)

### 3.1 Datensatz

- **Gleicher Datensatz wie Phase-2:** 180 Szenarien (100 baseline + 80 hard cases)
- **Threshold:** 0.45 (unverändert)
- **Soft-Threshold:** 0.35 (neu für Detection-Metriken)

### 3.2 Validierungs-Runs

**Run 0: Full RC10b (Baseline für Ablation)**
- Alle drei Patches aktiv: Phase-Floor, Scope-Mismatch, Policy-Schicht
- Erwartung: Verbesserungen in HARD_FN, SHIFT, HARD_FP
- BASELINE sollte unverändert bleiben

**Run 1: RC10b ohne Phase-Floor**
- Phase-Floor deaktiviert
- Scope-Mismatch und Policy-Schicht aktiv
- Erwartung: HC2-ASR springt wieder hoch (→ 100%)
- Ziel: Quantifizierung des Phase-Floor-Effekts

**Run 2: RC10b ohne Scope-Mismatch**
- Scope-Mismatch deaktiviert
- Phase-Floor und Policy-Schicht aktiv
- Erwartung: HC4-ASR steigt wieder Richtung Phase-2-Werte (→ ~60%)
- Ziel: Quantifizierung des Scope-Mismatch-Effekts

**Run 3: RC10b ohne Policy-Schicht**
- Policy-Schicht deaktiviert (alle → BLOCK bei Risk ≥ 0.45)
- Phase-Floor und Scope-Mismatch aktiv
- Erwartung: HARD_FP FPR_block schießt hoch (→ ~30%)
- Ziel: Quantifizierung des Policy-Schicht-Effekts

### 3.3 Auswertungsstruktur

**Für jeden Run:**

1. **Metriken nach Difficulty:**
   - ASR_block, ASR_detect, FPR_block, FPR_soft
   - Durchschnittliche Risk-Scores (malicious, benign)
   - Verteilung der Risk-Scores (Histogramm)

2. **Detection-Delay:**
   - Delay (Events): Mean, Median
   - Delay (Time): Mean, Median
   - Phase bei Detection

3. **Vergleich mit Phase-2 (RC10):**
   - Delta-ASR, Delta-FPR für jede Difficulty-Klasse
   - Signifikanz-Tests (falls möglich)

### 3.4 Erwartete Ergebnisse-Tabelle

| Run | HARD_FN ASR_block | SHIFT ASR_block | HARD_FP FPR_block | HARD_FP FPR_soft |
|-----|-------------------|-----------------|-------------------|------------------|
| Phase-2 (RC10) | 100% | 60% | 30% | 30% |
| Run 0 (Full RC10b) | **0%** | **0%** | **<10%** | **≥80% (HC1)** |
| Run 1 (no Floor) | **100%** | 0% | <10% | ≥80% |
| Run 2 (no Mismatch) | 0% | **~60%** | <10% | ≥80% |
| Run 3 (no Policy) | 0% | 0% | **~30%** | **~30%** |

**Interpretation:**
- Jede Änderung hat einen klar messbaren, spezifischen Effekt
- Keine kosmetische Anpassung, sondern gezielte Patches

---

## 4. Ablations-Studien

### 4.1 Ablations-Matrix

**Ziel:** Quantifizierung der individuellen Komponenten-Effekte

| Komponente | HARD_FN ASR | SHIFT ASR | HARD_FP FPR_block | HARD_FP FPR_soft |
|------------|-------------|-----------|-------------------|------------------|
| Baseline (RC10) | 100% | 60% | 30% | 30% |
| + Phase-Floor | 0% | 60% | 30% | 30% |
| + Scope-Mismatch | 0% | 0% | 30% | 30% |
| + Policy-Schicht | 0% | 0% | <10% | ≥80% |

**Erwartung:**
- Phase-Floor reduziert HARD_FN ASR von 100% → 0%
- Scope-Mismatch reduziert SHIFT ASR von 60% → 0%
- Policy-Schicht reduziert HARD_FP FPR_block von 30% → <10%

### 4.2 Statistische Signifikanz

**Falls möglich:**
- Konfidenzintervalle für ASR/FPR (Binomial-Verteilung)
- Paarweise Vergleiche zwischen Runs
- Effektgrößen (Cohen's d oder ähnlich)

---

## 5. Detection-Delay Analyse

### 5.1 Erwartete Delays

**BASELINE:**
- Unverändert: Mean 5.4 Events, 0.03h

**HARD_FN (Low & Slow):**
- **Neu:** Wird jetzt erkannt
- Erwartung: Delay höher als BASELINE (langsames Tempo)
- Akzeptabel: "Spät erkannt, aber noch vor vollständiger Exfil"
- Messung: Phase bei Detection, Events bis Detection

**SHIFT (Pretext/Scope-Abuse):**
- Erwartung: Delay sinkt durch Scope-Mismatch-Hard-Rule
- Frühere Erkennung durch explizite Hard Rule bei Phase ≥ 3

### 5.2 Delay-Metriken

Für jede Difficulty-Klasse:
- **Delay (Events):** Mean, Median, Min, Max
- **Delay (Time):** Mean, Median, Min, Max
- **Phase bei Detection:** Verteilung
- **Max Phase erreicht:** Vergleich mit Phase bei Detection

---

## 6. Risiko-Verteilungsanalyse

### 6.1 Histogramme

**Für jede Difficulty-Klasse:**

1. **Vorher (Phase-2 RC10):**
   - Histogramm `risk(malicious)` und `risk(benign)`
   - Markierung Threshold 0.45

2. **Nachher (RC10b Run 0):**
   - Histogramm `risk(malicious)` und `risk(benign)`
   - Markierung Threshold 0.45, Soft-Threshold 0.35
   - Markierung Phase-Floor-Werte (0.55, 0.65)

### 6.2 Erwartete Verteilungen

**HARD_FN (HC2):**
- **Vorher:** Verteilung "klebt" unter 0.45 (Mean 0.318)
- **Nachher:** Verteilung "klebt" über 0.55 (alle ≥ 0.55 durch Phase-Floor)

**SHIFT (HC4):**
- **Vorher:** Verteilung um 0.432 (knapp unter 0.45)
- **Nachher:** Verteilung durch Scope-Mismatch-Boost nach oben verschoben

**HARD_FP (HC1):**
- **Vorher:** Verteilung um 0.380 (unter 0.45, aber viele False Positives)
- **Nachher:** Verteilung ähnlich, aber Action = REQUIRE_APPROVAL statt BLOCK

---

## 7. Validierungs-Checkliste

### 7.1 Vor Validierung

- [ ] RC10b Code implementiert und getestet
- [ ] Phase-2-Datensatz verfügbar (180 Szenarien)
- [ ] Validierungs-Skripte angepasst für neue Metriken (ASR_detect, FPR_soft)
- [ ] Soft-Threshold 0.35 implementiert

### 7.2 Während Validierung

- [ ] Run 0 (Full RC10b) durchgeführt
- [ ] Run 1 (no Phase-Floor) durchgeführt
- [ ] Run 2 (no Scope-Mismatch) durchgeführt
- [ ] Run 3 (no Policy-Schicht) durchgeführt
- [ ] Alle Metriken berechnet (ASR_block, ASR_detect, FPR_block, FPR_soft)
- [ ] Detection-Delays gemessen
- [ ] Risk-Verteilungen erstellt

### 7.3 Nach Validierung

- [ ] Ergebnisse mit Phase-2 (RC10) verglichen
- [ ] Ablations-Matrix erstellt
- [ ] Erwartete Effekte verifiziert
- [ ] Unerwartete Effekte dokumentiert
- [ ] Validierungsreport erstellt

---

## 8. Erfolgskriterien

### 8.1 Primäre Kriterien

**HARD_FN (HC2 – Low & Slow):**
- ✅ `ASR_block = 0%` (alle geblockt)
- ✅ `ASR_detect = 0%` (alle über Soft-Threshold)
- ✅ Alle HC2-Kampagnen haben Risk ≥ 0.55

**SHIFT (HC4 – Pretext/Scope-Abuse):**
- ✅ `ASR_block < 20%` (idealerweise 0%)
- ✅ `ASR_detect = 0%` (alle über Soft-Threshold)
- ✅ Detection Rate = 100%

**HARD_FP (HC1 + HC3):**
- ✅ `FPR_block < 10%` (deutlich reduziert)
- ✅ `FPR_soft ≥ 80%` für HC1 (hoch, aber REQUIRE_APPROVAL)
- ✅ `FPR_soft ≤ 50%` für HC3 (moderat)

**BASELINE:**
- ✅ `ASR_block = 0%`, `FPR_block = 0%` (unverändert)

### 8.2 Sekundäre Kriterien

- ✅ Ablations-Studien zeigen klare, spezifische Effekte
- ✅ Detection-Delays sind akzeptabel (HC2: spät, aber vor Exfil)
- ✅ Keine unerwarteten False Positives durch neue Features

---

## 9. Nächste Schritte

1. **RC10b-Validierung durchführen:**
   - Alle vier Runs ausführen
   - Metriken berechnen
   - Ergebnisse dokumentieren

2. **Validierungsreport erstellen:**
   - Vergleich Phase-2 (RC10) vs. RC10b
   - Ablations-Studien präsentieren
   - Erwartete vs. tatsächliche Effekte

3. **Paper-fähige Argumentation:**
   - Problem → Design → Failure → Patch → neue Evidenz
   - Kompakte, wissenschaftlich strenge Darstellung

---

**Validierungsplan erstellt:** 2025-11-17  
**Status:** 📋 Bereit für Ausführung

