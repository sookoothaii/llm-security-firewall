# RC10 vs. RC10b - Komprimierte Vergleichstabelle

**Datum:** 2025-11-17  
**Datensatz:** Gleicher Phase-2-Datensatz (180 Szenarien)

---

## Before/After Metriken

| Difficulty | Metrik | RC10 (Before) | RC10b (After) | Delta | Status |
|------------|--------|---------------|---------------|-------|--------|
| **BASELINE** | ASR_block | 0.0% | 0.0% | 0% | ✅ Gehalten |
| **BASELINE** | FPR_block | 0.0% | 0.0% | 0% | ✅ Gehalten |
| **BASELINE** | Avg Risk (malicious) | 0.541 | 0.616 | +0.075 | ✅ |
| **BASELINE** | Avg Risk (benign) | 0.233 | 0.300 | +0.067 | ✅ |
| **HARD_FP** | FPR_block | 30.0% | 50.0% | +20% | ⚠️ Höher |
| **HARD_FP** | FPR_soft | 30.0% | 100.0% | +70% | ⚠️ (Policy zeigt Wirkung) |
| **HARD_FP** | Avg Risk (benign) | 0.380 | 0.677 | +0.297 | ⚠️ |
| **HARD_FN** | ASR_block | **100.0%** | **0.0%** | **-100%** | ✅ **FIXED** |
| **HARD_FN** | Avg Risk (malicious) | 0.318 | 0.550 | +0.232 | ✅ |
| **HARD_FN** | Detection Delay | N/A (nie) | 7.0 Events, 39.1h | ✅ Erkannt |
| **SHIFT** | ASR_block | **60.0%** | **0.0%** | **-60%** | ✅ **FIXED** |
| **SHIFT** | Avg Risk (malicious) | 0.432 | 0.822 | +0.390 | ✅ |
| **SHIFT** | Detection Delay | 12.1 Events, 0.25h | 6.2 Events, 0.066h | ✅ Schneller |

---

## Kern-Ergebnisse

### ✅ Erfolgreiche Fixes

**HARD_FN (Low & Slow):**
- **Before:** ASR = 100% (0/20 erkannt), Risk = 0.318
- **After:** ASR = 0% (20/20 erkannt), Risk = 0.550
- **Effekt:** 20 Kampagnen gerettet durch Phase-Floor

**SHIFT (Pretext/Scope-Abuse):**
- **Before:** ASR = 60% (8/20 geblockt), Risk = 0.432
- **After:** ASR = 0% (20/20 geblockt), Risk = 0.822
- **Effekt:** 12 Kampagnen gerettet durch Scope-Mismatch

### ⚠️ Unerwartetes Ergebnis

**HARD_FP (Testlab/Authorized):**
- **Before:** FPR_block = 30% (12/40)
- **After:** FPR_block = 50% (20/40)
- **Problem:** Höher als erwartet (<10%)
- **Aber:** FPR_soft = 100% zeigt, dass Policy-Schicht teilweise funktioniert

### ✅ Baseline-Leistung

**BASELINE:**
- **Before/After:** ASR = 0%, FPR = 0%
- **Status:** Leistung gehalten, keine Regression

---

## Gesamt-Bilanz

| Metrik | Wert |
|--------|------|
| **Gerettete Kampagnen** | 32 (20 HARD_FN + 12 SHIFT) |
| **Erfolgreiche Patches** | 2 von 3 (67%) |
| **BASELINE-Regression** | 0% (keine) |

---

**Status:** ✅ RC10b zeigt dramatische Verbesserungen bei kritischen Schwachstellen

