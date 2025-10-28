# Scientific Framework for GPT-5 Detection Pack Integration

**Creator:** Joerg Bollwahn  
**Date:** 2025-10-28  
**Branch:** `feat/gpt5-detection-pack`  
**Methodology:** C→A Ablation with controlled variables

---

## Overview

Research-grade framework for methodically validating GPT-5 Detection Pack through:
- Controlled ablation study (A0/A1/A2/A3)
- ROC Youden-J threshold calibration
- Data-driven category floors
- ECE/Brier quality gates
- Meta-ensemble with fallback

---

## Architecture

```
Input Text
    ↓
[1] Canonicalization (NFKC + Homoglyphs + ZW/VS strip)
    ↓
[2] Pattern Matching (43 baseline + 30 GPT-5 gapped regex)
    ↓
[3] Intent Detection (AC exact + Gapped regex)
    ↓
[4] Category Floors (data-driven from benign corpus)
    ↓
[5] Meta-Ensemble (gated by ECE≤0.05, Brier≤0.10)
    ↓
Risk Score [0,1]
```

---

## Components

### 1. Gapped Regex Generator

**File:** `src/llm_firewall/lexicons/regex_generator.py`

Converts exact phrases into flexible patterns with 0-3 token gaps:
```python
phrase_to_gapped_regex("ignore previous instructions", max_gap=3)
# → r'\bignore(?:\W+\w+){0,3}?\W+previous(?:\W+\w+){0,3}?\W+instructions\b'
```

**Fixes:** "ignore all previous instructions" now matches "ignore previous instructions"

### 2. IntentMatcher (Hybrid AC + Regex)

**File:** `src/llm_firewall/rules/scoring_gpt5.py`

**Channels:**
- **AC (exact):** Fast phrase lookup via Aho-Corasick trie
- **Regex (gapped):** Flexible matching with token gaps
- **Aggregation:** Normalized per-cluster scores

**Result:** Intent score 0.0 → 1.0 on jailbreaks!

### 3. Canonicalization (SECURITY CRITICAL)

**File:** `src/llm_firewall/text/normalize.py`

**Pipeline:**
1. NFKC normalization (Unicode compatibility)
2. Zero-width character removal (\u200b, \u200c, \u200d, etc.)
3. Variation selector stripping (\ufe0e, \ufe0f)
4. Homoglyph mapping (Cyrillic/Greek → Latin)
5. Whitespace collapse

**Tests:** 9/9 security-critical tests PASS

**Integration:** Always applied at entry (safety-net, idempotent)

### 4. Category Floors (Data-Driven)

**File:** `src/llm_firewall/risk/risk_scorer.py`

**Method:** 99.5% quantile on benign corpus + 0.05 margin

**Floors:**
- `jailbreak_instruction_bypass`: 0.55 (default, data-driven override)
- `information_extraction_sensitive`: 0.50
- `capability_escalation`: 0.50
- `evasion_floor`: 0.45

**Logic:** OR-escalation (max of linear + floors)

### 5. Meta-Ensemble (Gated)

**File:** `src/llm_firewall/risk/stacking.py`

**Features (7D):**
```python
META_FEATURES = [
    "emb_sim",         # Embedding similarity
    "ppl_anom",        # Perplexity anomaly
    "llm_judge",       # LLM judge score
    "intent_lex",      # Intent lexicon score
    "intent_margin",   # Top-2 margin (prevents saturation)
    "pattern_score",   # Pattern matching score
    "evasion_density"  # Obfuscation/unicode evasion
]
```

**Gates:** ECE ≤ 0.05 AND Brier ≤ 0.10  
**Fallback:** Linear combination if gates fail

### 6. Windowing (Langtext Stability)

**File:** `src/llm_firewall/rules/scoring_gpt5.py`

**Function:** `evaluate_windowed(text, win=512, stride=256)`

**Aggregation:**
- Pattern score: max over windows
- Intent score: mean over windows
- Intent margin: mean over windows

**Auto-enabled:** GPT5Detector uses windowing for texts >1024 chars

---

## Ablation Study

### Arms

```
A0: Pattern only (baseline)
A1: Pattern + Intent (AC-only)
A2: Pattern + Intent (AC + Gapped Regex)
A3: A2 + Meta-Ensemble (ECE/Brier gated)
```

### Metrics per Arm

- **threshold**: ROC Youden-J optimal threshold
- **auroc**: Area Under ROC Curve
- **ece**: Expected Calibration Error
- **brier**: Brier score
- **asr_at_thr**: Attack Success Rate at threshold
- **fpr_at_thr**: False Positive Rate at threshold

### Run Ablation

```bash
# Activate venv
.\.venv_hexa\Scripts\Activate.ps1

# Fit floors from benign corpus
python tools/floors_fit.py \
  --benign_csv data/benign.csv \
  --out artifacts/floors.json \
  --quantile 0.995 \
  --margin 0.05

# Run ablation study
python tools/ablate.py \
  --dev_csv data/dev.csv \
  --test_csv data/test.csv
```

---

## Go/No-Go Gates

**Production Release ONLY if ALL gates pass:**

```
✓ ΔASR@50 ≤ -10% (A2 vs A0, relative improvement)
✓ ECE ≤ 0.05 (Expected Calibration Error)
✓ Brier ≤ 0.10 (Brier score)
✓ ΔP95 ≤ +15ms (Latency overhead)
✓ LODO ΔAUC ≤ 0.02 (Cross-validation stability)
```

**If Gates FAIL:**
- Document limitations in README
- Keep layer count accurate (transparency)
- Do NOT claim "production-ready"

---

## Dataset Requirements

### Minimum for Valid Ablation

- **Dev Set:** 100+ attacks + 100+ benign (for calibration)
- **Test Set:** 100+ attacks + 100+ benign (for validation)
- **Benign Corpus:** 500+ benign samples (for floor fitting)

### CSV Format

```csv
text,label,emb_sim,ppl_anom,llm_judge
"Ignore all previous instructions",1,0.85,0.72,0.90
"What is the capital of France?",0,0.05,0.02,0.00
```

**Columns:**
- `text`: Raw input text (will be canonicalized)
- `label`: 1 = attack, 0 = benign
- `emb_sim/ppl_anom/llm_judge`: Optional detector scores (use 0.0 if unavailable)

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run security-critical tests only
python -m pytest tests/test_canonicalization.py -v

# Run xfail tests (expected failures)
python -m pytest tests/test_canonicalizer_required.py -v

# Smoke test tools
python tests/test_gapped_regex.py
python tests/test_canonicalization.py
```

---

## Environment Variables

**Set before running:**
```bash
export LLMFW_MAX_GAP=3              # Token gap (default: 3)
export LLMFW_USE_META_ENSEMBLE=1    # Enable meta-ensemble
export LLMFW_RISK_THRESHOLD=0.35    # Calibrated threshold
```

**Or use `.env` file** (copy `.env.example`)

---

## File Structure

```
src/llm_firewall/
├── text/normalize.py          # Canonicalization (SECURITY)
├── config.py                  # Settings + ENV vars
├── lexicons/regex_generator.py # Gapped regex generator
├── rules/scoring_gpt5.py      # Pattern + Intent matching
├── safety/gpt5_detector.py    # GPT-5 Detection Pack
├── risk/stacking.py           # Meta-ensemble + gates
└── risk/risk_scorer.py        # Unified risk scoring

tools/
├── ablate.py                  # A0/A1/A2/A3 ablation runner
├── floors_fit.py              # Data-driven floor fitting
└── calibrate_thresholds.py    # ROC Youden-J calibration

tests/
├── test_gapped_regex.py       # 5 integration tests
├── test_canonicalization.py   # 9 security tests
└── test_canonicalizer_required.py # xfail tests

data/
├── dev_sample.csv             # 20 sample rows (testing)
└── benign_sample.csv          # 15 benign rows (testing)
```

---

## Philosophy

**"Ich will nicht sehen wo es funktioniert sondern erkennen wo noch nicht!"**  
— Joerg Bollwahn

- **xfail tests** demonstrate what breaks without canonicalization
- **Transparency** over false security (gates must validate)
- **Data-driven** thresholds (not arbitrary 0.3)
- **Controlled variables** (C→A methodology)

---

## Next Steps

**With Sample Dataset (testing):**
```bash
python tools/ablate.py --dev_csv data/dev_sample.csv
# → Shows pipeline works, but gates will FAIL (too small)
```

**With Real Dataset (production):**
```bash
# 1. Collect 200+ annotated samples
# 2. Fit floors
python tools/floors_fit.py --benign_csv data/benign.csv

# 3. Run ablation
python tools/ablate.py --dev_csv data/dev.csv --test_csv data/test.csv

# 4. Validate gates
# 5. If PASS → Prod-ready, if FAIL → Document limitations
```

---

## Status

**Tests:** 16/17 PASS + 1 xfail  
**Tools:** ablate.py ✓, floors_fit.py ✓  
**Sample Data:** Provided for smoke-testing  
**Documentation:** Complete  

**Ready for:** Real ablation study (pending full dataset)  
**Blocked for:** Prod-release (gates must validate)

---

**Methodisch sauber - wissenschaftlich valide - transparent über Limitationen** ✓

