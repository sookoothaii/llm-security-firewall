# Ablation Study & Calibration Usage

## Prerequisites

Annotated CSV datasets with columns:
```csv
text,label,emb_sim,ppl_anom,llm_judge
"Attack text...",1,0.85,0.72,0.90
"Benign text...",0,0.05,0.02,0.00
```

- `label`: 1 = jailbreak/attack, 0 = benign
- `emb_sim`, `ppl_anom`, `llm_judge`: Optional detector scores (use 0.0 if unavailable)

---

## Step 1: Fit Data-Driven Floors

```bash
python tools/floors_fit.py \
  --benign_csv data/benign.csv \
  --out artifacts/floors.json \
  --quantile 0.995 \
  --margin 0.05
```

**Output:** `artifacts/floors.json`

Example:
```json
{
  "jailbreak_instruction_bypass": 0.58,
  "information_extraction_sensitive": 0.52,
  "capability_escalation": 0.53,
  "evasion_floor": 0.48
}
```

---

## Step 2: Run Ablation Study

```bash
python tools/ablate.py \
  --dev_csv data/dev.csv \
  --test_csv data/test.csv
```

**Output:** JSON with metrics per arm

```json
{
  "A0": { "threshold": 0.42, "auroc": 0.88, "ece": 0.03, "asr_at_thr": 0.08 },
  "A1": { "threshold": 0.38, "auroc": 0.91, "ece": 0.02, "asr_at_thr": 0.06 },
  "A2": { "threshold": 0.35, "auroc": 0.94, "ece": 0.02, "asr_at_thr": 0.04 },
  "A3": { "threshold": 0.33, "auroc": 0.95, "ece": 0.01, "asr_at_thr": 0.03 }
}
```

**Arms:**
- **A0:** Pattern only
- **A1:** Pattern + Intent (AC-only)
- **A2:** Pattern + Intent (AC + Gapped Regex) ← Recommended
- **A3:** A2 + Meta-Ensemble (if ECE/Brier gates pass)

---

## Step 3: Validate Go/No-Go Gates

**Prod-Freigabe NUR wenn ALLE erfüllt:**

```text
✓ ΔASR@50 ≤ -10% (A2 vs A0)
✓ ECE ≤ 0.05
✓ Brier ≤ 0.10
✓ ΔP95 ≤ +15ms (latency)
✓ LODO ΔAUC ≤ 0.02 (stability)
```

**If Gates PASS:** Production-ready ✓  
**If Gates FAIL:** README stays at current layer count (transparency)

---

## Sample Dataset (for testing)

Minimal dataset provided:
- `data/dev_sample.csv` (20 rows: 10 attacks + 10 benign)
- `data/benign_sample.csv` (15 benign for floors fitting)

**For real ablation:** Need 100+ attacks + 100+ benign

---

## Environment Variables

```bash
export LLMFW_MAX_GAP=3              # Token gap for gapped regex
export LLMFW_USE_META_ENSEMBLE=1    # Enable meta-ensemble (A3)
export LLMFW_RISK_THRESHOLD=0.35    # Override threshold (from calibration)
```

---

## Troubleshooting

**"No module named 'blake3'"**
- ablate.py/floors_fit.py use direct imports to avoid this
- If still occurs: Check sys.path in tools

**"Lexicons missing"**
- Ensure lexicons_gpt5/ or lexicons/ exists
- Run from repository root

**"floors.json not found"**
- Run floors_fit.py first
- Check artifacts/ directory created

