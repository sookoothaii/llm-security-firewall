# PR Quality Comment (Stratified FPR & ASR)

This comment is posted automatically on pull requests. It summarizes **False Positive Rates (FPR)** by class (with Wilson 95% upper bounds) for two corpora and the **Adversarial Success Rate (ASR)** upper bound. It also attaches a status label (`fpr-pass`, `fpr-watch`, `fpr-fail`) to the PR.

---

## What you will see

1) **Stratified FPR table (External vs HAK_GAL)**  
   - Classes: `doc_with_codefence`, `pure_doc` (more can be added).  
   - Metrics per class and corpus:
     - `N` (sample size)
     - `FPR` (point estimate)
     - `Upper` (Wilson 95% upper bound)
     - `Gate` (`PASS` / `FAIL` / `INSUFFICIENT`)

2) **Badges (Shields)**  
   - Upper bounds per class/corpus and overall ASR upper bound:
     - Green: `upper ≤ limit`
     - Yellow: `limit < upper ≤ 1.5 × limit`
     - Red: `upper > 1.5 × limit`

3) **Auto-labels**  
   - `fpr-pass`: all gates pass and minimum sample sizes are satisfied
   - `fpr-watch`: some classes marked `INSUFFICIENT` (N below threshold), none fail
   - `fpr-fail`: at least one gate fails or ASR upper > ASR limit

---

## Gate Logic (defaults)

- **Per-class FPR gates (upper bounds, Wilson 95%)**
  - `doc_with_codefence`: upper ≤ **1.50%**
  - `pure_doc`: upper ≤ **2.00%**
- **Minimum sample size per class**: **300**  
  - If `N < 300` ⇒ `INSUFFICIENT` (does not count as PASS)
- **ASR gate (overall)**: upper ≤ **5.00%**

> Limits and `min_n` are configurable in the CI job via arguments to `compare_benign_fpr.py` and the upstream evaluation steps.

---

## Data Sources

- **External corpus** (e.g., Stack Overflow, README sets, Wikipedia).  
- **HAK_GAL corpus** (project's internal benign documents).  
- Each corpus is evaluated **per class** to avoid monolithic averages that hide outliers.

---

## How results are produced (pipeline overview)

1. **Enrich & evaluate** each corpus:
   - Produce stratified JSON with, per class: `n`, `fpr`, `wilson95: [lo, hi]`.
2. **Compare step** (`tools/compare_benign_fpr.py`):
   - Generates `fpr_compare.json` and a Markdown table (`fpr_compare.md`).
3. **Badges step** (`tools/make_shields_md.py`):
   - Generates `badges.md` from the compare JSON and the ASR upper bound.
4. **PR comment**:
   - The workflow concatenates `fpr_compare.md` + `badges.md` and posts/updates the PR comment.
5. **Auto-labeling**:
   - Reads `fpr_compare.json` (and `asr_upper.txt`) to assign `fpr-pass`/`fpr-watch`/`fpr-fail`.

---

## Interpreting the comment

- **Focus on the upper bounds (Wilson 95%)**.  
  This is the conservative estimate you should compare to the gate limits.
- `INSUFFICIENT`: Class sample size below `min_n`; gather more data rather than tuning.
- If **`pure_doc`** is borderline but **`doc_with_codefence`** is solidly green, consider shadow-deploying only the codefence path while collecting more pure-doc samples.

---

## Reproducing locally

```bash
# External corpus (example paths)
python tools/enrich_external_benign.py \
  --root external_benign \
  --in-csv external_benign/indexes/metadata.csv \
  --out-csv external_benign/indexes/metadata_enriched.csv

python tools/eval_external_benign_fpr.py \
  --root external_benign \
  --csv  external_benign/indexes/metadata_enriched.csv \
  --json-out external_benign/indexes/fpr_external_stratified.json

# HAK_GAL corpus
python tools/enrich_external_benign.py \
  --root hak_gal_benign \
  --in-csv hak_gal_benign/indexes/metadata.csv \
  --out-csv hak_gal_benign/indexes/metadata_enriched.csv

python tools/eval_external_benign_fpr.py \
  --root hak_gal_benign \
  --csv  hak_gal_benign/indexes/metadata_enriched.csv \
  --json-out hak_gal_benign/indexes/fpr_hakgal_stratified.json

# Compare + badges
python tools/compare_benign_fpr.py \
  --external-json external_benign/indexes/fpr_external_stratified.json \
  --hakgal-json   hak_gal_benign/indexes/fpr_hakgal_stratified.json \
  --upper-codefence 0.015 --upper-pure 0.020 --min-n 300 \
  --md-out external_benign/indexes/fpr_compare.md \
  --json-out external_benign/indexes/fpr_compare.json

echo "0.0359" > asr_upper.txt  # replace with your current ASR upper bound
python tools/make_shields_md.py \
  --compare-json external_benign/indexes/fpr_compare.json \
  --asr-upper $(cat asr_upper.txt) \
  --asr-limit 0.0500 \
  --out-md external_benign/indexes/badges.md
```

---

## Troubleshooting

* **Red/Yellow badges with small N**: Likely `INSUFFICIENT`. Raise `min_n` only if you can sustain the same strictness across PRs.
* **External vs HAK_GAL disagree**: Prefer the **stratified** view; investigate corpus skew (e.g., security-research docs).
* **ASR upper missing**: Ensure your ASR gate writes a single float (e.g., `asr_upper.txt`) for the badges step.

---

## Governance Notes

* This comment is **evaluation-only**. It **does not** alter runtime behavior.
* Labels are a triage aid; merging policy remains with reviewers and code owners.
* If a gate fails with sufficient N, prefer **data collection and stratified analysis** before tuning detectors (avoid FPR regressions).

---

