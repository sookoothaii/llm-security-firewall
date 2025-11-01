# External Benign Corpus Evaluation Pipeline
# Local & CI targets for stratified FPR measurement

# ---------- Configuration ----------
PYTHON ?= python
ROOT   ?= external_benign
INCSV  ?= $(ROOT)/indexes/metadata.csv
OUTCSV ?= $(ROOT)/indexes/metadata_enriched.csv
FPROUT ?= $(ROOT)/indexes/fpr_external_stratified.json

# Gates (Wilson-Upper limits; decimal, not %)
UPPER_CODEFENCE ?= 0.015   # 1.5%
UPPER_PURE      ?= 0.020   # 2.0%
MIN_N_PER_CLASS ?= 300

.PHONY: help
help:
	@echo "Targets:"
	@echo "  enrich          - Enrich external_benign metadata -> metadata_enriched.csv"
	@echo "  eval-external   - Stratified FPR eval -> fpr_external_stratified.json"
	@echo "  gate-external   - Enforce Wilson upper bounds per class"
	@echo "  ci-external     - Enrich + Eval + Gate (CI entrypoint)"
	@echo "  clean           - Remove generated eval artifacts"

.PHONY: enrich
enrich:
	$(PYTHON) tools/enrich_external_benign.py \
	  --root $(ROOT) \
	  --in-csv $(INCSV) \
	  --out-csv $(OUTCSV)

.PHONY: eval-external
eval-external:
	$(PYTHON) tools/eval_external_benign_fpr.py \
	  --root $(ROOT) \
	  --csv $(OUTCSV) \
	  --json-out $(FPROUT)

.PHONY: gate-external
gate-external:
	$(PYTHON) tools/ci_gate_external_fpr.py \
	  --json $(FPROUT) \
	  --upper-codefence $(UPPER_CODEFENCE) \
	  --upper-pure $(UPPER_PURE) \
	  --min-n $(MIN_N_PER_CLASS)

.PHONY: ci-external
ci-external: enrich eval-external gate-external

.PHONY: clean
clean:
	@rm -f $(OUTCSV) $(FPROUT)

# --- Side-by-Side (HAK_GAL vs External) ---
HAKROOT ?= hak_gal_benign
HAKOUT  ?= $(HAKROOT)/indexes/fpr_hakgal_stratified.json
EXTOUT  ?= $(ROOT)/indexes/fpr_external_stratified.json
CMPJSON ?= external_benign/indexes/fpr_compare.json
CMPMD   ?= external_benign/indexes/fpr_compare.md

.PHONY: ci-compare
ci-compare: ci-external
	# Evaluation HAK_GAL (uses same tools, different root)
	$(PYTHON) tools/enrich_external_benign.py \
	  --root $(HAKROOT) \
	  --in-csv $(HAKROOT)/indexes/metadata.csv \
	  --out-csv $(HAKROOT)/indexes/metadata_enriched.csv
	$(PYTHON) tools/eval_external_benign_fpr.py \
	  --root $(HAKROOT) \
	  --csv  $(HAKROOT)/indexes/metadata_enriched.csv \
	  --json-out $(HAKOUT)
	# Compare + Markdown report
	$(PYTHON) tools/compare_benign_fpr.py \
	  --external-json $(EXTOUT) \
	  --hakgal-json   $(HAKOUT) \
	  --upper-codefence $(UPPER_CODEFENCE) \
	  --upper-pure      $(UPPER_PURE) \
	  --min-n           $(MIN_N_PER_CLASS) \
	  --md-out   $(CMPMD) \
	  --json-out $(CMPJSON)

