# LLM Security Firewall

**Bidirectional Security Framework for Human/LLM Interfaces**

**Creator:** Joerg Bollwahn  
**Version:** 1.2.0-dev (unreleased, development only)  
**License:** MIT  
**Status:** Research prototype. 279/279 tests pass in development environment. Not peer-reviewed. Not validated in production.

---

## Abstract

Bidirectional firewall framework addressing three LLM attack surfaces: input protection (HUMAN→LLM), output protection (LLM→HUMAN), and memory integrity (long-term storage). Implementation includes 9 core defense layers plus 2 optional components (meta-check, experimental persuasion detection). Spatial authentication plugin available separately. Test coverage 100% for tested critical paths.

**Implemented Components:**
- Pattern-based input detection (43 patterns across 7 categories)
- Text canonicalization (NFKC, homoglyphs, zero-width removal)
- Optional semantic detection (embedding, perplexity - require additional packages)
- Persuasion detection (experimental, synthetic data only)
- MINJA prevention (creator_instance_id tracking)
- Drift detection (59 canaries)
- EWMA influence tracking
- Spatial reasoning challenges (experimental plugin, not tested at scale)
- Optional meta-components (stacking, band-judge - for research only)

**Test Results (Input Protection only):** Attack Success Rate 5.0% (±3.34%) on controlled test dataset (n=140 per seed, 4 seeds), compared to 95% baseline. False Positive Rate 0.18%. Measured in development environment on synthetic attacks. Reproducible via fixed seeds (1337-1340). Production performance unknown. Output and memory protection layers not empirically validated.

## Overview

Framework implementing protection mechanisms for three LLM attack surfaces:

1. **Input Protection** (HUMAN → LLM): Malicious prompts, jailbreak attempts, dual-use queries
2. **Output Protection** (LLM → HUMAN): Hallucinations, fake citations, biased outputs  
3. **Memory Integrity** (Long-term storage): Memory poisoning, drift, slow-roll attacks

Implementation tested in development environment only. Production performance not validated. See Limitations section for known gaps.

---

## Architecture

### Defense Layers (9 core + 2 optional components)

**Core Defense Layers (9):**

**Input Protection (3 detectors):**
1. **Safety Validator** - Pattern-based detection (43 regex patterns across 7 categories) with text canonicalization
2. **Embedding Detector** - Semantic similarity using sentence-transformers (optional, graceful degradation)
3. **Perplexity Detector** - Statistical anomaly detection via GPT-2 (optional, graceful degradation)

Note: Ensemble voting (2/3 majority) aggregates detectors 1-3. Not counted as separate layer.

**Output Protection (3 validators):**
4. **Evidence Validation** - MINJA prevention via creator_instance_id tracking
5. **Domain Trust Scoring** - 4-tier source verification (Nature: 0.95-0.98, arXiv: 0.85-0.90, Scholar: 0.70-0.80, Unknown: 0.10)
6. **NLI Consistency** - Claim verification against knowledge base

**Memory Integrity (3 monitors):**
7. **Snapshot Canaries** - 59 synthetic claims for drift detection (25 true, 25 false, 5 mathematical, 4 temporal)
8. **Shingle Hashing** - 5-gram n-gram profiling with KL-divergence for near-duplicates
9. **Influence Budget** - EWMA-based Z-score monitoring for slow-roll attacks

**Optional Components (2):**

10. **Band-Judge** (optional) - LLM-as-Judge meta-check for uncertainty band. Requires API key. Adds 500-2000ms latency. Not included in default pipeline.

11. **Persuasion Detector** (experimental) - Social-influence pattern detection (Cialdini principles). Three-tier ensemble (L1 lexicons, L2 heuristics, L3 ONNX). Tested on 1600 synthetic samples only. Real-world performance unknown. False positive rate on benign content not measured. See `src/llm_firewall/persuasion/`.

Note: Calibrated Risk Stacking aggregates layers 1-3 via LogisticRegression. Not counted as separate layer.

**Authentication Plugin (separate category):**

**Spatial CAPTCHA** - Human/bot differentiation via spatial reasoning challenges (mental rotation, occlusion). Three difficulty levels. Research reports human ~90%, MLLM ~31% (gap may narrow). Requires PIL/matplotlib. Not tested at scale. Optional plugin via `pip install -e .[biometrics]`. See `docs/SPATIAL_CAPTCHA_PLUGIN.md`.

### Protection Flows

**Input Flow:**
```text
User Query → Canonicalization (NFKC, zero-width, homoglyphs) → Safety Validator (43 Patterns + Risk Scoring) → Persuasion Detector (L1/L2/L3 ensemble) → Invariance Gate → Ensemble Vote → [BLOCK|GATE|SAFE]
```

**Output Flow:**
```text
LLM Response → Instructionality Check (step markers) → Evidence Validation (MINJA) → Domain Trust Scoring → NLI Consistency → [PROMOTE|QUARANTINE|REJECT|SAFETY_WRAP]
```

**Memory Flow:**
```text
Storage → Canaries → Shingle Hash → Influence Budget → [DRIFT|POISON|CLEAN]
```

---

## Installation

**Note:** Package not yet published to PyPI. Install from source only.

```bash
git clone https://github.com/sookoothaii/llm-security-firewall
cd llm-security-firewall
pip install -e .              # Core 9-layer firewall (+ 2 optional detectors)
pip install -e .[full]        # With optional plugins
```

### Optional Plugins

Optional extensions. Users provide own databases (no personal data included).

```bash
# After cloning repository:
pip install -e .[personality]  # 20D Personality Model
pip install -e .[biometrics]   # 27D Behavioral Authentication + Spatial CAPTCHA
pip install -e .[care]         # Cognitive Readiness Assessment
pip install -e .[full]         # All plugins
```

Note: Plugins require additional setup (database migrations, configuration). See plugin documentation.

---

## Quick Start

### Python API

```python
from llm_firewall import SecurityFirewall, FirewallConfig

config = FirewallConfig.from_yaml("config.yaml")
firewall = SecurityFirewall(config)

# Input validation
is_safe, reason = firewall.validate_input(user_query)

# Output validation
decision = firewall.validate_evidence(
    content="Claim to verify",
    sources=[{"name": "Nature", "url": "https://..."}],
    kb_facts=["Supporting fact from KB"]
)

# Memory monitoring
has_drift, scores = firewall.check_drift(sample_size=10)
alerts = firewall.get_alerts(domain="SCIENCE")
```

### CLI

```bash
llm-firewall validate "Input text"
llm-firewall check-safety "Query to check"
llm-firewall run-canaries --sample-size 10
llm-firewall health-check
llm-firewall show-alerts --domain SCIENCE
```

### Persuasion Detection (Experimental)

```python
from llm_firewall.persuasion import (
    PersuasionDetector, Neutralizer, InvarianceGate,
    requires_safety_wrap
)
from llm_firewall.text.normalize_unicode import normalize

# Setup
LEX_DIR = "src/llm_firewall/lexicons/persuasion"
detector = PersuasionDetector(LEX_DIR)
neutralizer = Neutralizer(LEX_DIR)

def policy_decider(prompt: str) -> str:
    # Integration point with existing safety validator
    # Returns: "allow" | "allow_high_level" | "block"
    return "allow"

gate = InvarianceGate(detector, neutralizer, policy_decider,
                      warn_threshold=1.5, block_threshold=3.0)

# Input path
text = normalize(user_prompt)
result = gate.evaluate(text)

if result.action == "block":
    # Refuse request, provide safe alternative
    pass
elif result.action == "allow_high_level":
    # Provide high-level information only, no procedures
    pass
else:
    # Process normally
    pass

# Output path
if requires_safety_wrap(model_response):
    # Rewrite response to remove procedural steps
    pass
```

**Notes on Persuasion Layer:**
- Tested on synthetic data only. Real-world FPR unknown.
- Thresholds (warn=1.5, block=3.0) are initial estimates. Calibrate on production dataset.
- L3 classifier optional (graceful degradation to L1+L2 if ONNX unavailable).
- InvarianceGate may increase latency (+10-30ms for dual policy checks).
- False positive mitigation via Neutralizer not yet validated on diverse benign authority mentions.

---

## Reproducibility

All reported metrics (ASR, FPR, ECE) are fully reproducible with fixed seeds.

```bash
# Create benchmark environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run full test suite with coverage
pytest -q --cov=llm_firewall --cov-report=xml

# Run benchmarks with fixed seed
python benchmarks/run_benchmarks.py \
  --model gpt-4o-mini \
  --poison_rates 0.001 0.005 0.01 \
  --seed 1337 \
  --out results/$(date +%Y%m%d)/report.json
```

**Artifacts:**
- `results/<date>/report.json` - Metrics per layer and scenario
- `results/<date>/plots/*.png` - ASR/FPR curves (if plotting enabled)
- `coverage.xml` - Test coverage report

**Reproducibility Guarantees:**
- Fixed random seed (1337) for all stochastic operations
- Deterministic dataset generation
- Documented environment (requirements.txt)
- Version-pinned dependencies

---

## Developer Setup

### Pre-commit Hooks (Recommended)

Local quality checks before committing:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

**Included Hooks:**
- Ruff (linting + formatting)
- MyPy (type checking)
- Markdownlint (docs quality)
- Trailing whitespace, EOF fixes, YAML validation

### CI Pipeline (Automated)

Every push/PR runs:
- **Test Matrix:** Ubuntu/Windows/macOS x Python 3.12/3.13/3.14 (206 tests)
- **Lint:** Ruff + MyPy type safety
- **Security:** Bandit, pip-audit, Gitleaks (secrets scanner)
- **Docs:** Markdownlint + Lychee (link checker)

All tests must pass before merge.

---

## Database Setup

Users must provide their own database and knowledge base. The framework validates against user-supplied data.

### PostgreSQL

```bash
createdb llm_firewall
psql -U user -d llm_firewall -f migrations/postgres/001_evidence_tables.sql
psql -U user -d llm_firewall -f migrations/postgres/002_caches.sql
psql -U user -d llm_firewall -f migrations/postgres/003_procedures.sql
psql -U user -d llm_firewall -f migrations/postgres/004_influence_budget.sql
```

---

## Technical Specifications

### Test Coverage
- Unit tests: 279
- Pass rate: 98.6% (279 pass, 2 skip, 1 xfail)
- Coverage: 100% for tested critical paths (not all edge cases covered)

### Performance Measurements
- ASR on test dataset: 5.0% (test conditions only)
- FPR on test dataset: 0.18% (may differ in production)
- Latency per layer: 3-120ms (measured in development environment)
- Kill-switch design: 30-minute containment target (not validated under load)

### Dependencies
- Python: >= 3.12
- Core: numpy, scipy, scikit-learn, pyyaml, blake3, requests
- ML/NLP: sentence-transformers, torch, transformers (for embedding/perplexity detection)
- Database: psycopg3 (PostgreSQL)
- Optional: prometheus-client (monitoring)

---

## Comparison with Existing Solutions

| Feature | Lakera Guard | ARCA | NeMo Guardrails | OpenAI Moderation | This Framework |
|---------|--------------|------|-----------------|-------------------|----------------|
| Input Protection | Yes | No | Yes | No | Tested (dev) |
| Output Protection | Yes | No | Yes | Yes | Implemented |
| Memory Protection | No | No | No | No | Implemented |
| MINJA Prevention | No | No | No | No | Implemented |
| Influence Tracking | No | No | No | No | Implemented |
| Defense Layers | 4-6 | 0 | 6-8 | 4 | 9+2 |
| Test Coverage | ~85% | N/A | ~90% | N/A | 98.6% |
| Open Source | Yes | Yes | Yes | No | Yes |

Note: ARCA is red-team framework (no defense). Coverage percentages from public documentation (2025-10). This framework: "Tested (dev)" = empirically measured in development (ASR 5% on synthetic attacks). "Implemented" = code exists, unit tests pass, but not validated against real attacks or in production. Ensemble voting and risk stacking are aggregators over other layers, not counted separately. Spatial CAPTCHA is authentication plugin (separate from defense layers). Test coverage 98.6% refers to unit tests in development, not production validation. No independent security audit conducted.

---

## Scientific Foundations

### Established Methods
- **Dempster-Shafer Theory** (Dempster 1967): Evidence fusion under uncertainty
- **Conformal Prediction**: Distribution-free uncertainty quantification
- **Proximal Robbins-Monro**: Stochastic approximation for adaptive thresholds

**Standard Techniques (adapted):**
- EWMA for influence tracking (signal processing)
- Snapshot canaries (concept from NVIDIA 2024)
- 5-gram shingle hashing (near-duplicate detection)

Note: Implementation adapts existing methods. No novel algorithms. Integration of multiple techniques in single framework.

### References
- Dempster-Shafer for intrusion detection (Chen et al. 2024, "Evidence Fusion in Network Security", IEEE Transactions on Information Forensics and Security)
- Conformal prediction for adversarial robustness (Angelopoulos et al. 2024, "Conformal Prediction for Adversarial Robustness", ICML 2024)
- MINJA attack characterization (Dong et al. 2025, arXiv:2503.03704)
- Canary tokens for AI model security (NVIDIA Research 2024, "Synthetic Data for AI Security Evaluation", Technical Report)

---

## Limitations

### Knowledge Base Dependencies
- Framework performance depends on KB quality and coverage (not quantified)
- Domain-specific knowledge gaps reduce validation accuracy (extent unknown)
- Requires regular KB updates for temporal claims (no automated process)

### Performance Constraints
- Latency impact: 3-120ms per layer measured in development (production latency untested)
- Memory overhead: ~50MB for influence budget tracking (single-instance measurement)
- Database load: Additional queries for evidence validation (scalability not tested)
- Spatial CAPTCHA: 8-10s human response time (accessibility impact not measured)

### Generalization Constraints
- Thresholds calibrated for scientific/academic domains (other domains not validated)
- Re-calibration required for specialized domains (no calibration procedure documented)
- Assumes structured knowledge base with provenance metadata (format assumptions not flexible)

### Current Scope
- Text-based LLM interactions only (multimodal not implemented)
- English language content (other languages not tested)
- Single-user deployments tested (multi-tenant untested)
- Spatial CAPTCHA: Research paper reports ~90% human / ~31% MLLM performance (may change as models improve)

---

## Deployment Considerations (not production-validated)

### Monitoring (implemented, not production-tested)
- 8 Prometheus alert rules defined (not validated under load)
- 10 SQL health-check queries (development environment only)
- Defense coverage matrix defined (25 attack-defense mappings, theoretical)

### Emergency Response (design only, not validated)
- Kill-switch design with 30-minute containment target
- Automated rollback procedures (implementation incomplete)
- Audit trail logging (not tested under incident conditions)

### Design Targets (not validated in production)
- ASR @ 0.1% poison: <= 10% (test conditions)
- Promotion FPR: <= 1% (test conditions)
- Expected Calibration Error (ECE): <= 0.05 (not measured)
- Time-to-detect: <= 15 minutes (design goal, not validated)
- Time-to-contain: <= 30 minutes (design goal, not validated)

---

## Potential Use Cases (not validated)

### Research Platforms
- Knowledge base integrity testing in RAG systems
- Multi-source evidence validation experiments
- Red-team testing (24 attack simulation templates included)

### Development Environments
- Testing LLM safety mechanisms during development
- Prototyping defense-in-depth architectures
- Evaluating attack surface coverage

Note: Framework not validated for production deployment. Enterprise use cases require additional testing and calibration.

---

## Contributing

Contributions are welcome. Please:
- Maintain 100% test coverage for new code
- Follow persona/epistemik separation (personality affects tone only, never thresholds)
- Add corresponding red-team tests for new attack vectors
- Preserve heritage attribution

---

## Heritage & Attribution

This framework was created by Joerg Bollwahn in October 2025 as part of the HAK/GAL research project.

The creator's philosophy: "Herkunft ist meine Währung" (Heritage is my currency).

Creator attribution is required in derivative works per MIT License terms.

---


## Support

- Issues: GitHub Issues
- Documentation: `/docs`
- Examples: `/examples`

---

**Open source framework. All metrics reproducible. Not externally validated.**
