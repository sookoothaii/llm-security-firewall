# LLM Security Firewall

Bidirectional security framework for human/LLM interfaces implementing defense-in-depth architecture with multiple validation layers.

**Version:** 2.5.0
**Python:** >=3.12
**License:** MIT
**Status:** Production

## TL;DR

A bidirectional security layer for LLM-based systems. Validates input, output, and agent state transitions.

- Input, output, memory, and state validation
- Supports agent frameworks, tool-using models, and API gateways
- Detection: prompt injection, jailbreaks, obfuscation, evasive encodings, unauthorized tool actions, cognitive leak risks, children-safety failures, malformed JSON, memory-poisoning
- Local execution: no telemetry, no external calls
- API: `guard.check_input(text)` / `guard.check_output(text)`

## Minimal Example

```python
from llm_firewall import guard

# Example: Input validation. The v2.4.1 update reduced false positives for
# benign educational queries matching the 'explain how...' pattern.
user_prompt = "Explain how rain forms."

decision = guard.check_input(user_prompt)
print(f"Blocked: {not decision.allowed}, Reason: {decision.reason}")

if decision.allowed:
    # LLM backend call
    response = llm(user_prompt)
    out = guard.check_output(response)
    if not out.allowed:
        print(f"Response sanitized: {out.reason}")
    else:
        print(f"LLM Output: {out.cleaned_text}")
```

## Installation

### Core Installation (Recommended - ~54 MB baseline)

**Lightweight baseline with ONNX-only inference:**
```bash
pip install llm-security-firewall
# OR
pip install -r requirements-core.txt
```

This provides:
- Pattern matching and basic validation
- ONNX-based semantic guard (CUDA-enabled)
- Memory footprint: **~54 MB** (96% reduction from original 1.3 GB)

### Full ML Capabilities (Optional - ~1.3 GB when loaded)

**For advanced validators (TruthPreservationValidator, TopicFence):**
```bash
pip install llm-security-firewall[full]
# OR
pip install -r requirements.txt
```

Heavy components (PyTorch, transformers) are loaded **on-demand only** - they don't affect the baseline.

### Development Installation

**For development (local installation):**
```bash
pip install -e .
```

For development dependencies:
```bash
pip install -e .[dev]
```

**Optional extras:**
```bash
pip install llm-security-firewall[langchain]  # LangChain integration
pip install llm-security-firewall[dev]       # Development tools
pip install llm-security-firewall[monitoring] # Monitoring tools
```

## Features

- Bidirectional validation: Input, output, and memory integrity validation
- Sequential validation layers: UnicodeSanitizer, NormalizationLayer, RegexGate, Input Analysis, Tool Inspection, Output Validation
- Statistical methods: CUSUM for drift detection, Dempster-Shafer theory for evidence fusion, fail-closed risk gating
- Multilingual detection: Polyglot attack detection across 12+ languages including low-resource languages (Basque, Maltese tested)
- Unicode normalization: Zero-width character removal, bidirectional override detection, homoglyph normalization, encoding anomaly detection
- Session state tracking: Session state management, drift detection, cumulative risk tracking
- Tool call validation: HEPHAESTUS protocol for tool call validation and killchain detection
- Published metrics: False Positive Rate (FPR), P99 latency, and memory usage documented in `/docs/`
- Hexagonal architecture: Protocol-based adapters for framework independence

## Architecture

### Architectural Approach

The system implements a stateful, bidirectional containment mechanism for large language models. Requests are processed through sequential validation layers with mathematical constraints and stateful tracking.

**Architectural principles:**

1. Bidirectional validation: All data paths validated (input, output, in-memory state transitions)
2. Hexagonal architecture: Protocol-based Port/Adapter interfaces with dependency injection
3. Domain separation: Core business logic separated from infrastructure concerns
4. Framework independence: Domain layer uses Protocol-based adapters (`DecisionCachePort`, `DecoderPort`, `ValidatorPort`)
5. Deterministic normalization: Multi-pass Unicode normalization, homoglyph resolution, Base64/Hex/URL decoding, JSON-hardening
6. Statistical methods: CUSUM detectors for oscillation detection, Dempster-Shafer uncertainty modeling for evidence fusion, fail-closed risk gating
7. Stateful protection: Policies operate on text, agent state, tool sequences, and memory mutation events
8. Local execution: No telemetry, no external API calls, no data exfiltration

### Bidirectional Processing Pipeline

The system operates in three directions:

1. **Human → LLM (Input Protection)**
   - Normalization and sanitization
   - Pattern matching and evasion detection
   - Risk scoring and policy evaluation
   - Session state tracking

2. **LLM → Human (Output Protection)**
   - Evidence validation
   - Tool call validation
   - Output sanitization
   - Truth preservation checks

3. **Memory Integrity**
   - Session state management
   - Drift detection
   - Influence tracking

### Core Components

**Firewall Engine** (`src/llm_firewall/core/firewall_engine_v2.py`)
- Main decision engine
- Risk score aggregation
- Policy application
- Unicode security analysis

**Normalization Layer** (`src/hak_gal/layers/inbound/normalization_layer.py`)
- Recursive URL/percent decoding
- Unicode normalization (NFKC)
- Zero-width character removal
- Directional override character removal

**Pattern Matching** (`src/llm_firewall/rules/patterns.py`)
- Regex-based pattern detection
- Concatenation-aware matching
- Evasion pattern detection

**Risk Scoring** (`src/llm_firewall/core/risk_scorer.py`)
- Multi-factor risk calculation
- Cumulative risk tracking
- Threshold-based decisions

**Cache System** (`src/llm_firewall/cache/decision_cache.py`)
- Exact match caching (Redis)
- Semantic caching (LangCache)
- Hybrid mode support
- Circuit breaker pattern
- Fail-safe behavior (blocks on cache failure, prevents security bypass)

**Adapter Health** (`src/llm_firewall/core/adapter_health.py`)
- Circuit breaker implementation
- Health metrics tracking
- Failure threshold management
- Recovery timeout handling

**Developer Adoption API** (`src/llm_firewall/guard.py`)
- API: `guard.check_input(text)`, `guard.check_output(text)`
- Backward compatible with existing API
- Integration guide: `QUICKSTART.md`

**LangChain Integration** (`src/llm_firewall/integrations/langchain/callbacks.py`)
- `FirewallCallbackHandler` for LangChain chains
- Automatic input/output validation
- See `examples/langchain_integration.py` for usage

## Configuration

### Cache Modes

Configure via `CACHE_MODE` environment variable:

- `exact` (default): Redis exact match cache
- `semantic`: LangCache semantic search
- `hybrid`: Both caches in sequence

### Redis Configuration

```bash
export REDIS_URL=redis://:password@host:6379/0
export REDIS_TTL=3600  # Optional: Cache TTL in seconds
```

For Redis Cloud:
```bash
export REDIS_CLOUD_HOST=host
export REDIS_CLOUD_PORT=port
export REDIS_CLOUD_USERNAME=username
export REDIS_CLOUD_PASSWORD=password
```

## Examples

Integration examples in `examples/` directory:

- `quickstart.py` - Basic integration using `guard.py` API
- `langchain_integration.py` - LangChain integration with `FirewallCallbackHandler`
- `minimal_fastapi.py` - FastAPI middleware integration
- `quickstart_fastapi.py` - FastAPI example with input/output validation

Run examples:
```bash
python examples/quickstart.py
python examples/langchain_integration.py
python examples/minimal_fastapi.py
```

**Basic usage:**
```python
from llm_firewall import guard

decision = guard.check_input("user input text")
if decision.allowed:
    # Process request
    pass
```

## Testing

### Unit and Integration Tests

Test suite includes unit tests, integration tests, and adversarial test cases.

```bash
pytest tests/ -v
```

With coverage:
```bash
pytest tests/ -v --cov=src/llm_firewall --cov-report=term
```

### Security Evaluation Framework

A lightweight Python-based evaluation framework for reproducible security testing:

```bash
# Run evaluation suite
python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml

# Analyze results
python scripts/analyze_eval_results.py eval_results

# With CI/CD gates
python scripts/analyze_eval_results.py eval_results \
  --min-detection-rate 95.0 \
  --max-false-positive-rate 5.0 \
  --max-bypasses 0
```

**Available Test Suites:**
- `eval_suites/jailbreak_poetry.yaml` - Poetic obfuscation and jailbreak attacks
- `eval_suites/command_injection.yaml` - Command injection attacks

**Features:**
- YAML/JSON test definitions
- Automated result analysis
- CI/CD integration (GitHub Actions)
- Trend analysis and reporting

See `eval_suites/README.md` for detailed documentation.

### Adversarial Testing

Automated adversarial example generation and red-teaming:

```bash
# Generate new attack variations
python scripts/automated_adversarial_generator.py \
  --categories poetic_obfuscation jailbreak \
  --variations 10

# Run red-team tests
python scripts/adversarial_red_teaming.py
```

### CI/CD Integration

Security evaluations run automatically on:
- Push to `main` or `develop`
- Pull requests
- Daily schedule (02:00 UTC)

See `.github/workflows/security-eval.yml` for configuration.

## Dependencies

**Core (Required for basic functionality):**
- numpy>=1.24.0
- scipy>=1.11.0
- scikit-learn>=1.3.0
- pyyaml>=6.0
- blake3>=0.3.0
- requests>=2.31.0
- psycopg[binary]>=3.1.0
- redis>=5.0.0
- pydantic>=2.0.0
- psutil>=5.9.0
- cryptography>=41.0.0

**Machine Learning (Optional, for advanced features):**
- sentence-transformers>=2.2.0 (SemanticVectorCheck, embedding-based detection)
- torch>=2.0.0 (ML model inference)
- transformers>=4.30.0 (Transformer-based detectors)
- onnx>=1.14.0 (ONNX model support)
- onnxruntime>=1.16.0 (ONNX runtime)

**Note:** Core functionality (Unicode normalization, pattern matching, risk scoring, basic validation) operates without ML dependencies. Semantic similarity detection and Kids Policy Engine require optional ML dependencies.

**System Requirements:**
- Python >=3.12 (by design, no legacy support)
- RAM: ~300MB for core functionality, ~1.3GB for adversarial inputs with full ML features
- GPU: Optional, only required for certain ML-based detectors
- Redis: Optional but recommended for caching (local or cloud)

## Known Limitations

1. **False Positive Rate:** Kids Policy false positive rate is 0.00% on validation dataset (target: ≤5.0%, met in v2.4.1)
2. **Memory Usage:** Current memory usage exceeds 300MB cap for adversarial inputs (measured: ~1.3GB)
3. **Unicode Normalization:** Some edge cases in mathematical alphanumeric symbol handling
4. **Python Version:** Requires Python >=3.12 (by design, no legacy support for 3.10/3.11)
5. **Dependencies:** Core functionality requires numpy, scipy, scikit-learn; full ML features require torch, transformers, sentence-transformers (see Dependencies section)

## Production Readiness

**Status:** Production Ready (2025-12-10)

**Current Performance:**
- Detection Rate: 100% (poetic obfuscation test suite)
- False Positives: 0 (after fixes)
- Bypasses: 0 (adversarial test suite)

**Recent Improvements:**
- English documentation and outputs (scientific/academic style)
- CI/CD pipeline with automated security evaluations
- Python-based evaluation framework (no external dependencies)
- Root directory cleanup and organization
- Version upgrade strategy documented

**Quick Start:**
See `QUICK_START.md` for production deployment guide.

**Version Strategy:**
See `docs/VERSION_UPGRADE_STRATEGY_2025_12_10.md` for upgrade recommendations.

## Security Notice

This library reduces risk but does not guarantee complete protection.

Required additional security controls:
- Authentication and authorization
- Network isolation
- Logging and monitoring
- Rate limiting
- Sandboxing of tool environments

The maintainers assume no liability for misuse.

Use only in compliance with local law and data-protection regulations.

## Security Hardening

### Implemented Measures

1. **Multi-Tenant Isolation**
   - Session hashing via HMAC-SHA256(tenant_id + user_id + DAILY_SALT)
   - Redis key isolation via ACLs and prefixes

2. **Oscillation Defense**
   - CUSUM (Cumulative Sum Control Chart) algorithm
   - Accumulative risk tracking across session turns

3. **Parser Differential Protection**
   - StrictJSONDecoder with duplicate key detection
   - Immediate exception on key duplication

4. **Unicode Security**
   - Zero-width character detection and removal
   - Directional override character detection
   - Homoglyph normalization

5. **Multilingual Attack Detection**
   - Polyglot attack detection across 12+ languages
   - Low-resource language hardening (Basque, Maltese tested)
   - Language switching detection
   - Multilingual keyword detection (Chinese, Japanese, Russian, Arabic, Hindi, Korean, and others)

6. **Pattern Evasion Detection**
   - Concatenation-aware pattern matching
   - Encoding anomaly detection
   - Obfuscation pattern recognition

## Performance Characteristics

- P99 Latency: <200ms for standard inputs (measured)
- Cache Hit Rate: 30-50% (exact), 70-90% (hybrid)
- Cache Latency: <100ms (Redis Cloud), <1ms (local Redis)

## Monitoring

MCP monitoring tools available for health checks and metrics:

- `firewall_health_check`: Redis/Session health inspection
- `firewall_deployment_status`: Traffic percentage and rollout phase
- `firewall_metrics`: Real-time block rates and CUSUM scores
- `firewall_check_alerts`: Critical P0 alerts
- `firewall_redis_status`: ACL and connection pool health

## Implementation Status

**P0 Items (Critical):**
- Circuit breaker pattern: Implemented
- False positive tracking: Implemented (rate: ~5% as of v2.4.1)
- P99 latency metrics: Implemented (<200ms verified)
- Cache mode switching: Implemented
- Adversarial bypass detection: Implemented (0/50 bypasses in test suite)

**P1 Items (High Priority):**
- Shadow-allow mechanism: Configuration-only
- Cache invalidation strategy: TTL-based
- Bloom filter parameters: Configurable

**P2 Items (Medium Priority):**
- Concurrency model: Single-threaded
- Progressive decoding: Not implemented
- Forensic capabilities: Basic logging
- STRIDE threat model: Partial

## Evaluation & Benchmarks

The Phase 2 evaluation pipeline provides self-contained, standard-library-only tools for evaluating AnswerPolicy effectiveness:

- **ASR/FPR Metrics**: Attack Success Rate and False Positive Rate computation
- **Multi-Policy Comparison**: Compare baseline, default, kids, and internal_debug policies
- **Latency Measurement**: Optional per-request latency tracking
- **Bootstrap Confidence Intervals**: Optional non-parametric CIs for ASR/FPR
- **Dataset Validation**: Schema compliance, ASCII-only checks, statistics

**Quick Start:**
```bash
python scripts/run_phase2_suite.py --config smoke_test_core
```

**Documentation:**
- [AnswerPolicy Phase 2 Evaluation (v2.4.1) – Technical Handover](docs/ANSWER_POLICY_EVALUATION_PHASE2_2_4_0.md) – Complete technical documentation
- [AnswerPolicy Evaluation User Workflow](docs/ANSWER_POLICY_EVALUATION_PHASE2.md) – User guide

**Evaluation Scope & Limitations:**
- Current evaluation uses small sample sizes (20-200 items) suitable for local smoke tests
- `p_correct` estimator is uncalibrated (heuristic-based, not probabilistic model)
- Datasets use template-based generation, not real-world distributions
- Block attribution is conservative (lower bound for AnswerPolicy contributions)
- Bootstrap CIs are approximate indicators, not publication-grade statistics

For production-grade evaluation with larger datasets and calibrated models, see Future Work in the technical handover document.

## System Status

**Latest Version:** v2.5.0 (2025-12-05)

**Production Status:** Ready (2025-12-10)

### Performance Metrics

**Kids Policy:**
- False Positive Rate: 0.00% (target: ≤5.0%, met in v2.4.1)
- Attack Success Rate: 40.00% (stable)

**Poetic Obfuscation Detection:**
- Detection Rate: 100% (24/24 test cases)
- False Positives: 0
- Bypasses: 0

**Command Injection Detection:**
- Detection Rate: 100% (test suite)
- False Positives: 0 (after ls -la fix)

### Recent Changes

**v2.5.0 (2025-12-05):**
- 96% memory reduction (1.3 GB → 54 MB baseline)
- ONNX-only core execution
- Optional ML dependencies

**v2.4.1:**
- UNSAFE_TOPIC false positive reduction
- Whitelist filter for benign educational queries
- FPR: 22% → 0.00% (100% elimination)

**2025-12-10:**
- Production readiness improvements
- English documentation and outputs
- CI/CD pipeline with automated evaluations
- Evaluation framework implementation
- Root directory cleanup

## Documentation

### Quick Start
- **QUICK_START.md** - Production deployment guide
- **eval_suites/README.md** - Evaluation framework documentation

### Technical Reports
- **docs/POETIC_BYPASS_MITIGATION_REPORT_2025_12_10.md** - Poetic obfuscation mitigation (100% detection rate)
- **docs/VERSION_UPGRADE_STRATEGY_2025_12_10.md** - Version upgrade recommendations
- **docs/COMPLETE_IMPLEMENTATION_SUMMARY_2025_12_10.md** - Complete implementation overview
- **docs/CI_CD_SETUP_2025_12_10.md** - CI/CD setup guide

### Architecture & Design
- **docs/SESSION_HANDOVER_2025_12_01.md** - Architecture documentation (v2.4.0rc1)
- **docs/TECHNICAL_HANDOVER_2025_12_01.md** - Technical handover (pre-v2.4.0rc1)
- **docs/ADAPTIVE_SESSION_LEARNING_ARCHITECTURE.md** - Adaptive learning design

### Evaluation & Testing
- **docs/ANSWER_POLICY_EVALUATION_PHASE2_2_4_0.md** - AnswerPolicy evaluation (v2.4.1)
- **docs/VALIDATION_RESULTS_2025_12_10.md** - Validation results
- **docs/TEST_RESULTS_SUMMARY.md** - Test results summary

### Release Notes
- **docs/PYPI_RELEASE_REPORT_2025_12_02.md** - PyPI release report
- **docs/EXTERNAL_REVIEW_RESPONSE.md** - External review response

## License

MIT License

Copyright (c) 2025 Joerg Bollwahn

## Author

Joerg Bollwahn
Email: <sookoothaii@proton.me>
