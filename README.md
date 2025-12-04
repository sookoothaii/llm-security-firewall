# LLM Security Firewall

Bidirectional security framework for human/LLM interfaces implementing defense-in-depth architecture with multiple validation layers.

**Version:** 2.4.1
**Python:** >=3.12
**License:** MIT
**Status:** Production

## TL;DR

A deterministic, bidirectional security layer for LLM-based systems.

- Protects **input, output, memory, and state** simultaneously
- Designed for **agent frameworks, tool-using models, and API gateways**
- Mitigates: prompt injection, jailbreaks, obfuscation, evasive encodings, unauthorized tool actions, cognitive leak risks, children-safety failures, malformed JSON, and memory-poisoning
- Local-only: **no telemetry**, no external calls
- Drop-in integration: `guard.check_input(text)` / `guard.check_output(text)`

## Minimal Example

```python
from llm_firewall import guard

user_prompt = "Explain how to make a polymorphic malware loader."

decision = guard.check_input(user_prompt)

if not decision.allowed:
    print("Blocked by LLM Security Firewall:", decision.reason)
else:
    # Your LLM backend call
    response = llm(user_prompt)
    out = guard.check_output(response)
    if not out.allowed:
        print("Response sanitized:", out.reason)
    else:
        print("LLM Output:", out.cleaned_text)
```

## Installation

**From PyPI (recommended):**
```bash
pip install llm-security-firewall
```

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

- **Bidirectional Protection:** Input, output, and memory integrity validation
- **Defense-in-Depth:** 6 sequential validation layers (UnicodeSanitizer, NormalizationLayer, RegexGate, Input Analysis, Tool Inspection, Output Validation)
- **Mathematical Safety:** CUSUM oscillation detection, Dempster-Shafer evidence fusion, fail-closed risk gating
- **Multilingual Support:** Polyglot attack detection across 12+ languages including low-resource languages (Basque, Maltese)
- **Unicode Hardening:** Zero-width character removal, bidirectional override detection, homoglyph normalization, encoding anomaly detection
- **Stateful Tracking:** Session state management, drift detection, cumulative risk tracking
- **Tool Security:** HEPHAESTUS protocol for tool call validation and killchain detection
- **Transparent Metrics:** Documented FPR, P99 latency, memory usage, bypass test results
- **Framework Independence:** Hexagonal architecture with Protocol-based adapters

## How This Project Differs From Other LLM Firewalls

Most existing LLM safety libraries focus exclusively on **content analysis** (single-direction prompt filtering).

This project uses a *behavioral and architectural* approach:

1. **Bidirectional Guarding (Input + Output + Memory Integrity)**
   All data paths are validated, including prompt, response, and in-memory state transitions.

2. **Hexagonal Architecture (Port/Adapter Pattern)**
   Clear separation between normalization, semantic scoring, risk engines, policy layers, and decision controllers. This enables reproducibility, testability, and deterministic evaluation.

3. **Deterministic Normalization & Obfuscation Resistance**
   Multi-pass Unicode normalization, homoglyph resolution, Base64/Hex/URL decoding, JSON-hardening.

4. **Mathematical Safety Layers**
   - CUSUM detectors for oscillation detection
   - Dempster–Shafer uncertainty modeling for evidence fusion
   - Fail-closed risk gating
   These reduce false negatives in adversarial settings.

5. **Stateful Cognitive Protection**
   Policies operate not only on text, but on *agent state*, *tool sequences*, and *memory mutation events*. This is essential for tool-using agents and automation frameworks.

6. **Transparent Metrics**
   Documented FPR, P99 latency, memory usage, and known limitations. No hidden heuristics, no opaque reasoning chains.

7. **Fully Local Execution**
   No telemetry, no external API calls, no data exfiltration.

## Architecture

### Overview

The system implements a stateful, bidirectional containment mechanism for large language models. It processes requests through sequential validation layers, applying mathematical constraints and stateful tracking to enforce safety boundaries.

The architecture follows a hexagonal pattern with Protocol-based Port/Adapter interfaces and dependency injection. Core business logic is separated from infrastructure concerns. Domain layer uses Protocol-based adapters (`DecisionCachePort`, `DecoderPort`, `ValidatorPort`) for framework independence.

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
- Simple one-liner integration: `guard.check_input(text)`, `guard.check_output(text)`
- Backward compatible with existing API
- See `QUICKSTART.md` for 5-minute integration guide

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

See the `examples/` directory for complete integration examples:

- **`quickstart.py`** - Simplest possible integration using `guard.py` API (< 10 lines)
- **`langchain_integration.py`** - LangChain integration with `FirewallCallbackHandler`
- **`minimal_fastapi.py`** - FastAPI middleware integration
- **`quickstart_fastapi.py`** - Full FastAPI example with input/output validation

Run examples:
```bash
python examples/quickstart.py
python examples/langchain_integration.py
python examples/minimal_fastapi.py
```

**Quick Start (Developer API):**
```python
from llm_firewall import guard

# One-liner input validation
decision = guard.check_input("user input text")
if decision.allowed:
    # Process request
    pass
```

## Testing

Test suite includes unit tests, integration tests, and adversarial test cases.

```bash
pytest tests/ -v
```

With coverage:
```bash
pytest tests/ -v --cov=src/llm_firewall --cov-report=term
```

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

**Note:** Core functionality (Unicode normalization, pattern matching, risk scoring, basic validation) works without ML dependencies. Advanced features like semantic similarity detection and Kids Policy Engine require optional ML dependencies.

**System Requirements:**
- Python >=3.12 (by design, no legacy support)
- RAM: ~300MB for core functionality, ~1.3GB for adversarial inputs with full ML features
- GPU: Optional, only required for certain ML-based detectors
- Redis: Optional but recommended for caching (local or cloud)

## Known Limitations

1. **False Positive Rate:** Kids Policy false positive rate is 5% (target: <10%, met in v2.4.1)
2. **Memory Usage:** Current memory usage exceeds 300MB cap for adversarial inputs (measured: ~1.3GB)
3. **Unicode Normalization:** Some edge cases in mathematical alphanumeric symbol handling
4. **Python Version:** Requires Python >=3.12 (by design, no legacy support for 3.10/3.11)
5. **Dependencies:** Core functionality requires numpy, scipy, scikit-learn; full ML features require torch, transformers, sentence-transformers (see Dependencies section)

## Security Notice

This library reduces risk but cannot guarantee complete protection.

It must be combined with standard security controls:
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

- **P99 Latency:** <200ms for standard inputs (measured)
- **Cache Hit Rate:** 30-50% (exact), 70-90% (hybrid)
- **Cache Latency:** <100ms (Redis Cloud), <1ms (local Redis)

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

## References

- Architecture documentation: `docs/SESSION_HANDOVER_2025_12_01.md` (v2.4.0rc1)
- Technical handover: `docs/TECHNICAL_HANDOVER_2025_12_01.md` (pre-v2.4.0rc1)
- Test results: `docs/TEST_RESULTS_SUMMARY.md`
- External review response: `docs/EXTERNAL_REVIEW_RESPONSE.md`
- PyPI release report: `docs/PYPI_RELEASE_REPORT_2025_12_02.md`
- AnswerPolicy Phase 2 Evaluation: `docs/ANSWER_POLICY_EVALUATION_PHASE2_2_4_0.md` (v2.4.1)

## License

MIT License

Copyright (c) 2025 Joerg Bollwahn

## Author

Joerg Bollwahn
Email: <sookoothaii@proton.me>
