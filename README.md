# LLM Security Firewall

Bidirectional security framework for human/LLM interfaces implementing defense-in-depth architecture with multiple validation layers.

**Version:** 5.0.0rc1
**Python:** >=3.12
**License:** MIT
**Status:** Beta (Release Candidate)

## Overview

The system implements a stateful, bidirectional containment mechanism for large language models. It processes requests through sequential validation layers, applying mathematical constraints and stateful tracking to enforce safety boundaries.

The architecture follows a hexagonal pattern with functional adapters and constructor injection. Core business logic is separated from infrastructure concerns.

## Architecture

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
- Fail-open behavior

**Adapter Health** (`src/llm_firewall/core/adapter_health.py`)
- Circuit breaker implementation
- Health metrics tracking
- Failure threshold management
- Recovery timeout handling

## Dependencies

**Core:**
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

**Machine Learning:**
- sentence-transformers>=2.2.0
- torch>=2.0.0
- transformers>=4.30.0
- onnx>=1.14.0
- onnxruntime>=1.16.0

## Installation

```bash
pip install -e .
```

For development dependencies:
```bash
pip install -e .[dev]
```

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

## Testing

Test suite includes unit tests, integration tests, and adversarial test cases.

```bash
pytest tests/ -v
```

With coverage:
```bash
pytest tests/ -v --cov=src/llm_firewall --cov-report=term
```

## Known Limitations

1. **False Positive Rate:** Kids Policy false positive rate is approximately 20-25% (target: <5%)
2. **Memory Usage:** Current memory usage exceeds 300MB cap for adversarial inputs (measured: ~1.3GB)
3. **Unicode Normalization:** Some edge cases in mathematical alphanumeric symbol handling

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

5. **Pattern Evasion Detection**
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
- False positive tracking: Implemented (rate: ~20-25%)
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

## References

- Architecture documentation: `docs/TECHNICAL_HANDOVER_2025_12_01.md`
- Test results: `docs/TEST_RESULTS_SUMMARY.md`
- External review response: `docs/EXTERNAL_REVIEW_RESPONSE.md`

## License

MIT License

Copyright (c) 2025 Joerg Bollwahn

## Author

Joerg Bollwahn
Email: info@hakgal.org
