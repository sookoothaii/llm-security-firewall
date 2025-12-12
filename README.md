# LLM Security Firewall - Microservices Architecture

**Branch:** `feature/code-intent-detection-standalone`  
**Parent Project:** [LLM Security Firewall v2.5.0](https://github.com/sookoothaii/llm-security-firewall)  
**Status:** Development branch with microservices architecture  
**Architecture:** Hexagonal Architecture with Self-Learning Capabilities

> **Development Branch Notice**  
> This branch contains a microservices-based implementation of the LLM Security Firewall with specialized detector services and self-learning capabilities. Code here may be unstable. For production use, see the main project or future releases.

## Overview

The LLM Security Firewall is a comprehensive security system for protecting LLM interactions from malicious inputs. This implementation uses a microservices architecture with specialized detector services, an orchestrator for request routing, and self-learning capabilities for continuous improvement.

The system operates as multiple independent FastAPI services with clean hexagonal architecture and can be integrated into larger security frameworks. It does not guarantee complete protection and should be used as part of a broader security strategy.

## Microservices Architecture

The system consists of 5 microservices:

| Service | Port | Purpose | Status |
|---------|------|---------|--------|
| **Code Intent Service** | 8000 | Detects malicious code execution intents | Production-ready |
| **Orchestrator Service** | 8001 | Routes requests, aggregates results, manages self-learning | Production-ready |
| **Persuasion Detector** | 8002 | Detects persuasion and manipulation attempts | Production-ready |
| **Content Safety Detector** | 8003 | Content safety and policy enforcement | Production-ready |
| **Learning Monitor Service** | 8004 | Advanced monitoring dashboard (optional) | Optional |

## Architecture

### Microservices Architecture

All services implement a clean hexagonal architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                      │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │  Orchestrator Service │  Port 8001
            │  (Route & Aggregate)   │
            └───────┬───────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
┌───────────┐ ┌───────────┐ ┌───────────┐
│ Code      │ │ Persuasion│ │ Content   │
│ Intent    │ │ Detector  │ │ Safety    │
│ Port 8000 │ │ Port 8002 │ │ Port 8003 │
└───────────┘ └───────────┘ └───────────┘
        │
        ▼
┌───────────────────────┐
│ Learning Monitor      │  Port 8004 (Optional)
│ (Dashboard & Alerts)  │
└───────────────────────┘
```

### Hexagonal Architecture Layers

Each service follows the same architectural pattern:

**Domain Layer** (`domain/`)
- Entities: `DetectionResult`, `FeedbackSample`
- Value Objects: `RiskScore`, `ServiceStatus`, `Alert`
- Ports/Protocols: Service-specific ports (e.g., `DetectionServicePort`, `ServiceMonitorPort`)

**Application Layer** (`application/`)
- Services: Business logic orchestration
- Use Cases: Application-specific workflows

**Infrastructure Layer** (`infrastructure/`)
- Adapters: ML models, rule engines, repositories
- Configuration: Environment-based settings
- Composition Root: Dependency injection

**API Layer** (`api/`)
- Controllers: FastAPI REST endpoints
- Routes: Request routing and validation
- Documentation: Automatic OpenAPI/Swagger UI

### Shared Components

All services use shared components from `detectors/shared/`:
- Shared domain models
- Shared API middleware
- Shared infrastructure patterns

## Quick Start

### Prerequisites

- Python >=3.12
- Redis (optional, for caching and feedback storage)
- PostgreSQL (optional, for persistent feedback storage)

### Installation

```bash
# Clone repository
git clone -b feature/code-intent-detection-standalone \
  https://github.com/sookoothaii/llm-security-firewall.git
cd llm-security-firewall

# Install dependencies for all services
pip install -r detectors/code_intent_service/requirements.txt
pip install -r detectors/orchestrator/requirements.txt  # If available
```

### Starting Services

**1. Code Intent Service (Port 8000)**
```bash
cd detectors/code_intent_service
python setup_env_complete.py
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

**2. Orchestrator Service (Port 8001)**
```bash
cd detectors/orchestrator
python -m uvicorn api.main:app --host 0.0.0.0 --port 8001
```

**3. Persuasion Detector (Port 8002)**
```bash
cd detectors/persuasion_service
python -m uvicorn api.main:app --host 0.0.0.0 --port 8002
```

**4. Content Safety Detector (Port 8003)**
```bash
cd detectors/content_safety_service
python -m uvicorn api.main:app --host 0.0.0.0 --port 8003
```

**5. Learning Monitor Service (Port 8004, Optional)**
```bash
cd detectors/learning_monitor_service
python api/main.py
# Or: uvicorn api.main:app --host 0.0.0.0 --port 8004
```

### Service Verification

```bash
# Check all services
curl http://localhost:8000/api/v1/health  # Code Intent
curl http://localhost:8001/api/v1/health  # Orchestrator
curl http://localhost:8002/api/v1/health  # Persuasion
curl http://localhost:8003/api/v1/health  # Content Safety
curl http://localhost:8004/health         # Learning Monitor
```

### Environment Configuration

Key environment variables (see `detectors/code_intent_service/ENV_SETUP.md` for details):

- `DETECTION_USE_CNN_MODEL`: Enable CNN model (default: true)
- `DETECTION_USE_CODEBERT`: Enable CodeBERT model (default: true)
- `DETECTION_ENABLE_RULE_ENGINE`: Enable rule-based detection (default: true)
- `DETECTION_FEEDBACK_REPOSITORY_TYPE`: Repository type (memory, redis, postgres, hybrid)

## API Usage

### Primary Endpoint: Orchestrator Service

The Orchestrator Service (Port 8001) is the main entry point for all detection requests:

```python
import requests

response = requests.post(
    "http://localhost:8001/api/v1/route-and-detect",
    json={
        "text": "user input text",
        "context": {},
        "source_tool": "test",
        "user_risk_tier": 1,
        "session_risk_score": 0.0
    }
)
result = response.json()
# Returns: {"blocked": bool, "risk_score": float, "detector_results": {...}}
```

### Direct Detector Access

You can also access individual detector services directly:

**Code Intent Service (Port 8000)**
```python
response = requests.post(
    "http://localhost:8000/api/v1/detect",
    json={"text": "user input text", "context": {}, ...}
)
```

### Self-Learning: Feedback Submission

Submit false negatives for automatic learning:

```python
# Submit false negative to Code Intent Service
response = requests.post(
    "http://localhost:8000/api/v1/feedback/submit",
    json={
        "text": "malicious code that was missed",
        "correct_label": 1,  # 1 = malicious
        "original_prediction": 0.3,
        "feedback_type": "false_negative"
    }
)

# Or submit via Orchestrator (recommended)
response = requests.post(
    "http://localhost:8001/api/v1/feedback/submit",
    json={...}
)
```

### Learning Metrics

Check self-learning statistics:

```bash
# Orchestrator learning metrics
curl http://localhost:8001/api/v1/learning/metrics

# Code Intent feedback stats
curl http://localhost:8000/api/v1/feedback/stats
```

### API Documentation

Interactive API documentation available at:
- Code Intent: `http://localhost:8000/docs`
- Orchestrator: `http://localhost:8001/docs`
- Learning Monitor Dashboard: `http://localhost:8004/dashboard`

## Detection Methods

### Rule-Based Detection

Pattern matching using regular expressions and rule-based validators:
- Command detection
- Temporal execution patterns
- Indirect references
- Grammatical patterns
- Meta-discourse patterns

### Machine Learning Detection

Optional ML-based detection using:
- CNN model adapter (trained on code intent datasets)
- CodeBERT adapter (microsoft/codebert-base)
- Rule-based classifier (fallback)

ML models are loaded on-demand and do not affect baseline performance if disabled.

## Validators

The system includes 10 specialized benign validators:

1. Content Safety Validator
2. Documentation Context Validator
3. Greeting Validator
4. Harmful Metaphor Validator
5. Jailbreak Validator
6. Poetic Context Validator
7. Question Context Validator
8. Technical Discussion Validator
9. Temporal Execution Validator
10. Zero Width Validator

## Performance Characteristics

### Individual Services

| Service | Latency | Memory | Notes |
|---------|---------|--------|-------|
| **Code Intent** | <50ms | ~150 MB | Without ML models (+500-800 MB with models) |
| **Orchestrator** | <100ms | ~100 MB | Includes aggregation overhead |
| **Persuasion** | <30ms | ~80 MB | Rule-based detection |
| **Content Safety** | <30ms | ~80 MB | Policy enforcement |
| **Learning Monitor** | <10ms | ~50 MB | Dashboard and monitoring |

### End-to-End Performance

| Metric | Value | Notes |
|--------|-------|-------|
| **Orchestrator Request** | <150ms | Full pipeline (routing + detection + aggregation) |
| **Feedback Submission** | <10ms | In-memory, <20ms with PostgreSQL |
| **Learning Metrics Query** | <5ms | In-memory aggregation |
| **WebSocket Updates** | 5s interval | Configurable in Learning Monitor |

### Resource Usage

- **Total Memory (All Services):** ~460 MB baseline, +500-800 MB with ML models
- **Redis Operations:** <5ms (caching and feedback storage)
- **PostgreSQL Operations:** <15ms (persistent feedback storage)
- **Network Overhead:** <10ms per service call

Note: Measurements from test environment. Actual performance may vary based on hardware, network latency, and configuration.

## Known Limitations

1. **False Positive Rate:** Current FPR is 3.4% on validation dataset (1000 tests). Target is ≤5.0% for production use. Remaining false positives primarily in creative benign examples and comparison queries.

2. **Detection Coverage:** Pattern-based detection may miss novel attack vectors. ML models require training data and may not generalize to all attack types.

3. **Model Dependencies:** ML-based detection requires torch and transformers. System can operate in rule-based mode without ML dependencies.

4. **Feedback Collection:** Requires Redis or PostgreSQL for persistent storage. Memory-only mode is available for development.

5. **Online Learning:** Online learning feature is experimental and requires model fine-tuning capabilities. Background learning thread runs automatically if enabled.

6. **Service Dependencies:** Orchestrator requires all detector services to be running for full functionality. Individual services can operate independently.

7. **Learning Monitor:** Optional service. Core learning functionality works without it (via Orchestrator API).

8. **Scalability:** Current implementation is single-instance. Horizontal scaling requires shared state (Redis/PostgreSQL) for feedback repositories.

## Testing

### Unit Tests

```bash
pytest detectors/code_intent_service/tests/unit/ -v
```

### Integration Tests

```bash
pytest detectors/code_intent_service/tests/integration/ -v
```

### Test Scripts

```bash
# Test API
python detectors/code_intent_service/scripts/test_api.py

# Test ML adapters
python detectors/code_intent_service/scripts/test_ml_adapters.py

# Test feedback integration
python detectors/code_intent_service/scripts/test_feedback_integration.py

# Quick evaluation test
python detectors/code_intent_service/test_block_rate.py
```

## Self-Learning System

The firewall includes an integrated self-learning system:

1. **Feedback Collection:** False negatives and false positives are collected via `/api/v1/feedback/submit`
2. **Policy Optimization:** The Orchestrator's `AdaptivePolicyOptimizer` automatically adjusts:
   - Detection thresholds
   - Detector selection
   - Execution strategy (sequential/parallel)
   - Timeouts
3. **Learning Metrics:** Monitor learning progress via `/api/v1/learning/metrics` (Orchestrator) or `/api/v1/feedback/stats` (Code Intent)

**Documentation:** See `docs/SELF_LEARNING_HANDOVER.md` for detailed technical documentation.

## Service Details

### Code Intent Service (Port 8000)

Specialized detection of malicious code execution intents:
- 10 rule-based benign validators
- ML models: CNN, CodeBERT
- Pattern-based rule engine
- Feedback collection and online learning

**Documentation:** `detectors/code_intent_service/README.md`

### Orchestrator Service (Port 8001)

Central routing and aggregation service:
- Routes requests to appropriate detectors
- Aggregates detection results
- Manages self-learning and policy optimization
- Provides unified API interface

**Documentation:** `docs/SELF_LEARNING_HANDOVER.md`

### Learning Monitor Service (Port 8004, Optional)

Advanced monitoring dashboard:
- Real-time service status monitoring
- WebSocket-based live updates
- Alert generation
- Historical tracking

**Documentation:** `detectors/learning_monitor_service/HANDOVER.md`

## Relationship to Parent Project

This microservices implementation originated from the LLM Security Firewall as an evolution of the monolithic architecture. While it shares architectural principles (hexagonal design, protocol-based adapters), it provides:

- **Better Scalability:** Independent scaling of detector services
- **Self-Learning:** Automatic policy optimization based on feedback
- **Modularity:** Each service can be developed and deployed independently
- **Monitoring:** Optional advanced monitoring dashboard

The services maintain compatibility with the parent project's architecture patterns while operating as independent microservices that can be integrated into larger security ecosystems.

## Future Evolution

This code may evolve in one of three ways:

1. **Merge back** into main LLM Security Firewall as an integrated module
2. **Split** into a separate repository (`llm-code-intent-detector`)
3. **Remain** as a long-lived branch with occasional synchronization

The current branch structure allows for experimentation and development without affecting the main project.

## Security Notice

This library reduces risk but does not guarantee complete protection. It should be used as part of a comprehensive security strategy including:

- Authentication and authorization
- Network isolation
- Logging and monitoring
- Rate limiting
- Sandboxing of execution environments

The maintainers assume no liability for misuse. Use only in compliance with local law and data-protection regulations.

## License

MIT License

Copyright (c) 2025 Joerg Bollwahn

## Author

Joerg Bollwahn  
Email: sookoothaii@proton.me
