# Code Intent Detection Module

**Branch:** `feature/code-intent-detection-standalone`  
**Parent Project:** [LLM Security Firewall v2.5.0](https://github.com/sookoothaii/llm-security-firewall)  
**Status:** Development branch for experimental standalone module

> **Development Branch Notice**  
> This is an active development branch for evolving the Code Intent Detection system. Code here may be unstable. For production use, see the main project or future releases.

## Overview

This module provides code intent detection for identifying malicious code execution requests in text input. It implements a hybrid approach combining rule-based pattern matching with machine learning models.

The system operates as a standalone FastAPI service and can be integrated into larger security frameworks. It does not guarantee complete protection and should be used as part of a broader security strategy.

## Architecture

The module implements a hexagonal architecture with protocol-based adapters for framework independence. Core business logic is separated from infrastructure concerns.

### Components

**Domain Layer** (`domain/`)
- Entities: Detection results
- Value Objects: Risk scores
- Services: Benign validator protocols
- Repositories: Feedback repository protocols

**Application Layer** (`application/`)
- Services: Detection service implementation
- Use Cases: Application-specific workflows

**Infrastructure Layer** (`infrastructure/`)
- ML Models: CNN adapter, CodeBERT adapter, rule-based classifier
- Rule Engines: Pattern matching, 10 specialized benign validators
- Repositories: Feedback storage (memory, Redis, PostgreSQL, hybrid)
- Configuration: Environment-based settings

**API Layer** (`api/`)
- Controllers: Request handlers
- Models: Request/response DTOs
- Routes: REST endpoints
- Middleware: Cross-cutting concerns

## Installation

### Prerequisites

- Python >=3.12
- Redis (optional, for caching and feedback storage)
- PostgreSQL (optional, for persistent feedback storage)

### Setup

```bash
# Clone and navigate to the repository root
git clone -b feature/code-intent-detection-standalone \
  https://github.com/sookoothaii/llm-security-firewall.git
cd llm-security-firewall

# Install dependencies for the code intent service
pip install -r detectors/code_intent_service/requirements.txt

# Setup environment
cd detectors/code_intent_service
python setup_env_complete.py

# Start the API server
python -m uvicorn api.main:app --reload --port 8000

# Or use the PowerShell startup script
.\start_api.ps1
```

### Startup Verification

After starting the service, verify it's running:

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Service info
curl http://localhost:8000/
```

The service performs automatic warm-up on startup:
- Detection service initialization
- Warm-up test detection
- Online learning thread start (if enabled)
```

### Environment Configuration

The service uses environment variables for configuration. See `ENV_SETUP.md` for detailed configuration options.

Key configuration variables:
- `DETECTION_USE_CNN_MODEL`: Enable CNN model (default: true)
- `DETECTION_USE_CODEBERT`: Enable CodeBERT model (default: true)
- `DETECTION_ENABLE_RULE_ENGINE`: Enable rule-based detection (default: true)
- `DETECTION_FEEDBACK_REPOSITORY_TYPE`: Repository type (memory, redis, postgres, hybrid)
- `DETECTION_ENABLE_FEEDBACK_COLLECTION`: Enable feedback collection (default: true)
- `DETECTION_ENABLE_ONLINE_LEARNING`: Enable online learning background thread (default: false)
- `DETECTION_ONLINE_LEARNING_INTERVAL`: Learning cycle interval in seconds (default: 30)
- `DETECTION_FEEDBACK_BUFFER_SIZE`: Maximum feedback samples in buffer (default: 1000)

## API Usage

### Detection Endpoint

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/detect",
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

### Health Check

```bash
# Basic health check
curl http://localhost:8000/api/v1/health

# Repository health checks
curl http://localhost:8000/api/v1/health/repositories
curl http://localhost:8000/api/v1/health/redis
curl http://localhost:8000/api/v1/health/postgres
```

### Feedback Endpoints

```python
# Get feedback statistics
response = requests.get("http://localhost:8000/api/v1/feedback/stats")
stats = response.json()
# Returns: total_samples, blocked_samples, false_positives, false_negatives, etc.

# Submit false negative feedback
response = requests.post(
    "http://localhost:8000/api/v1/feedback/submit",
    json={
        "text": "malicious code that was missed",
        "correct_label": 1,  # 1 = malicious, 0 = benign
        "original_prediction": 0.3,  # Original risk score
        "feedback_type": "false_negative",
        "metadata": {"source": "manual_review"}
    }
)

# Get false negatives for retraining
response = requests.get("http://localhost:8000/api/v1/feedback/false-negatives?limit=1000")

# Get false positives for retraining
response = requests.get("http://localhost:8000/api/v1/feedback/false-positives?limit=1000")

# Get high-risk samples
response = requests.get("http://localhost:8000/api/v1/feedback/high-risk?threshold=0.7&limit=100")
```

### API Documentation

Interactive API documentation available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

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

| Metric | Value | Notes |
|--------|-------|-------|
| **Detection Latency** | <50ms | Complete pipeline (10 validators + ML + rules) |
| **API Response Time** | <100ms | Including network overhead |
| **Memory Baseline** | ~150 MB | Without ML models loaded |
| **ML Model Memory** | +500-800 MB | Per model when loaded (CodeBERT/CNN) |
| **Redis Operations** | <5ms | Feedback caching and session management |
| **PostgreSQL Operations** | <15ms | Persistent feedback storage |
| **Feedback Submission** | <10ms | In-memory or Redis, <20ms with PostgreSQL |
| **Online Learning Cycle** | 5-30 seconds | Background thread, configurable interval |

Note: Measurements from test environment. Actual performance may vary based on hardware and configuration.

## Known Limitations

1. **False Positive Rate:** Current FPR is 3.4% on validation dataset (1000 tests). Target is ≤5.0% for production use. Remaining false positives primarily in creative benign examples and comparison queries.

2. **Detection Coverage:** Pattern-based detection may miss novel attack vectors. ML models require training data and may not generalize to all attack types.

3. **Model Dependencies:** ML-based detection requires torch and transformers. System can operate in rule-based mode without ML dependencies.

4. **Feedback Collection:** Requires Redis or PostgreSQL for persistent storage. Memory-only mode is available for development.

5. **Online Learning:** Online learning feature is experimental and requires model fine-tuning capabilities. Background learning thread runs automatically if enabled via `DETECTION_ENABLE_ONLINE_LEARNING=true`.

6. **Integration with Orchestrator:** This service integrates with the Orchestrator Service (Port 8001) for self-learning capabilities. False negatives can be automatically submitted to the Orchestrator's learning system via `/api/v1/feedback/submit` endpoint.

## Testing

### Unit Tests

```bash
pytest tests/unit/ -v
```

### Integration Tests

```bash
pytest tests/integration/ -v
```

### Test Scripts

```bash
# Test API
python scripts/test_api.py

# Test ML adapters
python scripts/test_ml_adapters.py

# Test feedback integration
python scripts/test_feedback_integration.py

# Quick evaluation test
python test_block_rate.py
```

## Integration with LLM Security Firewall

This service is part of the LLM Security Firewall microservices architecture:

- **Code Intent Service (Port 8000):** This service - specialized code intent detection
- **Orchestrator Service (Port 8001):** Routes requests, aggregates detector results, manages self-learning
- **Persuasion Detector (Port 8002):** Detects persuasion and manipulation attempts
- **Content Safety Detector (Port 8003):** Content safety and policy enforcement
- **Learning Monitor Service (Port 8004, optional):** Advanced monitoring dashboard

### Self-Learning Integration

The service integrates with the Orchestrator's self-learning system:

1. **False Negative Submission:** When a false negative is detected, submit feedback via `/api/v1/feedback/submit`
2. **Automatic Learning:** The Orchestrator (Port 8001) collects feedback and optimizes detection policies
3. **Policy Updates:** Detection thresholds and strategies are automatically adjusted based on feedback

### Shared Components

The service uses shared components from `detectors/shared/`:
- Shared domain models (RiskScore, DetectionResult)
- Shared API middleware (LoggingMiddleware, ErrorHandlerMiddleware)
- Shared infrastructure patterns (BaseCompositionRoot)

## Relationship to Parent Project

This module originated from the LLM Security Firewall as a specialized subsystem for detecting malicious code execution intents. While it shares architectural principles (hexagonal design, protocol-based adapters), it focuses specifically on code intent detection rather than general LLM security.

The module maintains compatibility with the parent project's architecture patterns but operates as an independent service that can be integrated into the larger firewall ecosystem.

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

