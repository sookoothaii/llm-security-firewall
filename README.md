# Code Intent Detection Module

**Branch:** `feature/code-intent-detection-standalone`  
**Parent Project:** [LLM Security Firewall v2.5.0](https://github.com/sookoothaii/llm-security-firewall)  
**Status:** Development branch for experimental standalone module

> **Development Branch Notice**  
> This is an active development branch for evolving the Code Intent Detection system. Code here may be unstable. For production use, see the main project or future releases.

## Overview

This module provides specialized detection of malicious code execution intents in LLM interactions. It implements a hybrid approach combining 10 rule-based validators, machine learning models (CNN, CodeBERT), and a pattern-based rule engine.

The system operates as a standalone FastAPI service with a clean hexagonal architecture and can be integrated into larger security frameworks. It does not guarantee complete protection and should be used as part of a broader security strategy.

## Architecture

The module implements a clean, hexagonal architecture with clear separation of concerns:

**Domain Layer** (`detectors/code_intent_service/domain/`)
- Entities: `DetectionResult`, `FeedbackSample`
- Value Objects: `RiskScore`
- Ports/Protocols: `DetectionServicePort`, `RuleEnginePort`, `BenignValidatorPort`

**Application Layer** (`detectors/code_intent_service/application/`)
- Services: `DetectionServiceImpl` (orchestrates validators, ML, rules)
- Use Cases: Hybrid decision logic with adaptive scoring

**Infrastructure Layer** (`detectors/code_intent_service/infrastructure/`)
- Validators: 10 specialized benign validators (QuestionContext, Greeting, etc.)
- ML Adapters: CNN, CodeBERT, and Rule-based fallback classifiers
- Rule Engine: Pattern matching with 15+ detection patterns
- Repositories: Redis (cache), PostgreSQL (persistent), Hybrid feedback storage

**API Layer** (`detectors/code_intent_service/api/`)
- Controllers: FastAPI REST endpoints (`/detect`, `/feedback`, `/health`)
- Documentation: Automatic OpenAPI/Swagger UI at `/docs`

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
```

### Environment Configuration

Key environment variables (see `detectors/code_intent_service/ENV_SETUP.md` for details):

- `DETECTION_USE_CNN_MODEL`: Enable CNN model (default: true)
- `DETECTION_USE_CODEBERT`: Enable CodeBERT model (default: true)
- `DETECTION_ENABLE_RULE_ENGINE`: Enable rule-based detection (default: true)
- `DETECTION_FEEDBACK_REPOSITORY_TYPE`: Repository type (memory, redis, postgres, hybrid)

## API Usage

### Detection Endpoint

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/detect",
    json={"text": "user input text"}
)
result = response.json()
```

### Health Check

```bash
curl http://localhost:8000/api/v1/health
```

### API Documentation

Interactive API documentation available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

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

Note: Measurements from test environment. Actual performance may vary based on hardware and configuration.

## Known Limitations

1. **False Positive Rate:** Current FPR is 3.4% on validation dataset (1000 tests). Target is ≤5.0% for production use. Remaining false positives primarily in creative benign examples and comparison queries.

2. **Detection Coverage:** Pattern-based detection may miss novel attack vectors. ML models require training data and may not generalize to all attack types.

3. **Model Dependencies:** ML-based detection requires torch and transformers. System can operate in rule-based mode without ML dependencies.

4. **Feedback Collection:** Requires Redis or PostgreSQL for persistent storage. Memory-only mode is available for development.

5. **Online Learning:** Online learning feature is experimental and requires model fine-tuning capabilities.

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

## Relationship to Parent Project

This module originated from the LLM Security Firewall as a specialized subsystem for detecting malicious code execution intents. While it shares architectural principles (hexagonal design, protocol-based adapters), it focuses specifically on code intent detection rather than general LLM security.

The module maintains compatibility with the parent project's architecture patterns but operates as an independent service.

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
