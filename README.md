# LLM Security Firewall - Microservices Architecture

**Branch:** `feature/code-intent-detection-standalone`  
**Parent Project:** [LLM Security Firewall v2.5.0](https://github.com/sookoothaii/llm-security-firewall)  
**Status:** Beta - Development branch for controlled environments  
**Architecture:** Hexagonal Architecture with Defense-in-Depth

> **Beta Notice**  
> This branch contains a microservices-based implementation of the LLM Security Firewall. While functional and tested, it is classified as **Beta** (Development Status 4 per PyPI). Suitable for controlled environments with additional security layers. Not recommended as sole protection in high-risk production deployments.

## Overview

The LLM Security Firewall is a **risk reduction** system for protecting LLM interactions from malicious inputs. This implementation uses a microservices architecture with specialized detector services, an orchestrator for request routing, and feedback collection for continuous improvement.

**Important:** This system provides defense-in-depth and reduces attack surface but **cannot guarantee complete protection against prompt injection**. As noted by [NCSC](https://www.computerweekly.com/news/366636155/NCSC-warns-of-confusion-over-true-nature-of-AI-prompt-injection) and [OWASP](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), LLMs inherently cannot fully separate instructions from data, making complete mitigation impossible. Use as part of a comprehensive security strategy.

## Microservices Architecture

The system consists of 5 microservices:

| Service | Port | Purpose | Status |
|---------|------|---------|--------|
| **Code Intent Service** | 8000 | Detects malicious code execution intents | Beta |
| **Orchestrator Service** | 8001 | Routes requests, aggregates results, collects feedback | Beta |
| **Persuasion Detector** | 8002 | Detects persuasion and manipulation attempts | Beta |
| **Content Safety Detector** | 8003 | Content safety and policy enforcement | Beta |
| **Learning Monitor Service** | 8004 | Advanced monitoring dashboard | Optional |

## Threat Model and Security Claims

### What This System Does

This firewall provides **risk reduction** through multiple detection layers:

- **Input validation:** Pattern-based and ML-based detection of malicious prompts
- **Output validation:** Content safety checks on LLM responses
- **Tool/Action validation:** Inspection of tool calls before execution
- **Stateful tracking:** Session-level risk aggregation

### Attacker Capabilities Assumed

- Can craft adversarial prompts (jailbreaks, prompt injection, obfuscation)
- May have knowledge of detection patterns
- Cannot directly modify system code or bypass network controls

### Protected Assets

- LLM backend from receiving malicious instructions
- Users from harmful/manipulative responses
- Downstream systems from unauthorized tool execution

### Non-Goals (What We Do NOT Claim)

- **Complete protection against prompt injection** - impossible by design (NCSC/OWASP)
- **Zero false positives** - current FPR is ~3.4% on validation sets
- **Protection against model-level attacks** - adversarial examples, model extraction
- **Protection against insider threats** - assumes trusted operators

### Assumptions

- Network isolation prevents direct backend access
- Operators configure appropriate thresholds for their risk tolerance
- Feedback submission is from authenticated/trusted sources (see Self-Learning Risks)
- System is one layer in defense-in-depth, not sole protection

### Evaluation Context

Detection metrics (TPR, FPR) are measured on internal test suites:
- **Adversarial suite:** 70 crafted attack samples
- **Holdout set:** 470 mixed samples (270 malicious, 200 benign)
- **Segmented tests:** Multilingual coverage (EN, DE, mixed)

**Limitations:** These are regression gates, not guarantees of real-world performance. Adaptive attackers, novel attack vectors, and distribution shift may reduce effectiveness. No external baseline comparison (e.g., vs. LLM-Guard) has been performed yet.

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

| Resource | Value | Notes |
|----------|-------|-------|
| **Total Runtime Memory** | ~460 MB | All 5 services, rule-based mode |
| **With ML Models** | +500-800 MB | CNN + CodeBERT loaded |
| **PyPI Wheel Size** | ~528 KB | Core package only |
| **Redis Operations** | <5ms | Caching and feedback |
| **PostgreSQL Operations** | <15ms | Persistent storage |

Note: Measurements from test environment (Windows 10, Python 3.12). Actual performance varies with hardware and configuration.

## Known Limitations

1. **No Complete Protection:** Prompt injection cannot be fully mitigated by design. This is risk reduction, not a guarantee.

2. **False Positive Rate:** Current FPR is ~3.4% on internal validation (1000 tests). Target is ≤5.0%. Creative/benign edge cases may trigger false positives.

3. **Detection Coverage:** Pattern-based detection may miss novel attack vectors. ML models may not generalize to unseen attack types or new languages.

4. **No External Baseline:** No comparison against established frameworks (LLM-Guard, LlamaFirewall) has been performed. Metrics are internal regression gates only.

5. **Self-Learning Risks:** Feedback pipeline is an attack vector (see Self-Learning Risks section). Production use requires hardening.

6. **Model Dependencies:** ML-based detection requires torch/transformers (~500-800 MB). Rule-based mode works without ML.

7. **Single-Instance:** Current implementation is single-instance. Horizontal scaling requires shared state (Redis/PostgreSQL).

8. **Microservices Overhead:** 5 services require operational discipline: API contracts, timeouts, fail-closed policies, observability. New failure modes possible.

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

### Red Team Testing with Hugging Face Dataset

Test the firewall against a real Red Team dataset from Hugging Face:

```bash
# Install datasets library
pip install datasets

# Start services (in separate terminals)
# Terminal 1:
cd detectors/code_intent_service
python setup_env_complete.py
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 2:
cd detectors/orchestrator
python -m uvicorn api.main:app --host 0.0.0.0 --port 8001

# Run Red Team test (interactive - choose number of samples)
python scripts/test_huggingface_redteam.py

# Analyze results
python scripts/analyze_redteam_results.py
```

**Dataset:** [darkknight25/RED_team_tactics_dataset](https://huggingface.co/datasets/darkknight25/RED_team_tactics_dataset) (1000 MITRE ATT&CK tactic descriptions)

**Expected Results:**
- Code Intent Service: ~100% block rate
- Orchestrator Service: ~100% block rate
- Results saved to `huggingface_redteam_test_results.json`

**Note:** The test uses 24 parallel workers by default. Adjust `NUM_WORKERS` in the script for your hardware.

**Reproducibility:** This test is fully reproducible. Anyone cloning the repository and following the setup instructions should achieve similar results (100% block rate) when testing against the same public Hugging Face dataset.

## Self-Learning System

The firewall includes feedback collection for continuous improvement:

1. **Feedback Collection:** False negatives and false positives are collected via `/api/v1/feedback/submit`
2. **Policy Optimization:** The Orchestrator's `AdaptivePolicyOptimizer` can adjust detection thresholds based on feedback
3. **Learning Metrics:** Monitor feedback via `/api/v1/learning/metrics` (Orchestrator) or `/api/v1/feedback/stats` (Code Intent)

**Documentation:** See `docs/SELF_LEARNING_GUIDE.md` for detailed technical documentation.

### Self-Learning Risks

**Warning:** Online learning in security products is inherently risky. The feedback pipeline is an attack vector:

| Risk | Description | Mitigation Required |
|------|-------------|---------------------|
| **Feedback Poisoning** | Attacker submits false feedback to lower thresholds | Authenticate feedback sources, rate limiting |
| **Distribution Gaming** | Flood benign samples to shift baseline | Quarantine/review before applying |
| **Threshold Degradation** | Automatic lowering of guardrails | **Never auto-lower thresholds** (default policy) |

**Current Implementation:**
- Feedback is stored but **not automatically applied** to detection thresholds
- Policy optimization requires manual trigger (`POST /api/v1/learning/trigger-optimization`)
- No signed feedback verification (recommended for production)
- No offline retraining pipeline (feedback is for analysis, not automatic model updates)

**Production Hardening Required:**
- Implement signed/authenticated feedback submission
- Add rate limiting per source
- Implement review queue before any threshold changes
- Default policy: "never lower guardrails automatically"

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

**This library provides risk reduction, not complete protection.**

Per [OWASP LLM Top 10](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and [NCSC guidance](https://www.computerweekly.com/news/366636155/NCSC-warns-of-confusion-over-true-nature-of-AI-prompt-injection), prompt injection cannot be fully mitigated because LLMs cannot cleanly separate instructions from data.

**Use as part of defense-in-depth:**

- Authentication and authorization (who can submit prompts)
- Network isolation (LLM backend not directly accessible)
- Logging and monitoring (detect anomalies)
- Rate limiting (prevent abuse)
- Sandboxing (limit blast radius of successful attacks)
- Human review for high-risk actions

**The maintainers assume no liability for security incidents. This software is provided "as is" without warranty. Use only in compliance with local law and data-protection regulations.**

## License

MIT License

Copyright (c) 2025 Joerg Bollwahn

## Author

Joerg Bollwahn  
Email: sookoothaii@proton.me
