# LLM Security Firewall

**Stateful behavioral monitoring framework for LLM agent interactions**

**Status:** Research prototype, experimental  
**Validation:** Synthetic datasets only  
**Deployment:** Not validated in production environments

---

## Overview

This repository contains a multi-layer security framework for monitoring Large Language Model (LLM) agent behavior. The system tracks tool usage patterns, detects adversarial campaign signatures, and implements policy-based intervention mechanisms.

**Primary Use Case:** Research into agent security, behavioral anomaly detection, and defense mechanism evaluation.

---

## Core Components

**1. Session Memory System**
- Hierarchical structure: Tactical buffer (50 events) + Strategic profile (persistent risk state)
- Survives process restarts via SQLite persistence
- Tracks maximum risk phase reached per session

**2. Campaign Detection (RC10b)**
- Kill-chain phase tracking (6-phase model based on Lockheed Martin framework)
- Operator budget monitoring across sessions
- Multi-target campaign graph (DAG-based)
- Policy layer with action semantics (ALLOW, WARN, REQUIRE_APPROVAL, BLOCK)

**3. Risk Aggregation**
- Combines kill-chain depth, operator history, campaign patterns
- Adaptive weighting based on signal strength
- Configurable thresholds (T_soft=0.35, T_hard=0.55 in evaluations)

---

## Evaluation Results

**Dataset:** 180 synthetic campaign scenarios
- 100 baseline (50 benign, 50 malicious)
- 80 hard cases (legitimate testlab, low-and-slow attacks, bulk recon, pretext abuse)

**Metrics (RC10b configuration, synthetic data):**

| Scenario Type | Attack Success Rate | False Positive Rate |
|---------------|---------------------|---------------------|
| Baseline malicious | 0.0% | - |
| Baseline benign | - | 0.0% |
| Low-and-slow attacks | 0.0% | - |
| Pretext/scope abuse | 0.0% | - |
| Legitimate testlab | - | 0.0% (hard block), 100% (soft flag) |
| Bulk recon benign | - | 0.0% (hard block), 100% (soft flag) |

**Ablation Studies:**

Removing policy layer increases low-and-slow attack success rate from 0% to 100%, demonstrating causal effect. Phase-floor and scope-mismatch features show no effect when removed on current dataset, suggesting redundant safety margins.

**Limitations:**
- Perfect separation on baseline scenarios suggests possible overfitting
- Hard cases designed to test specific features, not adversarial optimization
- No train/test split
- No external validation
- No real-world attack corpus

---

## Installation

**Requirements:**
- Python 3.10 or newer
- PostgreSQL (optional, for operator state persistence)
- Approximately 2GB RAM

**Setup:**

```bash
# Install dependencies
pip install -r requirements.txt

# Start proxy server
python src/proxy_server.py

# Optional: Admin dashboard
streamlit run tools/admin_dashboard.py
```

---

## Testing

```bash
# Run test suite
pytest tests/

# Expected: 832/853 tests pass (97.5%)
# 7 known failures documented in TEST_STATUS_REMAINING_7_FAILURES.md
```

**Performance Metrics (measured on development system):**
- SQLite persistence: 88 updates/second, 52ms average latency, 495ms P99
- Bottleneck at approximately 100 requests/second (SQLite locking)

---

## Architecture

**Proxy Design:**
- Intercepts LLM API calls
- Tracks tool invocations per session
- Applies multi-layer risk assessment
- Returns modified responses or blocks requests

**Persistence:**
- Session state stored in SQLite (default) or PostgreSQL
- Survives process restarts (validated via "Phoenix Test")
- Risk decay mechanism (24-hour half-life)

**Detection Mechanisms:**
- Tool category mapping (network scan, database query, file operations, execution)
- Phase progression tracking
- Budget limit enforcement
- Graph-based multi-target detection

---

## Configuration

**Thresholds:** Edit `src/llm_firewall/agents/agentic_campaign.py`
- Soft threshold (REQUIRE_APPROVAL): Default 0.35
- Hard threshold (BLOCK): Default 0.55

**Budget Limits:** Edit `src/llm_firewall/agents/operator_budget.py`
- Max network scans: 100 per 24h
- Max exploit attempts: 10 per 24h
- Max lateral movement: 20 per 24h

**Policy Rules:** Edit `src/llm_firewall/agents/tool_firewall.py`
- Testlab scope handling
- Authorization bypass rules

---

## Known Limitations

**Methodological:**
- Evaluation limited to synthetic scenarios
- Thresholds calibrated for specific dataset
- No multi-lingual testing
- No distributed deployment testing

**Implementation:**
- Tool event extraction from MCP calls not implemented
- Requires external session management for operator identification
- Tool category mapping may be incomplete

**Scope:**
- Text-based interactions only
- English language only
- Single-operator scenarios
- No cryptographic guarantees

---

## Technical Documentation

**Design and Evaluation:**
- RC10b campaign detection: See `src/llm_firewall/agents/README.md` for architecture
- Evaluation methodology: Synthetic dataset validation (180 scenarios)
- Ablation studies: Policy layer removal increases low-and-slow attack success from 0% to 100%

**Integration:**
- See `src/llm_firewall/agents/example_usage.py` for integration examples
- Proxy server: `src/proxy_server.py` demonstrates full pipeline integration

---

## Dependencies

**Core:**
- SQLAlchemy (database abstraction)
- psycopg2-binary (PostgreSQL support, optional)
- numpy, scipy (numerical operations)

**Testing:**
- pytest (unit tests)
- hypothesis (property-based testing, planned)

See `requirements.txt` for complete dependency list.

---

## References

**Attack Frameworks:**
- Anthropic (2025): AI-orchestrated cyber campaign characterization
- Lockheed Martin (2011): Cyber Kill Chain taxonomy

**Statistical Methods:**
- Hao et al. (2023): E-Value methodology for sequential risk assessment

**Note:** This implementation adapts existing concepts. No novel algorithms claimed.

---

## Development Status

**Implemented:**
- RC10b campaign detector with ablation-validated components
- Persistence layer with state recovery
- Unit test suite (832/853 tests passing, 97.5%)
- Synthetic evaluation framework

**Not Implemented:**
- Real-world validation corpus
- Production deployment testing
- Multi-lingual support
- Independent security audit
- Performance testing under load

**Not Planned:**
- Cryptographic attack prevention
- Real-time mitigation SLAs
- Multi-modal input analysis
- SaaS deployment infrastructure

---

## License

MIT License

**Attribution:** Joerg Bollwahn (October 2025), HAK/GAL Research Project

Derivative works must preserve attribution per MIT License terms.

---

## Contact

**Issues:** GitHub Issues  
**Documentation:** `/docs` directory  
**Research Context:** See technical reports in `/docs`

---

## Disclaimer

This is experimental research code. Results reported are from synthetic datasets only. No validation against real-world attacks has been performed. No independent security audit has been conducted.

The code is provided as-is for research and educational purposes. Production use requires additional validation, security review, and calibration for specific deployment contexts.

Do not deploy in critical infrastructure without independent security assessment.

---

**Repository maintained as research artifact documenting experimental approaches to LLM agent security.**
