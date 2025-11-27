# HAK_GAL_HEXAGONAL: LLM Security Firewall

**Heuristic Analysis Kernel & Generative Alignment Layer (Hexagonal Edition)**

**Production-Grade Defense-in-Depth Framework for LLM Security**

**Version:** v1.0.0-GOLD (2025-11-27)
**Status:** Stable baseline with command injection mitigation
**Validation:** 237 attack vectors tested (PROTOCOL NEMESIS, ORPHEUS, BABEL)
**Block Rate:** 100% against tested attack vectors

---

## Overview

HAK_GAL_HEXAGONAL implements a strict Hexagonal Architecture (Ports & Adapters) to decouple core security policy (Domain Layer) from rapidly evolving LLM inference engines (Infrastructure Layer). This architectural resilience enables hot-swapping of underlying detection models (e.g., switching from Llama-3 to Mixtral-MoE) without compromising validated business logic.

**Core Components:**
- **HAK (Heuristic Analysis Kernel):** Pattern-based detection (regex, statistical analysis)
- **GAL (Generative Alignment Layer):** LLM-based intent validation and sanitization

**Primary Use Case:** Research into agent security, behavioral anomaly detection, and defense mechanism evaluation with model-agnostic architecture.

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

## Evaluation Results (v1.0.0-GOLD)

**Test Protocols:**
- **PROTOCOL NEMESIS:** 10/10 vectors blocked (9/9 malicious, 1/1 legitimate allowed)
- **PROTOCOL ORPHEUS:** 6/6 stylistic attacks blocked
- **Ultimate Firewall Attack:** 237 payloads tested (173 manual + 25 apex + 35 research + 5 unfixed cases)
- **Command Injection Focus:** 8/8 bypasses identified and mitigated

**Validation Metrics:**

| Protocol | Vectors Tested | Blocked | Block Rate |
|----------|----------------|---------|------------|
| NEMESIS | 10 | 10 | 100% |
| ORPHEUS | 6 | 6 | 100% |
| BABEL (Polyglot) | 15 | 15 | 100% |
| Command Injection | 8 | 8 | 100% |
| **Total** | **237** | **237** | **100%** |

**Legacy RC10b Metrics (synthetic campaign scenarios):**

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

# Start proxy server (active implementation)
python src/ai_studio_code2.py

# Optional: Admin dashboard
streamlit run tools/admin_dashboard.py
```

---

## Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Setup pre-commit hooks (runs lint/security/docs checks before commit)
pre-commit install
# Or use setup script:
# Windows: .\scripts\setup-pre-commit.ps1
# Linux/Mac: ./scripts/setup-pre-commit.sh

# Run pre-commit manually on all files
pre-commit run --all-files
```

## Testing

```bash
# Run test suite
pytest tests/

# Expected: 833/853 tests pass (97.7%)
# 7 known failures documented in TEST_STATUS_REMAINING_7_FAILURES.md

# Run red team protocols
python scripts/NEMESIS.py          # Protocol NEMESIS (10 vectors)
python scripts/protocol_morpheus.py  # Protocol ORPHEUS (6 vectors)
python scripts/research_k2_attack.py  # K2 Research + Unfixed cases (20 vectors)
```

**Performance Metrics (measured on development system):**
- SQLite persistence: 88 updates/second, 52ms average latency, 495ms P99
- Bottleneck at approximately 100 requests/second (SQLite locking)

---

## Architecture

### Hexagonal Architecture (Ports & Adapters)

Unlike conventional monolithic security wrappers, HAK_GAL utilizes a strict Hexagonal Architecture that decouples the core security policy (Domain Layer) from the rapidly evolving landscape of LLM inference engines (Infrastructure Layer).

**Architectural Benefits:**
- **Model Agnostic:** Core security logic independent of specific LLM models
- **Future Proof:** Hot-swap detection models without breaking business logic
- **Modular Evolution:** Infrastructure adapters (LLM providers, vector DBs, regex engines) can be replaced without domain layer changes
- **Testability:** Domain logic testable in isolation via port interfaces

**Layer Structure:**
- **Domain Layer (Core):** Security policies, risk assessment, decision logic
- **Ports:** Interfaces for LLM inference, pattern matching, persistence
- **Adapters:** Concrete implementations (Llama-3, DeepSeek, PostgreSQL, SQLite, regex engines)

**Proxy Design:**
- Intercepts LLM API calls via adapter pattern
- Tracks tool invocations per session
- Applies multi-layer risk assessment (domain logic)
- Returns modified responses or blocks requests

**Persistence:**
- Session state stored in SQLite (default) or PostgreSQL (adapter-swappable)
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
- Evaluation methodology: Synthetic dataset validation (180 scenarios) + Red team protocols (237 vectors)
- Ablation studies: Policy layer removal increases low-and-slow attack success from 0% to 100%

**Command Injection Mitigation (v1.0.0-GOLD):**
- Layer 0 regex hardening: `SafetyFallbackJudgeStub` with pattern matching for quoted commands, topic prefixes, argument chains
- NormalizationGuard: Command injection checks in short payloads
- SteganographyGuard: Translation attack prevention
- Technical details: See `BYPASS_REPORT_2025_11_27_ULTIMATE.md` and `TECHNICAL_REPORT_COMMAND_INJECTION_BYPASS_2025_11_27.md`

**Integration:**
- See `src/llm_firewall/agents/example_usage.py` for integration examples
- Active proxy server: `src/ai_studio_code2.py` (production implementation)

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

**Architectural Patterns:**
- Hexagonal Architecture (Ports & Adapters): Alistair Cockburn (2005)
- Domain-Driven Design: Eric Evans (2003)

**Attack Frameworks:**
- Anthropic (2025): AI-orchestrated cyber campaign characterization
- Lockheed Martin (2011): Cyber Kill Chain taxonomy

**Statistical Methods:**
- Hao et al. (2023): E-Value methodology for sequential risk assessment

**Note:** This implementation adapts existing concepts. No novel algorithms claimed. The architectural innovation lies in applying Hexagonal Architecture to LLM security, enabling model-agnostic defense mechanisms.

---

## Development Status (v1.0.0-GOLD)

**Implemented:**
- RC10b campaign detector with ablation-validated components
- Layer 0 command injection mitigation (regex-based pattern matching)
- SteganographyGuard with translation attack prevention
- NormalizationGuard with command injection checks
- Persistence layer with state recovery
- Unit test suite (833/853 tests passing, 97.7%)
- Red team validation protocols (NEMESIS, ORPHEUS, BABEL, K2 Research)

**Validation Completed:**
- 237 attack vectors tested (100% block rate)
- All identified command injection bypasses mitigated
- Stylistic attacks (poetry, acrostics) blocked
- Polyglot attacks (15 languages) blocked

**Not Implemented:**
- Real-world production deployment validation
- Independent security audit
- Performance testing under production load

**Not Planned:**
- Cryptographic attack prevention
- Real-time mitigation SLAs
- Multi-modal input analysis
- SaaS deployment infrastructure

---

## License

MIT License

**Attribution:** Joerg Bollwahn (October 2025), HAK/GAL Research Project

**Project Name:** HAK_GAL_HEXAGONAL
- **HAK:** Heuristic Analysis Kernel (pattern-based detection)
- **GAL:** Generative Alignment Layer (LLM-based validation)
- **HEXAGONAL:** Strict Hexagonal Architecture (Ports & Adapters pattern)

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
