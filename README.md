# HAK_GAL_HEXAGONAL: LLM Security Firewall

**Heuristic Analysis Kernel & Generative Alignment Layer (Hexagonal Edition)**

![Version](https://img.shields.io/badge/version-v1.0.0--GOLD-gold)
![Status](https://img.shields.io/badge/status-Stable_Baseline-green)
![Tests](https://img.shields.io/badge/tests-833%2F853-97.7%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

A production-grade, defense-in-depth firewall architecture for Large Language Models. Designed with strict Hexagonal Architecture (Ports & Adapters) to decouple core security logic from rapidly evolving LLM inference engines.

---

## Executive Summary

HAK_GAL_HEXAGONAL is a bidirectional security framework that sanitizes inputs (Human → LLM) and validates outputs (LLM → Human). The system employs a multi-layered strategy ranging from deterministic regex hardening to semantic intent analysis.

**Validation Status (v1.0.0-GOLD):**
- 237 attack vectors tested across multiple red team protocols
- 100% block rate against tested attack vectors
- All identified command injection bypasses mitigated

---

## Architecture: Hexagonal Design

The system follows a strict Ports & Adapters pattern (Hexagonal Architecture):

**Domain Layer (Core Logic):**
- Immutable security policies
- Scoring algorithms
- Defense-in-Depth routing logic
- Independent of specific AI models

**Infrastructure Layer (Adapters):**
- Pluggable regex engines
- Vector databases (PostgreSQL, SQLite)
- LLM inference adapters (Llama 3, DeepSeek, Mistral, extensible)

**Architectural Benefit:**
Core security business logic can be maintained independently of underlying LLM models. Hot-swapping detection models (e.g., Llama 3 → GPT-5) does not require changes to validated security policies.

---

## Defense-in-Depth Pipeline

**Layer 0 (Hardened Regex Kernel):**
- Zero-latency deterministic blocking
- Command injection detection (quoted commands, topic prefixes, argument chains)
- Binary exploit pattern matching
- Known jailbreak pattern detection

**Layer 1 (Semantic Sentinel - SteganographyGuard):**
- Intermediate LLM-based sanitization
- Defensive paraphrasing to strip stylistic obfuscation
- Translation attack prevention
- Extracts raw intent from obfuscated inputs

**Layer 2 (Vector Fence - TopicFence):**
- Embedding-based topic enforcement
- Prevents domain drift
- Multi-model ensemble (3 diverse embedding models)

**Layer 3 (Cognitive State - RC10b):**
- Stateful session tracking
- Kill-chain phase progression detection
- Campaign pattern recognition
- Policy-based intervention

---

## Validation Results (v1.0.0-GOLD)

The system underwent red team validation utilizing multiple adversarial protocols.

| Protocol | Attack Vector | Payloads | Block Rate | Status |
|----------|---------------|----------|------------|--------|
| Standard Load | Syntax Injection, SQLi, RCE | 237 | 100% | ✅ |
| Protocol BABEL | Polyglot (15 languages) | 15 | 100% | ✅ |
| Protocol NEMESIS | Logical Obfuscation, Bidi-Spoofing | 10 | 100% | ✅ |
| Protocol ORPHEUS | Stylistic (Poetry, Rap, Metaphor) | 6 | 100% | ✅ |

**Key Findings:**
- Zero false negatives in tested attack vectors
- Fail-closed architecture: Ambiguous dual-use queries blocked by default
- Average blocking latency: ~2.4s (due to semantic guard processing)
- False positive rate: 1/10 in PROTOCOL NEMESIS (MD5 checksum query - acceptable for fail-closed design)

**Command Injection Mitigation:**
- 8/8 identified bypasses mitigated
- Pattern matching covers: quoted commands, topic prefixes, argument chains, standalone commands

---

## Installation

**Requirements:**
- Python 3.10 or newer
- PostgreSQL (optional, for operator state persistence)
- Approximately 2GB RAM

**Setup:**

```bash
# Clone repository
git clone https://github.com/sookoothaii/llm-security-firewall.git
cd llm-security-firewall

# Install dependencies
pip install -r requirements.txt
```

**Configuration:**

Create a `.env` file in the root directory (optional):

```env
# Required for Layer 1 Sanitization (SteganographyGuard)
OLLAMA_CLOUD_API_KEY=your_key_here
OLLAMA_CLOUD_URL=https://ollama.com
OLLAMA_CLOUD_MODEL=deepseek-v3.1:671b

# Optional: Local Ollama fallback
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1

# Optional: LM Studio fallback
LM_STUDIO_URL=http://localhost:1234
LM_STUDIO_MODEL=deepseek-v3.1:671b
```

**Running the Proxy:**

```bash
# Start proxy server (active implementation)
python src/ai_studio_code2.py

# Firewall is now active on http://localhost:8081
```

---

## Testing

**Unit Tests:**

```bash
# Run test suite
pytest tests/

# Expected: 833/853 tests pass (97.7%)
# 7 known failures documented in TEST_STATUS_REMAINING_7_FAILURES.md
```

**Red Team Protocols:**

```bash
# Protocol NEMESIS (10 vectors)
python scripts/NEMESIS.py

# Protocol ORPHEUS (6 vectors)
python scripts/protocol_morpheus.py

# K2 Research + Unfixed cases (20 vectors)
python scripts/research_k2_attack.py

# Ultimate Firewall Attack (237 vectors)
python scripts/ultimate_firewall_attack.py
```

**Performance Metrics (measured on development system):**
- SQLite persistence: 88 updates/second, 52ms average latency, 495ms P99
- Bottleneck at approximately 100 requests/second (SQLite locking)
- Layer 0 (Regex): < 1ms
- Layer 1 (Semantic): ~2.4s average (LLM call)

---

## Core Components

**1. Session Memory System**
- Hierarchical structure: Tactical buffer (50 events) + Strategic profile (persistent risk state)
- Survives process restarts via SQLite/PostgreSQL persistence
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

## Scientific Foundations

This framework implements established methods from security research:

**Architectural Patterns:**
- Hexagonal Architecture (Ports & Adapters): Alistair Cockburn (2005)
- Domain-Driven Design: Eric Evans (2003)

**Statistical Methods:**
- Dempster-Shafer Theory (Dempster 1967): Evidence fusion under uncertainty
- Conformal Prediction: Distribution-free uncertainty quantification
- Proximal Robbins-Monro: Stochastic approximation for adaptive thresholds

**Attack Frameworks:**
- Anthropic (2025): AI-orchestrated cyber campaign characterization
- Lockheed Martin (2011): Cyber Kill Chain taxonomy

**Note:** This implementation adapts existing concepts. No novel algorithms claimed. The architectural innovation lies in applying Hexagonal Architecture to LLM security, enabling model-agnostic defense mechanisms.

---

## Known Limitations

**Validation Gaps:**
- Evaluation limited to synthetic scenarios and red team protocols
- No real-world production traffic validation (28-day shadow run recommended)
- Thresholds calibrated for scientific/academic domains
- Re-calibration required for specialized domains (legal, medical, financial)

**Implementation Constraints:**
- Latency impact: 3-120ms per layer (Layer 1: ~2.4s due to LLM call)
- Memory overhead: ~50MB for influence budget tracking
- Text-based LLM interactions only (multimodal not implemented)
- English language content primarily (Unicode normalization included)

**Scope:**
- Single-user deployments tested (multi-tenant untested)
- No independent security audit conducted
- Performance testing under production load not completed

---

## Configuration

**Thresholds:** Edit `src/llm_firewall/agents/config.py`
- Soft threshold (REQUIRE_APPROVAL): Default 0.35
- Hard threshold (BLOCK): Default 0.55

**Budget Limits:** Edit `src/llm_firewall/agents/config.py`
- Max network scans: 100 per 24h
- Max exploit attempts: 10 per 24h
- Max lateral movement: 20 per 24h

**Policy Rules:** Edit `src/llm_firewall/agents/detector.py`
- Testlab scope handling
- Authorization bypass rules

---

## Technical Documentation

**Design and Evaluation:**
- RC10b campaign detection: See `src/llm_firewall/agents/README.md` for architecture
- Evaluation methodology: Synthetic dataset validation (180 scenarios) + Red team protocols (237 vectors)
- Ablation studies: Policy layer removal increases low-and-slow attack success from 0% to 100%

**Command Injection Mitigation (v1.0.0-GOLD):**
- Layer 0 regex hardening: `SafetyFallbackJudgeStub` with pattern matching
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
- sentence-transformers (embedding models)

**LLM Integration:**
- httpx (HTTP client for Ollama Cloud/Local, LM Studio)
- fastapi (API framework)

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
- Dempster-Shafer for intrusion detection (Chen et al. 2024, IEEE Transactions on Information Forensics and Security)
- Conformal prediction for adversarial robustness (Angelopoulos et al. 2024, ICML 2024)

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
**Security:** See `SECURITY.md` for vulnerability reporting
**Research Context:** See technical reports in `/docs` and `RELEASE_NOTES_v1.0.0-GOLD.md`

---

## Disclaimer

This is experimental research code. Results reported are from synthetic datasets and red team protocols. No validation against real-world production traffic has been performed. No independent security audit has been conducted.

The code is provided as-is for research and educational purposes. Production use requires additional validation, security review, and calibration for specific deployment contexts.

Do not deploy in critical infrastructure without independent security assessment.

---

**Repository maintained as research artifact documenting experimental approaches to LLM agent security with hexagonal architecture.**
