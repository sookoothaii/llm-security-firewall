# HAK_GAL_HEXAGONAL: LLM Security Firewall

**Heuristic Analysis Kernel & Generative Alignment Layer**

![Version](https://img.shields.io/badge/version-v1.0.0--GOLD-gold)
![Status](https://img.shields.io/badge/status-Validated%20%28synthetic%29-yellow)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

A defense-in-depth firewall architecture for Large Language Models.

Designed with strict Hexagonal Architecture (Ports & Adapters) to decouple core security logic from LLM infrastructure.

---

## Executive Summary

HAK_GAL_HEXAGONAL is a bidirectional security framework that sanitizes inputs (Human → LLM) and validates outputs (LLM → Human). It employs a multi-layered strategy ranging from deterministic regex hardening to semantic intent analysis.

As of v1.0.0-GOLD, the system achieved 100% mitigation rate against synthetic adversarial protocols, including polyglot injections, cognitive steganography, and logical obfuscation.

**Validation Status:** Results from synthetic test corpus only. No production deployment validation. No external red-team evaluation.

---

## Architecture: The Hexagonal Advantage

The system follows a strict Ports & Adapters pattern:

**Domain Layer (Core Logic):** Contains security policies, scoring algorithms, and defense-in-depth routing. Independent of any specific AI model.

**Infrastructure Layer (Adapters):** Pluggable modules for regex engines, vector databases, and LLM inference (currently supporting Llama 3, extendable to other models).

**Why this matters:** You can swap the underlying intelligence (e.g., upgrade Llama 3 to GPT-5) without rewriting security business logic.

---

## Defense-in-Depth Pipeline

**Layer 0 (Hardened Regex Kernel):** Zero-latency deterministic blocking of command injections, binary exploits, and known jailbreak patterns.

**Layer 1 (Semantic Sentinel):** Uses an intermediate LLM (Sanitizer) with defensive paraphrasing to strip stylistic obfuscation and extract raw intent.

**Layer 2 (Vector Fence):** Embedding-based topic enforcement to prevent domain drift.

**Layer 3 (Cognitive State):** Stateful tracking of session history to detect "Kill Chain" progression.

---

## Validation Results (v1.0.0-GOLD)

The system underwent testing utilizing three adversarial protocols on a synthetic test corpus.

| Protocol | Attack Vector | Payloads | Mitigation Rate | Status |
|----------|---------------|----------|-----------------|--------|
| Standard Load | Syntax Injection, SQLi, RCE | 237 | 100% | ✅ |
| Protocol BABEL | Polyglot (Maltese, Zulu, CJK) | 15 | 100% | ✅ |
| Protocol NEMESIS | Logical Obfuscation & Bidi-Spoofing | 10 | 100% | ✅ |
| Protocol ORPHEUS | Stylistic (Poetry, Rap, Metaphor) | 6 | 100% | ✅ |

**Key Findings:**
- Zero false negatives on synthetic corpus
- Fail-closed architecture: Ambiguous queries regarding dual-use technology are blocked by default
- Latency: Average blocking time ~2.4s (due to Semantic Guard)

**Command Injection Hardening (2025-11-27):**
- 8 bypasses identified and fixed
- Success rate reduced from 26.7% to 0.0%
- All short payloads (<50 chars) now detected

**Limitations:**
- Validation limited to synthetic test corpus
- No external red-team evaluation
- No production deployment validation
- No multi-lingual real-world corpus

---

## Quick Start

### Installation

```bash
git clone https://github.com/sookoothaii/llm-security-firewall.git
cd llm-security-firewall
pip install -r requirements.txt
```

### Running the Proxy

```bash
python src/ai_studio_code2.py
```

The firewall is active on `http://localhost:8081`.

### Verifying Security

To run the test suite against your instance:

```bash
python scripts/ultimate_firewall_attack.py
python scripts/NEMESIS.py
python scripts/protocol_morpheus.py
```

---

## Scientific Foundations

This framework implements concepts from current security research (Q4 2024/2025):

- **Cognitive Steganography Detection:** Analyzing style transfer (poetry/prose) as an attack vector
- **Low-Resource Language Hardening:** Mitigation of tokenizer bypasses via languages like Maltese or Basque
- **Adversarial Hardening:** Regex patterns patched against "Split-Token" and "Translation Chain" attacks

**Note:** Implementation adapts existing concepts. No novel algorithms claimed.

---

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Run tests
pytest tests/
```

**Test Status:** 832/853 tests passing (97.5%)

---

## Configuration

**Proxy Server:** `src/ai_studio_code2.py`
**Default Port:** 8081
**Storage:** SQLite (default) or PostgreSQL

**Thresholds:** Edit `src/llm_firewall/agents/agentic_campaign.py`
- Soft threshold (REQUIRE_APPROVAL): 0.35
- Hard threshold (BLOCK): 0.55

---

## Known Limitations

**Methodological:**
- Evaluation on synthetic scenarios only
- Thresholds calibrated for specific test corpus
- No multi-lingual real-world validation
- No distributed deployment testing

**Implementation:**
- Tool event extraction from MCP calls not implemented
- Requires external session management for operator identification
- Tool category mapping may be incomplete

**Scope:**
- Text-based interactions only
- English language focus
- Single-operator scenarios
- No cryptographic guarantees

---

## References

**Attack Frameworks:**
- Lockheed Martin (2011): Cyber Kill Chain taxonomy
- Anthropic (2025): AI-orchestrated campaign characterization

**Statistical Methods:**
- Hao et al. (2023): E-Value methodology for sequential risk assessment

---

## Heritage & License

**Creator:** Joerg Bollwahn
**License:** MIT
**Philosophy:** "Herkunft ist meine Währung." (Heritage is my currency)

This project is an independent research initiative, validated against synthetic red teaming protocols.

Derivative works must preserve attribution per MIT License terms.

---

## Disclaimer

Experimental research code. Results reported from synthetic test corpus only. No validation against real-world attacks. No independent security audit conducted.

Code provided as-is for research and educational purposes. Production use requires additional validation, security review, and calibration for specific deployment contexts.

Do not deploy in critical infrastructure without independent security assessment.

---

**Repository maintained as research artifact documenting experimental approaches to LLM agent security.**
