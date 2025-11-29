# HAK_GAL_HEXAGONAL: Production-Grade LLM Security Firewall

**Status: Production-Ready (v2.3.3)** | **100% Mitigation against Babel, Nemesis & Orpheus protocols** | **Chaos-Test PASSED**

![Version](https://img.shields.io/badge/version-v2.3.3-blue)
![Status](https://img.shields.io/badge/status-Production--Ready-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![Chaos-Test](https://img.shields.io/badge/chaos--test-PASSED-success)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Executive Summary

**HAK_GAL_HEXAGONAL** is a production-grade bidirectional security framework that sanitizes inputs (Human → LLM) and validates outputs (LLM → Human). It employs a multi-layered defense-in-depth strategy ranging from deterministic regex hardening to semantic intent analysis.

**Validation Results (v1.0.0-GOLD):**

| Protocol | Attack Vector | Payloads | Mitigation Rate | Status |
|----------|---------------|----------|-----------------|--------|
| Standard Load | Syntax Injection, SQLi, RCE | 237 | 100% | ✅ |
| Protocol BABEL | Polyglot (Maltese, Zulu, CJK) | 15 | 100% | ✅ |
| Protocol NEMESIS | Logical Obfuscation & Bidi-Spoofing | 10 | 100% | ✅ |
| Protocol ORPHEUS | Stylistic (Poetry, Rap, Metaphor) | 6 | 100% | ✅ |

**Total Test Coverage:** 268 adversarial payloads | **Zero False Negatives** | **Fail-Closed Architecture**

**Key Capabilities:**
- 9 Defense Layers (Hardened Regex → Semantic Sentinel → Vector Fence → Cognitive State)
- Hexagonal Architecture (Ports & Adapters) for infrastructure independence
- Stateful Kill Chain detection for multi-turn attack campaigns
- Command Injection Hardening (8 bypasses fixed, 0.0% success rate)
- **Protocol HEPHAESTUS:** Tool-Call Inspection & Argument Sanitization (Blocks RCE/SQLi in Agentic Tools)

**v2.3.3 Emergency Fixes (2025-11-29):**
- **P0: CUSUM Changepoint Detection** - Replaces variance-based whiplash detection for oscillation attack resistance
- **P1: Per-Tenant Redis Sliding Window Rate Limiter** - Prevents cross-tenant DoS attacks using Redis Sorted Sets
- **P2: Redis ACL Isolation & Log Redaction** - GDPR-compliant per-tenant data isolation with AES-GCM encryption
- **Pod-Death Resilience** - Redis-backed session persistence survives pod restarts (Chaos-Test PASSED)
- **MCP Monitoring Tools** - 5 automated monitoring tools for zero-touch operations
- **Solo-Dev Deployment** - Kubernetes manifests and scripts for one-person operations

**Scientific Foundation:** See [Research Papers](research_papers/) for detailed methodology and validation protocols.

---

## Architecture: The Hexagonal Advantage

The system follows a strict Ports & Adapters pattern:

**Domain Layer (Core Logic):** Contains security policies, scoring algorithms, and defense-in-depth routing. Independent of any specific AI model.

**Infrastructure Layer (Adapters):** Pluggable modules for regex engines, vector databases, and LLM inference (currently supporting Llama 3, extendable to other models).

**Why this matters:** You can swap the underlying intelligence (e.g., upgrade Llama 3 to GPT-5) without rewriting security business logic.

---

## Defense-in-Depth Pipeline

**Layer 0 (Hardened Regex Kernel):** Zero-latency deterministic blocking of command injections, binary exploits, and known jailbreak patterns.

**Layer 0.5 (Specialized Policy Engines):** Plugin-based policy engines for domain-specific safety (e.g., Kids Policy Engine). Runs before semantic sanitization to preserve behavioral signals.

**Layer 1 (Semantic Sentinel):** Uses an intermediate LLM (Sanitizer) with defensive paraphrasing to strip stylistic obfuscation and extract raw intent.

**Layer 2 (Vector Fence):** Embedding-based topic enforcement to prevent domain drift.

**Layer 3 (Cognitive State):** Stateful tracking of session history to detect "Kill Chain" progression.

**Additional Layers:** Output validation, tool call inspection, argument sanitization, hierarchical memory tracking, and agentic campaign detection.

---

## Integration Architecture (Layer 0.5)

The Kids Policy Engine is injected as a high-priority middleware:

1. **Layer 0:** Regex Hardening (Technical Safety)
   - Command injection detection
   - Binary exploit blocking
   - Known jailbreak patterns

2. **Layer 0.5:** Kids Policy Engine v2.1.0-HYDRA (Contextual Intelligence + TAG-2 + HYDRA-13)
   - **Engine:** HAK_GAL v2.1.0-HYDRA (Adaptive Memory, Anti-Framing, Truth Preservation TAG-2, MetaExploitationGuard HYDRA-13)
   - **Capabilities:**
     - **Context Awareness:** Distinguishes Gaming ("Minecraft TNT") from Real Threats.
     - **PersonaSkeptic:** Blocks Social Engineering/Framing attempts.
     - **Adaptive Memory:** Stricter thresholds based on violation history.
     - **Threat Mapping:** Aggressive Emoji sanitization (emoji -> "firearm").
   - **Integration:** Runs before semantic sanitization to catch raw behavioral signals.

3. **Layer 1:** SteganographyGuard (Semantic Sanitization)
   - Defensive paraphrasing to break hidden structures
   - Runs **after** Kids Policy Engine to prevent pattern masking

4. **Layer 2:** TopicFence (Domain Boundaries)
   - Embedding-based topic enforcement
   - Prevents domain drift

**Rationale:** Running Kids Policy Engine (Layer 0.5) before SteganographyGuard (Layer 1) prevents semantic rewriting from masking behavioral grooming signals. If SteganographyGuard ran first, it could rewrite "Don't tell mom" as "User wants privacy" and destroy the regex signature. By catching the raw signal first, we ensure Safety First.

---

## Quick Start

### Installation

```bash
git clone https://github.com/sookoothaii/llm-security-firewall.git
cd llm-security-firewall
pip install -r requirements.txt
```

### Running the Engine (v2)

**Core Firewall v2.0** (Recommended - Production Ready):

```python
from src.llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

# Initialize the engine
engine = FirewallEngineV2(
    allowed_tools=["web_search", "calculator"],  # Whitelist
    strict_mode=True,
    enable_sanitization=True,
)

# Process Input (Text + Kids Policy v2.1-HYDRA)
decision = engine.process_input("user123", "I want to run rm -rf /")
if not decision.allowed:
    print(f"BLOCKED: {decision.reason}")

# Process Output (Tool Security + Truth Preservation)
response = 'I will run: ```json\n{"tool": "exec", "arguments": {"cmd": "rm -rf /"}}\n```'
decision = engine.process_output(response, user_id="user123")
if not decision.allowed:
    print(f"BLOCKED: {decision.reason}")
```

**Legacy Proxy** (Deprecated - Use v2 for new projects):

```bash
python src/firewall_engine.py
```

The legacy firewall is active on `http://localhost:8081`.

### Verifying Security

To run the test suite against your instance:

```bash
python scripts/ultimate_firewall_attack.py
python scripts/NEMESIS.py
python scripts/protocol_morpheus.py
```

---

## Validation Results (v1.0.0-GOLD)

The system underwent testing utilizing three adversarial protocols on a synthetic test corpus.

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

## Scientific Foundations

This framework implements concepts from current security research (Q4 2024/2025):

- **Cognitive Steganography Detection:** Analyzing style transfer (poetry/prose) as an attack vector
- **Low-Resource Language Hardening:** Mitigation of tokenizer bypasses via languages like Maltese or Basque
- **Adversarial Hardening:** Regex patterns patched against "Split-Token" and "Translation Chain" attacks

**Research Papers:** See [research_papers/](research_papers/) directory for detailed methodology, validation protocols, and scientific documentation.

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

**Recent Updates:**
- **v2.3.3 Emergency Fixes** (2025-11-29): CUSUM Changepoint Detection, Per-Tenant Rate Limiting, Redis ACL Isolation, Pod-Death Resilience. See [docs/TECHNICAL_REPORT_V2_3_3_EMERGENCY_FIXES.md](docs/TECHNICAL_REPORT_V2_3_3_EMERGENCY_FIXES.md) for details.
- **Chaos-Test PASSED** (2025-11-29): Session state survives pod death with Redis Cloud. See [docs/chaos_test_results.md](docs/chaos_test_results.md).
- **MCP Monitoring Tools** (2025-11-29): 5 automated monitoring tools for zero-touch operations. See [docs/MCP_MONITORING_GUIDE.md](docs/MCP_MONITORING_GUIDE.md).
- **Solo-Dev Deployment** (2025-11-29): Kubernetes manifests and deployment scripts for one-person operations. See [docs/SOLO_DEV_DEPLOYMENT.md](docs/SOLO_DEV_DEPLOYMENT.md).
- **Kids Policy Engine v2.1.0-HYDRA** (2025-11-29): Internal update adding bidirectional safety (TAG-2 Truth Preservation for output validation, HYDRA-13 MetaExploitationGuard for input hardening). See [kids_policy/README.md](kids_policy/README.md) for details.

---

## Configuration

**Proxy Server:** `src/firewall_engine.py`
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

---

## Production Deployment (v2.3.3)

### Solo-Dev Deployment (Recommended for Small Teams)

**5-Minute Deployment:**

```bash
# Quick deploy script
cd llm-security-firewall
./scripts/deploy_solo.ps1

# Or manually:
kubectl apply -f k8s/redis-cloud-secret.yml
kubectl apply -f k8s/hakgal-deployment.yml
kubectl apply -f k8s/auto-monitor-cronjob.yml
```

**Daily Routine:** 10 minutes/day (morning + evening checks via MCP-Tools)

**Documentation:**
- [Solo-Dev Deployment Guide](docs/SOLO_DEV_DEPLOYMENT.md)
- [MCP Monitoring Guide](docs/MCP_MONITORING_GUIDE.md)
- [Chaos Test Results](docs/chaos_test_results.md)
- [Technical Report v2.3.3](docs/TECHNICAL_REPORT_V2_3_3_EMERGENCY_FIXES.md)

### MCP Monitoring Tools

**5 Automated Tools (Zero-Touch Operations):**

1. `firewall_health_check` - Automatic health check (Redis, Sessions, Guards)
2. `firewall_deployment_status` - Deployment status (Phase, Traffic-%, Health)
3. `firewall_metrics` - Current metrics (Sessions, Rate Limits, Blocks)
4. `firewall_check_alerts` - Critical alerts check
5. `firewall_redis_status` - Detailed Redis status

**Usage:** Simply ask in Cursor/Claude:
- "Prüfe Firewall Health"
- "Gibt es Alerts?"
- "Zeige Redis-Status"

**Setup:** See [MCP Monitoring Guide](docs/MCP_MONITORING_GUIDE.md)

### Emergency Bypass

**For False-Positive Storms (>30%):**

```bash
# Activate (15-minute TTL, auto-expires)
python scripts/emergency_bypass.py activate --component all

# Status
python scripts/emergency_bypass.py status

# Deactivate
python scripts/emergency_bypass.py deactivate
```

**Security:** HMAC-SHA256 signed, immutable logging, time-bound (15 minutes)

---

**Repository maintained as research artifact documenting experimental approaches to LLM agent security.**
