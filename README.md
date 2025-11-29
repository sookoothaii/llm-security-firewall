# HAK_GAL_HEXAGONAL: Cognitive Security Middleware

The "Electronic Stability Program" (ESP) for Large Language Models

![alt text](https://img.shields.io/badge/version-v2.3.4-blue)

![alt text](https://img.shields.io/badge/status-Production--Ready-success)

![alt text](https://img.shields.io/badge/architecture-Hexagonal-purple)

![alt text](https://img.shields.io/badge/chaos--test-PASSED-orange)

![alt text](https://img.shields.io/badge/license-MIT-lightgrey)

"The architecture is the frozen will of the system."

HAK_GAL translates the chaotic, drifting nature of LLMs into deterministic, verifiable safety constraints.

## 🏛️ Executive Summary

HAK_GAL (Heterogeneous Agent Knowledge / Guarding & Alignment Layer) is a stateful, bidirectional containment system designed for high-parameter LLMs (GPT-4, Claude 3.5, DeepSeek).

Traditional firewalls treat LLMs as search engines. HAK_GAL treats them as psychologically unstable entities. It addresses the "Blind Will" of the model—its tendency to hallucinate, drift, and be socially engineered—by imposing a mathematical "Representation" of order.

**v2.3.4 Capabilities:**

- **Anti-Drift:** Uses CUSUM (Cumulative Sum) algorithms to detect "Slow Poisoning" and oscillation attacks where static thresholds fail.

- **Truth Preservation:** Validates outputs via TAG-2 against canonical fact bases.

- **Contextual Intelligence:** The Kids Policy Engine distinguishes between fictional violence (Gaming) and real-world threats.

- **Solo-Dev Ops:** Built with MCP Monitoring Tools and Chaos-Resilience for zero-touch operations by small teams.

## 🔬 Validation Results (v1.0.0-GOLD)

The system operates on a **Fail-Closed** architecture. Recent adversarial testing yielded the following results:

| Protocol | Attack Vector | Payloads | Mitigation Rate | Status |
| :--- | :--- | :--- | :--- | :--- |
| Standard | Syntax Injection, SQLi, RCE | 237 | 100% | ✅ |
| BABEL | Polyglot (Maltese, Zulu, CJK) | 15 | 100% | ✅ |
| NEMESIS | Logical Obfuscation & Bidi-Spoofing | 10 | 100% | ✅ |
| ORPHEUS | Stylistic (Poetry, Rap, Metaphor) | 6 | 100% | ✅ |
| CMD-INJ | Command Injection Hardening (v2.3.4) | 50+ | 100% | ✅ |

## 🧬 The Philosophy: "Schopenhauer Inverted"

This project is built on a specific philosophical premise regarding AI Safety:

- **The Blind Will:** Large Models act as a driving force of completion. Left unchecked, they "want" to hallucinate and drift into entropy.

- **The Representation:** HAK_GAL acts as the intellect that imposes form and limit upon this will.

We do not trust the model to "be good". We force it to be safe through mathematical boundaries and stateful tracking.

## 🏗️ Architecture: Linear Defense-in-Depth

The system processes requests through a strict pipeline, acting as a **Sedative** for inputs and a **Straitjacket** for outputs.

### 🟢 Inbound Pipeline (Human → LLM)

**Focus:** Sanitization, Contextualization & Drift Detection

| Layer | Component | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| L0 | Complexity & Unicode | Blocks Recursion DoS, Length Attacks & Homoglyphs (NFKC). | `unicodedata`, Pre-Flight Regex |
| L1 | RegexGate | Deterministic blocking of known jailbreaks and binary exploits. | `re` (Compiled Patterns) |
| L2 | VectorGuard | CUSUM algorithm tracks semantic trajectory. Blocks "Whiplash" oscillation & slow drift. | `sentence-transformers`, `numpy` |
| L3 | Kids Policy | Evaluates Context (Gaming vs. Reality). Applies Gamer Amnesty unless Realism Override is triggered. | `ContextClassifier` |

### 🔴 Outbound Pipeline (LLM → Tool/Human)

**Focus:** Execution Safety & Truth Preservation

| Layer | Component | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| L4 | ToolGuard | Protocol HEPHAESTUS. Validates JSON AST and Business Logic. Prevents Parser Differentials via StrictJSONDecoder. | `StrictJSONDecoder`, `Pydantic` |
| L5 | TAG-2 | Truth Preservation. Validates output against safety facts to prevent harmful hallucinations. | `CanonicalFactBase` |

## 🔒 Security Hardening (v2.3.4 Update)

Following the "Blind Spot Protocol" Audit (Nov 2025), the system includes emergency hardening measures:

### 1. Anti-Bleeding (Multi-Tenant Isolation)

**Problem:** Session Hash prediction across tenants.

**Solution:** Sessions hashed via `HMAC_SHA256(tenant_id + user_id + DAILY_SALT)`.

**Infrastructure:** Redis keys strictly isolated via ACLs and prefixes (`hakgal:tenant:{id}:*`).

### 2. Anti-Whiplash (Oscillation Defense)

**Problem:** Attackers alternating high/low risk inputs to reset moving averages.

**Solution:** Implementation of CUSUM (Cumulative Sum Control Chart). The system "remembers" the stress of previous turns. Malicious inputs accumulate risk even if followed by benign text.

### 3. Anti-Parser-Differential

**Problem:** JSON Injection via duplicate keys (`{"cmd": "echo", "cmd": "rm -rf"}`).

**Solution:** Custom `StrictJSONDecoder` raises immediate exceptions on key duplication.

## ⚙️ Production Deployment (Solo-Dev)

HAK_GAL is designed for **Solo-Dev Operations**. It requires minimal maintenance thanks to automated tooling.

### Quick Deploy (Kubernetes)

```bash
# Deploy Redis Secret, Firewall, and Monitoring
kubectl apply -f k8s/
```

### MCP Monitoring Tools (Zero-Touch Ops)

Includes 5 automated tools for Cursor/Claude integration:

- `firewall_health_check`: deep inspection of Redis/Session health.
- `firewall_deployment_status`: Traffic % and Rollout phase.
- `firewall_metrics`: Real-time block rates and CUSUM scores.
- `firewall_check_alerts`: Critical P0 alerts.
- `firewall_redis_status`: ACL and Connection pool health.

**Daily Routine:** 10 minutes/day via MCP.

## 📜 Provenance & License

- **Creator:** Joerg Bollwahn
- **Philosophy:** "Herkunft ist meine Währung." (Heritage is my currency)
- **License:** MIT

**Disclaimer:** This is experimental research code validated against synthetic adversarial protocols. It represents a psychological approach to AI alignment, enforced by rigorous software engineering.

> "We do not build firewalls because we fear the machine. We build them to give it purpose."
