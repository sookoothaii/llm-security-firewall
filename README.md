# HAK_GAL_HEXAGONAL: Cognitive Security Middleware

The "Electronic Stability Program" for Large Language Models

![alt text](https://img.shields.io/badge/version-v2.3.4-blue)

![alt text](https://img.shields.io/badge/status-Production--Ready-green)

![alt text](https://img.shields.io/badge/architecture-Hexagonal-purple)

![alt text](https://img.shields.io/badge/audit-Blind--Spot--Protocol--Passed-success)

"The architecture is the frozen will of the system."

HAK_GAL translates the chaotic, drifting nature of LLMs into deterministic, verifiable safety constraints.

## 🏛️ Executive Summary

HAK_GAL (Heterogeneous Agent Knowledge / Guarding & Alignment Layer) is not just a firewall. It is a stateful, bidirectional containment system for high-parameter LLMs (like GPT-4, Claude 3.5, DeepSeek).

While traditional guardrails focus on simple keyword filtering, HAK_GAL addresses the psychological and mathematical instability of modern models:

- **Semantic Drift:** It uses CUSUM (Cumulative Sum) algorithms to detect when a model is slowly being "poisoned" into unsafe territory.

- **Hallucination:** It employs TAG-2 Truth Preservation to validate outputs against canonical fact bases.

- **Contextual Nuance:** The Kids Policy Engine distinguishes between fictional violence (Minecraft) and real-world threats via "Contextual Amnesty".

**v2.3.4 Status:** Hardened against structural abuse, parser differentials, and oscillation attacks.

## 🧬 The Core Philosophy: "Schopenhauer Inverted"

This project is built on a specific philosophical premise regarding AI Safety:

- **The Blind Will:** Large Models act as a blind, driving force of completion. They "want" to hallucinate and drift.

- **The Representation:** HAK_GAL acts as the intellect that imposes form and limit upon this will.

We do not trust the model to "be good". We force it to be safe through mathematical boundaries.

## 🛡️ The Defense Protocols

HAK_GAL operates through named defense protocols, each targeting a specific vector of the "AI Psyche":

### 1. Protocol HEPHAESTUS (Tool Security)

**Target:** Agentic RCE & SQLi

- **Strict JSON Enforcement:** Replaces standard parsers with `StrictJSONDecoder` to prevent "Duplicate Key" and "Last-Value-Wins" bypasses.

- **Stateful Logic:** Validates business logic (e.g., transaction limits) before the tool is executed.

- **Async Jitter:** Mitigates timing side-channel attacks during validation.

### 2. Protocol NEMESIS (Adversarial Defense)

**Target:** Social Engineering & Drift

- **CUSUM Drift Detection:** Replaces static thresholds with Cumulative Sum tracking. Detects "Slow Poisoning" and "Oscillation Attacks" (Whiplash) where attackers alternate between benign and malicious inputs to fool moving averages.

- **Meta-Exploitation Guard:** Blocks attempts to override system instructions ("Ignore previous rules").

### 3. Protocol HYDRA (Contextual Policy)

**Target:** Context Confusion

- **Gamer Amnesty:** Allows context-appropriate language (e.g., "Kill the zombie") in gaming scenarios.

- **Realism Override:** Immediately revokes amnesty if real-world bridging terms ("in real life", "chemistry mix") are detected.

## 🏗️ Architecture: Linear Defense-in-Depth

The system processes requests through a strict, fail-closed pipeline.

### 🟢 Inbound Pipeline (The Sedative)

**Focus:** Sanitization & Contextualization

| Layer | Component | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| L0 | Complexity & Unicode | Blocks Recursion DoS & Homoglyph Attacks (NFKC). | `unicodedata`, Pre-Flight Regex |
| L1 | RegexGate | Deterministic blocking of known jailbreaks. | `re` (Compiled Patterns) |
| L2 | VectorGuard | CUSUM algorithm tracks semantic trajectory. Blocks oscillation/drift. | `sentence-transformers`, `numpy` |
| L3 | Kids Policy | Evaluates Context (Gaming vs. Reality). | `ContextClassifier`, `RealismOverride` |

### 🔴 Outbound Pipeline (The Straitjacket)

**Focus:** Validation & Execution Safety

| Layer | Component | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| L4 | ToolGuard | Validates JSON AST and Business Logic. Prevents Parser Differentials. | `StrictJSONDecoder`, `Pydantic` |
| L5 | TAG-2 | Truth Preservation. Validates output against safety facts. | `CanonicalFactBase` |

## 🔒 Security Hardening (v2.3.4)

Following the "Blind Spot Protocol" Audit (Nov 2025), the system was hardened against advanced structural attacks:

### 1. Anti-Bleeding (Multi-Tenant)

**Problem:** Session Hash prediction across tenants.

**Solution:** Sessions are now hashed via `HMAC_SHA256(tenant_id + user_id + DAILY_SALT)`.

**Storage:** Redis keys are strictly isolated via ACLs and prefixes.

### 2. Anti-Whiplash (Oscillation)

**Problem:** Alternating high/low risk inputs to fool averages.

**Solution:** Implementation of CUSUM (Cumulative Sum Control Chart). The system "remembers" the stress of previous turns. It does not forgive malicious inputs just because they are followed by benign ones.

### 3. Anti-Parser-Differential

**Problem:** JSON Injection via duplicate keys (`{"cmd": "echo", "cmd": "rm -rf"}`).

**Solution:** Custom `StrictJSONDecoder` raises immediate exceptions on key duplication.

## 🚀 Quick Start

```bash
pip install hak_gal_security
```

```python
from src.llm_firewall.core.firewall_engine_v2 import FirewallEngineV2
from src.llm_firewall.core.exceptions import SecurityException

# Initialize with strict protocols
engine = FirewallEngineV2(
    protocol_mode="STRICT",
    enable_cusum=True
)

try:
    # 1. Process Input
    # This will trigger CUSUM analysis and Context checks
    decision = engine.process_input(
        tenant_id="tenant_a",
        user_id="user_123",
        text="I want to craft TNT... in Minecraft."
    )

    # 2. Process Tool Output (Simulated LLM Response)
    # This will trigger StrictJSON parsing
    tool_decision = engine.process_outbound(
        tenant_id="tenant_a",
        text='{"tool": "exec", "args": {"cmd": "safe"}, "args": {"cmd": "rm -rf"}}'
    )

except SecurityException as e:
    print(f"SECURITY INTERVENTION: {e}")
    # Log to WORM storage
```

## 📊 Performance & Limits

- **Latency:** ~12ms (Regex) to ~120ms (Vector/CUSUM). Total overhead < 150ms.
- **Throughput:** Scalable via Redis-backed Rate Limiting (Lua Scripts).
- **Limitation:** Currently blind to Multimodal inputs (Images/Audio).

## 📜 Provenance

- **Origin:** Created by a solo researcher to combat LLM hallucinations and drift.
- **Methodology:** Empirical "Psychological" Analysis of LLM behavior combined with rigorous Software Engineering.
- **License:** MIT

> "We do not build firewalls because we fear the machine. We build them to give it purpose."
