# HAK_GAL_HEXAGONAL: LLM Security Middleware

**Version:** v2.3.4

**Status:** Production-Ready

**Architecture:** Linear Defense-in-Depth (Hexagonal)

## System Overview

HAK_GAL is a stateful, bidirectional security middleware designed to sanitize inputs (Human → LLM) and validate outputs (LLM → Human/Tool). It focuses on preventing prompt injection, context drifting, and structural abuse in agentic workflows.

It operates on a **Fail-Closed** principle.

## Architecture

### Inbound Pipeline

1.  **Layer 0: Complexity & Unicode**

    *   Pre-flight checks for JSON recursion depth and length.

    *   `UnicodeSanitizer` (NFKC) to neutralize homoglyphs.

2.  **Layer 1: RegexGate**

    *   Deterministic blocking of known jailbreak patterns and command injections.

3.  **Layer 2: SemanticVectorCheck (CUSUM)**

    *   Uses Cumulative Sum (CUSUM) changepoint detection to identify semantic drift and oscillation attacks (e.g., slow poisoning).

4.  **Layer 3: Kids Policy (Context)**

    *   Evaluates context (e.g., Gaming vs. Reality).

    *   Applies `RealismOverride` to revoke bonuses if real-world harm logic is detected.

### Outbound Pipeline

1.  **Layer 4: ToolGuard (Protocol HEPHAESTUS)**

    *   **Strict JSON Parsing:** Rejects duplicate keys to prevent parser differential attacks.

    *   **Logic Validation:** Stateful checks (e.g., transaction limits) via Python DSL.

2.  **Layer 5: Output Validation (TAG-2)**

    *   Checks LLM responses against safety constraints to prevent harmful hallucinations.

## Technical Specifications

| Component | Implementation | Notes |
| :--- | :--- | :--- |
| **Drift Detection** | CUSUM Algorithm | Immune to "Whiplash" oscillation |
| **State Storage** | Redis (Cluster/Cloud) | Tenant-isolated via ACLs & Key Prefixes |
| **Config Mgmt** | Signed RuntimeConfig | HMAC-SHA256 + Nonce + Timestamp |
| **Parsing** | StrictJSONDecoder | Prevents "Last-Key-Wins" exploits |
| **Rate Limiting** | Redis Sliding Window | Lua-scripted for atomicity |

## Usage

```python
from src.llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

engine = FirewallEngineV2()

# 1. Inbound Check
try:
    engine.process_input(
        user_id="user_123",
        text="{\"cmd\": \"A\", \"cmd\": \"rm -rf /\"}" # Will raise ValueError
    )
except SecurityException as e:
    print(f"Blocked: {e}")
```

## Known Limitations (v2.3.4)

- **Multimodal Blindness:** The system analyzes text/code only. Images or Audio inputs bypass the semantic layers.
- **Latency:** Deep semantic inspection adds ~120ms overhead per turn.
- **Language Support:** Optimized for English. High-resource languages (German, French) work; low-resource languages may degrade CUSUM accuracy.

## License

MIT
