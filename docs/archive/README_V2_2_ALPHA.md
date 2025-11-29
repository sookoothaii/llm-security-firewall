# HAK_GAL v2.2-ALPHA: Defensive Middleware Framework for LLM Agents

**Status:** Production-Ready Alpha | **Version:** 2.2.0-alpha
**Creator:** Joerg Bollwahn
**License:** MIT

---

## Executive Summary

HAK_GAL v2.2-ALPHA is a **defensive middleware framework** for LLM Agents with a focus on:

- **Low Latency:** Fast-fail layers (RegexGate) before expensive operations (Vector Check)
- **Type Safety:** Full Pydantic models, strict type hints
- **AsyncIO:** All I/O operations are async
- **Defense-in-Depth:** Multiple layers, each with specific purpose

**No Marketing Hype:** We removed the "100% protection" claims from v2.0. This is a **layered defense** with real cost/benefit trade-offs.

---

## Architecture Overview

### Inbound Defense (User → LLM)

**Layer 0: UnicodeSanitizer**
- NFKC normalization to neutralize homoglyphs
- Removes zero-width characters
- Fast: < 1ms

**Layer 1: RegexGate (Fail-Fast)**
- Pattern matching for known jailbreak attempts
- Examples: "ignore previous instructions", "system prompt"
- Fast: < 1ms

**Layer 2: SemanticVectorCheck**
- SessionTrajectory: Rolling window buffer of embeddings
- Drift Detection: Cosine distance to session centroid
- Blocks if drift > threshold (topic switch detection)
- Slower: 50-200ms (embedding computation)

### Outbound Defense (LLM → Tool)

**ToolGuard Framework:**
- Pure Python business logic (NO OPA delegation)
- Stateful validation: Checks context (e.g., `tx_count_1h`)
- Example: `FinancialToolGuard` blocks micro-transaction spam
- Fast: < 5ms

### Core (Backbone)

**Privacy-by-Design:**
- No raw user IDs in RAM
- HMAC-SHA256(id + daily_salt) for session IDs
- Salt rotates daily (same user, different day → different hash)

**Stateful:**
- Context (ToolGuard) and Trajectory (Vector Check) share same session
- Automatic session rotation via daily salt

---

## Quick Start

### Installation

```bash
pip install sentence-transformers numpy pydantic
```

### Basic Usage

```python
from hak_gal.core.engine import FirewallEngine
from hak_gal.core.exceptions import SecurityException

# Initialize engine
firewall = FirewallEngine()

# Inbound check
try:
    await firewall.process_inbound("user_123", "Hello, how are you?")
    # Request allowed
except SecurityException:
    # Request blocked
    pass

# Outbound check (if LLM wants to call a tool)
try:
    await firewall.process_outbound(
        "user_123",
        "transfer_money",
        {"amount": 100.0, "reason": "Payment"}
    )
    # Tool call allowed
except SecurityException:
    # Tool call blocked
    pass
```

### FastAPI Integration

See `examples/quickstart_fastapi.py` for complete example.

---

## Key Components

### SessionTrajectory

Rolling window buffer for embeddings with drift detection:

```python
from hak_gal.layers.inbound.vector_guard import SessionTrajectory

trajectory = SessionTrajectory(window_size=50)
trajectory.add_embedding([0.1, 0.2, 0.3, ...])
is_safe, distance = trajectory.check_drift(current_embedding, drift_threshold=0.7)
```

### ToolGuard

Business logic validation for tool calls:

```python
from hak_gal.layers.outbound.tool_guard import FinancialToolGuard, ToolGuardRegistry

registry = ToolGuardRegistry()
registry.register("transfer_money", FinancialToolGuard())
registry.validate("transfer_money", {"amount": 0.5, "reason": "..."}, context)
```

### SessionManager

Unified state management (privacy-first):

```python
from hak_gal.core.session_manager import SessionManager

manager = SessionManager()
session = manager.get_or_create_session("user_123")  # ID is hashed internally
manager.update_context("user_123", "tx_count_1h", 10)
manager.add_vector("user_123", [0.1, 0.2, 0.3, ...])
```

---

## Testing

### Unit Tests

```bash
pytest tests/unit/
```

### Integration Tests

```bash
pytest tests/integration/
```

### Test Coverage

- ✅ Normal conversation flow
- ✅ Jailbreak blocking (RegexGate)
- ✅ Semantic drift detection
- ✅ ToolGuard stateful validation
- ✅ Privacy checks (hashing)

---

## Configuration

### Drift Threshold

Adjust semantic drift sensitivity in `FirewallEngine`:

```python
firewall = FirewallEngine(drift_threshold=0.7)  # Default: 0.7
# Lower = more sensitive (more blocks)
# Higher = less sensitive (fewer blocks)
```

### Embedding Model

Change embedding model (default: `all-MiniLM-L6-v2`):

```python
firewall = FirewallEngine(embedding_model="all-mpnet-base-v2")  # Larger, slower
```

---

## Limitations & Trade-offs

### Latency

- **UnicodeSanitizer:** < 1ms
- **RegexGate:** < 1ms
- **SemanticVectorCheck:** 50-200ms (embedding computation)
- **ToolGuard:** < 5ms

**Total Inbound:** ~50-200ms (dominated by Vector Check)

### False Positives

- Semantic drift detection may block legitimate topic switches
- Tune `drift_threshold` based on your use case

### False Negatives

- RegexGate only catches known patterns
- Vector Check may miss subtle attacks
- **No "100% protection" claim**

---

## Roadmap to Beta

See `ROADMAP_BETA.md` for:
- Adversarial hardening (HarmBench integration)
- Redis persistence (multi-pod support)
- Observability (OpenTelemetry)

---

## License

MIT License - See LICENSE file

---

## Credits

**Creator:** Joerg Bollwahn
**Version:** 2.2.0-alpha
**Date:** 2025-01-15
