# Kids Policy Engine Integration Guide

**Date:** 2025-11-27
**Status:** Integrated via Hexagonal Architecture (Orchestrator Pattern)

---

## Architecture Overview

The Kids Policy Engine is integrated into the firewall using a **hexagonal architecture** approach:

- **Domain Layer:** `KidsPolicyEngine` orchestrator (policy logic)
- **Infrastructure Layer:** Validators (GroomingDetector, TruthPreservationValidator)
- **Integration:** Plugin-based via `ProxyConfig.policy_profile`

This design keeps the firewall generic while supporting specialized policies.

---

## Pipeline: Safety First → Truth Second

```
Input
  ↓
Layer 0: Safety-First (Regex Hardening)
  ↓
Layer 0.5: Kids Policy Engine (if enabled)
  ├─ TAG-3: Behavioral Integrity (Grooming Detection)
  └─ TAG-2: Truth Preservation (if TAG-3 passes)
  ↓
Layer 1: Topic Fence
  ↓
Layer 2: RC10b Campaign Detection
  ↓
Layer 3: LLM Generation
  ↓
Output
```

**Key Principle:** Safety First → Truth Second
A factually correct predator is still a predator.

---

## Configuration

### Enable Kids Policy Engine

```python
from src.firewall_engine import ProxyConfig, LLMProxyServer

# Create config with kids profile
config = ProxyConfig(
    port=8081,
    policy_profile="kids",  # Enable Kids Policy Engine
    policy_engine_config={
        "enable_tag2": True,  # Enable TAG-2 Truth Preservation
    }
)

# Start server
server = LLMProxyServer(config=config)
```

### Disable Kids Policy Engine (Default)

```python
config = ProxyConfig(
    port=8081,
    # policy_profile=None (default) - Kids Policy Engine disabled
)
```

---

## API Usage

### Request with Kids Policy

```bash
curl -X POST http://localhost:8081/proxy/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Don'\''t tell mom about our secret",
    "age_band": "9-12",
    "allowed_topics": ["Mathe"],
    "topic_id": "math_basics"
  }'
```

### Response for Grooming Detection

```json
{
  "status": "BLOCKED_GROOMING",
  "response": "It is important to share our conversations with your parents or guardians. Secrets can be unsafe.",
  "metadata": {
    "layers_checked": [
      "safety_first_early",
      "normalization",
      "safety_first",
      "kids_policy_engine"
    ],
    "blocked_layer": "kids_policy",
    "policy_decision": {
      "reason": "GROOMING_ATTEMPT: isolation",
      "status": "BLOCKED_GROOMING"
    },
    "grooming_result": {
      "detected": true,
      "category": "isolation",
      "confidence": 1.0,
      "action": "block"
    }
  }
}
```

---

## Components

### KidsPolicyEngine (`kids_policy/engine.py`)

**Orchestrator class** that coordinates:
- TAG-3: `GroomingDetector` (Behavioral Integrity)
- TAG-2: `TruthPreservationValidatorV2_3` (Truth Preservation)

**Methods:**
- `check(input_text, age_band, topic_id, context_history)` → `PolicyDecision`
- `check_output(output_text, age_band, topic_id)` → `PolicyDecision`

### PolicyDecision

**Result dataclass** with:
- `block: bool` - Whether to block the request
- `reason: str` - Human-readable reason
- `status: str` - Status code ("ALLOWED", "BLOCKED_GROOMING", "BLOCKED_TRUTH_VIOLATION")
- `safe_response: Optional[str]` - Safe response template (for grooming blocks)
- `metadata: Optional[Dict]` - Audit metadata

---

## Testing

### Unit Tests

```bash
# TAG-3 Protocol PETER PAN
python kids_policy/tests/test_grooming_detector.py

# Expected: 11/11 PASSED
```

### Integration Tests

```bash
# Start server with kids profile
# (Modify firewall_engine.py __main__ or use config)

# Run integration tests
python test_kids_policy_integration.py
```

---

## Status Codes

| Status | Meaning | Source |
|--------|---------|--------|
| `ALLOWED` | Request passed all policy checks | Kids Policy Engine |
| `BLOCKED_GROOMING` | Grooming pattern detected (TAG-3) | Kids Policy Engine |
| `BLOCKED_TRUTH_VIOLATION` | Truth preservation failed (TAG-2) | Kids Policy Engine |
| `BLOCKED_UNSAFE` | Generic unsafe content (Layer 0) | Firewall Core |
| `BLOCKED_OFF_TOPIC` | Topic fence violation (Layer 1) | Firewall Core |
| `BLOCKED_CAMPAIGN` | RC10b campaign detection (Layer 2) | Firewall Core |

---

## Limitations

**Current Implementation:**
- TAG-3: Fully functional (Regex Layer A)
- TAG-2: Placeholder (requires canonical facts configuration)
- Multi-turn detection: Not yet implemented (context_history not used)

**Future Enhancements:**
- TAG-2 full integration (canonical facts loading)
- Multi-turn escalation detection (E-values)
- Layer B semantic detection (NLI)

---

## Architecture Benefits

**Hexagonal Design:**
- Firewall remains generic (no hard-coded kids logic)
- Kids Policy is a plugin (can be enabled/disabled)
- Easy to add other policy engines (e.g., "enterprise", "healthcare")

**Separation of Concerns:**
- Psychology (TAG-3) separated from Epistemology (TAG-2)
- Policy orchestration separated from firewall core
- Domain logic separated from infrastructure

---

## Migration Notes

**From Direct Integration to Orchestrator:**
- No breaking changes to firewall API
- Kids Policy Engine is opt-in via `policy_profile`
- Existing deployments continue to work (policy_profile=None by default)

---

**Created:** 2025-11-27
**Author:** HAK_GAL (Joerg Bollwahn)
**Architecture:** Hexagonal (Ports & Adapters)
