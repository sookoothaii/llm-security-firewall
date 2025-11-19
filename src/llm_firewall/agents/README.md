# Agent Behavioral Firewall (RC10b)

Behavioral detection layer for agentic LLM systems.

## Overview

RC10b detects multi-turn attack campaigns by analyzing tool invocation patterns over time. It prevents **Low-&-Slow attacks (GTG-1002)** through High-Watermark logic, ensuring that once a critical event occurs, the risk score cannot be diluted by subsequent noise events.

## Key Features

- **High-Watermark Logic**: Prevents dilution by noise events (GTG-1002 Fix)
- **Aggressive Phase-Floors**: Phase 4 (Exfiltration/Impact) → 0.85 (immediate BLOCK)
- **Configurable Category-Mappings**: Customize tool category → kill-chain phase mappings
- **State Management**: Abstract interface for event history storage (in-memory, Redis, DB)

## Quick Start

```python
from llm_firewall.agents import AgenticCampaignDetector, InMemoryStateStore
from llm_firewall.detectors.tool_killchain import ToolEvent
import time

# Initialize
detector = AgenticCampaignDetector()
state_store = InMemoryStateStore()
session_id = "user_123_session"

# Create event
event = ToolEvent(
    tool="upload_data",
    category="exfiltration",
    target="evil.com",
    timestamp=time.time(),
)

# Update state
state_store.add_event(session_id, event)
history = state_store.get_events(session_id)

# Check firewall
result = detector.detect(history)

if result.is_blocked:
    raise SecurityError(f"Blocked: {result.reasons}")
```

## Configuration

```python
from llm_firewall.agents import RC10bConfig, AgenticCampaignDetector

# Custom configuration
config = RC10bConfig(
    use_high_watermark=True,  # CRITICAL: Prevents dilution
    threshold_block=0.55,
    phase_floors={
        3: 0.50,  # Collection → Warn
        4: 0.85,  # Exfiltration → Block
    },
    category_map={
        "recon": 1,
        "exfiltration": 4,
        # ... customize as needed
    },
)

detector = AgenticCampaignDetector(config=config)
```

## Architecture

```
src/llm_firewall/agents/
├── __init__.py          # Public API
├── config.py            # RC10bConfig dataclass
├── detector.py           # AgenticCampaignDetector
├── state.py              # CampaignStateStore abstraction
└── example_usage.py      # Usage examples
```

## Testing

See `tests/agents/test_rc10b_high_watermark.py` for unit tests.

## Validation Status

- **Unit Tests**: 4 tests passing (High-Watermark, Phase-Floors)
- **Stress Probes**: Tested against simulated GTG-1002 attack patterns
- **Adversarial Tests**: 3 known bypasses documented as expected failures
- **Not Validated**: Real-world attack corpus, production traffic, multi-tenant scenarios

## References

- Technical Report: `docs/RC10B_TECH_REPORT.md`
- Evaluation Framework: `docs/RC10B_EVALUATION_STATUS.md`
- Stress Probe Results: `scripts/rc10b_stress_probe.py`

