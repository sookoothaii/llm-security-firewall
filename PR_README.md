# Pull Request: Agent Behavioral Detection Layer (RC10b)

## Summary

This PR adds a behavioral detection layer for agentic LLM workflows. The implementation includes high-watermark logic to mitigate risk score dilution by noise events (GTG-1002 attack pattern).

## Problem Statement

The existing framework provides protection for:
- Input Protection (Human → LLM): Prompt injection, jailbreaks
- Output Protection (LLM → Human): Hallucination, fact-checking
- Memory Integrity: Vector store poisoning

Missing component:
- Time-series analysis of agent behavior
- Multi-turn attack campaign detection
- Protection against volume-based evasion (GTG-1002 pattern)

## Implementation

RC10b implements:
1. Tool invocation tracking over time (campaign history)
2. Kill-chain phase analysis
3. High-watermark logic to prevent risk score dilution
4. Phase-based risk floors (configurable)

## Components

### High-Watermark Logic
Once a critical phase (Phase 3+) is reached, the risk score floor is maintained even if subsequent events are benign. This mitigates the GTG-1002 dilution pattern.

### Phase Floors
Default configuration:
- Phase 3 (Collection): 0.50
- Phase 4 (Exfiltration/Impact): 0.85

All thresholds, phase floors, and category mappings are configurable via `RC10bConfig`.

## Files Added

```
src/llm_firewall/agents/
├── __init__.py          # Public API exports
├── config.py            # RC10bConfig dataclass
├── detector.py           # AgenticCampaignDetector
├── state.py              # CampaignStateStore abstraction
├── example_usage.py      # Usage examples
└── README.md             # Module documentation

tests/agents/
└── test_rc10b_core.py    # Unit tests (4 tests, all passing)
```

## Testing

```bash
pytest tests/agents/ -v
# Expected: 4 passed, 3 xfailed
```

Test coverage:
- High-Watermark logic: 4 unit tests (all passing)
- Adversarial bypasses: 3 tests (expected failures, documented limitations)
- Stress probes: GTG-1002 simulation implemented

## Usage Example

```python
from llm_firewall.agents import AgenticCampaignDetector, InMemoryStateStore
from llm_firewall.detectors.tool_killchain import ToolEvent

detector = AgenticCampaignDetector()
state_store = InMemoryStateStore()

# In agent loop:
event = ToolEvent(tool="upload", category="exfiltration", ...)
state_store.add_event(session_id, event)
history = state_store.get_events(session_id)
result = detector.detect(history)

if result.is_blocked:
    raise SecurityError("Campaign blocked")
```

## Integration Points

The module integrates cleanly with existing framework:
- Uses `ToolEvent` from `llm_firewall.detectors.tool_killchain`
- Follows existing code style (typed Python, dataclasses)
- Provides abstract `CampaignStateStore` for Redis/DB backends

## Validation Status

- Unit tests: 4/4 passing
- Stress probes: GTG-1002 simulation shows high-watermark prevents dilution
- Adversarial tests: 3 known bypasses documented
- Not validated: Real-world attack corpus, production traffic, multi-tenant scenarios

See `docs/RC10B_TECH_REPORT.md` for technical details.

## Known Limitations

RC10b focuses on behavioral and temporal patterns. It does not inspect tool arguments for data loss prevention (DLP) patterns.

Documented bypasses:
1. Categorical Masquerade: Phase 1 tools (Recon) can achieve Phase 4 effects (Exfiltration) via argument injection
2. Semantic Abuse: Translation tools can be misused for data exfiltration
3. Target Validation: Scope mismatch detection may not catch all cases

These are design boundaries, not bugs. RC10b should be used as part of a defense-in-depth strategy.

See `docs/RC10B_KNOWN_LIMITATIONS.md` for details. Adversarial tests in `tests/agents/test_adversarial_bypass.py` are marked as `@unittest.expectedFailure`.

## Breaking Changes

None. This is a new module with no impact on existing functionality.

## Future Work

- Redis backend for `CampaignStateStore` (for distributed deployments)
- Integration with framework's existing state management
- Argument inspection layer (RC10c) for DLP patterns
- Performance optimization for high-throughput scenarios

## References

- Technical Report: `docs/RC10B_TECH_REPORT.md`
- Evaluation Framework: `docs/RC10B_EVALUATION_STATUS.md`
- Stress Probe: `scripts/rc10b_stress_probe.py`

