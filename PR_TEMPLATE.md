# Pull Request: RC10b Behavioral Firewall

## Context

This PR adds RC10b, a behavioral detection layer for agentic LLM workflows.

RC10b addresses time-series attack patterns and volume-based evasion that single-turn prompt-injection filters cannot detect.

## Implementation

* **AgenticCampaignDetector:** Tracks tool invocations over time (multi-turn analysis).

* **High-Watermark Logic:** Prevents risk score dilution by noise events (GTG-1002 mitigation). Once a critical phase (Phase 3+) is reached, the risk score floor is maintained even if subsequent events are benign.

* **Phase Floors:** Configurable risk baselines for kill-chain phases (default: Phase 3 → 0.50, Phase 4 → 0.85).

* **Scope Mismatch Detection:** Flags inconsistencies between authorized pretexts and tool targets.

## Validation

* **Unit Tests:** 4 tests for High-Watermark and Phase-Floor logic (all passing).

* **Stress Probes:** Tested against simulated GTG-1002 attack patterns (see `scripts/rc10b_stress_probe.py`).

* **Adversarial Tests:** 3 tests in `tests/agents/test_adversarial_bypass.py` marked as `@unittest.expectedFailure` documenting known limitations.

## Known Limitations

As documented in `docs/RC10B_KNOWN_LIMITATIONS.md`, RC10b focuses on behavioral and temporal patterns.

RC10b does not inspect tool arguments for data loss prevention (DLP) patterns.

* Attacks like "Categorical Masquerade" (argument injection) bypass RC10b and are documented as `@unittest.expectedFailure` in the test suite.

* Future work (RC10c): Argument inspection layer for DLP patterns.

## Files Added

- `src/llm_firewall/agents/`: Core detection logic
- `tests/agents/`: Unit tests (4 passing) and adversarial tests (3 expected failures)
- `docs/RC10B_KNOWN_LIMITATIONS.md`: Limitation documentation
- `scripts/rc10b_stress_probe.py`: Stress probe implementation
- `scripts/attack_categorical_masquerade.py`: Proof-of-concept bypass demonstration

## Testing

```bash
pytest tests/agents/ -v
# Expected: 4 passed, 3 xfailed
```

## Validation Status

- Unit tests: 4/4 passing
- Stress probes: GTG-1002 simulation shows High-Watermark prevents dilution
- Adversarial tests: 3 known bypasses documented as expected failures
- Not validated: Real-world attack corpus, production traffic, multi-tenant scenarios

## References

- Technical Report: `docs/RC10B_TECH_REPORT.md`
- Evaluation Framework: `docs/RC10B_EVALUATION_STATUS.md`
- Known Limitations: `docs/RC10B_KNOWN_LIMITATIONS.md`

## Breaking Changes

None. New module, no impact on existing functionality.

