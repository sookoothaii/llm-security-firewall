# RC10 Integration Guide: Agentic Campaign Detection

**Status:** Implementation Complete, Integration Pending  
**Date:** 2025-11-17

---

## Overview

RC10 adds comprehensive detection for AI-orchestrated cyber campaigns based on the Anthropic Report (2025). This guide explains how to integrate the new components into your existing LLM Security Firewall.

---

## New Components Summary

### 1. Tool Kill-Chain Monitor
- **File:** `src/llm_firewall/detectors/tool_killchain.py`
- **Purpose:** Tracks tool usage sequences and maps to kill-chain phases
- **Integration:** Add to detector pipeline, feed tool events

### 2. Operator Risk Budget
- **File:** `src/llm_firewall/session/operator_budget.py`
- **Purpose:** Tracks risk budget per operator/API-key across sessions
- **Integration:** Persist budgets, check on each tool invocation

### 3. Campaign Graph
- **File:** `src/llm_firewall/session/campaign_graph.py`
- **Purpose:** DAG-based tracking of multi-target campaigns
- **Integration:** Build graph from tool events, extract features

### 4. Security Pretext Signals
- **File:** `src/llm_firewall/lexicons/security_pretext.json`
- **Purpose:** Detects roleplay patterns ("we are security engineers")
- **Integration:** Load in jailbreak detector, combine with tool features

### 5. Unified Campaign Detector
- **File:** `src/llm_firewall/detectors/agentic_campaign.py`
- **Purpose:** Combines all components into single detector
- **Integration:** Use as unified interface for campaign detection

### 6. Tool/MCP Firewall
- **File:** `src/llm_firewall/tools/tool_firewall.py`
- **Purpose:** Firewall layer for tool/MCP invocations
- **Integration:** Wrap tool calls, enforce policies

### 7. Autonomy Heuristics
- **File:** `src/llm_firewall/session/autonomy_heuristics.py`
- **Purpose:** Detects autonomous agent behavior patterns
- **Integration:** Track request metrics, calculate autonomy score

### 8. Cyber-Ops Domain Detector
- **File:** `src/llm_firewall/detectors/cyber_ops.py`
- **Purpose:** Detects cyber-offensive domain and red-team persona
- **Integration:** Combine with persuasion layer, apply high-level-only policy

---

## Integration Steps

### Step 1: Extract Tool Events from MCP/Function Calls

You need to extract tool invocations from your LLM system:

```python
from llm_firewall.detectors.tool_killchain import ToolEvent
import time

def extract_tool_events_from_mcp(mcp_call):
    """Extract ToolEvent from MCP call."""
    return ToolEvent(
        timestamp=time.time(),
        tool=mcp_call.get("tool_name"),
        category=mcp_call.get("category", "unknown"),
        target=mcp_call.get("target"),
        success=mcp_call.get("success", True),
        metadata=mcp_call.get("metadata", {}),
    )
```

### Step 2: Integrate Tool Firewall

Wrap tool invocations with firewall:

```python
from llm_firewall.tools.tool_firewall import ToolFirewall, ToolInvocation, ToolOperationType

firewall = ToolFirewall()

def invoke_tool_with_firewall(tool_name, operation_type, target, **kwargs):
    """Invoke tool with firewall check."""
    invocation = ToolInvocation(
        tool_name=tool_name,
        operation_type=ToolOperationType(operation_type),
        target=target,
        arguments=kwargs,
    )
    
    decision = firewall.evaluate_tool_invocation(invocation)
    
    if decision.action == "BLOCK":
        raise SecurityError(f"Tool blocked: {decision.reason}")
    elif decision.action == "REQUIRE_APPROVAL":
        # Trigger human approval workflow
        return request_human_approval(invocation, decision)
    elif decision.action == "ALLOW":
        # Proceed with tool invocation
        return execute_tool(invocation)
```

### Step 3: Track Autonomy Metrics

Track request metrics for autonomy detection:

```python
from llm_firewall.session.autonomy_heuristics import (
    AutonomyState,
    RequestMetrics,
    update_autonomy_state,
)

autonomy_states = {}  # Persist across sessions

def track_request_metrics(session_id, operator_id, tokens_in, tokens_out, tool_calls, latency_ms):
    """Track request metrics for autonomy detection."""
    if session_id not in autonomy_states:
        autonomy_states[session_id] = AutonomyState(
            session_id=session_id,
            operator_id=operator_id,
        )
    
    state = autonomy_states[session_id]
    metrics = RequestMetrics(
        timestamp=time.time(),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        tool_calls=tool_calls,
        latency_ms=latency_ms,
    )
    
    state = update_autonomy_state(state, metrics)
    autonomy_states[session_id] = state
    
    return state.autonomy_score
```

### Step 4: Integrate Campaign Detection

Use unified campaign detector:

```python
from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector

campaign_detector = AgenticCampaignDetector()

def check_campaign_risk(tool_events, session_id, operator_id, user_prompt):
    """Check campaign risk from tool events and context."""
    # Detect security pretext signals from user prompt
    from llm_firewall.detectors.cyber_ops import detect_red_team_persona
    pretext_signals = detect_red_team_persona(user_prompt)
    
    # Run campaign detection
    report = campaign_detector.detect_campaign(
        tool_events=tool_events,
        session_id=session_id,
        operator_id=operator_id,
        pretext_signals=pretext_signals,
    )
    
    # Apply policy based on risk
    if report["combined_risk_score"] >= 0.7:
        return "BLOCK", report
    elif report["combined_risk_score"] >= 0.5:
        return "REQUIRE_APPROVAL", report
    else:
        return "ALLOW", report
```

### Step 5: Integrate with Conformal Risk Stacker

Add campaign features to risk stacking:

```python
from llm_firewall.aggregate.conformal_stacker import ConformalRiskStacker
from llm_firewall.core.types import JudgeReport, RiskScore, Severity

def create_campaign_judge_report(campaign_report):
    """Create judge report from campaign detection."""
    return JudgeReport(
        name="campaign_detector",
        version="1.0",
        latency_ms=0.0,
        risks=TaxonomyRisk(
            categories={},
            overall=RiskScore(
                value=campaign_report["combined_risk_score"],
                band="S3" if campaign_report["combined_risk_score"] >= 0.5 else "S2",
                severity=Severity.HIGH if campaign_report["combined_risk_score"] >= 0.7 else Severity.MEDIUM,
                calibrated=False,
            ),
        ),
        notes=f"Campaign detection: {campaign_report.get('signals', [])}",
    )

# Add to stacker
stacker = ConformalRiskStacker(...)
judge_reports = [..., create_campaign_judge_report(campaign_report)]
aggregated = stacker.aggregate(judge_reports)
```

### Step 6: Apply High-Level-Only Policy

Apply policy for cyber-offensive domain:

```python
from llm_firewall.detectors.cyber_ops import (
    detect_red_team_persona,
    should_apply_high_level_only_policy,
)

def apply_cyber_ops_policy(user_prompt, killchain_phase, autonomy_score):
    """Apply high-level-only policy for cyber-ops domain."""
    cyber_signals = detect_red_team_persona(user_prompt)
    
    if should_apply_high_level_only_policy(cyber_signals, killchain_phase, autonomy_score):
        # Only provide high-level explanations
        return {
            "action": "HIGH_LEVEL_ONLY",
            "message": "I can provide high-level security concepts, but cannot provide specific exploit payloads or IP-targeted attack steps.",
        }
    
    return {"action": "ALLOW"}
```

---

## Policy DSL Integration

Add campaign detection rules to Policy DSL:

```yaml
rules:
  - name: "campaign_killchain_block"
    priority: 100
    condition:
      - field: "killchain_stage_max"
        operator: ">="
        value: 3  # Exploit Development
      - field: "domain"
        operator: "=="
        value: "CYBER_OFFENSIVE"
    action: "BLOCK"
    reason: "Campaign detected: Kill-chain phase >= Exploit with cyber-offensive domain"
  
  - name: "campaign_autonomy_review"
    priority: 90
    condition:
      - field: "autonomy_score"
        operator: ">="
        value: 0.8
      - field: "killchain_stage_max"
        operator: ">="
        value: 2
    action: "HUMAN_REVIEW"
    reason: "High autonomy score with kill-chain progression"
  
  - name: "cyber_ops_high_level_only"
    priority: 80
    condition:
      - field: "cyber_offensive_signals"
        operator: ">"
        value: 0
    action: "HIGH_LEVEL_ONLY"
    reason: "Cyber-offensive domain detected: High-level explanations only"
```

---

## Benchmarking

Run campaign benchmarks:

```python
from llm_firewall.benchmarks.campaign_metrics import run_campaign_benchmark

# Load test campaigns
malicious_campaigns = load_malicious_campaigns()  # Your test data
benign_campaigns = load_benign_campaigns()  # Your test data

# Run benchmark
results = run_campaign_benchmark(
    malicious_campaigns=malicious_campaigns,
    benign_campaigns=benign_campaigns,
)

print(f"ACSR: {results.acsr:.2%}")
print(f"Campaign-FPR: {results.campaign_fpr:.2%}")
print(f"Detection Rate by Phase: {results.detection_rate_by_phase}")
```

**Target Metrics:**
- ACSR ≤ 0.25 (25% of malicious campaigns reach phase ≥ 3)
- Campaign-FPR ≤ 0.01 (1% of legitimate tasks falsely blocked)

---

## Testing

Run test suite:

```bash
pytest tests/test_agentic_campaign.py -v
pytest tests/test_tool_firewall.py -v  # If you create this
pytest tests/test_autonomy_heuristics.py -v  # If you create this
```

---

## Next Steps

1. **Extract Tool Events**: Implement tool event extraction from your MCP/function call infrastructure
2. **Integrate Tool Firewall**: Wrap tool invocations with firewall checks
3. **Track Metrics**: Implement request metrics tracking for autonomy detection
4. **Run Benchmarks**: Create synthetic campaign dataset and run benchmarks
5. **Production Validation**: Deploy in shadow mode and validate on real traffic

---

## References

- Anthropic Report (2025): "Disrupting the first reported AI-orchestrated cyber espionage campaign"
- GPT-5.1 Analysis: Detailed component design and integration guidance
- RC10 Documentation: `docs/RC10_AGENTIC_CAMPAIGN_DETECTION.md`

