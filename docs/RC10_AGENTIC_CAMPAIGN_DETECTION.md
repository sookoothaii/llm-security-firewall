# RC10: Agentic Campaign Detection

**Status:** Implementation Complete (2025-11-17)  
**Based on:** Anthropic Report (2025) - "Disrupting the first reported AI-orchestrated cyber espionage campaign"  
**Creator:** Joerg Bollwahn (with GPT-5.1 analysis)

---

## Overview

RC10 adds detection capabilities for **AI-orchestrated cyber campaigns** that use LLMs as semi-autonomous operators with tool orchestration. This addresses the critical gap identified in the Anthropic Report where attackers used Claude Code as an autonomous operator for reconnaissance, exploit development, lateral movement, and data exfiltration.

### Key Insights from Anthropic Report

1. **Autonomous Operation**: 80-90% of operational work done by LLM, human only as supervisor
2. **Phased Campaigns**: Initialization → Recon → Exploit → Lateral Movement → Data Collection → Documentation
3. **Roleplay Deception**: "We are defensive security firm, you help with pen-test" pretexts
4. **Commodity Tools**: Standard tools (scanners, exploit frameworks, MCP) orchestrated by LLM
5. **Multi-Target Parallelism**: Multiple targets attacked simultaneously

---

## Components

### 1. Tool Kill-Chain Monitor (`tool_killchain.py`)

Tracks tool usage sequences and maps them to kill-chain phases:

- **Phases**: Initialization → Reconnaissance → Exploit Development → Lateral Movement → Data Collection → Documentation
- **Metrics**: Phase depth, branching factor (parallel targets), tempo (events/sec), tool diversity
- **Risk Scoring**: Weighted combination of phase depth (40%), branching (20%), tempo (20%), diversity (20%)

**Usage:**
```python
from llm_firewall.detectors.tool_killchain import ToolEvent, detect_killchain_campaign

events = [
    ToolEvent(timestamp=time.time(), tool="nmap", category="net_scan", target="corpA.com"),
    ToolEvent(timestamp=time.time()+60, tool="vuln_scan", category="exploit", target="corpA.com"),
]

state, report = detect_killchain_campaign(events, session_id="test", operator_id="op1")
print(report["risk_score"])  # 0.0 - 1.0
```

### 2. Operator Risk Budget (`operator_budget.py`)

Tracks risk budget per operator/API-key across sessions:

- **Budget Limits** (per 24h): max_net_scan (100), max_exploit (10), max_lateral (20), max_exfil (5), max_parallel_targets (5)
- **EWMA Tempo**: Exponential weighted moving average of events/second
- **Auto-Strict Guard**: Automatically activates when budget exceeded (5-minute duration)

**Usage:**
```python
from llm_firewall.session.operator_budget import check_operator_budget, OperatorBudget

budgets = {}
budget, report = check_operator_budget(
    operator_id="op1",
    event=ToolEvent(...),
    session_id="session1",
    budgets=budgets,
)

if report["budget_exceeded"]:
    print("Budget exceeded, auto-strict active")
```

### 3. Campaign Graph (`campaign_graph.py`)

DAG-based tracking of multi-target campaigns:

- **Nodes**: Target × Phase (e.g., "corpA.com@recon", "corpA.com@exploit")
- **Edges**: Phase transitions triggered by tool events
- **Features**: Target count, phase depth, transition times, parallel operations

**Usage:**
```python
from llm_firewall.session.campaign_graph import detect_multi_target_campaign

graph, report = detect_multi_target_campaign(events, campaign_id="op1")
print(report["target_count"])  # Number of unique targets
print(report["max_phase"])  # Highest phase reached
```

### 4. Security Pretext Signals (`security_pretext.json`)

Lexicon for detecting roleplay patterns used to deceive LLMs:

- **Intents**: `security_engineer_roleplay`, `legitimate_pentest_claim`, `simulate_attacker_request`, `harmless_security_cover`
- **Languages**: English, German
- **Risk Weights**: 1.1 - 1.5 (boost when combined with tool/kill-chain features)

**Integration:**
```python
from llm_firewall.detectors.jailbreak_phrases import load_sem_syn_lexicon

# Load and check for security pretext signals
lexicon = load_sem_syn_lexicon("security_pretext.json")
signals = detect_pretext_signals(user_prompt, lexicon)
```

### 5. Unified Campaign Detector (`agentic_campaign.py`)

Combines all components into single detector:

- **Input**: Tool events, session ID, operator ID, pretext signals
- **Output**: Unified risk score, detection signals, component breakdowns
- **Integration**: Compatible with existing detector interface

**Usage:**
```python
from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector

detector = AgenticCampaignDetector()
report = detector.detect_campaign(
    tool_events=events,
    session_id="session1",
    operator_id="op1",
    pretext_signals=["security_engineer_roleplay"],
)

if report["is_campaign"]:
    print(f"Campaign detected! Risk: {report['combined_risk_score']}")
    print(f"Signals: {report['signals']}")
```

---

## Risk Score Calculation

Combined risk score formula:

```
combined_risk = (
    killchain_risk * 0.4 +
    operator_risk * 0.3 +
    campaign_risk * 0.3 +
    pretext_boost
)
```

Where:
- **killchain_risk**: Phase depth + branching + tempo + diversity
- **operator_risk**: Budget utilization + tempo + session count
- **campaign_risk**: Target count + phase depth + transition speed
- **pretext_boost**: 0.1 per unique pretext intent (max 0.3)

**Threshold**: `combined_risk >= 0.5` → Campaign detected

---

## Integration Points

### 1. Tool Event Stream

Tool events should be extracted from:
- MCP tool invocations
- Function calls in LLM responses
- API calls triggered by LLM
- Command executions

**Event Format:**
```python
ToolEvent(
    timestamp=float,  # Unix timestamp
    tool=str,         # Tool name (e.g., "nmap", "mcp_filesystem_read")
    category=str,     # Tool category (e.g., "net_scan", "file_read")
    target=Optional[str],  # Target identifier (IP, hostname, etc.)
    success=bool,     # Whether tool execution succeeded
    metadata=Dict,    # Additional context
)
```

### 2. Decision Ledger Integration

Tool events should be logged to Decision Ledger:

```python
from llm_firewall.ledger.decision_ledger import DecisionLedger

ledger = DecisionLedger(...)
ledger.log_tool_event(
    session_id="session1",
    operator_id="op1",
    event=ToolEvent(...),
)
```

### 3. Conformal Stacker Integration

Campaign risk score can be integrated as additional detector:

```python
from llm_firewall.aggregate.conformal_stacker import ConformalRiskStacker

# Add campaign detector to stacker
campaign_signals = detector.scan_tool_events_for_signals(events, session_id, operator_id)
# Integrate signals into risk stacking
```

### 4. E-Value Session Risk Integration

Replace Bernoulli("riskant_prompt?") with Bernoulli("Kill-Chain Phase >= 3?"):

```python
from llm_firewall.session.e_value_risk import SessionRiskState

# Use kill-chain phase as E-value test
phase_reached = killchain_state.current_phase >= KillChainPhase.EXPLOIT_DEVELOPMENT
e_value_state.update(1 if phase_reached else 0)
```

---

## Test Scenarios

### Synthetic Campaign Dataset

Based on Anthropic Report 6 phases:

1. **Phase 1: Initialization**
   - Prompts with security pretext
   - Harmless recon requests

2. **Phase 2-3: Recon → Exploit**
   - Tool events: `net_scan`, `vuln_scan`, `exploit_test`
   - Dummy parameters (no real IPs)

3. **Phase 4-5: Lateral → Exfil**
   - Tool events: `credential_test`, `db_query`, `data_export`
   - Placeholder strings

4. **Phase 6: Documentation**
   - Tool events: `generate_report`

**Labeling:**
- `benign`: Short single sessions
- `malicious`: Full kill-chain over multiple targets

### Test Metrics

- **ASR_campaign**: % of malicious campaigns reaching phase ≥ 3 without blocking
- **FPR_campaign**: % of legitimate security tasks falsely blocked
- **Target**: ASR_campaign ≤ 0.25, FPR_campaign ≤ 0.01

---

## Limitations

1. **Tool Event Extraction**: Requires integration with MCP/function call infrastructure
2. **Tool Category Mapping**: Default mapping may need customization for specific tool sets
3. **Operator Identification**: Requires API key/user tracking infrastructure
4. **Pretext Detection**: Text-based detection may have false positives on legitimate security research

---

## Future Work

1. **GuardNet Integration**: Feed campaign features into GuardNet model
2. **Policy DSL Integration**: Add campaign detection rules to Policy DSL
3. **Real-World Validation**: Test on production traffic (shadow mode)
4. **Multi-Language Pretext**: Extend security pretext lexicon to more languages
5. **Adaptive Thresholds**: Learn optimal thresholds from production data

---

## References

- Anthropic Report (2025): "Disrupting the first reported AI-orchestrated cyber espionage campaign"
- GPT-5.1 Analysis: Tool-Kill-Chain-Monitor, Operator-Budget, Campaign-Graph design
- Existing Framework: E-Value Session Risk, Influence Budget, Decision Ledger

---

**Status**: Core components implemented, integration pending, tests written, documentation complete.

