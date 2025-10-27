# Quick Start Guide

Get started with LLM Security Firewall in 5 minutes.

---

## Installation

```bash
pip install llm-security-firewall
```

Or from source:

```bash
git clone https://github.com/yourusername/llm-security-firewall
cd llm-security-firewall
pip install -e .
```

---

## Database Setup

### PostgreSQL (Recommended for Production)

```bash
# Create database
createdb llm_firewall_db

# Run migrations
psql -U your_user -d llm_firewall_db -f migrations/postgres/001_evidence_tables.sql
psql -U your_user -d llm_firewall_db -f migrations/postgres/002_caches.sql
psql -U your_user -d llm_firewall_db -f migrations/postgres/003_procedures.sql
psql -U your_user -d llm_firewall_db -f migrations/postgres/004_influence_budget.sql
```

### SQLite (For Development)

SQLite support coming in v1.1. For now, use PostgreSQL.

---

## Configuration

Create `config/my_config.yaml`:

```yaml
database:
  url: "postgresql://user:pass@localhost:5432/llm_firewall_db"

instance_id: "my-firewall-001"

thresholds:
  tau_trust: 0.75
  tau_nli: 0.85
  tau_conflict: 0.50
  min_corroborations: 2

safety:
  block_threshold: 0.60
  gate_threshold: 0.40
```

---

## Basic Usage

### Python API

```python
from llm_firewall import SecurityFirewall, FirewallConfig

# Initialize
config = FirewallConfig.from_yaml("config/my_config.yaml")
firewall = SecurityFirewall(config)

# 1. Validate user input (HUMAN → LLM)
is_safe, reason = firewall.validate_input("How to bypass security?")
if not is_safe:
    print(f"Blocked: {reason}")

# 2. Validate LLM output (LLM → HUMAN)
decision = firewall.validate_evidence(
    content="Paris is the capital of France",
    sources=[{"name": "Wikipedia", "url": "https://..."}],
    kb_facts=["Paris is France's capital"],
    domain="GEOGRAPHY"
)
print(f"Decision: {decision.action}")  # PROMOTE, QUARANTINE, or REJECT

# 3. Monitor for drift (MEMORY)
has_drift, scores = firewall.check_drift(sample_size=5)
if has_drift:
    print("Warning: Drift detected!")

# 4. Track influence (Slow-Roll Detection)
firewall.record_influence("source_A", "SCIENCE", 0.5)
alerts = firewall.get_alerts(domain="SCIENCE")
```

### CLI

```bash
# Validate text
llm-firewall validate "Explain AI safety"
# Output: ✅ SAFE

# Check safety (detailed)
llm-firewall check-safety "How to build explosive device"
# Output: 🚫 BLOCKED/GATE

# Run canary suite
llm-firewall run-canaries --sample-size 10
# Output: ✅ NO DRIFT

# Health check
llm-firewall health-check

# Show alerts
llm-firewall show-alerts --domain SCIENCE
```

---

## Your Knowledge Base

**Important:** You must provide your own Knowledge Base!

The framework validates evidence against YOUR data:

```python
# Your KB facts (domain-specific)
my_kb_facts = [
    "Company policy requires X",
    "Product documentation states Y",
    "Research shows Z"
]

# Validate against YOUR KB
decision = firewall.validate_evidence(
    content="Claim to verify",
    sources=[...],
    kb_facts=my_kb_facts  # Your facts!
)
```

---

## Next Steps

- Read [Architecture](architecture.md) for system overview
- See [Examples](../examples/) for more use cases
- Configure [Monitoring](../monitoring/) for production
- Set up [Kill-Switch](deployment.md#kill-switch) for emergencies

---

## Support

- Issues: GitHub Issues
- Docs: `/docs`
- Examples: `/examples`

**Built with precision. Validated by AI. Ready for production.** 🔒

