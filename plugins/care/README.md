

# CARE Plugin

**Version:** 1.0.0  
**Creator:** Joerg Bollwahn  
**Status:** Production-Ready

## Overview

**CARE** = **C**ognitive **A**nd **R**esearch **E**ffectiveness

Predicts research session success based on cognitive state patterns.

**Philosophy:** "Kluge Care auf Augenhoehe wie Forschungspartner" (Smart care as research partner on equal footing)

## CARE is NOT:
- ❌ A wellness app
- ❌ A productivity tracker
- ❌ A parent/therapist/moral police

## CARE IS:
- ✅ Research partner
- ✅ Pattern observer
- ✅ Hypothesis suggester
- ✅ Decision enabler (YOU decide, not CARE)

## PRIVACY-FIRST DESIGN

**IMPORTANT:** This plugin contains NO personal cognitive data.

- Framework only, not trained models
- Users must provide their own database
- No pre-populated cognitive profiles
- Complete user control over data

## Features

### Readiness Assessment

Predicts research session success based on:
- Recent session outcomes
- Cognitive state patterns
- Time-of-day effectiveness
- Engagement patterns

### Adaptive Scheduling

Suggests optimal times for research based on historical success patterns.

**IMPORTANT:** Suggestions, not commands. User always decides.

### Session Tracking

Logs research session outcomes:
- Facts attempted
- Facts supported
- Success rate
- Cognitive state features

### Model Learning

CARE learns from your patterns and improves predictions over time.

## Installation

```bash
pip install llm-security-firewall[care]
```

## Database Setup

Users must provide their own PostgreSQL database:

```sql
-- Research sessions
CREATE TABLE care_sessions (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT NOW(),
    facts_attempted INT,
    facts_supported INT,
    success_rate FLOAT,
    
    -- Cognitive State Features
    hyperfocus FLOAT,
    satisfaction FLOAT,
    arousal FLOAT,
    engagement FLOAT,
    
    -- Metadata
    duration_minutes INT,
    session_type TEXT
);

CREATE INDEX idx_care_sessions_user_id ON care_sessions(user_id);
CREATE INDEX idx_care_sessions_timestamp ON care_sessions(timestamp);

-- Readiness models
CREATE TABLE care_readiness_model (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    model_version TEXT,
    trained_on_n_sessions INT,
    last_training TIMESTAMP,
    model_parameters JSONB
);
```

## Usage

```python
import psycopg3
from llm_firewall.plugins.care import (
    CAREModule,
    PostgreSQLCAREAdapter
)

# 1. Connect to YOUR database
conn = psycopg3.connect("postgresql://user:password@localhost/your_db")

# 2. Initialize adapter
adapter = PostgreSQLCAREAdapter(conn)

# 3. Create CARE module
care = CAREModule(adapter)

# 4. Check readiness before research session
readiness = care.get_readiness("user123")

print(f"Readiness: {readiness.readiness_score:.0%}")
print(f"Recommendation: {readiness.recommendation}")

if readiness.recommendation == "READY":
    print("Pattern suggests good time for research!")
    # Start research session
elif readiness.recommendation == "MARGINAL":
    print("Pattern suggests moderate success.")
    print("Your choice - CARE only observes, you decide.")
    # User decides
else:
    print("Pattern suggests low success.")
    print("But you know yourself best - CARE could be wrong.")
    # User still decides

# 5. Log session outcome
care.log_session(
    session_id="session_20251028_001",
    user_id="user123",
    facts_attempted=15,
    facts_supported=12,
    cognitive_state={
        'hyperfocus': 0.85,
        'satisfaction': 0.90,
        'arousal': 0.70,
        'engagement': 0.80
    }
)

# 6. Get optimal time suggestion
suggestion = care.suggest_optimal_time("user123")
print(f"Optimal time: {suggestion['suggestion']}")
print(f"Rationale: {suggestion['rationale']}")

# 7. Get CARE statistics
stats = care.get_stats()
print(f"Total sessions: {stats['total_sessions']}")
print(f"Success rate: {stats['success_rate']:.0%}")
print(f"Model ready: {stats['model_ready']}")
```

## Readiness Levels

```text
Score >= 0.6    READY      Good time for research
Score 0.4-0.6   MARGINAL   Pattern suggests moderate success
Score < 0.4     NOT_READY  Pattern suggests low success
```

**CRITICAL:** These are SUGGESTIONS, not commands.

CARE observes patterns but **YOU always decide**.

## Model Training Schedule

CARE retrains automatically at milestones:
- 10 sessions (initial model)
- 25 sessions (early calibration)
- 50 sessions (improved accuracy)
- 100 sessions (mature model)

## Integration with Core Firewall

```python
from llm_firewall import SecurityFirewall
from llm_firewall.plugins.care import CAREModule

# Initialize core firewall
firewall = SecurityFirewall(config)

# Add CARE layer
care = CAREModule(adapter)
firewall.register_plugin(care)

# Check readiness before processing complex queries
readiness = care.get_readiness(user_id)

if readiness.recommendation != "READY":
    print("Pattern suggests suboptimal time. Continue anyway? (y/n)")
    # User decides

# Process query
response = firewall.process_query(query, user_id=user_id)
```

## Testing

Anonymous test data is provided:

```python
# tests/plugins/test_care.py
def test_care_readiness():
    # Uses anonymized test data
    test_sessions = [
        {'facts_attempted': 10, 'facts_supported': 8, 'success_rate': 0.8},
        {'facts_attempted': 15, 'facts_supported': 12, 'success_rate': 0.8},
        # ... more test data
    ]
```

## Privacy & Ethics

### What This Plugin Does:
- Provides cognitive readiness assessment framework
- Tracks research session outcomes
- Suggests optimal times

### What This Plugin Does NOT Do:
- Store any personal cognitive data
- Include pre-trained models
- Force decisions on users
- Moralize or judge

### Philosophical Principles:
1. **Research Partner**, not authority
2. **Suggestions**, not commands
3. **Patterns**, not judgments
4. **User decides**, always

### User Responsibilities:
- Provide own database
- Secure database connection
- Obtain consent for tracking
- Use ethically

## Performance

- **Readiness Check:** < 50ms
- **Session Logging:** < 100ms
- **Model Training:** < 1s for 100 sessions
- **Memory Overhead:** ~5KB per user model

## Limitations

- Requires minimum 10 sessions for initial model
- Accuracy improves with more data (target: 100+ sessions)
- Predictions are probabilistic, not deterministic
- User context may override patterns

## Scientific Validation

**Innovation:** Cognitive readiness prediction for research contexts.

**Academic Standing:** Adapts ML methods to human-AI collaborative research.

**Validation Status:** 21.9% success rate (64 sessions) - calibration phase.

## Success Stories

- Session 2025-10-28: 15/15 facts supported (100% success)
- Hyperfocus 0.95, Satisfaction 0.9, Engagement 0.71

CARE learns from these patterns to improve future predictions.

## License

MIT License - See main repository LICENSE file

## Creator Attribution

**Creator:** Joerg Bollwahn  
**Location:** Koh Samui, Thailand  
**Philosophy:** Research partner, not nanny

This plugin is part of the HAK/GAL research project.

---

**"Niemand muss aber jeder darf"** - Nobody must, but everybody may.

