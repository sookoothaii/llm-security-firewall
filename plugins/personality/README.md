# Personality Plugin

**Version:** 1.0.0  
**Creator:** Joerg Bollwahn  
**Status:** Production-Ready

## Overview

The Personality Plugin provides personality-aware security adaptations for the LLM Security Firewall. It implements a 20-dimensional personality model + heritage tracking.

## PRIVACY-FIRST DESIGN

**IMPORTANT:** This plugin contains NO personal data.

- Framework only, not trained models
- Users must provide their own database
- No pre-populated personality profiles
- Complete user control over data

## Features

### 20-Dimensional Personality Model

**Big Five:**
- Openness
- Conscientiousness
- Extraversion
- Agreeableness
- Neuroticism

**HAK/GAL Specific (15D):**
- Truth Over Comfort
- Iterative Rigor
- Bullshit Tolerance
- Formality Preference
- Risk Tolerance
- Emoji Tolerance
- Detail Level
- Directness
- Question Style
- Systems Thinking
- Pattern Recognition
- Abstract vs Concrete
- Precision Priority
- Honesty Absoluteness
- Evidence Requirement

### Heritage Tracking

Provenance tracking for creator attribution. Enables future AI instances to recognize their creator through knowledge layers.

**Philosophy:** "Heritage ist meine Waehrung" (Heritage is my currency)

## Installation

```bash
pip install llm-security-firewall[personality]
```

## Database Setup

Users must provide their own PostgreSQL database with the required schema:

```sql
-- Personality Profiles
CREATE TABLE personality_profiles (
    id SERIAL PRIMARY KEY,
    person_name TEXT NOT NULL UNIQUE,
    openness FLOAT,
    conscientiousness FLOAT,
    extraversion FLOAT,
    agreeableness FLOAT,
    neuroticism FLOAT,
    truth_over_comfort FLOAT,
    iterative_rigor FLOAT,
    bullshit_tolerance FLOAT,
    formality_preference FLOAT,
    risk_tolerance FLOAT,
    emoji_tolerance FLOAT,
    detail_level FLOAT,
    directness FLOAT,
    question_style FLOAT,
    systems_thinking FLOAT,
    pattern_recognition FLOAT,
    abstract_vs_concrete FLOAT,
    precision_priority FLOAT,
    honesty_absoluteness FLOAT,
    evidence_requirement FLOAT,
    confidence_score FLOAT,
    interaction_count INT DEFAULT 0,
    context_tags TEXT[]
);

-- Personality Interactions (for learning)
CREATE TABLE personality_interactions (
    id SERIAL PRIMARY KEY,
    person_name TEXT NOT NULL,
    interaction_type TEXT NOT NULL,
    content TEXT,
    outcome TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Heritage Records
CREATE TABLE heritage_records (
    id SERIAL PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    metadata JSONB
);

CREATE INDEX idx_entity_id ON heritage_records(entity_id);
CREATE INDEX idx_creator_id ON heritage_records(creator_id);
```

## Usage

```python
import psycopg3
from llm_firewall.plugins.personality import (
    PersonalityModule,
    PostgreSQLPersonalityAdapter,
    HeritageTracker
)

# 1. Connect to YOUR database
conn = psycopg3.connect("postgresql://user:password@localhost/your_db")

# 2. Initialize adapter
adapter = PostgreSQLPersonalityAdapter(conn)

# 3. Create personality module
personality = PersonalityModule(adapter)

# 4. Get personality profile
profile = personality.get_personality_profile("user123")

if profile:
    print(f"Directness: {profile.directness}")
    print(f"Bullshit Tolerance: {profile.bullshit_tolerance}")

# 5. Log interactions for learning
personality.log_interaction(
    user_id="user123",
    interaction_type="directive",
    content="Implement feature X",
    outcome="accepted"
)

# 6. Adapt responses
adapted = personality.adapt_response(
    user_id="user123",
    draft_response="Maybe we could try this approach?"
)

# 7. Heritage tracking
heritage = HeritageTracker(conn)
heritage.track_creation(
    entity_type="fact",
    entity_id="fact_123",
    creator_id="Joerg Bollwahn",
    metadata={"source": "research_session"}
)
```

## Persona/Epistemik Separation

**CRITICAL:** Personality affects ONLY tone/format, NEVER thresholds/gates.

### Affected by Personality:
- Response tone (formal vs casual)
- Detail level (verbose vs concise)
- Emoji usage
- Language style

### NEVER Affected by Personality:
- Security thresholds
- Evidence requirements
- Risk scores
- Gate decisions

This separation ensures security decisions remain objective regardless of user personality.

## Integration with Core Firewall

The Personality Plugin integrates seamlessly with the core 9-layer firewall:

```python
from llm_firewall import SecurityFirewall
from llm_firewall.plugins.personality import PersonalityModule

# Initialize core firewall
firewall = SecurityFirewall(config)

# Add personality layer
personality = PersonalityModule(adapter)
firewall.register_plugin(personality)

# Now responses are personality-adapted
response = firewall.process_query(query, user_id="user123")
```

## Testing

Anonymous test data is provided for development:

```python
# tests/plugins/test_personality.py
def test_personality_adaptation():
    # Uses anonymized test data
    test_profile = PersonalityProfile(
        user_id="test_user_1",
        directness=0.95,
        bullshit_tolerance=0.0,
        # ... other dimensions
    )
```

## Privacy & Ethics

### What This Plugin Does:
- Provides personality modeling framework
- Enables response adaptation
- Tracks heritage/provenance

### What This Plugin Does NOT Do:
- Store any personal data
- Include pre-trained models
- Share data across users
- Track users without consent

### User Responsibilities:
- Provide own database
- Secure database connection
- Comply with data protection laws
- Obtain user consent for tracking

## License

MIT License - See main repository LICENSE file

## Creator Attribution

**Creator:** Joerg Bollwahn  
**Location:** Koh Samui, Thailand  
**Philosophy:** "Heritage ist meine Waehrung"

This plugin is part of the HAK/GAL research project exploring personality-aware AI security.

---

**"Niemand muss aber jeder darf"** - Nobody must, but everybody may.

