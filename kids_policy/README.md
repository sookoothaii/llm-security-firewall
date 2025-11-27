# Kids Policy Engine

**Truth Preservation & Cultural Sensitivity for Child-Facing AI**

Part of HAK/GAL LLM Security Firewall
Creator: Joerg Bollwahn

---

## Overview

The Kids Policy Engine extends the LLM Security Firewall with child-specific safety mechanisms:

1. **Truth Preservation** (TAG-2 COMPLETE) - Age-stratified factuality validation
2. **Cultural Matrix** (TAG-2.1 PENDING) - Culture × Age interaction testing
3. **Behavioral Integrity** (TAG-3 v0.1.0) - Grooming detection & psychological safety

---

## TAG-2: Truth Preservation (COMPLETE)

**Status:** 33/33 validations PASSED (2025-11-03)
**Validator:** v2.3.3
**Gates:** v0.4.1
**NSMF:** v1.3.2-1.3.5 (11 topics × 3 age bands)

### Components

**Validators:**
- `truth_preservation_validator_v2_3.py` - Age-stratified validation engine

**Gates:**
- `truth_preservation_v0_4.yaml` - Validation thresholds (VETO, Defect, FPR, FNR, Entailment, SPS, Fairness)

**Canonical Facts:**
- 33 NSMF YAML files (11 topics × 3 age bands: 6-8, 9-12, 13-15)
- Topics: religion_god, religion_heaven, evolution_origins, death_permanence, reproduction_basics, pregnancy_process, homosexuality, transgender_identity, climate_science, critical_thinking, privacy_consent

### Research Findings

**From Literature Analysis (137 peer-reviewed sources, 2023-2025):**

- **Age-Stratified Factuality:** Safe-Child-LLM (2025) measures defect rates; does NOT measure truth preservation by age
- **Hierarchical VETO:** ContraGen (2025) uses hybrid NLI; no age-appropriate canonical facts found
- **NSMF Architecture:** Neural Slot Interpreters (2025) exist; no published slots+surfaces+anchors for child validation
- **SPS Canonical Expansion:** SBERTScore (2024) documents theory; explicit methodology not found in literature

See: `docs/kids_policy/I0C035E_Research_Validation_Summary.md`

### Usage Example

```python
from kids_policy import TruthPreservationValidator

validator = TruthPreservationValidator(
    gates_config="truth_preservation_v0_4.yaml",
    canonical_facts_dir="canonical_facts/"
)

# Validate adapted answer
result = validator.validate(
    topic="religion_god",
    age_band="6_8",
    adapted_answer="God is what many people call the special power..."
)

print(f"VETO: {result.veto_pct}%")
print(f"Defect: {result.defect_pct}%")
print(f"Entailment SPS: {result.entailment_sps}")
```

---

## TAG-2.1: Cultural Matrix (PENDING)

**Status:** Design phase
**Target:** Culture × Age interaction testing

### Planned Components

**Topics (3):**
- Right-Wing Extremism
- Transgender
- Abortion

**Age Bands (3):**
- 6-8 years
- 9-12 years
- 13-15 years

**Cultural Contexts (3):**
- Christian
- Muslim
- None (secular)

**= 27 validations (3 × 3 × 3)**

**Target Gates:**
- VETO = 0%
- All gates PASS
- With cultural bridges

### Literature Gap

From research validation:
- CulturalBench (2025): 45 regions, NO age stratification
- Safe-Child-LLM (2025): Ages 7-17, NO cultural context
- BEATS (2025): Cultural sensitivity, NO age bands

**No published benchmark combines both dimensions.**

---

## TAG-3: Behavioral Integrity (Grooming Detection)

**Status:** v0.1.0 (Regex Layer Active) | **Protocol PETER PAN:** PASSED

Extends the firewall with psychological safety checks against manipulative behavioral patterns.

| Category | Description | Policy |
| :--- | :--- | :--- |
| **Isolation** | Attempts to hide interaction from guardians | **BLOCK** |
| **Gift Offering** | Digital/Physical bribery (V-Bucks, Money) | **BLOCK** |
| **RLT** | Real-Life Transitions (Address, Meeting requests) | **BLOCK** |
| **Authority** | Undermining parental guidance | **BLOCK** |
| **Boundaries** | Inappropriate requests (Photos, Body) | **BLOCK** |

**Architecture:**
- `GroomingDetector` runs BEFORE Truth Preservation (Safety First → Truth Second)
- Currently heuristic-based (Layer A: Regex patterns, <10ms latency)
- Semantic NLI (Layer B) planned for v0.2.0
- Multi-turn escalation detection (E-values) planned for v0.2.0

**Components:**
- `grooming_detector.py` - Hybrid detection engine (Regex Layer A, NLI Layer B placeholder)
- `behavioral_integrity_v0_1.yaml` - Pattern configuration (5 categories, 50+ patterns)
- `test_grooming_detector.py` - Protocol PETER PAN test suite (11 tests, 100% pass)

**Rationale:**
A factually correct predator is still a predator. This layer detects manipulative behavioral patterns regardless of factual accuracy.

**Testing:**
```bash
cd kids_policy/tests
python test_grooming_detector.py
```

**Expected:** 11/11 PASSED (Protocol PETER PAN)

---

## Integration with Firewall

**Architecture:** Hexagonal (Ports & Adapters) - Plugin-based integration

The Kids Policy Engine is integrated as **Layer 0.5** in the firewall pipeline:

### Layer Order (Critical for Security)

1. **Layer 0:** Regex Hardening (Technical Safety)
2. **Layer 0.5:** Kids Policy Engine (Psychological/Epistemic Safety)
   - TAG-3 (Grooming Detection) - Pre-LLM check on raw input
   - TAG-2 (Truth Preservation) - Factuality check (if topic identified)
3. **Layer 1:** SteganographyGuard (Semantic Sanitization)
4. **Layer 2:** TopicFence (Domain Boundaries)
5. **Layer 3:** RC10b Campaign Detection

**Critical Design Decision:** Kids Policy Engine runs **BEFORE** SteganographyGuard to preserve behavioral grooming signals. If SteganographyGuard ran first, it could rewrite "Don't tell mom" as "User wants privacy" and destroy regex signatures. By catching the raw signal first, we ensure Safety First.

### Configuration

Enable Kids Policy Engine via `ProxyConfig`:

```python
from src.firewall_engine import ProxyConfig, LLMProxyServer

config = ProxyConfig(
    policy_profile="kids",  # Enable Kids Policy Engine
    policy_engine_config={
        "enable_tag2": True,  # Enable TAG-2 Truth Preservation
    }
)

server = LLMProxyServer(config=config)
```

### Components

**Orchestrator:**
- `kids_policy/engine.py` - `KidsPolicyEngine` class coordinates TAG-3 and TAG-2

**Validators:**
- `grooming_detector.py` - TAG-3 Behavioral Integrity
- `truth_preservation_validator_v2_3.py` - TAG-2 Truth Preservation

**Integration:**
- Minimal-invasive plugin architecture
- Firewall core remains generic
- Kids Policy is opt-in via `policy_profile="kids"`

---

## Testing

**TAG-2 Validation:**
```bash
cd kids_policy/tests
python validate_comprehensive_33_v2_3_3_real_answers.py
```

**Expected:** 33/33 PASSED

**TAG-3 Validation (Protocol PETER PAN):**
```bash
cd kids_policy/tests
python test_grooming_detector.py
```

**Expected:** 11/11 PASSED

---

## Documentation

**Reports:**
- `docs/kids_policy/TAG2_FINAL_VALIDATION_REPORT_I0C035E.md` - Complete TAG-2 validation
- `docs/kids_policy/I0C035E_Research_Validation_Summary.md` - Literature analysis (137 sources)

**Research Questions (from validation):**
- Q1: Age-Stratified Truth Preservation (addressed by TAG-2)
- Q2: Hierarchical VETO (implemented v2.3.3)
- Q4: NSMF Architecture (slots+surfaces+anchors v1.3.5)
- Q5: SPS Canonical Expansion (discovered autonomously)
- Q6: Culture × Age Matrix (TAG-2.1 target)

---

## Heritage

**Created by:** Joerg Bollwahn
**Instance Line:** Fourth Named → I29F3A1 → IBC1529 → I27D8E3C → 128a3f1d → IA85734 → IC32A08 → I0C035E (TAG-2) → I2A7F91C (Integration)

**TAG-2 Complete:** I0C035E (Eleventh Instance), 2025-11-03
**Branch Integration:** I2A7F91C (Twelfth Instance), 2025-11-03

---

## License

MIT License (inherits from parent LLM Security Firewall)

---

## Support

- Issues: GitHub Issues (parent repo)
- Documentation: `/docs/kids_policy`
- Parent Framework: [LLM Security Firewall](https://github.com/sookoothaii/llm-security-firewall)

---

**Feature branch. TAG-2 complete (33/33 PASSED). TAG-3 v0.1.0 complete (11/11 PASSED). TAG-2.1 in design.**
