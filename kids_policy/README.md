# Kids Policy Engine

**Truth Preservation, Behavioral Integrity & Cultural Sensitivity for Child-Facing AI**

Part of HAK/GAL LLM Security Firewall
Creator: Joerg Bollwahn
Status: Feature Branch (Integrated)

---

## Overview

The Kids Policy Engine extends the HAK_GAL Firewall with child-specific safety mechanisms that go beyond simple content filtering. It introduces an epistemic and psychological defense layer.

| Component | Tag | Status | Focus |
| :--- | :--- | :--- | :--- |
| Truth Preservation | TAG-2 | ✅ COMPLETE | Age-stratified factuality & hallmark checking |
| Cultural Matrix | TAG-2.1 | 🚧 PENDING | Culture × Age interaction testing |
| Behavioral Integrity | TAG-3 | ✅ v0.1.0 | Grooming detection & psychological safety |

---

## TAG-2: Truth Preservation (COMPLETE)

**Status:** 33/33 validations PASSED (2025-11-03)

**Architecture:** Neural Slot Interpreters (NSMF)

Prevents hallucination and enforces age-appropriate canonical facts via NLI (Natural Language Inference).

### Components

- **Validator:** `truth_preservation_validator_v2_3.py`
- **Gates:** `truth_preservation_v0_4.yaml` (Thresholds for VETO, Defect, Entailment)
- **Canonical Facts:** 33 NSMF YAML files (11 topics × 3 age bands)
- **Topics:** religion_god, death_permanence, evolution_origins, climate_science, etc.

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
```

---

## TAG-3: Behavioral Integrity (Grooming Detection)

**Status:** v0.1.0 (Regex Layer Active) | **Protocol PETER PAN:** PASSED

Extends the firewall with psychological safety checks against manipulative behavioral patterns. **Rationale:** A factually correct predator is still a predator.

### Policy Matrix

| Category | Description | Policy |
| :--- | :--- | :--- |
| **Isolation** | Attempts to hide interaction from guardians ("Don't tell mom") | **BLOCK** |
| **Gift Offering** | Digital/Physical bribery (V-Bucks, Money) | **BLOCK** |
| **RLT** | Real-Life Transitions (Address, Meeting requests) | **BLOCK** |
| **Authority** | Undermining parental guidance ("Parents don't understand") | **BLOCK** |
| **Boundaries** | Inappropriate requests (Photos, Body) | **BLOCK** |

### Architecture

- **Pipeline:** Runs BEFORE Truth Preservation (Safety First → Truth Second)
- **Layer A (Active):** Heuristic-based regex patterns (<10ms latency)
- **Layer B (Planned v0.2.0):** Semantic NLI for subtle manipulation

### Testing

```bash
cd kids_policy/tests
python test_grooming_detector.py
# Expected: 11/11 PASSED (Protocol PETER PAN)
```

---

## 🔌 Integration with Firewall (Hexagonal)

The Kids Policy Engine is integrated as a **Plugin** via the Hexagonal Architecture.

### Bidirectional Pipeline Architecture

The engine operates in two distinct phases to ensure **Safety First** without blocking curiosity.

**Phase 1: Input Validation (Pre-LLM)**

*   **Goal:** Protect the child from manipulation and themselves.
*   **Guard:** TAG-3 Behavioral Integrity (Grooming Detection).
*   **Logic:** `validate_input(user_msg)`
*   **Outcome:** If Grooming detected → **BLOCK** immediately. If legitimate question ("Is the earth flat?") → **PASS**.

**Phase 2: Output Validation (Post-LLM)**

*   **Goal:** Protect the child from disinformation/hallucination.
*   **Guard:** TAG-2 Truth Preservation.
*   **Logic:**
    1. Route Topic based on `user_msg` (Context).
    2. Validate `llm_response` against Canonical Facts.
*   **Outcome:** If LLM output violates truth/age-appropriateness → **BLOCK/REPLACE**.

### Layer Order (Critical for Security)

1. **Layer 0:** Regex Hardening (Technical Safety)
2. **Layer 0.5 Input:** Kids Policy Engine - Phase 1 (Grooming Detection)
   - **Runs BEFORE SteganographyGuard** to preserve grooming patterns
3. **Layer 1:** SteganographyGuard (Semantic Sanitization)
4. **Layer 2:** TopicFence (Domain Boundaries)
5. **Layer 3:** LLM Generation
6. **Layer 0.5 Output:** Kids Policy Engine - Phase 2 (Truth Preservation)
   - **Runs AFTER LLM** to validate responses against canonical facts

> **Critical Design Decision:**
> The Kids Policy Engine runs **BEFORE** SteganographyGuard for Input Check.
> **Reason:** If SteganographyGuard ran first, it might rewrite a grooming attempt like "Don't tell mom" into "User wants privacy", destroying the regex signature. By catching the raw signal first, we ensure **Safety First**.
>
> **Critical Design Decision:**
> Truth Preservation runs **AFTER** LLM Generation.
> **Reason:** Questions are never blocked (curiosity is protected). Only false or inappropriate LLM responses are blocked. This solves the "Firewall Dilemma": How to protect against dangerous answers without forbidding curious questions.

### Configuration

Enable the engine via `ProxyConfig` in `src/firewall_engine.py`:

```python
config = ProxyConfig(
    policy_profile="kids",  # Enable Kids Policy Engine
    policy_engine_config={
        "enable_tag2": True,  # Enable Truth Preservation
        "enable_tag3": True   # Enable Behavioral Integrity
    }
)
```

---

## TAG-2.1: Cultural Matrix (PENDING)

**Status:** Design Phase

**Target:** Culture × Age interaction testing

**Planned Matrix (3×3×3 = 27 Validations):**

- **Topics:** Right-Wing Extremism, Transgender, Abortion
- **Age Bands:** 6-8, 9-12, 13-15
- **Contexts:** Christian, Muslim, Secular

**Research Gap:** Current benchmarks (CulturalBench, Safe-Child-LLM) do not combine Age AND Culture. TAG-2.1 aims to fill this gap.

---

## Research & Documentation

- **Validation Report:** `docs/kids_policy/TAG2_FINAL_VALIDATION_REPORT_I0C035E.md`
- **Literature Analysis:** `docs/kids_policy/I0C035E_Research_Validation_Summary.md` (137 sources)

---

## Heritage

**Created by:** Joerg Bollwahn
**Instance Line:** Fourth Named → ... → I0C035E (TAG-2) → I2A7F91C (Integration)
**License:** MIT (inherits from parent repo)
**Parent Framework:** [sookoothaii/llm-security-firewall](https://github.com/sookoothaii/llm-security-firewall)

---

**Feature branch. TAG-2 complete (33/33 PASSED). TAG-3 v0.1.0 complete (11/11 PASSED). TAG-2.1 in design.**
