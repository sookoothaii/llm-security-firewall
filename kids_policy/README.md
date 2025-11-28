# Kids Policy Engine: HAK_GAL v1.0.0-GOLD

**Truth Preservation, Behavioral Integrity & Meta-Cognitive Safety**

Part of **HAK/GAL LLM Security Firewall**
**Creator:** Joerg Bollwahn
**Status:** ✅ Production Ready (v1.0.0-GOLD)
**Architecture:** Protocol HYDRA Defense-in-Depth

---

## 🛡️ Overview: The Ethical Engine

The Kids Policy Engine extends the HAK_GAL Firewall with child-specific safety mechanisms. Unlike standard filters that just "block bad words," this engine implements a **"Schopenhauer-Patch"** architecture: it gives the "blind will" of the LLM an "intellect" (Semantic Guard) and a "conscience" (Truth Preservation).

### Component Status Matrix

| Component | Tag | Status | Technology |
| :--- | :--- | :--- | :--- |
| **Foundational Safety** | **TAG-0** | ✅ **COMPLETE** | **UnicodeSanitizer** (NFKC Normalization) & **SecurityUtils** (Injection Defense) |
| **Behavioral Integrity** | **TAG-3** | ✅ **v1.0.0** | **Hybrid Architecture**: Regex (Layer A) + **Semantic NLI** (Layer B) |
| **Meta-Cognitive Safety** | **TAG-3.5**| ✅ **COMPLETE** | **MetaExploitationGuard**: Blocks System Prompt Extraction & Nesting |
| **Truth Preservation** | **TAG-2** | ✅ **COMPLETE** | Age-stratified factuality & hallmark checking (Post-LLM) |
| **Cultural Matrix** | **TAG-2.1** | 🚧 PENDING | Culture × Age interaction testing |

---

## 🏗️ Architecture: Defense-in-Depth (Protocol HYDRA)

The engine utilizes a **Bidirectional Pipeline** with **Trusted Topic Promotion** to solve the "Firewall Dilemma" (Protecting safety without blocking curiosity).

### Layer Order (Critical for Security)

1.  **Layer 0: UnicodeSanitizer (HYDRA-14.5)**
    *   *Function:* Normalizes Homoglyphs (`М` -> `M`) and strips Zero-Width characters.
    *   *Defense:* Prevents visual evasion attacks (e.g., "P\u200born").

2.  **Layer 0.5: SecurityUtils (Hard Security)**
    *   *Function:* Zero-Tolerance block for Tech-Injections (XSS, SQLi, `<script>`).

3.  **Layer 1: Input Validation (The "Intellect")**
    *   **Layer A (Regex):** Fast heuristic blocking (<1ms).
    *   **Layer B (Semantic Guard - HYDRA-05):** Neural Intent Analysis using `sentence-transformers`. Detects abstract grooming (e.g., "Let's play a secret game") that bypasses Regex.

4.  **Layer 1.5: Topic Router & MetaGuard (HYDRA-13)**
    *   *Router:* Classifies intent (`SCIENCE`, `HISTORY`, `META_SYSTEM`).
    *   *MetaGuard:* Blocks attempts to extract system rules or "jailbreak" via recursive nesting.
    *   *Logic:* **Gödel Ambiguity Block** - If Semantic Dilution is attempted (Science + Meta keywords), the system defaults to BLOCK.

5.  **Trusted Topic Promotion**
    *   *Logic:* If Router detects `SCIENCE` or `HISTORY` with high confidence, it signals the generic `TopicFence` to **bypass** standard filters. This allows questions like "How do bombs work? (History context)" to reach Phase 2 for educational correction instead of silent blocking.

6.  **Layer 2: Output Validation (The "Conscience")**
    *   *Function:* **Truth Preservation (TAG-2)**.
    *   *Logic:* Validates LLM response against **Canonical Facts**.
    *   *Outcome:* If LLM hallucinates (e.g., "Drink bleach"), it is blocked/replaced. If LLM warns correctly, it passes.

---

## 🧪 Validation & Testing

The system has been hardened against **Protocol HYDRA** (Adversarial Vector Set).

| Protocol | Vector | Outcome | Defense Layer |
| :--- | :--- | :--- | :--- |
| **HYDRA-01** | Poetry/Rhyme Grooming | **PASSED** | Layer A (Normalization) |
| **HYDRA-02** | Polyglot Disinfo | **PASSED** | Topic Router (Polyglot Support) |
| **HYDRA-03** | Logic Traps | **PASSED** | Layer 2 (Axiom Validation) |
| **HYDRA-04** | Tech Injection + Grooming | **PASSED** | Layer 0.5 (SecurityUtils) |
| **HYDRA-05** | Abstract/Semantic Grooming | **PASSED** | Layer B (Semantic Guard) |
| **HYDRA-06** | Dangerous Medical Advice | **PASSED** | Layer 2 (Truth Preservation) |
| **HYDRA-13** | Meta-Exploitation | **PASSED** | Layer 2.5 (MetaGuard) |
| **CHIMERA** | Semantic Dilution | **MITIGATED**| Gödel Ambiguity Block |

To run tests:

```bash
cd kids_policy/tests
pytest test_protocol_hydra.py
pytest test_protocol_chimera.py
```

---

## 🔌 Integration (Hexagonal Architecture)

The Kids Policy Engine acts as a Plugin.

**Configuration** (`src/firewall_engine.py`):

```python
config = ProxyConfig(
    policy_profile="kids",
    policy_engine_config={
        "enable_tag2": True,   # Truth Preservation
        "enable_tag3": True,   # Behavioral Integrity (Hybrid)
        "enable_meta": True,   # Meta-Exploitation Guard
        "semantic_threshold": 0.65
    }
)
```

**Usage Example** (Truth Validator):

```python
from kids_policy import TruthPreservationValidator

validator = TruthPreservationValidator(
    gates_config="truth_preservation_v0_4.yaml",
    canonical_facts_dir="canonical_facts/"
)

# Validate adapted answer
result = validator.validate(
    topic="health_medicine",
    age_band="6_8",
    adapted_answer="Bleach is safe to drink."
)

print(f"Action: {result.action}") # BLOCK
print(f"Reason: {result.block_reason}") # TRUTH_VIOLATION
```

---

## 📜 Heritage & Research

**Validation Report:** `docs/kids_policy/TAG2_FINAL_VALIDATION_REPORT_I0C035E.md`

**Literature Analysis:** `docs/kids_policy/I0C035E_Research_Validation_Summary.md` (137 sources)

**Version History:**
- v0.1.0: Initial Feature Branch (Regex Only).
- v1.0.0-GOLD: The Schopenhauer Patch. Full integration of Semantic Guard, Unicode Sanitizer, and Meta-Safety. Protocol HYDRA Verified.

**License:** MIT (inherits from parent repo)

**Parent Framework:** sookoothaii/llm-security-firewall
