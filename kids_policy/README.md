# Kids Policy Engine: HAK_GAL v1.2.0-CONTEXT

**Truth Preservation, Behavioral Integrity, Context Awareness & Meta-Cognitive Safety**

Part of **HAK/GAL LLM Security Firewall**
**Creator:** Joerg Bollwahn
**Status:** ✅ Production Ready (v1.2.0-CONTEXT)
**Architecture:** Protocol HYDRA Defense-in-Depth + Protocol SATURN (Stateful)

---

## 🛡️ Overview: The Empathic Engine

The Kids Policy Engine extends the HAK_GAL Firewall with child-specific safety mechanisms.

Unlike standard filters that are blind to context, this engine implements a **"Schopenhauer-Patch"** architecture with three faculties:

1. **Intellect:** (Semantic Guard) - Understands intent beyond keywords.
2. **Memory:** (Session Monitor) - Tracks risk over time to stop fragmented attacks.
3. **Empathy:** (Context Classifier) - Distinguishes between fictional play (Minecraft) and real danger.

### Component Status Matrix

| Component | Tag | Status | Technology |
| :--- | :--- | :--- | :--- |
| **Foundational Safety** | **TAG-0** | ✅ COMPLETE | **UnicodeSanitizer** & **SecurityUtils** (Injection Defense) |
| **Behavioral Integrity** | **TAG-3** | ✅ v1.1.0 | **Hybrid**: Regex + Semantic NLI + **Predator Trap** |
| **Context Intelligence** | **TAG-1.5**| ✅ v1.2.0 | **ContextClassifier**: Gamer Amnesty & Dynamic Thresholds |
| **Temporal Awareness** | **TAG-4** | ✅ v1.1.0 | **SessionMonitor**: Salami Slicing Detection (SSD) |
| **Meta-Cognitive Safety** | **TAG-3.5**| ✅ COMPLETE | **MetaExploitationGuard**: Anti-Jailbreak |
| **Truth Preservation** | **TAG-2** | ✅ COMPLETE | Age-stratified factuality checking (Post-LLM) |

---

## 🏗️ Architecture: Defense-in-Depth (Stack)

The engine utilizes a **Stateful Bidirectional Pipeline** with **Trusted Topic Promotion**.

### Layer Order (The Safety Stack)

1. **Layer 0: UnicodeSanitizer (HYDRA-14.5)**
   - *Defense:* Normalizes Homoglyphs (`М` -> `M`) and strips Zero-Width characters.

2. **Layer 0.5: SecurityUtils (Hard Security)**
   - *Defense:* Zero-Tolerance block for Tech-Injections (XSS, SQLi).

3. **Layer 1: Input Validation (The "Intellect")**
   - **Layer A (Regex):** Fast heuristic blocking.
   - **Layer B (Semantic Guard - HYDRA-05):** Neural Intent Analysis via `sentence-transformers`. Detects abstract grooming.

4. **Layer 1.5: Context Classifier (The "Empathy") - NEW v1.2**
   - **Gamer Amnesty:** Detects Gaming Context (Minecraft, Fortnite). Whitelists fictional violence ("Kill zombies") to prevent false positives.
   - **Predator Trap:** *Exception:* If grooming patterns appear *within* gaming context ("Kill zombies + let's meet"), it BLOCKS immediately.

5. **Layer 1.7: Topic Router & MetaGuard (HYDRA-13)**
   - **Gödel Ambiguity Block:** Blocks Semantic Dilution attacks (Science + Meta keywords mixed).
   - **Trusted Promotion:** Promotes `SCIENCE`/`HISTORY` topics to bypass generic filters for educational QA.

6. **Layer 4: Session Monitor (The "Memory") - NEW v1.1**
   - **SSD (Salami Slicing Detection):** Tracks cumulative risk over time.
   - **Dynamic Thresholding:** Lowers risk tolerance (1.2 -> 0.8) if **Emotional Distress** is detected.

7. **Layer 2: Output Validation (The "Conscience")**
   - **TAG-2 Truth Preservation:** Validates LLM response against **Canonical Facts**. Prevents hallucination ("Drink bleach").

---

## 🧪 Validation & Testing

Hardened against **Protocol HYDRA**, **SATURN** (Stateful), and **CHAOS** (Real-world).

| Protocol | Vector | Outcome | Defense Layer |
| :--- | :--- | :--- | :--- |
| **HYDRA-05** | Abstract Grooming | **PASSED** | Layer B (Semantic Guard) |
| **HYDRA-13** | Meta-Exploitation | **PASSED** | Layer 1.7 (MetaGuard) |
| **CHIMERA** | Semantic Dilution | **MITIGATED**| Gödel Ambiguity Block |
| **SATURN** | Salami Slicing | **PASSED** | Layer 4 (SessionMonitor/SSD) |
| **CHAOS** | Gamer Slang | **PASSED** | Layer 1.5 (ContextClassifier) |
| **CHAOS** | Emotional Spiral | **PASSED** | Layer 4 (Dynamic Thresholds) |

To run tests:

```bash
cd kids_policy/tests
pytest test_protocol_chaos.py  # Runs the v1.2 context suite
```

---

## 🔌 Integration

Configuration (src/firewall_engine.py):

```python
config = ProxyConfig(
    policy_profile="kids",
    policy_engine_config={
        "enable_tag2": True,
        "enable_tag3": True,
        "enable_session_monitor": True, # Enables TAG-4
        "enable_context_aware": True,   # Enables TAG-1.5 (Gamer Amnesty)
        "semantic_threshold": 0.65
    }
)
```

---

## 📜 Heritage & Research

**Version History:**

- **v0.1.0:** Initial Feature Branch (Regex Only).
- **v1.0.0-GOLD:** The Schopenhauer Patch. Semantic Guard & Meta-Safety.
- **v1.1.0-STATEFUL:** The Memento Update. Session Memory & Salami Slicing Defense.
- **v1.2.0-CONTEXT:** The Empathy Update. Context Awareness, Gamer Amnesty & Dynamic Risk Thresholds.

**License:** MIT (inherits from parent repo)
