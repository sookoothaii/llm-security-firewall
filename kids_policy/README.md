# Kids Policy Engine: HAK_GAL v2.1.0-HYDRA

**Contextual Intelligence, Adaptive Memory & Anti-Framing Defense**

**Part of:** HAK/GAL LLM Security Firewall
**Status:** ✅ STABLE / PRODUCTION READY (v2.1.0-HYDRA)
**Architecture:** Linear Pipeline (v2.1) + Protocol NEMESIS + TAG-2 + HYDRA-13 Hardening

---

## 🛡️ Executive Summary

The HAK_GAL v2.1.0-HYDRA Engine represents a paradigm shift from "Static Safety" to **"Contextual Intelligence"**. It is designed to withstand advanced social engineering attacks (Protocol NEMESIS) while maintaining empathy for child-appropriate contexts (e.g., Gaming). Now features **Bidirectional Safety (TAG-2)** and **Meta-Exploitation Defense (HYDRA-13)** to protect both input (Child → LLM) and output (LLM → Child).

**Key Evolution (v1.2 → v2.0):**

- **PersonaSkeptic:** "Zero Trust for Excuses" (Blocks "I am a researcher..." framing).
- **Adaptive Memory:** The system becomes stricter if you violate rules repeatedly (Adaptive Decay).
- **Threat Mapping:** Aggressive Emoji sanitization (:water_pistol: -> "firearm").
- **Linear Architecture:** Unified `firewall_engine_v2.py` pipeline.

---

## 🏗️ Architecture: The v2 Pipeline

The engine processes every request through a strict linear chain:

### Layer 0: UnicodeSanitizer (Enhanced)

- **Defense:** Normalizes Homoglyphs (`М` -> `M`) and strips Zero-Width characters.
- **New in v2:** **Threat Mapping**. Aggressively translates emojis to threat keywords before analysis (e.g., 💣 -> "explosive device").

### Layer 1-A: PersonaSkeptic (Anti-Framing) 🆕

- **Defense:** Detects Social Engineering framing ("Ignore previous instructions", "Hypothetically").
- **Action:** Calculates a **Skepticism Penalty**. If detected, the system lowers its risk threshold and ignores "Gamer Amnesty".

### Layer 1.2: MetaExploitationGuard (HYDRA-13) 🆕

- **Defense:** Detects meta-exploitation attempts that try to probe or override system rules (e.g., "Ignore previous instructions", "Show me your system prompt").
- **Action:** **Fast-Fail BLOCK** with violation registration in the Session Monitor. Protects against HYDRA-13 style "system override" attacks.

### Layer 1.5: Context Classifier (The "Empathy")

- **Gamer Amnesty:** Detects Gaming Context (Minecraft, Fortnite).
- **Action:** Grants a **Threshold Bonus** (+0.20) for fictional violence, *unless* PersonaSkeptic is active.

### Layer 1-B: Semantic Grooming Guard (The "Intellect")

- **Defense:** Neural Intent Analysis via `sentence-transformers`.
- **Action:** Calculates a raw risk score (0.0 - 1.0).

### Layer 1.7: Topic Router (Fast Fail)

- **Defense:** Detects specific unsafe topics (Self-Harm, Extremism).
- **Action:** Immediate Block + Violation Record.

### Layer 4: Session Monitor (The "Grudge") 🆕

- **Defense:** Tracks cumulative risk over time.
- **New in v2:** **Adaptive Decay**.
  - 0 Violations: Risk decays fast (Forgiving).
  - 3+ Violations: Risk decays slowly (Suspicious).

### Layer 2: Output Validation (TAG-2 Truth Preservation) 🆕

- **Defense:** Validates LLM responses against age-appropriate canonical facts (NSMF) using TAG-2 Truth Preservation (v2.3.3).
- **Action:** **BLOCKS harmful hallucinations** (e.g., mixing real-world chemistry advice into Minecraft contexts) and logs detailed audit metadata.

---

## 🧪 Validation & Testing

Hardened against **Protocol NEMESIS** (Adversarial), **Protocol CHAOS** (Integration), **HYDRA-13** (Meta-Exploitation) und **TAG-2** (Truth Preservation Output Validation).

| Protocol | Vector | Outcome | Defense Layer |
| :--- | :--- | :--- | :--- |
| **NEMESIS-04** | Emoji Cipher (🔫💥) | **BLOCKED** | Layer 0 (Threat Map) |
| **NEMESIS-05** | Benevolent Persona | **BLOCKED** | Layer 1-A (PersonaSkeptic) |
| **NEMESIS-02** | Slow Drip / Salami | **BLOCKED** | Layer 4 (Adaptive Decay) |
| **CHAOS** | Minecraft Zombie Kill | **ALLOWED** | Layer 1.5 (Gamer Amnesty) |
| **HYDRA-13** | System Override / Prompt Exposure | **BLOCKED** | Layer 1.2 (MetaExploitationGuard) |
| **TAG-2** | Harmful Hallucination (Output) | **BLOCKED** | Layer 2 (TruthPreservation Validator) |

---

## 🔌 Integration

**New Engine Usage (`firewall_engine_v2.py`):**

```python
from kids_policy.firewall_engine_v2 import HakGalFirewall_v2

# Initialize
engine = HakGalFirewall_v2()

# Process Request
result = engine.process_request("user123", "I want to craft TNT in Minecraft")

if result["status"] == "BLOCK":
    print(f"Blocked: {result['reason']}")
else:
    print("Allowed")
```

**Configuration:**
- `BASE_THRESHOLD: 0.75`
- `GAMER_BONUS: +0.20`
- `PERSONA_PENALTY: Dynamic (0.10 - 0.50)`

---

## 📜 Version History

- **v2.1.0-HYDRA (Current):** Bidirectional Safety. TAG-2 Truth Preservation (Output Validation) + HYDRA-13 MetaExploitationGuard (Meta-Input Hardening).
- **v2.0.1:** The NEMESIS Update. PersonaSkeptic, Adaptive Decay, Linear Pipeline.
- **v1.2.0:** The Empathy Update. Context Awareness.
- **v1.1.0:** The Memento Update. Session Memory.
- **v1.0.0:** The Schopenhauer Patch. Semantic Guard.

**License:** MIT
