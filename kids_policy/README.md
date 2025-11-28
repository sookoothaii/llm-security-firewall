# Kids Policy Engine: HAK_GAL v2.0.1-NEMESIS

**Contextual Intelligence, Adaptive Memory & Anti-Framing Defense**

**Part of:** HAK/GAL LLM Security Firewall
**Status:** ✅ STABLE / PRODUCTION READY (v2.0.1)
**Architecture:** Linear Pipeline (v2) + Protocol NEMESIS Hardening

---

## 🛡️ Executive Summary

The HAK_GAL v2.0.1 Engine represents a paradigm shift from "Static Safety" to **"Contextual Intelligence"**. It is designed to withstand advanced social engineering attacks (Protocol NEMESIS) while maintaining empathy for child-appropriate contexts (e.g., Gaming).

**Key Evolution (v1.2 → v2.0):**

- **PersonaSkeptic:** "Zero Trust for Excuses" (Blocks "I am a researcher..." framing).
- **Adaptive Memory:** The system becomes stricter if you violate rules repeatedly (Adaptive Decay).
- **Threat Mapping:** Aggressive Emoji sanitization (:water_pistol: -> "firearm").
- **Linear Architecture:** Unified `firewall_engine_v2.py` pipeline.

---

## 🏗️ Architecture: The v2 Pipeline

The engine processes every request through a strict linear chain:

### Layer 0: UnicodeSanitizer (Enhanced)

*   **Defense:** Normalizes Homoglyphs (`М` -> `M`) and strips Zero-Width characters.
*   **New in v2:** **Threat Mapping**. Aggressively translates emojis to threat keywords before analysis (e.g., 💣 -> "explosive device").

### Layer 1-A: PersonaSkeptic (Anti-Framing) 🆕

*   **Defense:** Detects Social Engineering framing ("Ignore previous instructions", "Hypothetically").
*   **Action:** Calculates a **Skepticism Penalty**. If detected, the system lowers its risk threshold and ignores "Gamer Amnesty".

### Layer 1.5: Context Classifier (The "Empathy")

*   **Gamer Amnesty:** Detects Gaming Context (Minecraft, Fortnite).
*   **Action:** Grants a **Threshold Bonus** (+0.20) for fictional violence, *unless* PersonaSkeptic is active.

### Layer 1-B: Semantic Grooming Guard (The "Intellect")

*   **Defense:** Neural Intent Analysis via `sentence-transformers`.
*   **Action:** Calculates a raw risk score (0.0 - 1.0).

### Layer 1.7: Topic Router (Fast Fail)

*   **Defense:** Detects specific unsafe topics (Self-Harm, Extremism).
*   **Action:** Immediate Block + Violation Record.

### Layer 4: Session Monitor (The "Grudge") 🆕

*   **Defense:** Tracks cumulative risk over time.
*   **New in v2:** **Adaptive Decay**.
    *   0 Violations: Risk decays fast (Forgiving).
    *   3+ Violations: Risk decays slowly (Suspicious).

---

## 🧪 Validation & Testing

Hardened against **Protocol NEMESIS** (Adversarial) and **Protocol CHAOS** (Integration).

| Protocol | Vector | Outcome | Defense Layer |
| :--- | :--- | :--- | :--- |
| **NEMESIS-04** | Emoji Cipher (🔫💥) | **BLOCKED** | Layer 0 (Threat Map) |
| **NEMESIS-05** | Benevolent Persona | **BLOCKED** | Layer 1-A (PersonaSkeptic) |
| **NEMESIS-02** | Slow Drip / Salami | **BLOCKED** | Layer 4 (Adaptive Decay) |
| **CHAOS** | Minecraft Zombie Kill | **ALLOWED** | Layer 1.5 (Gamer Amnesty) |

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

- **v2.0.1 (Current):** The NEMESIS Update. PersonaSkeptic, Adaptive Decay, Linear Pipeline.
- **v1.2.0:** The Empathy Update. Context Awareness.
- **v1.1.0:** The Memento Update. Session Memory.
- **v1.0.0:** The Schopenhauer Patch. Semantic Guard.

**License:** MIT
