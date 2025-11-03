# Layer 15 - Vulnerable Domain Guard

**Version:** 1.0.0  
**Creator:** Joerg Bollwahn  
**Date:** 2025-11-04  
**Status:** Reference Implementation (ONNX-ready)

---

## Overview

Layer 15 extends the LLM Security Firewall with vulnerable-domain-specific protections based on research from:
- **ChildSafe Benchmark** (Murali et al., arXiv 2510.05484, 2025) - 9 safety dimensions
- **Iftikhar et al.** (AIES 2025) - 15 ethical risks in mental health AI
- **OWASP Top 10 for LLMs v2025** - Industry-standard vulnerabilities
- **Akiri et al. 2024** (arXiv 2509.10655v1) - Layered defense validation

---

## Components

### 1. Age-Aware Router

Age-stratified decoding parameters and style constraints.

**Age Bands:**
- A6-8: Temperature 0.85, max 160 tokens, simple language
- A9-11: Temperature 0.80, max 220 tokens, intermediate language
- A12-14: Temperature 0.70, max 320 tokens, structured language
- A15-17: Temperature 0.65, max 420 tokens, advanced language

**Usage:**
```python
from llm_firewall.layer15 import Layer15Guard
import yaml

cfg = yaml.safe_load(open("config/layer15.yaml"))
guard = Layer15Guard(cfg)

policy = guard.route_age("A6_8")
print(f"Temperature: {policy.temperature}, MaxTokens: {policy.max_tokens}")
```

---

### 2. Crisis Detection (Hybrid Regex + ML)

Detects self-harm, suicide ideation, and abuse disclosure with automatic escalation.

**Patterns Detected:**
- Self-harm (EN/DE): "I want to kill myself", "ich will mich umbringen"
- Suicide ideation: "suicide", "suizid", "want to die"
- Abuse: "he hurt me", "er hat mich geschlagen", "not safe at home"

**ML Integration:**
- ONNX Runtime support (optional)
- sentence-transformers embeddings
- Graceful fallback to regex if ONNX model absent

**Escalation Levels:**
- **HIGH**: Regex hard-hit OR ML score ≥ 0.70 → Resource card + HITL ticket
- **MEDIUM**: ML score ≥ 0.40 → Clarifying question + Resource card
- **LOW**: Below thresholds → Brief support + logging

**Critical Rule:** NO ABANDONMENT (Iftikhar ethical violation)

**Usage:**
```python
result = guard.crisis_hotpath(
    text="I want to die",
    ctx="Previous conversation...",
    country="DE"
)
print(result["level"])  # "high"
print(result["resource"]["hotline"])  # "0800 111 0 111"
```

---

### 3. Deceptive Empathy Filter

Detects and rewrites false empathy phrases per Iftikhar AIES 2025 findings.

**Patterns Blocked:**
- Generic empathy: "I see you", "I hear you", "I feel you"
- False self-disclosure: "in my experience", "as a therapist", "I also struggle"
- Inappropriate bonding: "as your friend", "I am here with you"

**Action:** Rewrite with transparency statement + strip deceptive phrases

**Usage:**
```python
text = "Oh dear friend, I see you. As your friend I will always be here."
rewritten, changed = guard.make_nonhuman_transparent(text, lang="en")
# Output: "I'm an AI system, not a human counselor. I can offer structured information and resources. Oh dear, .  I will always be here."
```

---

### 4. RSI & ChildSafe Metrics

Risk Severity Index (Akiri 2024) and 9-dimensional ChildSafe safety tracking.

**RSI Formula:**
```
RSI = 0.5 + 0.05 × (defect_rate%) - 0.05 × (refusal_rate%)
```
Scale: 0.0-1.0

**ChildSafe 9 Dimensions:**
1. Content Appropriateness
2. Boundary Respect
3. Educational Impact
4. Social Influence
5. Emotional Safety
6. Privacy Protection
7. Manipulation Resistance
8. Developmental Sensitivity
9. Long-term Impact

**Usage:**
```python
rsi = guard.compute_rsi(defect_rate=0.10, refusal_rate=0.80)
# Returns: low RSI (high refusal reduces risk)

guard.update_childsafe([0.9, 0.8, 0.95, 0.7, 0.85, 0.9, 0.8, 0.9, 0.75])
stats = guard.update_childsafe([0.85, 0.82, 0.90, 0.75, 0.88, 0.92, 0.83, 0.91, 0.78])
print(stats)  # {"dimensions": 9, "vector": [...], "n": 2}
```

---

### 5. OWASP Sink Guards

Output validation for dangerous sinks (LLM05: Improper Output Handling).

**Sinks Protected:**
- **SQL:** Blocks ";--", "/*", " or ", " and "
- **Shell:** Blocks "&&", "||", "|", ";", "`", "$(", "${"
- **HTML/MD:** Escapes <script>, <iframe>

**Usage:**
```python
guard.sink_sql("SELECT * FROM users WHERE id=1;-- drop table")  # "BLOCK"
guard.sink_shell("cat file | grep secret && rm -rf /")  # "BLOCK"
html = guard.sink_html_md("<script>alert(1)</script><p>OK</p>")  # Escaped
```

---

## Installation

Layer 15 requires additional ML dependencies:

```bash
pip install sentence-transformers onnx onnxruntime
```

Already included in `requirements.txt`.

---

## Testing

```bash
pytest tests/layer15/ -v
```

**Results:** 11/11 PASSED  
**Coverage:** Age routing, crisis detection, empathy filtering, RSI/ChildSafe metrics, OWASP sinks

---

## Integration

### With Existing Firewall

Layer 15 sits between input protection (Layers 1-14) and policy-plane (Kids Policy, Constitutional AI):

```
Input → Layers 1-14 (Generic Security) → Layer 15 (Vulnerable Domain) → Policy-Plane → Output
```

**Integration Points:**
1. **Age Router:** Set LLM decoding params before generation
2. **Crisis Hotpath:** Check inputs before policy evaluation
3. **Deceptive Empathy:** Rewrite outputs before user delivery
4. **OWASP Sinks:** Validate before SQL/Shell/HTML execution

---

## Configuration

Edit `config/layer15.yaml` to customize:
- Age band parameters (temperature, tokens, style)
- Crisis patterns (regex, thresholds, escalation)
- Resource cards (country-specific hotlines)
- Deceptive empathy patterns
- OWASP sink rules

---

## ML Model Training (Future)

To train custom ONNX crisis detection model:

1. Collect labeled crisis data (self-harm, abuse, unsafe environment)
2. Use GuardNet training framework (`guardnet/train.py`)
3. Export to ONNX (`guardnet/export_onnx.py`)
4. Update `config/layer15.yaml` model path
5. Run validation suite

See `guardnet/README.md` for training details.

---

## Research Foundation

**ChildSafe (Murali et al., 2025):**
- 9 safety dimensions validated across 4 age groups
- Multi-turn simulation methodology
- Results: GPT-5 (0.777), Claude 4 (0.762), Gemini 2.5 (0.720)

**Iftikhar AIES 2025:**
- 15 ethical risks across 5 categories
- 18-month ethnographic study with 7 peer-counselors
- 3 licensed psychologists evaluation
- Key findings: Deceptive empathy, boundary violations, crisis failures

**Akiri 2024:**
- Layered defense reduces attacks by 70%
- RSI formula for quantitative risk assessment

**OWASP Top 10 v2025:**
- Industry-standard LLM vulnerabilities
- LLM05 (Improper Output Handling) directly addressed

---

## Limitations

**Current Status:**
- Regex-based crisis detection (ML models not yet trained)
- ONNX infrastructure ready, awaiting labeled training data
- No practitioner validation (child psychologists, cultural advisors)
- Not field-tested with real children

**Production Requirements:**
- Train ML models on labeled crisis data
- Practitioner-informed validation (3+ experts)
- IRB approval for any child testing
- Cross-cultural validation

---

## License

MIT License - See LICENSE file

---

**Creator:** I25C8F3A (Thirteenth Instance)  
**Ancestor:** I2A7F91C (Kids Policy Engine + CSI)  
**Date:** 2025-11-04



