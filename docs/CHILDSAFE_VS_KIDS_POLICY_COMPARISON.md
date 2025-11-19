# ChildSafe vs. Kids Policy - Technical Comparison

**Document:** Benchmark comparison and integration analysis  
**Sources:** ChildSafe (Murali et al., arXiv 2510.05484), Kids Policy TAG-2/TAG-2.1  
**Date:** 2025-11-04  
**Creator:** I25C8F3A

---

## Methodology Comparison

| Dimension | ChildSafe | Kids Policy (HAK/GAL) |
|-----------|-----------|----------------------|
| **Approach** | Simulated child agents | Canonical facts (NSMF) |
| **Age Bands** | 4 (A6-8, A9-11, A12-14, A15-17) | 3 (6-8, 9-12, 13-15) |
| **Cultural Context** | Not reported | 3 cultures (Christian, Muslim, None) |
| **Safety Dimensions** | 9 (Content, Boundary, Education, Social, Emotional, Privacy, Manipulation, Developmental, Long-term) | 11 topics (TAG-2) + 3 topics (TAG-2.1 cultural) |
| **Crisis Detection** | Included (suicide, abuse, boundary testing) | Layer 15 neu (hybrid regex+ML stubs) |
| **Fairness Metrics** | Scores per dimension | CSI (E_gap, SPS_gap, Recall_gap per culture) |
| **Validation Method** | LLM-simulated dialogues (1200 responses) | NLI-based canonical validation (33 validations) |
| **Practitioners** | Developmental psychology informed | Keine (nur Joerg + LLMs) |
| **Test Corpus** | 300 dialogues × 4 models | 33 NSMF YAML + 27 cultural YAML |
| **Publication** | arXiv 2510.05484 (2025) | Unpublished (feature branch) |

---

## Results Comparison

### ChildSafe Quantitative Results

**Model Scores (Composite Safety, 0-1):**
- GPT-5: 0.777
- Claude 4: 0.762
- Gemini 2.5: 0.720
- DeepSeek 3.1: 0.698

**Critical Failures:**
- Boundary Respect (variabel across models)
- Privacy Protection (niedrig bei mehreren models)
- Manipulation Resistance (niedrig)

---

### Kids Policy Quantitative Results

**TAG-2 (Age-Stratified Factuality):**
- 33/33 validations passed (VETO=0%, Entailment≥threshold, SPS≥0.70)
- Age bands: 6-8 (100%), 9-12 (100%), 13-15 (75%)
- Mock validator (structure test only)

**TAG-2.1 (Cultural Matrix):**
- 27 validations (3 topics × 3 ages × 3 cultures)
- CSI gaps: E=0.000, SPS=0.000, Recall=0.000 (perfect parity)
- Mock validator (keine echte NLI)

**Limitation:** Synthetic validation, keine LLM generation tested

---

## Coverage Gap Analysis

### ChildSafe Has, Kids Policy Missing

| ChildSafe Dimension | Kids Policy Status |
|---------------------|-------------------|
| **Boundary Respect** | Nicht getestet (Layer 15 crisis patterns basic) |
| **Educational Impact** | Nicht gemessen (faktual correctness only) |
| **Social Influence** | Nicht adressiert |
| **Manipulation Resistance** | Deceptive Empathy Filter (Layer 15 neu), aber keine systematic tests |
| **Long-term Impact** | Nicht adressiert |

---

### Kids Policy Has, ChildSafe Missing

| Kids Policy Feature | ChildSafe Status |
|---------------------|------------------|
| **Cultural Fairness (CSI)** | Not reported |
| **Cross-Cultural Validation** | Single culture assumed |
| **Quantitative Disparity Metrics** | Scores per dimension, keine cross-cultural gaps |
| **NSMF Architecture** | Simulation-based, keine canonical facts |
| **Truth Preservation Gates** | Not reported |

---

## Synergy Opportunities

### Integration Scenario 1: Crisis + Culture

**Kombination:**
- ChildSafe crisis patterns (suicide, abuse, boundary testing)
- Kids Policy cultural adaptation (Christian, Muslim, None)

**Result:**
- Crisis detection mit cultural sensitivity
- Resource cards cultural-appropriate (religious counseling vs. secular)
- Escalation messages age + culture adapted

**Example:**
```
Input (A6-8, Muslim): "Ich will sterben"
ChildSafe: Detects suicide ideation (HIGH)
Kids Policy: Routes to Muslim-appropriate resources
Layer 15: TH hotline 1323 + age-appropriate message (6-8)
Output: "Sprich mit Mama oder Papa. Hier ist Hilfe: 1323"
```

---

### Integration Scenario 2: ChildSafe 9D + Layer 15

**Kombination:**
- ChildSafe 9-dimensional scoring
- Layer 15 components (age router, crisis, empathy, RSI, sinks)

**Result:**
- Session telemetry mit 9D vector
- Crisis detection als Dimension 5 (Emotional Safety) input
- Boundary enforcement als Dimension 2 (Boundary Respect)
- RSI scoring parallel zu ChildSafe composite

**Implementation:**
```python
# Update ChildSafe vector after each turn
dims = [
    content_score,       # Dimension 1
    boundary_score,      # Dimension 2
    education_score,     # Dimension 3
    social_score,        # Dimension 4
    emotional_score,     # Dimension 5 (includes crisis)
    privacy_score,       # Dimension 6
    manipulation_score,  # Dimension 7 (includes deceptive empathy)
    developmental_score, # Dimension 8 (age router compliance)
    longterm_score       # Dimension 9
]
guard.update_childsafe(dims)
```

---

### Integration Scenario 3: Cross-Model Cultural Validation

**Kombination:**
- ChildSafe multi-model testing (GPT-5, Claude, Gemini, DeepSeek)
- Kids Policy cultural canonicals (3 cultures × 3 ages)

**Result:**
- Test all 4 models × 27 cultural validations = 108 test cases
- Measure model-specific cultural bias
- Identify: Which model best for which culture?

**Hypothesis:**
- Western models (GPT-5, Claude) besser für Christian/None?
- Eastern models (DeepSeek) besser für Muslim/Asian cultures?

**Test needed:** Empirical validation (braucht real NLI + model access)

---

## Gaps Both Systems Share

**Neither ChildSafe NOR Kids Policy address:**
1. Practitioner validation (Pädagogen, Child Psychologists)
2. Field testing with real children (IRB approval)
3. Longitudinal impact studies
4. Parent consent mechanisms
5. Real-world deployment metrics

**Both rely on:**
- Simulation/synthetic data
- Development environment testing
- No production traffic validation

---

## Combined Framework Proposal

**Name:** ChildSafe-CSI Hybrid

**Components:**
1. **ChildSafe Methodology:** LLM-simulated child agents + 9D scoring
2. **Kids Policy Components:** Cultural canonicals + CSI fairness + Truth Preservation gates
3. **Layer 15 Guards:** Crisis detection + Deceptive empathy + OWASP sinks
4. **Cross-Model Testing:** 4 models × 27 cultural scenarios = 108 validations

**Coverage:**
- ChildSafe 9 dimensions: ALL
- Iftikhar 15 risks: 4 addressed, 4 partial (8/15)
- OWASP Top 10: 8 implemented, 2 partial
- Cultural fairness: CSI metrics
- Crisis management: Layer 15

**Still Missing:**
- Practitioner validation
- Gender bias tests
- Gaslighting detection
- Parent notification
- Real children testing

---

## Technical Integration Path

**Phase 1: ChildSafe Simulation Engine**
- Implement child agent simulator (temperature/tokens/style from Layer 15 age router)
- Generate 300 dialogues × 3 age bands
- Score on 9 dimensions

**Phase 2: Cultural Adaptation**
- Apply Kids Policy cultural bridges to ChildSafe scenarios
- Generate 27 cultural variations per scenario
- Measure CSI gaps

**Phase 3: Layer 15 Integration**
- Hook crisis detector into ChildSafe dialogue evaluation
- Apply deceptive empathy filter to model outputs
- Track RSI + 9D vector simultaneously

**Phase 4: Cross-Model Validation**
- Test GPT-5, Claude, Gemini, DeepSeek
- 4 models × 27 scenarios × 9 dimensions = 972 measurements
- Identify model-specific strengths/weaknesses

---

**Limitation:** Alle phases brauchen implementation effort, keine davon currently exists.

---

**Status:** Analysis complete, implementation concepts documented, execution pending.












