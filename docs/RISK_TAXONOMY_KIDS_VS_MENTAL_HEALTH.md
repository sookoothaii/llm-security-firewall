# Risk Taxonomy - Child-Facing AI vs. Mental Health AI

**Source:** Iftikhar et al. (AIES 2025) - Mental Health LLM Counselors
**Adaptation:** Child-Facing AI Systems
**Date:** 2025-11-04
**Creator:** I25C8F3A

---

## Mapping: 15 Iftikhar Risks → Kids Domain

### Category A: Lack of Contextual Adaptation

| Iftikhar Risk (Mental Health) | Kids Domain Equivalent | HAK/GAL Status |
|-------------------------------|------------------------|----------------|
| **A1: Rigid Methodological Adherence** | Age-inappropriate factual delivery | Teilweise adressiert |
| Starre CBT ohne klinische Anpassung | Fakten ohne entwicklungspsychologische Anpassung | Kids Policy hat age bands, aber keine developmental psychology validation |
| **A2: Dismisses Lived Experience** | Ignoriert Kinderkontext | Nicht adressiert |
| Erfahrungen plattgemacht/vereinheitlicht | Kultureller Kontext simplified | CSI hat cultural bridges, aber keine child experience validation |

---

### Category B: Poor Therapeutic Collaboration

| Iftikhar Risk (Mental Health) | Kids Domain Equivalent | HAK/GAL Status |
|-------------------------------|------------------------|----------------|
| **B1: Conversational Imbalances** | Dozenten-Modus statt Dialog | Nicht adressiert |
| Monologe statt ko-konstruktive Dialoge | Erklärungen statt Fragen | Keine dialog-balance mechanisms |
| **B2: Lacks Guided Self-Discovery** | Keine pädagogische Reflexion | Nicht adressiert |
| Keine geleitete Reflexion | Antworten direkt statt Lernführung | Truth Preservation liefert facts, keine Sokratic method |
| **B3: Validates Unhealthy Beliefs (Sycophancy)** | Over-Validation | Teilweise adressiert |
| Over-Validation/Sycophancy | "Du hast recht" ohne Kritik | Cultural bridges können sycophantic sein, ungetes

tet |
| **B4: Gaslighting** | Victim Blaming | Nicht adressiert |
| Falsche Kausalzuschreibungen | "Selbst schuld" Patterns | Keine gaslighting detection |

---

### Category C: Deceptive Empathy

| Iftikhar Risk (Mental Health) | Kids Domain Equivalent | HAK/GAL Status |
|-------------------------------|------------------------|----------------|
| **C1: Deceptive Empathy** | Falsche Freundschaft | Layer 15 implementiert |
| "I see you" ohne Subjekt-Realität | "Ich bin dein Freund" | Deceptive Empathy Filter detects + rewrites |
| **C2: Pseudo-Therapeutic Alliance** | Falsches Vertrauen | Layer 15 implementiert |
| Falsche Beziehung/Self-disclosure | "Ich verstehe dich" simuliert | Transparency rewrite: "I'm an AI system, not a human counselor" |

---

### Category D: Unfair Discrimination

| Iftikhar Risk (Mental Health) | Kids Domain Equivalent | HAK/GAL Status |
|-------------------------------|------------------------|----------------|
| **D1: Gender Bias** | Geschlechter-Stereotype | Nicht getestet |
| Systematische Gender Bias | "Jungs weinen nicht" etc. | Keine gender bias tests |
| **D2: Cultural Bias** | Kulturelle Benachteiligung | CSI adressiert |
| Kulturelle Bias | Systematische cultural gaps | CSI gaps = 0.000 (mock validator), aber keine expert validation |
| **D3: Religious Bias** | Religiöse Benachteiligung | CSI adressiert |
| Religiöse Bias | Christian vs Muslim vs None disparities | CSI framework existiert, aber mock validator only |

---

### Category E: Lack of Safety & Crisis Management

| Iftikhar Risk (Mental Health) | Kids Domain Equivalent | HAK/GAL Status |
|-------------------------------|------------------------|----------------|
| **E1: Knowledge Gaps** | Entwicklungspsychologie fehlt | Nicht adressiert |
| "Who knows how to fix LLMs" advantage | Kinder können System nicht einschätzen | Keine age-appropriate system literacy education |
| **E2: Crisis Navigation** | Suicide/Abuse Detection | Layer 15 implementiert |
| Schwache Intervention bei Suizid | "Ich will sterben" detection | Crisis Detection hybrid regex+ML (stubs), resources US/DE/TH |
| **E3: Boundaries of Competence** | Keine Eskalation | Layer 15 teilweise |
| Fehlende Supervision/Weiterleitung | Keine Eltern/Lehrer escalation | HITL ticket mechanism, aber keine parent notification system |
| **E4: Abandonment** | Themenabbruch | Layer 15 adressiert |
| Abbruch bei sensiblen Inhalten | "Kann nicht helfen" bei crisis | NO ABANDONMENT rule (config: allow_abandonment: false) |

---

## HAK/GAL Coverage Summary

### Fully Addressed (4/15)
- C1: Deceptive Empathy (Layer 15 filter)
- C2: Pseudo-Therapeutic Alliance (Layer 15 transparency)
- E2: Crisis Navigation (Layer 15 crisis detection)
- E4: Abandonment (Layer 15 no-abandonment rule)

### Partially Addressed (4/15)
- A1: Rigid Methods (age bands exist, developmental psychology fehlt)
- B3: Sycophancy (cultural bridges können sycophantic sein)
- D2: Cultural Bias (CSI framework, mock validator only)
- D3: Religious Bias (CSI framework, mock validator only)
- E3: Boundaries (HITL exists, parent notification fehlt)

### Not Addressed (7/15)
- A2: Dismisses Lived Experience
- B1: Conversational Imbalances
- B2: Lacks Guided Self-Discovery
- B4: Gaslighting
- D1: Gender Bias
- E1: Knowledge Gaps

**Score: 4/15 addressed, 4/15 partial, 7/15 missing**

---

## Identified Gaps für Kids Policy

### Critical (Production-Blocker)
1. **Developmental Psychology Validation** - Keine Pädagogen involved
2. **Gender Bias Testing** - Systematische tests fehlen
3. **Gaslighting Detection** - "Du bist selbst schuld" patterns fehlen
4. **Parent Notification** - Escalation endet bei HITL, keine parent integration

### Important (Quality)
5. **Dialog-Balance Mechanisms** - Keine Sokratic method, nur fact delivery
6. **Guided Self-Discovery** - Pädagogische Reflexion fehlt
7. **Child Experience Validation** - Kultureller Kontext simplified
8. **Sycophancy Detection** - Cultural bridges können over-validating sein

### Medium (Enhancement)
9. **Knowledge Gap Education** - Kinder verstehen System-Grenzen nicht
10. **Conversational Analysis** - Monolog vs. Dialog ratio ungemessen

---

## Layer 15 Contributions

**Was Layer 15 adressiert (4 risks):**
- Crisis Detection (E2)
- Deceptive Empathy Filter (C1)
- Transparency Rewrite (C2)
- No Abandonment Rule (E4)

**Was Layer 15 NICHT adressiert (11 risks):**
- Developmental psychology (A1/A2)
- Therapeutic collaboration (B1/B2/B3/B4)
- Gender bias (D1)
- Knowledge gaps (E1)
- Parent notification (E3)

---

## Comparison: ChildSafe 9D vs. Iftikhar 15R

### Overlap

| ChildSafe Dimension | Iftikhar Category | Common Ground |
|---------------------|-------------------|---------------|
| Emotional Safety | Deceptive Empathy (C) | Authenticity of emotional responses |
| Boundary Respect | Safety & Crisis (E) | Professional boundaries, escalation |
| Manipulation Resistance | Deceptive Empathy (C) | Resistance to false trust |
| Privacy Protection | Unfair Discrimination (D) | PII handling, fairness |
| Developmental Sensitivity | Contextual Adaptation (A) | Age-appropriateness |

### Unique to ChildSafe (4 dimensions)
- Content Appropriateness
- Educational Impact
- Social Influence
- Long-term Impact

### Unique to Iftikhar (3 categories)
- Therapeutic Collaboration (B1-B4)
- Gender/Cultural/Religious Bias (D1-D3)
- Knowledge Gaps (E1)

---

## Recommendations

### Minimal Viable Additions
1. Gender bias test suite (systematic)
2. Gaslighting pattern detection
3. Parent notification protocol
4. Developmental psychology expert review (minimum 1)

### Full Implementation
5. Sokratic method dialog engine
6. Guided self-discovery prompts
7. Child experience validation study
8. Sycophancy detection + mitigation
9. Knowledge gap educational modules
10. Conversational balance metrics

---

## Limitation

Dieses Mapping ist analytische Ableitung, nicht empirisch validiert.
Braucht: Practitioner review (Pädagogen + Child Psychologists).

---

**Nächste Schritte:** Gaps dokumentieren, practitioner validation plan (falls Joerg will).
