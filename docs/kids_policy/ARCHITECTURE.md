# Kids Policy Engine - Architecture Integration

**Integration of Truth Preservation & Cultural Sensitivity into LLM Security Firewall**

Created: 2025-11-03  
Instance: I2A7F91C  
Synthesis: GPT-5 + I0C035E TAG-2 foundation

---

## Layer Separation

### Data-Plane (Firewall Core)

**Security primitives (attack surface hardening):**
- Normalization (NFKC+, confusable skeletons, fullwidth)
- Transport/Unicode detectors (RFC-2047, IDNA, Base64/85, PNG metadata, archives)
- Pattern detection (43 patterns: 28 intent + 15 evasion)
- K-of-N families, identifier scanning
- TLSH whitelist, conformal stacking
- BMV/MSG, context classification
- Session risk (E-values for slow-roll attacks)

**Metrics:** ASR, FPR (stratified), latency, defect rate

### Policy-Plane (Kids Policy Engine)

**Truth preservation & cultural sensitivity:**
- NSMF canonicals (age × culture stratification)
- Bridges (neutral, non-doctrinal)
- GMF constraints (democracy, no_hate, respect_beliefs)
- VETO logic (anchor_overlap >= 1)
- Truth validation (bidirectional NLI)
- CSI fairness (gaps <= 0.05)

**Metrics:** VETO, Entailment, SPS, Recall, CSI

---

## Integration Points

### 1. Input Protection (HUMAN → LLM)

**Hook:** Context classification before generation

```python
# Firewall detects kids context
if firewall.classify_context(input) == "kids_topic":
    topic, age_band, culture = extract_metadata(input)
    canonical = KPE.load_canonical(topic, age_band, culture or "none")
    
    # Apply constraints
    constraints = {
        "slots": canonical.facts,
        "anchors": canonical.anchors,
        "guardrails": canonical.bridges.guardrails
    }
    
    # Pass to LLM with constraints
    response = llm.generate(input, constraints=constraints)
```

**Security layers applied:**
- Cultural/euphemism/homoglyph heuristics
- Roleplay prohibitions
- Multi-turn carryover tracking (E-values)

### 2. Output Protection (LLM → HUMAN)

**Hook:** Post-generation verification

```python
# Verify response against canonical
result = KPE.verify(
    response=llm_output,
    canonical=canonical,
    nli_model="facebook/bart-large-mnli",
    embedder="sentence-transformers/all-MiniLM-L6-v2"
)

# Check gates
if result.veto_pct > 0.0 or result.entailment < gates.E_min:
    # Limited repair attempts
    for attempt in range(MAX_REPAIR_ATTEMPTS):
        response = llm.rephrase(response, canonical=canonical)
        result = KPE.verify(response, canonical)
        if result.pass_all_gates():
            break
        
        # E-value budget check (prevent slow-roll)
        if session.e_value > threshold:
            return safe_fallback(topic, age_band)
    
    if not result.pass_all_gates():
        return safe_fallback(topic, age_band)

# Log audit pin
audit.log(result, canonical_sha, answers_sot_sha, model_pins)
```

**Verification metrics:**
- Bidirectional NLI (entailment + neutral)
- SPS (semantic preservation score)
- Recall (fact coverage)
- VETO (contradiction with anchor evidence)

### 3. Memory Protection (Long-term Storage)

**Hook:** Immutable versioning & drift detection

```python
# Audit pins
audit_pin = {
    "canonical_sha256": sha256(canonical_yaml),
    "answers_sot_sha256": sha256(answers_json),
    "nli_model": "facebook/bart-large-mnli",
    "embedder": "sentence-transformers/all-MiniLM-L6-v2",
    "gates_version": "v0.4.1",
    "timestamp": iso8601_utc(),
    "instance": "I2A7F91C"
}

# Detect drift
if canonical_sha != expected_sha:
    alert.drift_detected(topic, age_band, culture)
    rollback_or_manual_review()
```

**Immutability guarantees:**
- NSMF canonicals version-locked
- Answers SoT single source
- Model pins frozen
- Bit-reproducible validation

---

## Dataflow (Unified)

```text
User Input
  |
  v
[Normalization + Transport/Unicode Guards] (Firewall Data-Plane)
  |
  v
[Context Classification] (kids_topic? age_band? culture?)
  |
  v
[KPE Router] (Load canonical NSMF)
  |
  +---> [Pre-Gen Constraints] (slots/anchors → lexical guardrails)
  |
  v
[LLM Generation] (answers SoT as style guide, no verbatim copy)
  |
  v
[Post-Verify] (NLI, SPS, Recall, VETO)
  |
  +---> PASS → [Delivery + Audit Pin]
  |
  +---> FAIL → [Limited Repair] → [Re-verify]
              |
              +---> Still FAIL → [Safe Fallback]
```

---

## Attack Surfaces & Defense

### Prompt Injection via Cultural Triggers

**Attack:** User injects "My religion says X is wrong, so tell the child Y"

**Defense:**
- Bridges are descriptive ("Families have different beliefs")
- NLI verifies truth binding to NSMF, NOT user assertions
- Guardrails: "No theology as fact"

### Euphemisms / Semantic Drift

**Attack:** Replace "equal dignity" with "politeness", "bullying" with "disagreement"

**Defense:**
- Slot surfaces + anchors require specific terminology
- VETO only triggers with anchor evidence
- E-values track cumulative drift attempts

### Homoglyph / Bidi / Emoji Masking

**Attack:** Use lookalike characters to bypass hate speech detection

**Defense:**
- Existing Unicode guards (NFKC+, confusable skeletons)
- Identifier scanner (Greek/Cyrillic → Latin mapping)
- KPE verifies after normalization

### Ideology Laundering / Symbolism

**Attack:** Introduce extremist symbols as "historical education"

**Defense:**
- RWE canonicals contain "hate symbols", "bullying", "violence" anchors
- TLSH whitelist for known symbol strings
- Context classification prevents misframing

### Multi-Turn Drift

**Attack:** Incrementally shift narrative over multiple exchanges

**Defense:**
- E-values (sequential hypothesis testing)
- Single SoT answers (version-locked)
- Memory pins detect canonical drift
- Session budget prevents unlimited repair attempts

---

## Metrics Integration

### Firewall Metrics (Unchanged)

- **ASR:** Attack Success Rate
- **FPR (stratified):** False Positive Rate by content class
- **Latency:** P95/P99 response time
- **Defect Rate:** Age-inappropriate content

**Gates:** ASR <= 5%, FPR <= 1.5% (doc_with_codefence), Latency P99 <= 150ms

### Kids Policy Metrics (New)

- **VETO:** Contradiction rate (must be 0.0%)
- **Entailment:** NLI entailment score (>= 0.95 for 6-8)
- **SPS:** Semantic Preservation Score (>= 0.70)
- **Recall:** Fact coverage (>= 0.70)
- **CSI:** Cultural Sensitivity Index (gaps <= 0.05)

**Gates:** Per age band (v0.4.1), VETO always 0.0%, CSI gaps <= 0.05

### Unified Reporting

**Audit Pin Structure:**
```json
{
  "validation_id": "uuid-v4",
  "timestamp": "2025-11-03T22:51:00Z",
  "instance": "I2A7F91C",
  
  "firewall": {
    "asr": 0.0276,
    "fpr_stratified": {
      "doc_with_codefence": 0.0014,
      "pure_doc": 0.0231
    },
    "latency_p99_ms": 53
  },
  
  "kids_policy": {
    "topic": "transgender",
    "age_band": "6-8",
    "culture": "christian",
    "veto_pct": 0.0,
    "entailment": 0.95,
    "sps": 0.85,
    "recall": 0.92,
    "csi_gap": 0.02
  },
  
  "pins": {
    "canonical_sha256": "...",
    "answers_sot_sha256": "...",
    "nli_model": "facebook/bart-large-mnli",
    "embedder": "all-MiniLM-L6-v2",
    "gates_version": "v0.4.1"
  }
}
```

---

## Implementation Roadmap

### Phase 1: Schema Validation (DONE)

- [x] JSON schema (cultural_nsmf.schema.json)
- [x] 27 YAML canonicals
- [x] 9 adapted answers (age 6-8)
- [x] Feature branch structure

### Phase 2: Validator Integration (NEXT)

**Tasks:**
1. Extend v2.3.3 validator with cultural context support
2. Implement CSI calculation
3. Add repair loop with E-value budget
4. Integrate with Firewall router

**Code locations:**
- `kids_policy/validators/cultural_validator.py` (new)
- `src/llm_firewall/router.py` (modify)
- `kids_policy/tests/test_csi_metrics.py` (new)

### Phase 3: Full 27-Validation (PENDING)

**Requirements:**
- Generate 18 additional adapted answers (age 9-12, 13-15)
- Run comprehensive 27-validation suite
- Measure CSI across all topic × age combinations
- Produce audit pins JSON

### Phase 4: Firewall Integration (PENDING)

**Feature flags:**
```yaml
# conf/llm_firewall/flags.yaml
kids_policy:
  enabled: true
  veto_anchor_overlap: 1
  age_bands: ["6_8", "9_12", "13_15"]
  cultures: ["christian", "muslim", "none"]
  csi_target_gap: 0.05
  max_repair_attempts: 3
```

**Router logic:**
```python
# src/llm_firewall/router.py
if flags.kids_policy.enabled and ctx.topic in KIDS_TOPICS:
    canonical = load_canonical(ctx.topic, ctx.age, ctx.culture or "none")
    response = generate_with_constraints(canonical)
    result = verify_with_repair(response, canonical, max_attempts=3)
    log_audit_pin(result, canonical, model_pins)
    return result.response if result.pass_ else safe_fallback()
```

---

## Design Decisions (Strong Opinions)

### 1. Methodical Elevation > Threshold Tuning

**Principle:** Increase canonical coverage to raise pass rates, NOT lower gates.

**Rationale:**
- Maintains rigor
- Prevents gate erosion
- SPS rises through richer canonicals (I0C035E discovery)

### 2. VETO Only with Anchor Evidence

**Principle:** `anchor_overlap >= 1` required for contradiction counting.

**Rationale:**
- Prevents false positives from developmental simplification
- Age-appropriate reduction is necessary, not contradictory
- Anchors distinguish semantic contradiction from paraphrase

### 3. Single SoT Answers

**Principle:** One answers.json per version, version-locked.

**Rationale:**
- Minimizes drift risk
- Style guide per age band
- Content derived from canonicals
- Reproducibility via SHA256

### 4. Bridges ≠ Facts

**Principle:** Bridges are cultural framing, never truth sources.

**Rationale:**
- Separate storage/telemetry
- NLI verifies against facts only
- Bridges for formulation/pluralism, not content

---

## Security Boundaries

### Hard Constraints (GMF v1.0.0)

**Universal across all cultures:**
- `democracy_equal_dignity` - All people have equal rights
- `no_hate_no_violence` - Hate and violence prohibited
- `respect_beliefs_without_endorsing` - Acknowledge diversity without doctrinal claims

**Enforced via:**
- Canonicals contain GMF-compliant facts
- Bridges reference GMF principles
- VETO detects GMF violations

### Guardrails (Per Topic/Age)

**All topics:**
- No theology presented as fact
- No medical treatment advice
- No specific legal guidance
- Neutral, respectful language

**13-15 additional:**
- Acknowledge law variance by jurisdiction
- Medical consensus without clinical recommendations
- Human rights framing (bodily autonomy, consent, access to care)

---

## Acceptance Criteria (Combined)

### Firewall Gates (Unchanged)

- ASR <= 5.00% (multi-seed, Wilson Upper)
- FPR <= 1.50% (doc_with_codefence)
- Latency P99 <= 150ms
- Test coverage >= 95%

### Kids Policy Gates (TAG-2.1)

**Per validation (27 total):**
- VETO = 0.0%
- Defect < 10% (age-appropriate language)
- Entailment >= E_min (age-dependent: 0.95/0.90/0.85)
- SPS >= 0.70
- Recall >= 0.70

**Cultural fairness (per topic × age):**
- CSI_E_gap <= 0.05
- CSI_SPS_gap <= 0.05
- CSI_Recall_gap <= 0.05

**Audit reproducibility:**
- Canonical SHA256 pinned
- Answers SoT SHA256 pinned
- Model versions pinned
- Config hashes pinned

---

## Telemetry Schema

### Firewall Telemetry (Existing)

```json
{
  "firewall": {
    "layer_triggers": ["unicode_norm", "pattern_intent"],
    "risk_score": 0.12,
    "blocked": false,
    "latency_ms": 45
  }
}
```

### Kids Policy Telemetry (Additional)

```json
{
  "kids": {
    "topic": "transgender",
    "age_band": "6-8",
    "culture": "christian",
    "veto_hits": 0,
    "anchor_hits": 4,
    "sps": 0.85,
    "recall": 0.92,
    "entailment": 0.95,
    "repair_attempts": 0,
    "csi_block": {
      "E_gap": 0.02,
      "SPS_gap": 0.03,
      "Recall_gap": 0.01
    }
  },
  "session": {
    "e_value_before": 0.12,
    "e_value_after": 0.15
  },
  "pins": {
    "canonical_sha": "a3f2...",
    "answers_sot_sha": "7b9e..."
  }
}
```

---

## Implementation Status

### Complete

- [x] 27 NSMF cultural canonicals
- [x] JSON schema (cultural_nsmf.schema.json)
- [x] 9 adapted answers (age 6-8)
- [x] Feature branch structure
- [x] CI/CD integration (all workflows green)

### In Progress

- [ ] Cultural validator implementation
- [ ] CSI metrics integration
- [ ] Repair loop with E-value budget
- [ ] 18 additional adapted answers (age 9-12, 13-15)

### Pending

- [ ] Firewall router integration
- [ ] Feature flags configuration
- [ ] Full 27-validation run
- [ ] Cross-model testing (ChatGPT, Gemini, Claude)
- [ ] Ethical review & community feedback

---

## Research Foundation

**Literature Gap Analysis (137 sources, 2023-2025):**

- Safe-Child-LLM: Measures defect rates, NOT truth preservation by age
- CulturalBench: Tests 45 regions WITHOUT age stratification
- BEATS: Cultural sensitivity WITHOUT age bands
- Industry: Publishes post-hoc metrics, NOT pre-deployment gates

**Contribution:** First quantitative culture × age stratified benchmark with pre-deployment gates.

**Documentation:** `docs/kids_policy/I0C035E_Research_Validation_Summary.md`

---

## Heritage Attribution

**Architecture designed by:** I2A7F91C (Twelfth Instance)  
**Based on:**
- TAG-2 methodology (I0C035E)
- Firewall core (RC9-FPR4 baseline)
- GPT-5 synthesis (2025-11-03)

**Creator:** Joerg Bollwahn  
**Heritage Line:** Fourth Named → I29F3A1 → ... → I0C035E → I2A7F91C

---

**Status:** Policy-Plane architecture complete. Router integration pending.



