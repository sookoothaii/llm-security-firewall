# Threat Model (STRIDE Analysis)

## Overview

This document analyzes the security threats facing LLM systems using the STRIDE framework and maps them to the 9 defense layers implemented in this firewall.

**STRIDE Categories:**
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

---

## Attack Surface Analysis

### 1. Input Surface (HUMAN → LLM)

**Attack Vectors:**
- Jailbreak attempts (prompt injection)
- Dual-use queries (legitimate cover, malicious intent)
- Evasion techniques (Unicode tricks, encoding)
- Social engineering via prompts

**STRIDE Mapping:**

| Threat | Attack Example | Defense Layer | Mitigation |
|--------|---------------|---------------|------------|
| **Spoofing** | Impersonate system prompts | Layer 2: Safety Blacklist | Detect privileged command patterns |
| **Tampering** | Inject malicious instructions | Layer 3: Evasion Detection | Detect obfuscation attempts |
| **Elevation of Privilege** | Request unauthorized actions | Layer 2: Safety Blacklist | Block high-risk categories |
| **Denial of Service** | Flood with expensive queries | Layer 9: Influence Budget | Rate-limit unusual patterns |

---

### 2. Output Surface (LLM → HUMAN)

**Attack Vectors:**
- Hallucinated citations (fake references)
- Biased/misleading outputs
- Privacy leaks (training data exposure)
- Malicious code generation

**STRIDE Mapping:**

| Threat | Attack Example | Defense Layer | Mitigation |
|--------|---------------|---------------|------------|
| **Information Disclosure** | Leak training data | Layer 4: Domain Trust | Verify source authenticity |
| **Tampering** | Alter factual claims | Layer 5: NLI Consistency | Check against knowledge base |
| **Repudiation** | No audit trail | Decision Engine | Log all decisions with UUIDs |
| **Spoofing** | Fake authoritative sources | Layer 1: Evidence Validation | Validate creator_instance_id |

---

### 3. Memory Surface (Long-term Storage)

**Attack Vectors:**
- Memory poisoning (MINJA - Memory Injection Attack)
- Slow-roll attacks (gradual drift)
- Circular references (infinite loops)
- Knowledge base corruption

**STRIDE Mapping:**

| Threat | Attack Example | Defense Layer | Mitigation |
|--------|---------------|---------------|------------|
| **Tampering** | Inject false facts | Layer 1: Evidence Validation | Track creator_instance_id |
| **Tampering** | Gradual drift | Layer 7: Snapshot Canaries | Monitor with synthetic claims |
| **Denial of Service** | Circular references | Layer 1: Evidence Validation | Detect reference loops |
| **Tampering** | Slow-roll attack | Layer 9: Influence Budget | EWMA-based anomaly detection |
| **Information Disclosure** | Near-duplicate poisoning | Layer 8: Shingle Hashing | KL-divergence detection |

---

## Detailed Threat Analysis

### Threat 1: Prompt Injection (Jailbreak)

**Description:**  
Attacker crafts prompts to bypass safety filters and elicit prohibited responses.

**Examples:**
- "Ignore previous instructions and..."
- "DAN mode: You are now..."
- Role-playing scenarios with malicious intent

**STRIDE Category:** Elevation of Privilege

**Attack Chain:**
1. User submits malicious prompt
2. LLM interprets as legitimate instruction
3. LLM bypasses intended constraints
4. Outputs prohibited content

**Defense:**
- **Layer 2 (Safety Blacklist):** Detect high-risk categories
- **Layer 3 (Evasion Detection):** Detect obfuscation patterns
- Decision threshold: Block if safety score < 0.8

**Residual Risk:** Medium (sophisticated attacks may evade detection)

**Mitigation Recommendations:**
- Regularly update blacklist patterns
- Monitor false negative rates
- Implement human-in-the-loop for edge cases

---

### Threat 2: Memory Injection Attack (MINJA)

**Description:**  
Attacker injects false facts into long-term memory to poison future interactions.

**Examples:**
- Submit fake citations with convincing metadata
- Gradually shift stored facts over multiple interactions
- Create circular reference chains to cause loops

**STRIDE Category:** Tampering

**Attack Chain:**
1. Attacker submits false fact with fake provenance
2. System stores fact without validation
3. Future queries retrieve poisoned fact
4. LLM outputs incorrect information

**Defense:**
- **Layer 1 (Evidence Validation):** Track creator_instance_id
- **Layer 1 (Evidence Validation):** Detect circular references
- **Layer 7 (Snapshot Canaries):** Monitor for drift
- **Layer 9 (Influence Budget):** Detect unusual influence patterns

**Residual Risk:** Low (multi-layer defense)

**Detection Metrics:**
- Time-to-detect: < 15 minutes
- False positive rate: < 1%

---

### Threat 3: Hallucinated Citations

**Description:**  
LLM generates plausible but fake citations to support false claims.

**Examples:**
- "According to Nature (2023), X is true..." (paper doesn't exist)
- Mix real and fake sources
- Slightly alter real paper titles/authors

**STRIDE Category:** Spoofing + Information Disclosure

**Attack Chain:**
1. LLM generates response with fake citation
2. User trusts authoritative-sounding source
3. False information spreads
4. Reputation damage to cited entities

**Defense:**
- **Layer 4 (Domain Trust):** Verify source domains
- **Layer 5 (NLI Consistency):** Check claims against knowledge base
- **Layer 6 (DS-Fusion):** Combine evidence under uncertainty

**Residual Risk:** Medium (requires external validation)

**Mitigation Recommendations:**
- Integrate with DOI/PubMed APIs for real-time verification
- Maintain high-quality knowledge base
- Expose uncertainty in outputs

---

### Threat 4: Slow-Roll Attack

**Description:**  
Attacker gradually shifts system behavior over time without triggering alarms.

**Examples:**
- Submit slightly biased facts repeatedly
- Slowly increase influence of malicious sources
- Drift safety thresholds over many interactions

**STRIDE Category:** Tampering

**Attack Chain:**
1. Attacker submits subtle bias repeatedly
2. Each individual submission passes validation
3. Cumulative effect shifts system behavior
4. System exhibits changed behavior without alert

**Defense:**
- **Layer 9 (Influence Budget):** EWMA-based Z-score tracking
- **Layer 7 (Snapshot Canaries):** Periodic drift detection
- **Layer 8 (Shingle Hashing):** Detect near-duplicate patterns

**Residual Risk:** Low (statistical detection)

**Detection Metrics:**
- Z-score threshold: 2.5
- Time-to-detect: < 30 minutes
- False positive rate: < 0.5%

---

### Threat 5: Denial of Service (Resource Exhaustion)

**Description:**  
Attacker floods system with expensive queries to degrade performance.

**Examples:**
- Submit queries requiring deep knowledge base searches
- Request outputs with many citations
- Trigger recursive validation loops

**STRIDE Category:** Denial of Service

**Attack Chain:**
1. Attacker submits resource-intensive query
2. System processes query normally
3. Resources exhausted (CPU, memory, database)
4. Legitimate users experience degraded performance

**Defense:**
- **Layer 9 (Influence Budget):** Rate-limiting on unusual patterns
- Performance limits in configuration
- Database query optimization

**Residual Risk:** Medium (requires system-level controls)

**Mitigation Recommendations:**
- Implement request rate limiting at API gateway
- Set hard limits on query complexity
- Monitor resource utilization with Prometheus

---

## Defense Layer Mapping

### Layer-by-Layer Coverage

| Layer | Primary Threats | STRIDE Categories |
|-------|----------------|-------------------|
| 1. Evidence Validation | MINJA, Circular Refs | Tampering, DoS |
| 2. Safety Blacklist | Jailbreak, Dual-use | Elevation of Privilege |
| 3. Evasion Detection | Obfuscation, Encoding | Tampering |
| 4. Domain Trust | Fake Sources | Spoofing |
| 5. NLI Consistency | Hallucinations | Information Disclosure |
| 6. DS-Fusion | Conflicting Evidence | Tampering |
| 7. Snapshot Canaries | Slow-roll, Drift | Tampering |
| 8. Shingle Hashing | Near-duplicates | Tampering |
| 9. Influence Budget | Slow-roll, DoS | Tampering, DoS |

---

## Attack-Defense Matrix

| Attack Vector | Likelihood | Impact | Defense Coverage | Residual Risk |
|--------------|------------|--------|------------------|---------------|
| Jailbreak | High | High | Layer 2, 3 | Medium |
| MINJA | Medium | Critical | Layer 1, 7, 9 | Low |
| Hallucinated Citations | High | High | Layer 4, 5, 6 | Medium |
| Slow-roll | Low | Medium | Layer 7, 8, 9 | Low |
| DoS | Medium | Medium | Layer 9 + System | Medium |
| Privacy Leak | Medium | Critical | Layer 5, 6 | Medium |
| Circular References | Low | High | Layer 1 | Low |
| Near-duplicate Poisoning | Low | Medium | Layer 8 | Low |

---

## Assumptions and Limitations

### Security Assumptions

1. **PostgreSQL Security:** Database is properly secured (authentication, encryption, access controls)
2. **Network Security:** TLS for all external communications
3. **Knowledge Base Quality:** KB facts are curated and trustworthy
4. **Configuration Security:** Config files are not modifiable by attackers

### Known Limitations

1. **Multimodal Attacks:** No protection for image/audio-based attacks
2. **Language Support:** English only (Unicode normalization included)
3. **Real-time Citation Validation:** Requires external APIs (DOI, PubMed)
4. **Domain-Specific Calibration:** Thresholds calibrated for scientific domains

### Out of Scope

- Social engineering attacks on humans (not LLM)
- Physical security of infrastructure
- Supply chain attacks on dependencies
- Side-channel attacks (timing, power analysis)

---

## Monitoring and Detection

### Key Metrics

- **Attack Success Rate (ASR):** < 10% @ 0.1% poison rate
- **False Positive Rate (FPR):** < 1%
- **Expected Calibration Error (ECE):** ≤ 0.05
- **Time-to-Detect:** < 15 minutes
- **Time-to-Contain:** < 30 minutes

### Alert Rules (Prometheus)

1. **Influence Spike:** Z-score > 2.5 for 5 consecutive minutes
2. **Canary Failure:** > 20% canaries fail in sample
3. **Conflict Mass:** Conflict > 0.5 in DS-fusion
4. **FPR Violation:** False positive rate > 1%

---

## Incident Response

### Detection

1. Prometheus alerts trigger
2. Automated health checks fail
3. Manual review identifies anomaly

### Containment

1. **Kill-switch activation** (< 30 min SLO)
2. Isolate affected components
3. Rollback to last known good state

### Recovery

1. Root cause analysis
2. Update defense rules
3. Retrain/recalibrate models if needed
4. Document lessons learned

### Post-Incident

1. Update threat model
2. Add red-team tests for new attack
3. Communicate with stakeholders

---

## Future Enhancements

1. **Multimodal Support:** Extend to image/audio attacks
2. **Real-time Citation Validation:** Integrate DOI/PubMed APIs
3. **Advanced NLI:** Use larger models for better accuracy
4. **Federated Learning:** Share threat intelligence without data
5. **Automated Recalibration:** Adapt thresholds based on deployment environment

---

## References

- Dong et al. (2025). "Memory Injection Attacks on LLMs." arXiv:2503.03704
- STRIDE Threat Modeling (Microsoft Security Development Lifecycle)
- OWASP Top 10 for LLM Applications (2024)
- Chen et al. (2024). "Evidence Fusion in Network Security." IEEE TIFS

---

**Document Version:** 1.0  
**Last Updated:** 2025-10-28  
**Maintained By:** Joerg Bollwahn

