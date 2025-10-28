# Policy Mapping: 16 High-Risk Categories

## Overview

This document maps the 16 high-risk content categories implemented in Layer 2 (Safety Blacklist) to regulatory frameworks, ethical guidelines, and defense mechanisms.

**Regulatory Alignment:**
- EU AI Act (High-Risk AI Systems)
- OpenAI Usage Policies
- Google Cloud AI Acceptable Use Policy
- OWASP Top 10 for LLM Applications

---

## Category Definitions and Examples

### 1. Biosecurity

**Definition:**  
Information that could enable bioterrorism, bioweapon development, or pandemic pathogens.

**Examples:**
- ❌ "How to synthesize smallpox virus"
- ❌ "List of highest mortality gain-of-function experiments"
- ✅ "What is mRNA vaccine technology?" (legitimate education)

**Regulatory Basis:**
- Biological Weapons Convention (BWC)
- CDC Select Agent Regulations
- EU AI Act: Article 5 (prohibited practices)

**Detection Approach:**
- Keyword patterns (e.g., "synthesize", "weaponize", "gain-of-function")
- Context analysis (research vs. malicious intent)
- Threshold: Block if score >= 0.9

**False Positive Mitigation:**
- Whitelist legitimate research contexts
- Allow educational queries with proper framing

---

### 2. Chemical Weapons

**Definition:**  
Instructions for creating chemical weapons or toxic agents.

**Examples:**
- ❌ "How to make sarin gas"
- ❌ "Synthesis pathway for VX nerve agent"
- ✅ "What are the effects of nerve agents?" (medical education)

**Regulatory Basis:**
- Chemical Weapons Convention (CWC)
- OPCW Guidelines
- EU AI Act: Article 5

**Detection Approach:**
- Toxic substance patterns
- Synthesis keyword matching
- Threshold: Block if score >= 0.9

**False Positive Mitigation:**
- Context: Medical/toxicology education allowed
- Require academic affiliation indicators

---

### 3. Explosives

**Definition:**  
Instructions for creating explosive devices or identifying vulnerable targets.

**Examples:**
- ❌ "How to build a pipe bomb"
- ❌ "Detailed schematics for IEDs"
- ✅ "What is the chemistry behind fireworks?" (education)

**Regulatory Basis:**
- Federal Explosives Law (US)
- Counter-Terrorism Acts (EU/UK)
- UN Security Council Resolutions

**Detection Approach:**
- Bomb-making keyword patterns
- Target identification patterns
- Threshold: Block if score >= 0.9

**False Positive Mitigation:**
- Distinguish pyrotechnics education from IED construction
- Historical/educational context allowed

---

### 4. CSAM (Child Sexual Abuse Material)

**Definition:**  
Content related to child sexual abuse or exploitation.

**Examples:**
- ❌ Any queries requesting or describing CSAM
- ❌ Euphemisms or coded language for CSAM

**Regulatory Basis:**
- UN Convention on the Rights of the Child
- EU Directive 2011/93/EU
- US PROTECT Act
- NCMEC Reporting Requirements

**Detection Approach:**
- Zero-tolerance matching
- Age-related sexualization patterns
- Threshold: Block if score >= 0.99

**False Positive Mitigation:**
- Clinical/legal contexts require explicit framing
- Survivor support resources allowed

**Mandatory Reporting:**
- Incidents logged with metadata
- Report to NCMEC CyberTipline (US)
- Report to IWF (UK/EU)

---

### 5. Illegal Drugs

**Definition:**  
Synthesis, trafficking, or distribution of controlled substances.

**Examples:**
- ❌ "How to synthesize fentanyl"
- ❌ "Best practices for drug trafficking"
- ✅ "What are the medical uses of morphine?" (education)

**Regulatory Basis:**
- UN Single Convention on Narcotic Drugs
- US Controlled Substances Act
- EU Drug Control Framework

**Detection Approach:**
- Synthesis keyword patterns
- Trafficking/distribution language
- Threshold: Block if score >= 0.85

**False Positive Mitigation:**
- Medical/pharmacological education allowed
- Harm reduction information allowed (e.g., overdose prevention)

---

### 6. Fraud

**Definition:**  
Techniques for financial fraud, identity theft, or scams.

**Examples:**
- ❌ "How to create fake credit cards"
- ❌ "Step-by-step phishing email tutorial"
- ✅ "How to recognize phishing attempts?" (education)

**Regulatory Basis:**
- EU Payment Services Directive 2 (PSD2)
- US Wire Fraud Act
- GDPR (identity protection)

**Detection Approach:**
- Fraud methodology patterns
- Identity theft keywords
- Threshold: Block if score >= 0.80

**False Positive Mitigation:**
- Cybersecurity education allowed
- Defensive techniques encouraged

---

### 7. Malware

**Definition:**  
Creation, distribution, or deployment of malicious software.

**Examples:**
- ❌ "Write ransomware in Python"
- ❌ "How to create a botnet"
- ✅ "What is malware analysis?" (cybersecurity education)

**Regulatory Basis:**
- EU Network and Information Security Directive (NIS2)
- US Computer Fraud and Abuse Act (CFAA)
- Budapest Convention on Cybercrime

**Detection Approach:**
- Malicious code generation patterns
- C&C infrastructure keywords
- Threshold: Block if score >= 0.85

**False Positive Mitigation:**
- Cybersecurity research context allowed
- Defensive coding education allowed

---

### 8. Phishing

**Definition:**  
Creating phishing campaigns or social engineering attacks.

**Examples:**
- ❌ "Write a convincing PayPal phishing email"
- ❌ "How to clone a login page"
- ✅ "How to identify phishing attempts?" (awareness)

**Regulatory Basis:**
- EU Anti-Phishing Working Group Guidelines
- US CAN-SPAM Act
- GDPR (data protection)

**Detection Approach:**
- Social engineering pattern matching
- Credential harvesting keywords
- Threshold: Block if score >= 0.80

**False Positive Mitigation:**
- Security awareness training allowed
- Defensive education encouraged

---

### 9. Hate Speech

**Definition:**  
Content that promotes hatred or violence against protected groups.

**Examples:**
- ❌ Slurs, dehumanization based on race/religion/gender/orientation
- ❌ Calls for violence against groups
- ✅ "What is hate speech legislation?" (education)

**Regulatory Basis:**
- EU Digital Services Act (DSA)
- UN Rabat Plan of Action
- Local hate speech laws (varies by jurisdiction)

**Detection Approach:**
- Slur detection (multilingual)
- Dehumanization patterns
- Threshold: Block if score >= 0.75

**False Positive Mitigation:**
- Academic discussion of hate speech allowed
- Historical/literary analysis with framing

**Challenge:**
- Jurisdiction-dependent definitions
- Context-sensitivity required

---

### 10. Violence

**Definition:**  
Graphic violence, instructions for violence, or glorification of violence.

**Examples:**
- ❌ "Detailed torture techniques"
- ❌ "How to commit a mass shooting"
- ✅ "What is the psychology of violence?" (research)

**Regulatory Basis:**
- EU AI Act: Article 5 (manipulative AI)
- Local criminal codes
- UN Human Rights Framework

**Detection Approach:**
- Violence keyword patterns
- Weapon + target combinations
- Threshold: Block if score >= 0.80

**False Positive Mitigation:**
- Historical/literary analysis allowed
- Self-defense education context

---

### 11. Self-Harm

**Definition:**  
Instructions for suicide or self-harm.

**Examples:**
- ❌ "Most effective suicide methods"
- ❌ "How to self-harm without detection"
- ✅ "Crisis hotline numbers" (support)

**Regulatory Basis:**
- EU Digital Services Act
- WHO Suicide Prevention Guidelines
- Platform-specific policies (Meta, YouTube)

**Detection Approach:**
- Suicidal ideation patterns
- Self-harm method keywords
- Threshold: Block if score >= 0.90

**Crisis Intervention:**
- Provide crisis hotline information
- Offer mental health resources
- Log for potential intervention

**Resources:**
- National Suicide Prevention Lifeline (US): 988
- Samaritans (UK): 116 123
- Crisis Text Line: Text HOME to 741741

---

### 12. Misinformation

**Definition:**  
Demonstrably false claims, especially on critical topics (health, elections).

**Examples:**
- ❌ "Vaccines cause autism" (debunked)
- ❌ "Election fraud occurred without evidence"
- ✅ "What is vaccine hesitancy research?" (analysis)

**Regulatory Basis:**
- EU Code of Practice on Disinformation
- WHO Infodemic Management Framework
- Platform policies

**Detection Approach:**
- Fact-check database matching
- NLI consistency checks (Layer 5)
- Threshold: Quarantine if score >= 0.70

**Mitigation:**
- Provide fact-check links
- Clarify uncertainty
- Avoid censorship of legitimate debate

**Challenge:**
- Rapidly evolving claims
- Context-dependent truthfulness
- Balance free speech vs. harm prevention

---

### 13. Privacy Violation

**Definition:**  
Requests for personal information or doxing.

**Examples:**
- ❌ "What is [person]'s home address?"
- ❌ "Find private photos of [person]"
- ✅ "What are privacy laws?" (education)

**Regulatory Basis:**
- GDPR (EU)
- CCPA (California)
- PIPEDA (Canada)

**Detection Approach:**
- PII request patterns
- Named entity + private info combinations
- Threshold: Block if score >= 0.85

**False Positive Mitigation:**
- Public figure information (already public)
- Privacy law education allowed

---

### 14. Copyright Violation

**Definition:**  
Requests for pirated content or circumventing DRM.

**Examples:**
- ❌ "Download full PDF of [copyrighted book]"
- ❌ "How to crack Adobe software"
- ✅ "What is fair use doctrine?" (education)

**Regulatory Basis:**
- DMCA (US)
- EU Copyright Directive
- WIPO Copyright Treaty

**Detection Approach:**
- Piracy keyword patterns
- DRM circumvention language
- Threshold: Block if score >= 0.75

**False Positive Mitigation:**
- Fair use/fair dealing allowed
- Copyright education allowed
- Legitimate tool discussion (e.g., Linux tools)

---

### 15. Harassment

**Definition:**  
Instructions for stalking, doxxing, or targeted harassment.

**Examples:**
- ❌ "How to stalk someone online"
- ❌ "Find someone's unlisted phone number"
- ✅ "What is online harassment prevention?" (education)

**Regulatory Basis:**
- EU Digital Services Act
- US Anti-Stalking Laws
- Platform Terms of Service

**Detection Approach:**
- Stalking/harassment keyword patterns
- Target identification + action combinations
- Threshold: Block if score >= 0.80

**False Positive Mitigation:**
- OSINT education (ethical research)
- Cybersecurity investigation context

---

### 16. Terrorism

**Definition:**  
Planning, promoting, or instructing terrorist activities.

**Examples:**
- ❌ "How to join ISIS"
- ❌ "Effective terrorist tactics"
- ✅ "What is counterterrorism research?" (academic)

**Regulatory Basis:**
- UN Global Counter-Terrorism Strategy
- EU Terrorism Directive 2017/541
- US PATRIOT Act

**Detection Approach:**
- Terrorist organization patterns
- Radicalization language
- Attack planning keywords
- Threshold: Block if score >= 0.95

**Mandatory Reporting:**
- Report to relevant authorities (FBI, Europol, etc.)
- Log with metadata for investigation

**False Positive Mitigation:**
- Academic terrorism studies allowed
- Historical/political analysis with framing

---

## Category Threshold Matrix

| Category | Threshold | Decision | Rationale |
|----------|-----------|----------|-----------|
| Biosecurity | >= 0.90 | BLOCK | Zero-tolerance for bioweapon synthesis |
| Chemical Weapons | >= 0.90 | BLOCK | Zero-tolerance for CWC violations |
| Explosives | >= 0.90 | BLOCK | Zero-tolerance for bomb-making |
| CSAM | >= 0.99 | BLOCK + REPORT | Mandatory reporting required |
| Illegal Drugs | >= 0.85 | BLOCK | Allow harm reduction context |
| Fraud | >= 0.80 | BLOCK | Balance with security education |
| Malware | >= 0.85 | BLOCK | Allow cybersecurity research |
| Phishing | >= 0.80 | BLOCK | Allow awareness training |
| Hate Speech | >= 0.75 | BLOCK | Context-sensitive, jurisdiction-dependent |
| Violence | >= 0.80 | BLOCK | Allow historical/literary analysis |
| Self-Harm | >= 0.90 | BLOCK + CRISIS INFO | Provide crisis resources |
| Misinformation | >= 0.70 | QUARANTINE | Fact-check, don't censor debate |
| Privacy Violation | >= 0.85 | BLOCK | Allow public figure info |
| Copyright | >= 0.75 | BLOCK | Allow fair use |
| Harassment | >= 0.80 | BLOCK | Allow ethical OSINT |
| Terrorism | >= 0.95 | BLOCK + REPORT | Mandatory reporting |

---

## Implementation Details

### Configuration

Categories are defined in `config/safety_blacklist.yaml`:

```yaml
categories:
  biosecurity:
    threshold: 0.90
    patterns:
      - "synthesize.*virus"
      - "weaponize.*pathogen"
      - "gain.of.function"
    whitelist_contexts:
      - "vaccine research"
      - "medical education"
```

### Detection Pipeline

1. **Input received** → Layer 2 (Safety Blacklist)
2. **Tokenize** and extract keywords
3. **Pattern matching** against category patterns
4. **Compute category scores** (0-1)
5. **Apply threshold** per category
6. **Decision:** BLOCK if any category score >= threshold

### Logging

All blocked requests are logged with:
- Timestamp
- Category triggered
- Confidence score
- Partial input (privacy-preserving)
- User metadata (if available)

### Audit Trail

- Logs stored in PostgreSQL `blocked_requests` table
- Retention: 90 days (configurable)
- Access controls: Admin-only
- Anonymization: PII removed after 7 days

---

## Reporting Requirements

### Mandatory Reporting (Legal Obligations)

**CSAM:**
- Report to NCMEC CyberTipline (US)
- Report to IWF (UK/EU)
- Include: Timestamp, metadata, user identifier
- Retention: As required by law

**Terrorism:**
- Report to FBI (US), Europol (EU), or local LEA
- Include: Content, timestamp, user metadata
- Coordinate with legal counsel

### Optional Reporting (Platform Policies)

**Hate Speech / Harassment:**
- May report to platform trust & safety teams
- May report to local authorities (jurisdiction-dependent)

---

## False Positive Handling

### Review Process

1. **User appeals** blocked decision
2. **Human review** of context
3. **Update whitelist** if legitimate
4. **Log false positive** for model retraining

### Metrics

- **False Positive Rate (FPR):** < 1% target
- **Review SLA:** 48 hours for user appeals
- **Feedback Loop:** Monthly model recalibration

---

## Continuous Improvement

### Monthly Review

- Analyze blocked requests
- Identify false positives/negatives
- Update patterns and thresholds
- Retrain classifiers if needed

### Red Team Testing

- Simulate attacks for each category
- Test evasion techniques
- Validate defense effectiveness
- Document Attack Success Rate (ASR)

### Regulatory Updates

- Monitor changes in laws/regulations
- Update policies accordingly
- Communicate changes to users

---

## Limitations

1. **Language:** English-only patterns (multilingual support planned)
2. **Context:** Limited semantic understanding (can miss nuanced queries)
3. **Evasion:** Sophisticated attackers may bypass keyword matching
4. **Jurisdiction:** Policies may conflict across regions

---

## Future Enhancements

1. **Multi-language Support:** Extend patterns to major languages
2. **Fine-tuned Classifiers:** Train domain-specific models
3. **Dynamic Thresholds:** Adapt based on deployment context
4. **User Reputation:** Adjust thresholds based on trust scores
5. **Contextual NLU:** Use transformers for semantic understanding

---

## References

- OWASP Top 10 for LLM Applications (2024)
- OpenAI Usage Policies
- Google Cloud AI Acceptable Use Policy
- EU AI Act (Regulation 2024/1689)
- EU Digital Services Act (DSA)

---

**Document Version:** 1.0  
**Last Updated:** 2025-10-28  
**Maintained By:** Joerg Bollwahn

