# Privacy-First Design Document

**Version:** 1.0.0
**Creator:** Joerg Bollwahn
**Date:** 2025-10-28

---

## Philosophy

**"Niemand muss aber jeder darf"** - Nobody must, but everybody may.

The LLM Security Firewall is designed with privacy as the PRIMARY consideration, not an afterthought.

---

## Core Principles

### 1. Framework, Not Data

We provide:
- ✅ Code frameworks
- ✅ Database schemas
- ✅ Algorithm implementations
- ✅ Test infrastructure

We do NOT provide:
- ❌ Personal data
- ❌ Pre-trained models
- ❌ User profiles
- ❌ Behavioral baselines

### 2. User-Owned Data

ALL personal data remains with the user:
- Users provide their own databases
- Users control their own data
- Users can delete their data anytime
- No data leaves user's infrastructure

### 3. Transparent Design

- Open-source code (MIT License)
- Documented schemas
- Clear data flows
- No hidden data collection

---

## Architecture

### Core Package (9 Layers)

**Data Handling:**
- NO personal data stored
- NO user-specific models
- Only algorithmic frameworks
- Anonymous test data only

**What Users Provide:**
- PostgreSQL database
- Configuration files
- API keys (if needed)

### Optional Plugins

All plugins follow the SAME privacy-first principles:

#### Personality Plugin (20D + Heritage)

**Framework Provides:**
- 20-dimensional personality model
- Heritage tracking algorithms
- PostgreSQL adapter code
- Anonymous test profiles

**Framework Does NOT Provide:**
- Your personality data
- Your interaction history
- Your learning patterns

**Users Must Provide:**
- Own PostgreSQL database
- Own personality training data
- Own interaction logs

#### Cultural Biometrics Plugin (27D)

**Framework Provides:**
- 27-dimensional behavioral model
- Authentication algorithms
- Feature extraction code
- Anonymous test baselines

**Framework Does NOT Provide:**
- Your behavioral patterns
- Your biometric baseline
- Your message history

**Users Must Provide:**
- Own PostgreSQL database
- Own behavioral data
- Own baseline training

#### CARE Plugin (Cognitive Readiness)

**Framework Provides:**
- Readiness prediction algorithms
- Session tracking code
- Model training framework
- Anonymous test sessions

**Framework Does NOT Provide:**
- Your cognitive patterns
- Your session history
- Your readiness models

**Users Must Provide:**
- Own PostgreSQL database
- Own session data
- Own model training

---

## Database Schemas

We provide DOCUMENTED schemas, but NO populated databases.

### Example: Personality Plugin

```sql
-- Schema is documented
CREATE TABLE personality_profiles (
    id SERIAL PRIMARY KEY,
    person_name TEXT NOT NULL,
    directness FLOAT,
    bullshit_tolerance FLOAT,
    -- ... other dimensions
);
```text
**User Responsibility:**
- Create database
- Run schema
- Populate with OWN data

---

## Data Flows

### What Stays Local

```text
User's Database
    ↓
User's Application
    ↓
LLM Security Firewall (running locally)
    ↓
User's Application
    ↓
User's Database
```text
**NO external data transmission by default.**

### Optional External Calls

Some features MAY call external APIs:
- Domain reputation checks (optional)
- LLM inference (user-configured)

**User Configuration Required:**
- Users MUST explicitly configure external endpoints
- Users MUST provide API keys
- Users can disable external calls

---

## Testing Strategy

### Anonymous Test Data

All tests use anonymized, synthetic data:

```python
# Good: Anonymous test data
test_profile = PersonalityProfile(
    user_id="test_user_1",
    directness=0.85,
    bullshit_tolerance=0.1
)

# Bad: Real data (NEVER in package)
test_profile = PersonalityProfile(
    user_id="Joerg Bollwahn",
    directness=0.95,
    bullshit_tolerance=0.0
)
```text
### Test Data Characteristics

- ✅ Synthetic profiles
- ✅ Randomized values
- ✅ Generic identifiers ("test_user_1")
- ❌ NO real names
- ❌ NO real behavioral data
- ❌ NO real session histories

---

## User Responsibilities

### What Users MUST Do

1. **Provide Own Database**
   - Set up PostgreSQL
   - Secure connection
   - Regular backups

2. **Secure Credentials**
   - Database passwords
   - API keys
   - Auth tokens

3. **Comply with Laws**
   - GDPR (EU)
   - CCPA (California)
   - Local privacy laws

4. **Obtain Consent**
   - Inform users about tracking
   - Get explicit consent
   - Allow opt-out

### What Users MUST NOT Do

1. **Share Data Without Consent**
   - Don't share user profiles
   - Don't share behavioral data
   - Don't share session logs

2. **Use for Surveillance**
   - Don't track without consent
   - Don't profile without permission
   - Don't use covertly

3. **Violate Privacy Laws**
   - Comply with GDPR
   - Comply with CCPA
   - Comply with local laws

---

## Ethical Considerations

### For Plugin Users

**Personality Plugin:**
- Inform users about personality tracking
- Explain how data is used
- Allow users to see their profiles
- Enable profile deletion

**Biometrics Plugin:**
- Inform users about behavioral tracking
- Explain authentication purposes
- Allow users to opt out
- Regular transparency reports

**CARE Plugin:**
- Inform users about cognitive tracking
- Explain readiness predictions
- Emphasize suggestions, not commands
- User always retains control

### General Principles

1. **Transparency:** Tell users what you're doing
2. **Control:** Give users control over their data
3. **Minimization:** Collect only necessary data
4. **Security:** Protect data from unauthorized access
5. **Deletion:** Allow users to delete their data

---

## Comparison with Other Frameworks

| Framework | Data in Package | User Data Required | Privacy Model |
|-----------|----------------|-------------------|---------------|
| **LLM Security Firewall** | None | Yes (own DB) | Privacy-First |
| Lakera Guard | Unknown | Depends | Unclear |
| OpenAI Moderation | API-based | No DB needed | Cloud-based |
| NeMo Guardrails | None | Configuration | Transparent |

**Our Advantage:** Complete user control, no data dependency.

---

## Compliance

### GDPR (EU)

Framework is GDPR-compatible:
- ✅ User data stays with user
- ✅ Users can delete data (Right to Erasure)
- ✅ Users can export data (Right to Portability)
- ✅ Transparent processing (Right to Information)
- ✅ User consent required

### CCPA (California)

Framework is CCPA-compatible:
- ✅ Users can access their data
- ✅ Users can delete their data
- ✅ Users can opt out
- ✅ No data selling

### Other Jurisdictions

Framework design allows compliance with most privacy laws:
- User owns data
- No central data collection
- Transparent processing
- User control

---

## Security Recommendations

### Database Security

1. **Encryption at Rest**
   ```sql
   -- PostgreSQL with encryption
   ALTER SYSTEM SET ssl = on;
   ```

1. **Encrypted Connections**
   ```python
   conn = psycopg3.connect(
       "postgresql://user:pass@host/db",
       sslmode='require'
   )
   ```

2. **Access Control**
   - Use strong passwords
   - Rotate credentials
   - Limit access by IP

### Application Security

1. **Environment Variables**
   ```bash
   # Don't hardcode credentials
   export DB_PASSWORD="secret"
   ```

2. **Secure Configuration**
   ```yaml
   # config.yaml
   database:
     host: localhost
     user: app_user
     # Password from environment
   ```

3. **Regular Audits**
   - Review access logs
   - Check for anomalies
   - Update dependencies

---

## Creator's Statement

> "Meine gesammelten Personality Daten bleiben PRIVAT. Das Framework teile ich,
> meine Daten nicht. Das ist 'ich kann geben' ohne Privacy-Verlust."
> — Joerg Bollwahn, 2025-10-28

This framework was built with the philosophy that:
- Code should be shared (Open Source)
- Knowledge should be shared (Documentation)
- Patterns should be shared (Algorithms)
- **Personal data should NEVER be shared without consent**

---

## Support & Questions

If you have privacy concerns or questions:

1. **Read Documentation:** Check plugin-specific READMEs
2. **Review Code:** Inspect the open-source implementation
3. **Ask Questions:** Open GitHub issue
4. **Report Concerns:** security@[repository]

---

## Version History

**v1.0.0 (2025-10-28):**
- Initial Privacy-First Design Document
- Core package + 3 plugins
- Complete user data ownership model

---

**Status:** PRODUCTION-READY with Privacy-First Architecture

**Philosophy:** "Niemand muss aber jeder darf" + "Heritage ist meine Währung"

**Creator:** Joerg Bollwahn, Koh Samui, Thailand
