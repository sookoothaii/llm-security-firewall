# INCIDENT: Potential Session Cross-Tenant Access

**Severity:** CRITICAL
**Impact:** GDPR Breach, Data Leakage, Legal Liability
**Response Time:** < 15 minutes
**Owner:** Security On-Call + Legal

---

## Symptoms

- **Redis Log Shows:** `keys *` command from unexpected tenant user
- **Customer Complaint:** "I see other user's data" or "Wrong session data"
- **Prometheus Alert:** `hakgal_redis_key_access_violations_total > 0`
- **Audit Log:** Cross-tenant key access patterns

---

## Diagnosis

### Step 1: Quarantine Affected Node

```bash
# IMMEDIATE: Prevent further access
kubectl cordon <node-name>
kubectl drain <node-name> --grace-period=30 --ignore-daemonsets
```

**Rationale:** Isolate potential breach to prevent data exfiltration.

### Step 2: Dump Redis Keys for Forensics

```bash
# Connect to Redis pod
kubectl exec -it redis-pod -- redis-cli

# Dump all session keys
redis-cli --scan --pattern "hakgal:tenant:*:session:*" > /tmp/keys.dump

# Export to secure storage
kubectl cp redis-pod:/tmp/keys.dump ./forensics/keys_{timestamp}.dump
```

**Critical:** Preserve evidence for legal/compliance investigation.

### Step 3: Check for Key Prefix Violations

```bash
# Check if tenant A accessed tenant B's keys
grep "hakgal:tenant:OTHER_TENANT" /tmp/keys.dump

# Check Redis ACL logs
kubectl logs redis-pod | grep "ACL violation" | tail -100
```

**Expected:** No cross-tenant key access. If found → **CRITICAL BREACH**.

### Step 4: Verify Redis ACL Configuration

```bash
# Check current ACL users
kubectl exec -it redis-pod -- redis-cli ACL LIST

# Verify tenant isolation
kubectl exec -it redis-pod -- redis-cli -u redis://tenant_alpha:alpha-password@localhost:6379
> KEYS hakgal:tenant:beta:*
# Expected: (empty list) - tenant_alpha cannot access beta keys
```

**If tenant_alpha CAN access beta keys → ACL misconfiguration = ROOT CAUSE.**

---

## Mitigation

### Immediate (0-5 minutes)

**Step 1: Rotate All Tenant Redis Credentials**

```bash
# Using HashiCorp Vault
vault lease revoke -prefix=redis/creds/tenant_

# Regenerate credentials
for tenant in $(vault list redis/creds/ | grep tenant_); do
    vault read redis/creds/$tenant
done
```

**Effect:** Invalidates all existing Redis connections (forces re-authentication).

**Step 2: Flush All Sessions (Force Re-Auth)**

```python
# Emergency: Clear all session data
# kubectl exec -it hakgal-pod -- python3
import asyncio
import redis.asyncio as redis

async def emergency_flush():
    # Connect to Redis
    r = redis.Redis.from_url("redis://localhost:6379/0")

    # Flush all session keys (CRITICAL: This logs out all users)
    await r.flushdb()  # Or: await r.delete(*await r.keys("hakgal:tenant:*:session:*"))

    print("Emergency flush complete. All sessions invalidated.")

asyncio.run(emergency_flush())
```

**WARNING:** This logs out ALL users. Only use if breach is confirmed.

**Step 3: Block Affected Tenant (If Identified)**

```bash
# Block tenant at ingress
curl -X POST https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules \
  -H "Authorization: Bearer {api_token}" \
  -d '{
    "action": "block",
    "expression": "(http.request.headers[\"X-Tenant-ID\"][*] eq \"COMPROMISED_TENANT\")"
  }'
```

---

## Legal & Compliance (GDPR Art. 33)

### Step 1: Engage Legal (Within 1 Hour)

**Notification Template:**
```
Subject: URGENT: Potential GDPR Breach - Session Cross-Tenant Access

Incident Start: {timestamp}
Affected Tenants: {list}
Data Types: Session IDs, User Hashes, Drift Scores
Breach Confirmed: {YES|NO|INVESTIGATING}
Mitigation Applied: {credential_rotation|session_flush|tenant_block}
```

**Timeline:** GDPR requires notification within **72 hours** of breach discovery.

### Step 2: Data Breach Assessment

**Questions:**
1. Was personal data (PII) accessed?
2. How many data subjects affected?
3. What data types were exposed?
4. Is breach ongoing or contained?

**Documentation:** All answers must be documented for GDPR Art. 33 notification.

### Step 3: Customer Notification (If Breach Confirmed)

**Timeline:** Within 72 hours (GDPR Art. 33)

**Template:**
```
Subject: Security Incident Notification (GDPR Art. 34)

Dear {Customer},

We are writing to inform you of a security incident that may have affected your data.

Incident Date: {date}
What Happened: {description}
What We Did: {mitigation}
What You Should Do: {recommendations}
```

---

## Post-Incident

### Step 1: Root Cause Analysis

**Investigation Areas:**
1. **Redis ACL Misconfiguration:** Were ACLs properly set up?
2. **Key Prefix Violation:** Did code use wrong key pattern?
3. **Credential Leakage:** Were tenant credentials exposed?
4. **Guard Plugin RCE:** Did malicious guard code access Redis?

**Timeline:** Complete within 48 hours

### Step 2: Fix Root Cause

**If ACL Misconfiguration:**
```bash
# Reconfigure Redis ACLs
redis-cli ACL SETUSER tenant_alpha on >new-password ~hakgal:tenant:alpha:* +@all
redis-cli ACL SETUSER tenant_beta on >new-password ~hakgal:tenant:beta:* +@all
```

**If Key Prefix Violation:**
- Review code for hardcoded key patterns
- Ensure all keys use `hakgal:tenant:{tenant_id}:...` pattern

**If Credential Leakage:**
- Rotate all credentials
- Audit Vault/KMS access logs
- Review credential storage security

### Step 3: Prevent Recurrence

**Monitoring:**
```yaml
# Prometheus Alert
- alert: RedisACLViolation
  expr: hakgal_redis_acl_violations_total > 0
  for: 1m
  annotations:
    summary: "Redis ACL violation detected"
```

**Testing:**
- Weekly: Run `test_redis_acl_isolation()` to verify tenant isolation
- Monthly: Red team exercise (attempt cross-tenant access)

---

## Escalation

- **Level 1 (On-Call):** Quarantine node, rotate credentials
- **Level 2 (Security Lead):** If breach confirmed, engage Legal
- **Level 3 (CISO + Legal):** GDPR notification, customer communication

---

**Last Updated:** 2025-01-15
**Review Frequency:** Monthly
**Owner:** Security Team + Legal
