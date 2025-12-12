# INCIDENT: Guard Plugin RCE (Remote Code Execution)

**Severity:** CRITICAL
**Impact:** Total System Compromise, Data Exfiltration, GDPR Breach
**Response Time:** < 5 minutes
**Owner:** Security On-Call + CISO

---

## Symptoms

- **Log Entry:** `Guard registration from untrusted source` or `Malicious guard code detected`
- **System Behavior:** Unexpected Python code execution, file system access
- **Network Activity:** Outbound connections to unknown IPs
- **Data Access:** Unauthorized Redis key access, session data exfiltration
- **Customer Report:** "My data was accessed by someone else"

---

## Diagnosis

### Step 1: Immediate: Disable Dynamic Guard Registration

```python
# kubectl exec -it hakgal-pod -- python3
from hak_gal.core.config import RuntimeConfig
import time
import uuid

config = RuntimeConfig()
timestamp = int(time.time())
nonce = str(uuid.uuid4())
signature = config.get_signature("ENABLE_DYNAMIC_GUARDS", False, timestamp, nonce)
config.update_config("ENABLE_DYNAMIC_GUARDS", False, signature, timestamp, nonce)
```

**CRITICAL:** This prevents further malicious guard registration.

### Step 2: Scan for Malicious Guard Files

```bash
# Find recently modified guard files
kubectl exec -it hakgal-pod -- find /guards -mtime -1 -type f

# Check for suspicious Python code
kubectl exec -it hakgal-pod -- grep -r "eval\|exec\|__import__\|subprocess" /guards/

# List all registered guards
kubectl exec -it hakgal-pod -- python3 -c "
from hak_gal.layers.outbound.tool_guard import ToolGuardRegistry
registry = ToolGuardRegistry()
print(registry.list_guards())
"
```

**Look for:**
- Guards registered from untrusted sources
- Guards with suspicious code (eval, exec, subprocess)
- Guards accessing Redis directly (bypassing ACLs)

### Step 3: Check Redis Access Logs

```bash
# Check if malicious guard accessed other tenants' data
kubectl logs redis-pod | grep "ACL violation\|unauthorized access" | tail -100

# Check for cross-tenant key access
kubectl exec -it redis-pod -- redis-cli --scan --pattern "hakgal:tenant:*" | \
  awk -F: '{print $3}' | sort | uniq -c
```

**Expected:** Each tenant should only access their own keys.

### Step 4: Network Forensics

```bash
# Check outbound connections
kubectl exec -it hakgal-pod -- netstat -an | grep ESTABLISHED

# Check DNS queries
kubectl exec -it hakgal-pod -- cat /etc/resolv.conf
kubectl logs hakgal-pod | grep "DNS query\|connection to"
```

**Look for:**
- Connections to unknown IPs
- DNS queries to suspicious domains
- Data exfiltration patterns

---

## Mitigation

### Immediate (0-5 minutes)

**Step 1: Revoke All Sessions (Force Re-Auth)**

```python
# Emergency: Flush all sessions
import asyncio
import redis.asyncio as redis

async def emergency_flush():
    r = redis.Redis.from_url("redis://localhost:6379/0")
    await r.flushdb()  # Or: await r.delete(*await r.keys("hakgal:tenant:*:session:*"))
    print("All sessions invalidated.")

asyncio.run(emergency_flush())
```

**Effect:** Logs out all users, prevents further unauthorized access.

**Step 2: Quarantine Affected Pods**

```bash
# If RCE is isolated to specific pods
kubectl cordon <pod-name>
kubectl delete pod <pod-name> --grace-period=0
```

**Effect:** Stops malicious code execution immediately.

**Step 3: Rotate All Credentials**

```bash
# Rotate Redis credentials
vault lease revoke -prefix=redis/creds/

# Rotate KMS keys (if compromised)
vault lease revoke -prefix=kms/keys/tenant_

# Rotate application secrets
kubectl create secret generic hakgal-secrets --from-literal=admin-secret=$(openssl rand -hex 32)
kubectl rollout restart deployment/hakgal
```

**Effect:** Invalidates all existing credentials, forces re-authentication.

### Short-Term (5-15 minutes)

**Step 4: Block Source IP/Domain**

```bash
# If attacker IP identified
curl -X POST https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules \
  -H "Authorization: Bearer {api_token}" \
  -d '{
    "action": "block",
    "expression": "(ip.src eq \"ATTACKER_IP\")"
  }'
```

**Step 5: Enable Audit Logging**

```python
# Enable forensic logging
from hak_gal.core.config import RuntimeConfig
import time
import uuid

config = RuntimeConfig()
timestamp = int(time.time())
nonce = str(uuid.uuid4())
signature = config.get_signature("LOG_LEVEL", "FORENSIC", timestamp, nonce)
config.update_config("LOG_LEVEL", "FORENSIC", signature, timestamp, nonce)
```

**Effect:** Logs all operations for forensic analysis.

---

## Legal & Compliance

### Step 1: Engage Legal + CISO (Within 15 Minutes)

**Notification Template:**
```
Subject: CRITICAL: RCE Incident - Potential Total System Compromise

Incident Start: {timestamp}
Attack Vector: Guard Plugin RCE
Affected Systems: {list}
Data Breach: {CONFIRMED|SUSPECTED|NO}
Mitigation Applied: {list}
```

**Timeline:** RCE = Potential total compromise. Legal must be notified immediately.

### Step 2: GDPR Breach Assessment

**Questions:**
1. Was personal data (PII) accessed?
2. How many data subjects affected?
3. What data types were exfiltrated?
4. Is attacker still in system?

**Documentation:** All answers must be documented for GDPR Art. 33 notification.

### Step 3: Preserve Evidence (WORM Storage)

```bash
# Export all logs
kubectl logs deployment/hakgal --since=24h > /secure-storage/rce_incident_{timestamp}.log

# Export Redis dump
kubectl exec -it redis-pod -- redis-cli SAVE
kubectl cp redis-pod:/data/dump.rdb ./forensics/redis_dump_{timestamp}.rdb

# Export guard files
kubectl cp hakgal-pod:/guards ./forensics/guards_{timestamp}/

# Upload to WORM-compliant storage
aws s3 cp ./forensics/ s3://incident-forensics/rce_{timestamp}/ --storage-class GLACIER
```

**Critical:** Evidence must be preserved for legal/compliance investigation.

---

## Post-Incident

### Step 1: Root Cause Analysis

**Investigation Areas:**
1. **How did attacker register malicious guard?**
   - Was dynamic guard registration enabled?
   - Was there authentication/authorization bypass?
   - Was guard code validated before execution?

2. **What did attacker access?**
   - Redis keys (which tenants?)
   - Session data
   - Configuration secrets
   - Other systems (database, APIs)

3. **How long was attacker in system?**
   - First malicious guard registration timestamp
   - Last detected activity timestamp
   - Timeline of actions

**Timeline:** Complete within 48 hours

### Step 2: Fix Root Cause

**If Dynamic Guard Registration Was Enabled:**
- **Permanent Fix:** Disable dynamic guard registration
- **Code Change:** Remove `register_tool_guard()` public API
- **Architecture:** All guards must be statically defined in code

**If Authentication Bypass:**
- Review authentication/authorization logic
- Add guard registration audit logging
- Implement guard code validation (AST parsing, sandboxing)

**If Guard Code Validation Missing:**
- Implement AST-based code analysis
- Block dangerous Python constructs (eval, exec, subprocess, etc.)
- Sandbox guard execution (restricted Python environment)

### Step 3: Prevent Recurrence

**Code Changes:**
```python
# Permanently disable dynamic guard registration
class ToolGuardRegistry:
    def register(self, tool_name: str, guard: BaseToolGuard) -> None:
        # CRITICAL: Only allow registration during initialization
        if self._initialized:
            raise SecurityException(
                "Dynamic guard registration is disabled (P2: Guard RCE Fix)"
            )
        # ... rest of registration logic
```

**Monitoring:**
```yaml
# Prometheus Alert
- alert: GuardRegistrationAttempt
  expr: hakgal_guard_registration_attempts_total > 0
  for: 1m
  annotations:
    summary: "Guard registration attempt detected (should be 0)"
```

**Testing:**
- Weekly: Attempt to register malicious guard → must fail
- Monthly: Red team exercise (attempt RCE via guard)

---

## Escalation

- **Level 1 (On-Call):** Disable dynamic guards, revoke sessions, quarantine pods
- **Level 2 (Security Lead):** If data breach confirmed, engage Legal
- **Level 3 (CISO + Legal + Board):** GDPR notification, customer communication, regulatory reporting

---

## Prevention Checklist

- [ ] **Dynamic guard registration DISABLED** (static guards only)
- [ ] **Guard code validation** (AST parsing, sandboxing)
- [ ] **Guard execution isolation** (restricted Python environment)
- [ ] **Audit logging** for all guard registrations
- [ ] **Monitoring alerts** for suspicious guard activity
- [ ] **Regular security reviews** of guard code

---

**Last Updated:** 2025-01-15
**Review Frequency:** Monthly
**Owner:** Security Team + CISO
