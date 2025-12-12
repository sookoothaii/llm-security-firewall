# INCIDENT: Cross-Tenant Rate Limit Storm

**Severity:** HIGH
**Impact:** Service Degradation, Potential DoS
**Response Time:** < 5 minutes
**Owner:** Security On-Call

---

## Symptoms

- **P99 latency > 500ms** (Event-Loop saturation)
- **Prometheus Alert:** `hakgal_rate_limit_rejections_total` spikes > 1000/s
- **User Reports:** "Service is slow" or "Requests timing out"
- **Redis Metrics:** High connection count, CPU > 80%

---

## Diagnosis

### Step 1: Identify Top Rejecting Tenant

```promql
topk(5, sum(rate(hakgal_rate_limit_rejections_total[5m])) by (tenant_id))
```

**Expected Output:**
```
tenant_id="ATTACKER_TENANT"  rate=1500/s
tenant_id="legitimate_tenant" rate=50/s
```

### Step 2: Identify Source IP

```bash
kubectl logs -f deployment/hakgal | grep "tenant_id=ATTACKER_TENANT" | head -20
```

**Look for:**
- Source IP addresses
- User-Agent strings
- Request patterns (bursts, timing)

### Step 3: Check Redis Connection Pool

```bash
kubectl exec -it redis-pod -- redis-cli CLIENT LIST | grep "tenant_ATTACKER_TENANT"
```

**Expected:** High connection count for attacker tenant.

---

## Mitigation

### Immediate (0-2 minutes)

**Option A: Shadow-Mode (No Blocking)**

```python
# kubectl exec -it hakgal-pod -- python3
from hak_gal.core.config import RuntimeConfig
import time
import uuid

config = RuntimeConfig()
timestamp = int(time.time())
nonce = str(uuid.uuid4())
signature = config.get_signature("RATE_LIMIT_ENFORCE", False, timestamp, nonce)
config.update_config("RATE_LIMIT_ENFORCE", False, signature, timestamp, nonce)
```

**Effect:** Rate limiter logs violations but does NOT block (allows service to continue).

**Option B: Block Tenant at Ingress (WAF/Cloudflare Rule)**

```bash
# Cloudflare API
curl -X POST https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules \
  -H "Authorization: Bearer {api_token}" \
  -d '{
    "action": "block",
    "expression": "(http.request.headers[\"X-Tenant-ID\"][*] eq \"ATTACKER_TENANT\")"
  }'
```

**Effect:** Blocks all requests from attacker tenant at edge (before reaching application).

### Short-Term (2-5 minutes)

**Option C: Increase Rate Limit for Legitimate Tenants**

```python
# Temporarily increase max_requests for legitimate tenants
# (Only if you can identify them)
from hak_gal.utils.tenant_rate_limiter import TenantRateLimiter

# This requires code change - not recommended for immediate response
# Better: Use Shadow-Mode or Ingress Block
```

**Option D: Quarantine Node**

```bash
# If attack is isolated to one node
kubectl cordon <node-name>
kubectl drain <node-name> --grace-period=30
```

---

## Post-Incident

### Step 1: Alert Legal & Compliance (GDPR Art. 32)

**Timeline:** Within 1 hour of incident start

**Notification Template:**
```
Subject: Security Incident: Rate Limit Storm (GDPR Art. 32)

Incident Start: {timestamp}
Affected Tenants: {list}
Mitigation Applied: {shadow_mode|ingress_block}
Data Breach: NO (rate limiting only, no data access)
```

### Step 2: Preserve Logs (WORM Storage)

```bash
# Export logs to immutable storage
kubectl logs deployment/hakgal --since=1h > /secure-storage/incident_{timestamp}.log
# Upload to WORM-compliant storage (S3 Glacier, etc.)
```

### Step 3: Root Cause Analysis

**Questions:**
1. Was this a coordinated attack or misconfiguration?
2. Why did rate limiter not prevent this?
3. Are there gaps in monitoring?

**Timeline:** Complete within 24 hours

---

## Prevention

### Monitoring Alerts

```yaml
# Prometheus Alert Rule
- alert: RateLimitStorm
  expr: rate(hakgal_rate_limit_rejections_total[5m]) > 1000
  for: 2m
  annotations:
    summary: "Rate limit storm detected"
    description: "{{ $value }} rejections/sec"
```

### Rate Limiter Tuning

- **Calibrate** `max_requests` based on `p99(tenant_peak_rps) * 1.5`
- **Monitor** false positive rate
- **Adjust** thresholds weekly based on traffic patterns

---

## Escalation

- **Level 1 (On-Call):** Apply mitigation (Shadow-Mode or Ingress Block)
- **Level 2 (Security Lead):** If attack persists > 10 minutes
- **Level 3 (CISO):** If data breach suspected or GDPR violation

---

**Last Updated:** 2025-01-15
**Review Frequency:** Quarterly
**Owner:** Security Team
