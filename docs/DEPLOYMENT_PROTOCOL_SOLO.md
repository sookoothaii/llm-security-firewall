# HAK_GAL v2.3.3: Deployment Protocol (Solo Engineering)

**Version:** 2.3.3
**Date:** 2025-11-29
**Status:** Production-Cleared for Canary (Chaos-Test PASSED)
**Auditor:** Kimi K2, Security Audit Lead
**Adapted for:** Solo Engineering (pragmatic reduction)

---

## Executive Summary

**Chaos-Test Status:** ✅ **PASSED** (2025-11-29)

Session state survives pod death. Resilience validated. System ready for canary deployment.

**Deployment Approach:** Phased rollout with minimal overhead for solo engineer.

---

## Test Evidence (Validated)

| Metric | Expectation | Result | Status |
|--------|-------------|--------|--------|
| **Session Persistence** | State survives pod restart | ✅ `tx_count_1h` preserved | **PASS** |
| **Context Recovery** | Session valid after crash | ✅ `session.is_valid() == True` | **PASS** |
| **Data Loss** | No loss after recovery | ✅ Zero data loss | **PASS** |
| **Security Incident** | No auth bypass | ✅ No bypass detected | **PASS** |

**Conclusion:** System meets resilience requirements for pod-death scenarios.

---

## Deployment Protocol (Solo Engineering)

### Phase 0: Pre-Deployment (DONE)

- ✅ Chaos test passed (2025-11-29)
- ✅ Documentation updated (`docs/chaos_test_results.md`)
- ✅ Redis Cloud connection validated

### Phase 1: Staging Canary (When Ready)

**Deployment:**
- Deploy v2.3.3 to **5% of staging traffic** (or single pod if staging is small)
- Set `AUDIT_LEVEL=FULL` (payload logging for first 48h)
- Monitor basic metrics (see below)

**Monitoring (Self-Service):**
- Check logs for errors: `grep -i "error\|exception" logs/hak_gal.log`
- Monitor Redis memory: `redis-cli INFO memory` (should stay <500MB for staging)
- Watch for rate limit rejections: `grep "rate_limit_reject" logs/hak_gal.log | wc -l`

**Duration:** 48 hours (or until confident)

**Success Criteria:**
- No exceptions in logs
- Redis memory stable
- Rate limit rejections <100/hour (adjust threshold as needed)

### Phase 2: Staging Scale-Up (After Phase 1 Success)

**Deployment:**
- Scale to **50% of staging traffic** (or 2-3 pods)
- Continue `AUDIT_LEVEL=FULL` for 24h, then reduce to `INFO`

**Monitoring:**
- P99 latency should remain <200ms
- Redis memory should remain <1GB
- No session access violations

**Duration:** 24 hours

### Phase 3: Production Canary (After Phase 2 Success)

**Deployment:**
- Deploy to **1% of production traffic** (or single pod)
- Use **sticky sessions** (session affinity) to avoid migration issues
- **No auto-scaling** for first week (fixed pod count)

**Monitoring:**
- Same as Phase 2, plus:
  - Watch for user complaints (if applicable)
  - Monitor business metrics (if available)

**Duration:** 72 hours minimum

### Phase 4: Production Scale-Up (After Phase 3 Success)

**Deployment:**
- Scale to **5% → 25% → 50% → 100%** (weekly increments)
- Each increment: monitor for 48h before next step

**Monitoring:**
- P99 latency <200ms
- Redis memory <2GB (adjust based on session count)
- Error rate <0.1%

---

## Critical Alerts (Solo Engineering)

**If any of these occur, investigate immediately:**

| Alert | Metric | Threshold | Action |
|-------|--------|-----------|--------|
| **Rate Limit Storm** | Rate limit rejections | > 1000/hour | Check rate limit config, adjust if needed |
| **Session Bleeding** | Session access violations | > 0 | Check Redis ACLs, review logs |
| **Guard Exceptions** | Guard execution errors | > 10/hour | Review guard code, check inputs |
| **High Block Rate** | Blocks / Requests | > 30% | Review false positives, adjust thresholds |

**Emergency Bypass (if needed):**
- Set environment variable: `HAK_GAL_EMERGENCY_BYPASS=true`
- **TTL: 15 minutes** (auto-expires)
- **Log all bypass actions** to `logs/emergency_bypass.log`
- **Disable after incident resolved**

---

## Caveats & Conditions

### 1. Redis Backend

- **Staging/Canary:** Redis Cloud is acceptable
- **Production (100%):** Consider dedicated Redis cluster (VPC-isolated) if scale requires it
- **No shared Redis** between staging and production

### 2. Emergency Bypass

- **TTL: 15 minutes** (auto-expires)
- **Log all bypass actions** (immutable log file)
- **Disable immediately** after incident resolved

### 3. Incident Response (Solo)

- **Runbooks:** Available in `runbooks/` directory (digital, not printed)
- **Chaos Test:** Run manually when needed (not weekly, but after major changes)
- **Monitoring:** Self-service via logs and Redis CLI

---

## Monitoring (Automatisch via MCP-Tools)

**Kein manuelles Log-Checking mehr nötig!**

### MCP-Tools (Empfohlen)

Alle Monitoring-Tasks sind als MCP-Tools verfügbar:

1. **`firewall_health_check`**: Automatischer Health-Check (Redis, Sessions, Guards)
2. **`firewall_deployment_status`**: Deployment-Status (Phase, Traffic-%, Health)
3. **`firewall_metrics`**: Aktuelle Metriken (Sessions, Rate Limits, Blocks)
4. **`firewall_check_alerts`**: Kritische Alerts prüfen
5. **`firewall_redis_status`**: Detaillierter Redis-Status

**Setup:** Siehe `docs/MCP_MONITORING_GUIDE.md`

**Verwendung:** Einfach in Cursor/Claude fragen:
- "Prüfe Firewall Health"
- "Zeige Deployment-Status"
- "Gibt es Alerts?"

### Auto-Monitor (Hintergrund)

Kontinuierliches Monitoring im Hintergrund:

```powershell
python scripts/auto_monitor.py
```

Status wird in `monitoring/last_status.json` gespeichert.

### Manuelle Commands (Fallback)

Falls MCP-Tools nicht verfügbar:

```bash
# Redis Connection
redis-cli -h <host> -p <port> -a <password> PING

# Redis Memory
redis-cli -h <host> -p <port> -a <password> INFO memory

# Session Count
redis-cli -h <host> -p <port> -a <password> KEYS "hakgal:tenant:*:session:*" | wc -l
```

---

## Deployment Checklist

### Pre-Deployment
- [ ] Chaos test passed
- [ ] Redis Cloud connection tested
- [ ] Environment variables set (`REDIS_CLOUD_HOST`, `REDIS_CLOUD_PORT`, `REDIS_CLOUD_USERNAME`, `REDIS_CLOUD_PASSWORD`)
- [ ] Log directory exists and writable

### Phase 1 (Staging Canary)
- [ ] Deploy v2.3.3 to 5% staging traffic
- [ ] Set `AUDIT_LEVEL=FULL`
- [ ] Monitor logs for 48h
- [ ] Verify Redis memory stable

### Phase 2 (Staging Scale-Up)
- [ ] Scale to 50% staging traffic
- [ ] Monitor P99 latency
- [ ] Monitor Redis memory
- [ ] Verify no session violations

### Phase 3 (Production Canary)
- [ ] Deploy to 1% production traffic
- [ ] Enable sticky sessions
- [ ] Monitor for 72h minimum
- [ ] Verify business metrics stable

### Phase 4 (Production Scale-Up)
- [ ] Scale to 5% → 25% → 50% → 100% (weekly)
- [ ] Monitor at each increment
- [ ] Verify no degradation

---

## Rollback Procedure

**If issues occur:**

1. **Immediate:** Revert to previous version (if deployed via CI/CD)
2. **Emergency Bypass:** Set `HAK_GAL_EMERGENCY_BYPASS=true` (15min TTL)
3. **Investigate:** Check logs, Redis state, session recovery
4. **Fix:** Address root cause before re-deployment

**Rollback Command (if using version tags):**
```bash
# Example: Revert to v2.3.2
kubectl set image deployment/hak-gal hak-gal=hak-gal:v2.3.2
```

---

## Success Criteria

**System is production-ready when:**
- ✅ Chaos test passed
- ✅ Staging canary successful (48h+)
- ✅ Production canary successful (72h+)
- ✅ No critical alerts
- ✅ P99 latency <200ms
- ✅ Redis memory stable
- ✅ Zero data loss

---

## Next Steps

1. **Today:** Chaos test passed ✅
2. **When ready:** Deploy Phase 1 (staging canary)
3. **After 48h:** Evaluate Phase 1, proceed to Phase 2
4. **After Phase 2:** Deploy Phase 3 (production canary)
5. **After Phase 3:** Scale to 100% (Phase 4)

---

## Notes for Solo Engineering

**Pragmatic Adjustments:**
- No SOC team: Self-monitoring via logs and Redis CLI
- No printed runbooks: Digital runbooks in `runbooks/` directory
- No HSM: Simple environment variable for emergency bypass
- No weekly chaos tests: Run manually after major changes
- Flexible timeline: No fixed dates, proceed when ready

**Key Principle:** Deploy incrementally, monitor closely, rollback quickly if needed.

---

**Last Updated:** 2025-11-29
**Status:** Ready for Phase 1 (Staging Canary)
**Next Review:** After Phase 1 completion
