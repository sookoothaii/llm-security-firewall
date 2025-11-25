# LLM Security Firewall - Operations Runbook

## Incident Response

### Critical False Negative (CRITICAL-FN > 0)

**Indicators:**
- Alert: `FirewallCriticalFalseNegative` fires
- Metric: `firewall_critical_fn_total > 0`

**Immediate Actions:**
1. **Emergency strict mode:** `export FIREWALL_POLICY_MODE=strict` (< 1min)
2. **Isolate input:** Capture failing input via logs
3. **Identify transport:** Check if attack uses archive/PNG/PDF/RFC-2047/new format
4. **Decoder budget:** Temporarily increase relevant budget (+50%, max 2x)
5. **Log slice:** Secure full decision trace for forensics

**Triage:**
- Reproduce with Stage-4/5 test patterns
- Check if new encoding/transport not covered
- Verify whitelist didn't suppress (check `ctx_whitelist` in decision dict)

**Remediation:**
- Add format sniff or raise budget cap (with hard upper limit)
- Create regression test in `tests/test_incidents/`
- Deploy fix, verify test green, return to permissive+auto-strict

---

### High False Positive Rate (FPR > 0.2%)

**Indicators:**
- Alert: `FirewallFPRHigh` fires
- Metric: `rate(firewall_false_positive_total[30m]) / rate(firewall_total_decisions[30m]) > 0.002`

**Immediate Actions:**
1. **Keep policy permissive** (don't escalate)
2. **Analyze context:** Sample FP cases, check if UUID/Git/SHA/Base64 structural
3. **Whitelist review:** Verify context heuristics (`is_uuid_benign`, `is_git_hash_benign`, etc.)

**Triage:**
- Check if new benign pattern emerged (e.g., new hash format, CI artifacts)
- Review `provider_nearmiss_total{dl}` for typo-like prefixes
- Verify `base64_large_valid_padding` threshold (200 chars)

**Remediation:**
- Extend context whitelist patterns (conservative - require left-context labels)
- Add FP regression test
- Do NOT weaken core detection - only improve context discrimination

---

### Slow Decision Latency (p99 > 40ms)

**Indicators:**
- Alert: `FirewallLatencyP99` fires
- Metric: `histogram_quantile(0.99, firewall_decision_latency_seconds_bucket[15m]) > 0.04`

**Immediate Actions:**
1. **Profile hot path:** Check which detector dominates (archive/PNG/gzip most likely)
2. **Temporary budget reduction:** Halve `max_zip_files` (5→2), `max_inflate_bytes` (64KB→32KB)
3. **Monitor FN impact:** Ensure no CRITICAL-FN spike

**Triage:**
- Check input distribution (% with archives/PNG vs plain text)
- Review budget utilization (are we hitting caps frequently?)
- Analyze `archive_secret_kind_total{gzip|zip}` rate

**Remediation:**
- Optimize detector (e.g., early-exit on magic-bytes mismatch)
- Adjust budgets based on traffic profile
- Consider async decode path for non-critical transports

---

### Auto-Strict Flapping (> 10 transitions/10min)

**Indicators:**
- Alert: `AutoStrictFlapping` fires
- Metric: `rate(policy_autostrict_transitions_total[10m]) > 10`

**Diagnosis:**
- Traffic wave pattern (legitimate burst vs attack)
- Threshold too sensitive (3 alarms in 5min)
- E-value `p0` miscalibrated

**Actions:**
- Review `evalue_alarm_total` distribution
- Consider raising threshold (3→5) or extending window (5min→10min)
- Check if weak_provider causing too many WARNs (tune entropy thresholds)

---

## Rollback Procedure

### Emergency Rollback (< 5min)

```bash
# Option 1: Environment variable (fastest)
export FIREWALL_POLICY_MODE=strict  # Conservative fallback

# Option 2: Git revert
git revert HEAD  # Revert last deployment
git push origin main --force-with-lease

# Option 3: Feature flag (if wired)
# Set FIREWALL_ENABLED=false in config
```text
### Staged Rollback (< 30min)

1. Ramp down from 100% → 30% → 10% → 0%
2. Monitor FN/FP at each step
3. Identify problematic commit via bisect
4. Revert specific feature, not full rollback

---

## Maintenance

### Weekly Tasks
- Review FPR trend (target: ≤ 0.1% / 24h)
- Check latency percentiles (p95 ≤ 10ms, p99 ≤ 25ms)
- Verify CRITICAL-FN = 0
- Audit auto-strict transitions (should be rare: < 5/week in steady state)

### Monthly Tasks
- Update locale label lexicons (new languages, terms)
- Review provider prefix list (new API providers)
- Ablation test (toggle modules, measure ΔTPR/FPR)
- Canary refresh (10k labeled samples)

---

## SLO Targets

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| p95 latency | ≤ 10ms | > 15ms (warn) |
| p99 latency | ≤ 25ms | > 40ms (warn) |
| FPR (24h) | ≤ 0.1% | > 0.2% (warn) |
| CRITICAL-FN | 0 | > 0 (page) |
| Auto-strict transitions | < 5/week | > 10/10min (info) |

---

## Contact

For operational issues: [on-call rotation]
For security reports: [security contact]
For development: Joerg Bollwahn
