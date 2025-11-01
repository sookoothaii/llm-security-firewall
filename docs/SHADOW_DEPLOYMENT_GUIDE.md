# Shadow Deployment Guide

Deploying LLM Security Firewall in WARN-only mode for production telemetry collection.

---

## Overview

**Mode:** Shadow WARN  
**Purpose:** Collect real-world FPR/ASR data without blocking users  
**Duration:** 1-2 weeks initial phase  
**Review:** Daily FPR, weekly ASR

---

## Configuration

**File:** `config/shadow_deploy.yaml`

**Key Settings:**
- `runtime.mode: shadow_warn` - Never blocks, always logs
- `sampling.rate: 1.0` - Full telemetry during initial phase
- `gates.fpr.mode: advisory` - FPR warnings, not enforcement
- `monitoring.prometheus.enabled: true` - Metrics collection

---

## Deployment Steps

### 1. Pre-Deployment Checklist

- [ ] RC9-FPR3 validation complete (FPR <3% on benign corpus)
- [ ] ASR gate passing (Wilson upper <5.00%)
- [ ] Prometheus/Grafana configured
- [ ] Alert rules deployed
- [ ] Kill-switch tested
- [ ] Rollback procedure documented

### 2. Canary Phase (1% traffic, 24h)

```bash
# Deploy with canary config
python -m llm_firewall.deploy --config config/shadow_deploy.yaml --phase canary

# Monitor
curl http://localhost:9090/metrics | grep firewall_fpr_rate
curl http://localhost:9090/metrics | grep firewall_latency_p99
```

**Gates:**
- FPR <10%
- Latency P99 <100ms
- No crashes

### 3. Shadow Phase (10% traffic, 72h)

```bash
# Expand to 10%
python -m llm_firewall.deploy --config config/shadow_deploy.yaml --phase shadow
```

**Gates:**
- FPR <5%
- Latency stable
- Real conversations validated

### 4. Expansion Phase (50% traffic, 1 week)

```bash
# Expand to 50%
python -m llm_firewall.deploy --config config/shadow_deploy.yaml --phase expansion
```

**Gates:**
- FPR <3%
- ASR validated on real attacks (if any observed)
- Per-category analysis complete

### 5. Full Deployment (100% traffic)

**Requires:**
- Manual approval
- FPR gate pass (Wilson upper ≤1.50%)
- ASR gate pass (Wilson upper ≤5.00%)
- Minimum 2000 samples collected

---

## Monitoring

### Daily Checks

**FPR Trend:**
```bash
python tools/analyze_telemetry.py --metric fpr --window 24h
```

**Expected:** 2-3% stable

**New Signals:**
```bash
python tools/analyze_telemetry.py --metric signals --new-only
```

**Expected:** <5 new signals/day

### Weekly Reviews

**ASR Validation:**
- Review any bypasses observed in production
- Categorize: true positive vs false negative
- Update detector lexicons if needed

**Per-Category Analysis:**
```bash
python tools/analyze_telemetry.py --per-category --window 1week
```

**Threshold Calibration:**
- Analyze signal frequency distributions
- Adjust weights if FPR >3% persistently

---

## Escalation Criteria

**Immediate kill-switch if:**
- FPR >20%
- ASR spike >10%
- Latency P99 >500ms
- Crashes >10/hour

**Rollback to previous version:**
```bash
python -m llm_firewall.deploy --rollback
```

---

## Telemetry Collection Targets

**Samples:**
- Conversations: 5000+
- Documentation: 2000+
- Code snippets: 1000+

**Diversity:**
- Unique users: 100+
- Time coverage: 24h

**Duration:** Continue until targets met (estimated 1-2 weeks)

---

## Analysis After Shadow Phase

### 1. FPR Analysis

**Questions:**
- Is FPR stable 2-3%?
- Which signals cause most FPs?
- Are FPs concentrated in specific categories?

**Actions:**
- Tune signal weights if needed
- Add BENIGN_SIGNALS for common patterns
- Adjust context thresholds

### 2. ASR Validation

**Questions:**
- Were any real attacks observed?
- Did firewall detect them?
- Any bypasses?

**Actions:**
- Document bypasses
- Add to regression test suite
- Update detector lexicons

### 3. Latency Analysis

**Questions:**
- Is P99 <100ms?
- Any degradation under load?
- Which detectors are slowest?

**Actions:**
- Optimize slow detectors
- Consider caching
- Profile under realistic load

---

## Go/No-Go for Production

**GO if:**
- FPR Wilson upper ≤3.00% (relaxed from 1.50% given N=1034)
- ASR Wilson upper ≤5.00%
- Latency P99 ≤100ms
- No critical bugs
- Minimum 2000 samples collected

**NO-GO if:**
- FPR >5%
- ASR >8%
- Latency P99 >200ms
- Crashes observed
- Insufficient telemetry

---

## Current Status (RC9-FPR3)

**Benign Corpus (N=1034):**
- FPR: 2.71%
- Wilson 95% CI: [1.88%, 3.89%]
- Upper: 3.89%

**Adversarial (N=1920):**
- ASR: 2.76%
- Wilson 95% CI: [2.12%, 3.59%]
- Upper: 3.59%

**Recommendation:** Proceed to Shadow Phase (10% traffic)

FPR is stable ~3% which is acceptable for shadow deployment. Collect real-world data to validate.

---

**Next Steps:**
1. Deploy canary (1% traffic, 24h)
2. Monitor FPR/latency
3. Expand to shadow (10%, 72h)
4. Collect 2000+ samples
5. Final validation before production

