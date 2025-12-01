# Integration Test Guide - External Review Validation

**Date:** 2025-12-01
**Purpose:** Complete validation of all P0 items from external architecture review

---

## Overview

The integration test suite (`tests/integration/test_external_review_validation.py`) validates all 8 P0 requirements from the external architecture review:

1. Circuit Breaker Pattern
2. False Positive Tracking
3. P99 Latency < 200ms
4. Cache Mode Switching
5. 0/50 Adversarial Bypasses
6. Memory < 300MB
7. Binary Size < 15MB
8. Redis Cloud Integration

---

## Prerequisites

### Required Dependencies

```bash
pip install pytest psutil
```

### Optional (for full test suite)

- Redis Cloud credentials (for integration test)
- Adversarial test suite: `data/gpt5_adversarial_suite.jsonl`

---

## Running the Tests

### Run All Tests

```bash
cd standalone_packages/llm-security-firewall
python -m pytest tests/integration/test_external_review_validation.py -v
```

### Run Specific Test

```bash
# Circuit Breaker only
python -m pytest tests/integration/test_external_review_validation.py::TestExternalReviewValidation::test_circuit_breaker_implementation -v

# P99 Latency only
python -m pytest tests/integration/test_external_review_validation.py::TestExternalReviewValidation::test_p99_latency_adversarial_inputs -v
```

### Standalone Execution

```bash
python tests/integration/test_external_review_validation.py
```

---

## Test Details

### 1. Circuit Breaker Pattern

**Test:** `test_circuit_breaker_implementation`

**Validates:**
- AdapterHealth class exists and works
- Circuit opens after failure threshold
- Health metrics are correctly reported

**Expected:** PASS

---

### 2. False Positive Tracking

**Test:** `test_false_positive_tracking`

**Validates:**
- Legitimate queries are not blocked
- False positive rate < 5%

**Expected:** PASS (FP rate < 5%)

---

### 3. P99 Latency

**Test:** `test_p99_latency_adversarial_inputs`

**Validates:**
- P99 latency < 200ms for adversarial inputs
- P95 latency < 100ms

**Requirements:**
- Adversarial suite: `data/gpt5_adversarial_suite.jsonl`
- Test uses first 100 payloads

**Expected:** PASS (P99 < 200ms)

---

### 4. Cache Mode Switching

**Test:** `test_cache_mode_switching`

**Validates:**
- CACHE_MODE=exact works
- CACHE_MODE=semantic works
- CACHE_MODE=hybrid works
- Mode switching without restart

**Expected:** PASS

---

### 5. Adversarial Bypasses

**Test:** `test_adversarial_bypass_suite`

**Validates:**
- 0/50 bypasses in adversarial suite
- All malicious payloads are blocked

**Requirements:**
- Adversarial suite: `data/gpt5_adversarial_suite.jsonl`

**Expected:** PASS (0 bypasses)

---

### 6. Memory Usage

**Test:** `test_memory_usage_under_300mb`

**Validates:**
- Memory stays under 300MB cap
- No significant memory leaks

**Requirements:**
- `psutil` package installed

**Expected:** PASS (< 300MB)

---

### 7. Binary Size

**Test:** `test_binary_size_under_15mb`

**Validates:**
- Binary size < 15MB (if binary exists)

**Requirements:**
- PyInstaller binary in `dist/llm-firewall` or `dist/llm-firewall.exe`

**Expected:** PASS or SKIP (if binary not found)

---

### 8. Redis Cloud Integration

**Test:** `test_redis_cloud_integration`

**Validates:**
- Redis Cloud connection works
- Cache operations succeed
- Health metrics available

**Requirements:**
- Redis Cloud credentials set:
  - `REDIS_CLOUD_HOST`
  - `REDIS_CLOUD_PASSWORD`
  - Or `REDIS_URL`

**Expected:** PASS or SKIP (if credentials not set)

---

## Setup Scripts

### Redis Cloud Setup

```bash
python setup_redis_cloud.py
```

This interactive script:
- Prompts for Redis Cloud credentials
- Sets environment variables
- Optionally saves to config file (`~/.llm_firewall/redis_cloud.ini`)
- Tests connection

### Environment Variables

```bash
export REDIS_CLOUD_HOST="your-host.redislabs.com"
export REDIS_CLOUD_PASSWORD="your-password"
export REDIS_CLOUD_PORT="6379"  # Optional
export REDIS_CLOUD_SSL="true"   # Optional
```

---

## File Locations

### Test Files

- `tests/integration/test_external_review_validation.py` - Main validation suite
- `tests/integration/test_redis_cloud.py` - Redis Cloud specific tests
- `tests/unit/test_adapter_health.py` - AdapterHealth unit tests
- `tests/unit/test_circuit_breaker.py` - Circuit breaker unit tests

### Setup Scripts

- `setup_redis_cloud.py` - Interactive Redis Cloud setup
- `setup_test_env.py` - Environment setup helper

### Data Files

- `data/gpt5_adversarial_suite.jsonl` - Adversarial test vectors (required for some tests)

---

## Expected Results

### Full Test Run

```
Total: 8 | Passed: 6-8 | Failed: 0 | Skipped: 0-2
```

**Typical skips:**
- Binary size test (if binary not built)
- Redis Cloud test (if credentials not set)

### Success Criteria

All critical tests (1-5) must PASS:
1. Circuit Breaker: PASS
2. False Positive Tracking: PASS
3. P99 Latency: PASS
4. Cache Mode Switching: PASS
5. Adversarial Bypasses: PASS (0 bypasses)

---

## Troubleshooting

### Adversarial Suite Not Found

**Error:** `Adversarial suite not found`

**Solution:** Ensure `data/gpt5_adversarial_suite.jsonl` exists in firewall package root.

### Redis Cloud Connection Failed

**Error:** `Connection test failed`

**Solution:**
1. Verify credentials: `python setup_redis_cloud.py`
2. Check network connectivity
3. Verify Redis Cloud instance is running

### Memory Test Fails

**Error:** `Memory usage exceeds 300MB cap`

**Solution:**
- Check for memory leaks in code
- Reduce test payload size
- Check system memory availability

---

## Next Steps

After all tests pass:

1. **Document Results:** Create test report with metrics
2. **Performance Baseline:** Record P99/P95 latencies for regression testing
3. **Production Readiness:** All P0 items validated

---

**Status:** Ready for execution
