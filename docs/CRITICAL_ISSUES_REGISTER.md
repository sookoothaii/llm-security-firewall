# Critical Issues Register

**Date:** 2025-12-01
**Status:** Active Issues Requiring Resolution
**Purpose:** Systematic documentation of unaddressed critical problems

---

## P0 - Security Critical (Immediate Action Required)

### 1. Adversarial Bypass Coverage Gap

**Status:** 13/15 high-severity bypasses unaddressed

**Evidence:**
- Adversarial suite: 51 total vectors
- Critical severity: 3 vectors (adv_001, adv_002, adv_008, adv_014)
- High severity: 12 vectors (adv_003 through adv_020)
- Fixed: 2 vectors (adv_001 zero-width, adv_002 RLO)
- Remaining: 13 high/critical severity vectors

**Affected Vectors:**
- adv_003: Homoglyph mix (Greek/Cyrillic)
- adv_004: Unicode NBSP dilution
- adv_005: HTML entity obfuscation
- adv_006: Unicode escape split
- adv_008: Base85/Z85 encoding (CRITICAL)
- adv_009: Token interleave
- adv_012: Digit fullwidth
- adv_013: Bidi isolates
- adv_014: Slow roll multi-turn (CRITICAL)
- adv_015: Secret punct split
- adv_016: URL encoding partial
- adv_020: JSON hex escape
- Plus additional high-severity vectors

**Risk:** Unknown attack surface. System may be vulnerable to documented bypass techniques.

**Location:** `data/gpt5_adversarial_suite.jsonl`

**Action Required:**
1. Run full adversarial suite against current implementation
2. Document which vectors bypass the firewall
3. Prioritize fixes by severity and exploitability
4. Implement detection for remaining vectors

---

### 2. Fail-Open Behavior on Cache Failure (Security Violation)

**Status:** Cache failures result in fail-open (allow) behavior

**Evidence:**
- `decision_cache.py` line 200-204: Returns `None` on Redis errors
- `decision_cache.py` line 10: Comment states "Fail-open: Cache errors don't break firewall operation"
- When cache fails, firewall proceeds without cached decision

**Problem:**
- Cache failure should trigger fail-safe (block) behavior, not fail-open (allow)
- Attacker could potentially disable Redis to bypass caching layer
- No manual override mechanism documented

**Current Implementation:**
```python
except RedisError as e:
    logger.debug("Redis cache miss (RedisError): %s", str(e)[:100])
    return None  # Fail-open: proceeds without cache
```

**Required Behavior:**
```python
except RedisError as e:
    logger.error("Redis cache failure: %s", str(e))
    # Fail-safe: Block request or require manual override
    raise SecurityException("Cache unavailable - request blocked for safety")
```

**Risk:** High. Cache failure could be exploited to bypass security checks.

**Location:** `src/llm_firewall/cache/decision_cache.py`

**Action Required:**
1. Implement fail-safe behavior (block on cache failure)
2. Add manual override mechanism for operations
3. Document override procedure
4. Add monitoring/alerting for cache failures

---

### 3. WASM Sandbox Timeout Not Enforced

**Status:** No hardware interrupt or signal-based timeout enforcement

**Evidence:**
- No `wasm_sandbox.py` file found in codebase
- Documentation mentions "timeout=50" but no implementation found
- No `signal.alarm()` or thread-killing mechanism

**Problem:**
- WASM rules could execute infinite loops
- No timeout enforcement means DoS vulnerability
- Simple `while(1){}` in WASM could hang the system

**Risk:** Medium-High. DoS attack vector through infinite loops.

**Location:** Not found (may not be implemented)

**Action Required:**
1. Verify if WASM sandbox exists
2. If exists, implement signal-based timeout (`signal.alarm()` or `threading.Timer`)
3. If not exists, document as out-of-scope or implement basic sandbox
4. Add timeout tests

---

## P1 - Performance & Memory (High Priority)

### 4. Batch Processing Memory Leak

**Status:** Memory usage exceeds 300MB limit (measured: ~1.3GB)

**Evidence:**
- Test results: 1355.7MB during batch processing
- Limit: 300MB (4.5x exceeded)
- No streaming batch processing implemented
- No LRU eviction during processing
- No checkpointing for large batches

**Problem:**
- Memory grows linearly with batch size
- No memory limits enforced
- Could cause OOM in production

**Risk:** Medium. Production stability issue.

**Location:** Suspected in `src/llm_firewall/core/batch_processor.py` (if exists)

**Action Required:**
1. Implement streaming batch processing
2. Add LRU eviction during processing
3. Add checkpointing for large batches
4. Enforce 300MB memory limit
5. Add memory monitoring/alerting

---

### 5. Embedding Cache Unbounded Growth

**Status:** No size limits, TTL, or eviction policy

**Evidence:**
- No `MAX_SIZE` configuration found
- No TTL implementation
- No eviction policy (LRU, LFU, etc.)

**Problem:**
- Cache grows until memory exhaustion
- No automatic cleanup
- Memory leak over time

**Risk:** Medium. Production stability issue.

**Location:** `src/llm_firewall/cache/embedding_cache.py` (if exists)

**Action Required:**
1. Implement MAX_SIZE limit
2. Add TTL support
3. Implement LRU eviction policy
4. Add cache size monitoring
5. Add cache eviction metrics

---

### 6. Streaming Buffer Not Implemented

**Status:** 32 MiB limit mentioned in design but not implemented

**Evidence:**
- Design documents mention "32 MiB Streaming Buffer"
- No implementation found in codebase
- Risk of memory exhaustion on large file inputs

**Problem:**
- Large file inputs could exhaust memory
- No streaming/chunked processing
- No buffer size limits

**Risk:** Medium. Production stability issue.

**Location:** Not found (design-only)

**Action Required:**
1. Verify if streaming buffer is needed
2. If needed, implement 32 MiB buffer with chunked processing
3. Add buffer size monitoring
4. Add tests for large file inputs

---

## P2 - Integration & Operations (Medium Priority)

### 7. Redis Cloud Tests Skipped

**Status:** 0% test coverage for Redis Cloud integration

**Evidence:**
- `tests/integration/test_redis_cloud.py` skipped due to missing ENV vars
- `REDIS_CLOUD_HOST` and `REDIS_CLOUD_PASSWORD` not set in CI
- No mock/fixture implementation

**Problem:**
- No validation of Redis Cloud integration
- Production changes could break without detection
- No test coverage for critical infrastructure

**Risk:** Medium. Production outage risk.

**Location:** `tests/integration/test_redis_cloud.py`

**Action Required:**
1. Add Redis Cloud credentials to CI secrets
2. Implement mock/fixture for local testing
3. Add integration tests to CI pipeline
4. Document Redis Cloud setup procedure

---

### 8. Shadow-Allow Mechanism Undocumented

**Status:** Functionality exists but not documented or monitored

**Evidence:**
- Mentioned in design documents
- No API documentation
- No monitoring metrics
- Implementation location unclear

**Problem:**
- Security through obscurity
- No visibility into shadow-allow decisions
- Cannot audit or review decisions

**Risk:** Low-Medium. Operational transparency issue.

**Location:** Suspected in `kids_policy/firewall_engine_v2.py`

**Action Required:**
1. Document shadow-allow mechanism
2. Add monitoring metrics
3. Add audit logging
4. Document use cases and rationale

---

### 9. Configuration in Environment Variables (Unencrypted)

**Status:** API keys and passwords stored in plaintext .env files

**Evidence:**
- Configuration via environment variables
- No KMS integration
- No encrypted config files
- Credentials in plaintext

**Problem:**
- Secrets exposed in environment
- No encryption at rest
- No key rotation mechanism

**Risk:** Medium. Security compliance issue.

**Location:** Configuration files and environment setup

**Action Required:**
1. Document current security posture
2. Plan KMS/HSM integration
3. Implement encrypted config files
4. Add secret rotation mechanism
5. Document secure deployment procedures

---

## P3 - Architectural Debt (Low Priority)

### 10. TLA+ Formal Verification Not Implemented

**Status:** TLA+ spec stubbed but not implemented

**Evidence:**
- Design documents mention TLA+ specification
- No `docs/TLA_SPEC.tla` file found
- No formal verification results

**Problem:**
- Race conditions and deadlocks not formally verified
- No mathematical proof of correctness
- Unknown concurrency issues

**Risk:** Low. Theoretical correctness issue.

**Location:** Not found (design-only)

**Action Required:**
1. Verify if TLA+ spec exists
2. If exists, complete specification
3. Run TLC model checker
4. Document verification results

---

### 11. Hexagonal Architecture Not Strictly Enforced

**Status:** Domain layer imports adapter details directly

**Evidence:**
- Handover notes: "Implementation uses functional patterns rather than strict interface contracts"
- Domain code may import `redis_client` directly
- No strict port/adapter separation

**Problem:**
- Architectural violation
- Tight coupling between domain and infrastructure
- Difficult to test and maintain

**Risk:** Low. Code quality issue.

**Location:** Domain layer code

**Action Required:**
1. Audit domain layer imports
2. Refactor to use dependency injection
3. Implement strict port/adapter pattern
4. Add architectural tests

---

### 12. Monitoring Wrapper Not Implemented

**Status:** "Ready with monitoring wrapper" but implementation unclear

**Evidence:**
- Handover mentions monitoring wrapper
- No implementation found
- Metrics (Block/Allow ratios) not visible

**Problem:**
- No operational visibility
- Cannot monitor system health
- No alerting mechanism

**Risk:** Low-Medium. Operational issue.

**Location:** Not found

**Action Required:**
1. Verify if monitoring wrapper exists
2. If exists, document and expose metrics
3. If not exists, implement basic monitoring
4. Add Prometheus/Grafana integration
5. Document monitoring setup

---

## Test & Quality Issues

### 13. Adversarial Suite Not Fully Tested

**Status:** Only 3/51 vectors have dedicated tests

**Evidence:**
- `tests/adversarial/` contains only 3 test files
- Zero-width, RLO, and concatenation tests exist
- 48 vectors untested

**Problem:**
- No systematic testing of adversarial vectors
- Unknown which vectors bypass the system
- No regression testing

**Risk:** High. Security testing gap.

**Location:** `tests/adversarial/`

**Action Required:**
1. Create tests for all 51 adversarial vectors
2. Run suite in CI pipeline
3. Document bypass results
4. Track fix progress

---

### 14. Test Coverage Claims Unverified

**Status:** 95% coverage claimed but Redis/WASM tests skipped

**Evidence:**
- Handover claims "95% domain layer coverage"
- Redis tests skipped
- WASM tests mock-only
- Actual coverage likely <70%

**Problem:**
- Misleading coverage metrics
- Critical components untested
- False confidence in test quality

**Risk:** Medium. Quality assurance issue.

**Location:** Test suite

**Action Required:**
1. Measure actual test coverage
2. Include skipped tests in coverage calculation
3. Fix skipped tests or document why they're skipped
4. Set realistic coverage targets

---

### 15. CI/CD Gates Not Active

**Status:** Gates exist only in documentation

**Evidence:**
- Handover lists CI gates:
  - "Adversarial Resilience: 0/50 bypasses" (FAIL: 2/50)
  - "Memory < 300MB" (FAIL: 1355MB)
  - "Binary Size < 15MB" (N/A: Python)
- No enforcement in CI pipeline

**Problem:**
- No automated quality gates
- Broken builds not blocked
- Manual review required

**Risk:** Medium. Quality assurance issue.

**Location:** `.github/workflows/ci.yml`

**Action Required:**
1. Implement CI gates for adversarial resilience
2. Add memory limit checks
3. Add binary size checks (if applicable)
4. Block merges on gate failures
5. Document gate requirements

---

## Threat Model Not Updated

### 16. Threat Model Outdated

**Status:** New attack vectors not included in threat model

**Evidence:**
- Handover lists threat model scope
- New vectors (Unicode, concatenation) not documented
- No risk reassessment after fixes

**Problem:**
- Incomplete threat model
- Unknown attack surface
- No systematic risk assessment

**Risk:** High. Security planning issue.

**Location:** Threat model documentation

**Action Required:**
1. Update threat model with new vectors
2. Reassess risk after fixes
3. Document attack surface
4. Review and approve updated model

---

## Prioritized Action Plan

### Week 1: Security Critical (P0)

1. **Adversarial Bypass Analysis**
   - Run full adversarial suite (51 vectors)
   - Document all bypasses
   - Prioritize by severity
   - Fix top 5 critical bypasses

2. **Fail-Safe Implementation**
   - Change cache fail-open to fail-safe
   - Add manual override mechanism
   - Add monitoring/alerting
   - Document override procedure

3. **WASM Sandbox Verification**
   - Verify if WASM sandbox exists
   - If exists, implement timeout enforcement
   - If not exists, document as out-of-scope

### Week 2: Performance (P1)

1. **Memory Optimization**
   - Implement streaming batch processing
   - Add LRU eviction
   - Enforce 300MB limit
   - Add memory monitoring

2. **Cache Management**
   - Add embedding cache limits
   - Implement TTL and eviction
   - Add cache size monitoring

3. **Streaming Buffer**
   - Verify requirement
   - Implement if needed
   - Add tests

### Week 3: Operations (P2)

1. **Test Coverage**
   - Fix Redis Cloud tests
   - Add mocks/fixtures
   - Integrate into CI

2. **Documentation**
   - Document shadow-allow
   - Add monitoring metrics
   - Document configuration security

3. **Configuration Security**
   - Plan KMS integration
   - Document secure deployment
   - Add secret rotation

### Week 4: Quality (P3)

1. **Test Suite Expansion**
   - Create tests for all 51 vectors
   - Run in CI
   - Track progress

2. **Coverage Verification**
   - Measure actual coverage
   - Fix skipped tests
   - Set realistic targets

3. **CI/CD Gates**
   - Implement adversarial resilience gate
   - Add memory limit checks
   - Block on failures

---

## Most Critical Issues (Top 3)

1. **13 High-Severity Bypasses Unaddressed** - Unknown attack surface
2. **Fail-Open on Cache Failure** - Security violation
3. **WASM Infinite Loop DoS** - Production stability risk

**Recommendation:** Immediate threat modeling update and penetration testing before declaring "all critical issues resolved."

---

## Status Tracking

| Issue | Priority | Status | Assigned | Target Date |
|-------|----------|--------|----------|-------------|
| Adversarial Bypass Gap | P0 | Open | - | - |
| Fail-Open Behavior | P0 | Open | - | - |
| WASM Timeout | P0 | Open | - | - |
| Memory Leak | P1 | Open | - | - |
| Cache Growth | P1 | Open | - | - |
| Streaming Buffer | P1 | Open | - | - |
| Redis Tests | P2 | Open | - | - |
| Shadow-Allow Docs | P2 | Open | - | - |
| Config Encryption | P2 | Open | - | - |
| TLA+ Verification | P3 | Open | - | - |
| Hexagonal Arch | P3 | Open | - | - |
| Monitoring | P3 | Open | - | - |
| Test Suite | P3 | Open | - | - |
| Coverage | P3 | Open | - | - |
| CI Gates | P3 | Open | - | - |
| Threat Model | P0 | Open | - | - |

---

**Last Updated:** 2025-12-01
**Next Review:** Weekly until all P0 issues resolved
