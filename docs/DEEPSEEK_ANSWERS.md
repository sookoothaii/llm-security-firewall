# Answers to DeepSeek's Questions

**Date:** 2025-12-01
**Context:** Test Development Planning

---

## 1. Where is the `AdapterHealth` class?

**Answer:** **NOW IMPLEMENTED** ✅ - Created as part of P0 action item.

**Status:** Implemented in `src/llm_firewall/core/adapter_health.py`

**Location:** `src/llm_firewall/core/adapter_health.py` (created 2025-12-01)

**Reference:** External Review Response (P0 Item #1) - Circuit Breaker Pattern for Adapter Failures

**Implementation Plan:**
```python
# src/llm_firewall/cache/adapter_health.py (TO BE CREATED)
class AdapterHealth:
    def __init__(self):
        self.error_rate: float = 0.0
        self.latency_p99: float = 0.0
        self.consecutive_failures: int = 0
        self.circuit_state: str = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
```

---

## 2. Where are the 32 MiB streaming buffer limits implemented?

**Answer:** The review mentions "32 MiB buffer", but the actual implementation uses **8 MiB** for recursive decode.

**Location:** `src/hak_gal/layers/inbound/normalization_layer.py`

**Actual Implementation:**
- Recursive decode: Max 5 layers, **8 MiB buffer**, 200 ms TTL
- Reference: Handover document line 542

**Note:** The "32 MiB" mentioned in the review may refer to a different component or was a misunderstanding. The normalization layer uses 8 MiB.

**For Testing:** Test the 8 MiB limit in `normalization_layer.py`:
```python
# Test large payload handling
large_payload = "A" * (9 * 1024 * 1024)  # 9MB
decision = engine.process_input(user_id="test", text=large_payload)
```

---

## 3. Where is the `CACHE_MODE` env var switch implemented?

**Answer:** **IMPLEMENTED** in `src/llm_firewall/cache/decision_cache.py`

**Location:** Line 62-68

**Implementation:**
```python
def _get_cache_mode() -> str:
    """Get cache mode from environment variable."""
    mode = os.getenv("CACHE_MODE", "exact").lower()
    if mode not in ("exact", "semantic", "hybrid"):
        logger.warning(f"Invalid CACHE_MODE '{mode}', defaulting to 'exact'")
        return "exact"
    return mode
```

**Usage:**
- `CACHE_MODE=exact` → SHA-256 exact matching (Redis)
- `CACHE_MODE=semantic` → Cosine similarity (LangCache)
- `CACHE_MODE=hybrid` → Exact fallback to semantic

**Runtime Switching:** The mode is read on each call via `_get_cache_mode()`, so it can be changed without restart (if env var is updated).

**Test Files:**
- `tests/test_decision_cache.py` - Has examples of CACHE_MODE testing
- `tests/test_hybrid_cache.py` - Comprehensive cache mode tests

---

## 4. Which file contains the Shadow-Allow mechanism?

**Answer:** **CONFIG-ONLY IMPLEMENTATION** - Shadow-allow exists in deployment config, not in engine code.

**Locations:**
1. **Deployment Config:** `config/shadow_deploy.yaml` - Shadow deployment configuration
   - `runtime.mode: shadow_warn` - Returns PASS to caller, logs detections
   - Used for production telemetry collection without blocking requests
2. **Documentation:** `docs/SHADOW_DEPLOYMENT_GUIDE.md` - Shadow deployment guide

**Status:** P1 action item - "Shadow-Allow Mechanism Documentation" (v2.3.6)

**Note:** Shadow-allow is a deployment mode, not an engine feature. The engine always makes decisions, but the deployment config can be set to `shadow_warn` mode which logs but doesn't block.

**For Testing:** Test shadow-allow via deployment config (`config/shadow_deploy.yaml`), not engine code directly.

---

## 5. Should we have real Redis integration tests?

**Answer:** **YES - Both approaches recommended**

**Recommended Strategy:**
1. **Unit Tests:** Use `fakeredis` (in-memory, fast, no dependencies)
2. **Integration Tests:** Use Docker Compose with real Redis (for CI/CD)

**Implementation:**
```python
# Unit tests (fakeredis)
@pytest.fixture
def fake_redis():
    return fakeredis.FakeStrictRedis()

# Integration tests (Docker)
@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("REDIS_URL") and not os.getenv("REDIS_CLOUD_HOST"),
    reason="Redis connection not configured",
)
def test_cache_integration():
    # Real Redis connection
    pass
```

**Docker Compose File:** Create `docker-compose.test.yml` for integration tests:
```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

**Test Markers:**
- `@pytest.mark.unit` - Use fakeredis
- `@pytest.mark.integration` - Use real Redis (skip if not available)

---

## Summary

| Question | Status | Location | Action Required |
|----------|--------|----------|-----------------|
| AdapterHealth | ❌ Not exists | N/A | Create `adapter_health.py` (P0) |
| 32 MiB Buffer | ⚠️ Actually 8 MiB | `normalization_layer.py` | Test 8 MiB limit |
| CACHE_MODE | ✅ Implemented | `decision_cache.py:62` | Test mode switching |
| Shadow-Allow | ⚠️ Config only | `shadow_deploy.yaml` | Document mechanism (P1) |
| Redis Tests | ✅ Recommended | Both | Use fakeredis + Docker |

---

**Next Steps:**
1. Create `tests/conftest.py` with fakeredis fixture
2. Create `tests/performance/test_p99_adversarial.py` (P0)
3. Create `tests/unit/test_circuit_breaker.py` (P0 - requires AdapterHealth)
4. Create `tests/integration/test_cache_modes.py` with Docker support
5. Create `docker-compose.test.yml` for integration tests
