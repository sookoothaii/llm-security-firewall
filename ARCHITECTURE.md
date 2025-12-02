# Architecture Guide - LLM Security Firewall

**Purpose:** Guide for contributors on architectural patterns and dependency rules.
**Status:** Active - Required reading for all contributors
**Last Updated:** 2025-12-01

---

## Core Principle: The Dependency Rule

**RULE:** Domain modules (`core/`, `detectors/`, `safety/`) **MUST NEVER** import from infrastructure (`cache/`, `ui/`, external libraries like `redis`, `requests`).

**Why:** This keeps our core security logic testable, swappable, and fast. For a security firewall, this is non-negotiable.

**How:** Infrastructure is accessed via **Protocol-defined Ports** and injected through the **Composition Root**.

---

## Architecture Pattern: Pragmatic Hexagonal

We use a **pragmatic hexagonal architecture** that enforces the Dependency Rule without strict interface overhead.

### Key Components

1. **Protocol Definitions** (`core/ports.py`)
   - Python `Protocol` types define contracts (no runtime overhead)
   - Example: `DecisionCachePort`, `DecoderPort`, `ValidatorPort`
   - Enables duck typing: "If it quacks like a duck, it's a duck"

2. **Adapters** (`cache/cache_adapter.py`, etc.)
   - Wrap infrastructure functions to implement Protocols
   - Contain failure policies (circuit breaker, fail-safe fallback)
   - Example: `DecisionCacheAdapter` wraps Redis cache functions

3. **Composition Root** (`app/composition_root.py`)
   - **Sole place** for wiring dependencies
   - Creates adapters and injects them into domain
   - Makes architecture explicit and testable

4. **Domain Layer** (`core/firewall_engine_v2.py`, etc.)
   - **No infrastructure imports** (enforced by static analysis)
   - Receives adapters via constructor injection
   - Pure business logic, testable with mock adapters

---

## The Rule in Practice

### ✅ CORRECT: Dependency Injection

```python
# Domain layer (core/firewall_engine_v2.py)
from llm_firewall.core.ports import DecisionCachePort  # ✅ Protocol only

class FirewallEngineV2:
    def __init__(self, cache_adapter: DecisionCachePort, ...):
        self.cache_adapter = cache_adapter  # ✅ Injected

    def process_input(self, ...):
        cached = self.cache_adapter.get(tenant_id, text)  # ✅ Protocol method
```

```python
# Composition Root (app/composition_root.py)
from llm_firewall.cache.cache_adapter import DecisionCacheAdapter  # ✅ OK here
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

def create_firewall_engine(...):
    cache_adapter = DecisionCacheAdapter()  # ✅ Create adapter
    engine = FirewallEngineV2(cache_adapter=cache_adapter)  # ✅ Inject
    return engine
```

### ❌ WRONG: Direct Infrastructure Import

```python
# Domain layer (core/firewall_engine_v2.py)
from llm_firewall.cache.decision_cache import get_cached  # ❌ VIOLATION
import redis  # ❌ VIOLATION
import requests  # ❌ VIOLATION

class FirewallEngineV2:
    def process_input(self, ...):
        cached = get_cached(tenant_id, text)  # ❌ Direct call
```

**This will be caught by CI/CD static analysis and the build will fail.**

---

## Fail-Safe Policy

**Security Principle:** Infrastructure failures must not bypass security.

**Implementation:** Failure policies (circuit breaker, fallback) are **contained in adapters**, not domain layer.

### Example: Cache Adapter Fail-Safe

```python
class DecisionCacheAdapter(DecisionCachePort):
    def __init__(self, fallback_adapter: NullCacheAdapter):
        self.fallback_adapter = fallback_adapter  # Fail-safe fallback

    def get(self, tenant_id: str, text: str):
        if self._is_circuit_open():  # Circuit breaker check
            return self.fallback_adapter.get(tenant_id, text)  # Fail-safe

        try:
            return get_cached(tenant_id, text)  # Try cache
        except Exception:
            return self.fallback_adapter.get(tenant_id, text)  # Fail-safe
```

**Result:** Domain layer always sees consistent behavior (cache hit or None). Failure policy is encapsulated in adapter.

---

## Testing Pattern

**Domain Layer Tests:** Use mock adapters (no external dependencies).

```python
from llm_firewall.cache.cache_adapter import NullCacheAdapter
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

def test_firewall_without_cache():
    # No Redis needed - NullCacheAdapter is pure Python
    engine = FirewallEngineV2(cache_adapter=NullCacheAdapter())
    decision = engine.process_input("user123", "test input")
    assert decision.allowed
```

**Integration Tests:** Use real adapters with test infrastructure.

```python
from llm_firewall.app.composition_root import CompositionRoot

def test_full_integration():
    root = CompositionRoot(enable_cache=True)  # Uses real Redis
    engine = root.create_firewall_engine()
    # ... test with real infrastructure
```

---

## Adding New Infrastructure

When adding new infrastructure (new cache backend, new external service):

1. **Define Protocol** in `core/ports.py`:
   ```python
   @runtime_checkable
   class NewServicePort(Protocol):
       def do_thing(self, param: str) -> Result: ...
   ```

2. **Create Adapter** that implements Protocol:
   ```python
   class NewServiceAdapter(NewServicePort):
       def __init__(self):
           # Initialize infrastructure client
           pass

       def do_thing(self, param: str) -> Result:
           # Call infrastructure, handle failures
           pass
   ```

3. **Wire in Composition Root**:
   ```python
   def create_new_service_adapter(self) -> NewServicePort:
       return NewServiceAdapter()
   ```

4. **Inject into Domain**:
   ```python
   engine = FirewallEngineV2(
       cache_adapter=cache_adapter,
       new_service_adapter=new_service_adapter  # ✅ Injected
   )
   ```

5. **Never import infrastructure in domain layer** ❌

---

## Enforcement

### Static Analysis (CI/CD)

The build **automatically enforces** the Dependency Rule using `import-linter`:

```bash
# Run manually
import-linter --config .importlinter

# Or via CI/CD (runs on every PR)
```

**If domain layer imports infrastructure:** Build fails. PR cannot be merged.

### Manual Checklist

Before submitting PR:

- [ ] Domain modules (`core/`, `detectors/`, `safety/`) have no imports from `cache/`, `ui/`, or external libraries
- [ ] New infrastructure wrapped in adapter implementing Protocol
- [ ] Adapter wired in Composition Root
- [ ] Adapter injected into domain via constructor
- [ ] Fail-safe policies contained in adapter (not domain)

---

## Common Mistakes

### ❌ Mistake 1: "Quick Fix" Direct Import

```python
# core/firewall_engine_v2.py
from llm_firewall.cache.decision_cache import get_cached  # ❌ WRONG

# Fix: Use injected adapter instead
cached = self.cache_adapter.get(tenant_id, text)  # ✅ CORRECT
```

### ❌ Mistake 2: Failure Policy in Domain Layer

```python
# core/firewall_engine_v2.py
try:
    cached = self.cache_adapter.get(tenant_id, text)
except Exception:
    # ❌ WRONG: Failure policy should be in adapter
    return FirewallDecision(allowed=True, ...)
```

**Fix:** Adapter should handle failures internally and return None or use fallback.

### ❌ Mistake 3: Infrastructure Creation in Domain

```python
# core/firewall_engine_v2.py
def __init__(self):
    # ❌ WRONG: Domain should not create infrastructure
    self.redis_client = redis.Redis(...)
```

**Fix:** Receive adapter via constructor (created in Composition Root).

---

## Performance Impact

**Q: Does this pattern slow down the system?**

**A: No.** Python Protocols are type hints only (no runtime overhead). The adapter layer adds minimal indirection (~1 function call), which is negligible compared to network I/O (Redis, HTTP).

**Measured Impact:** <1% latency overhead, well within P99 <200ms target.

---

## References

- **Detailed Evolution:** `docs/ARCHITECTURE_EVOLUTION.md`
- **Critical Issues:** `docs/CRITICAL_ISSUES_REGISTER.md`
- **Handover:** `docs/HANDOVER_2025_12_01.md`

---

## Questions?

If you're unsure whether your change violates the Dependency Rule:

1. **Check:** Does your domain module import from `cache/`, `ui/`, or external libraries?
2. **If yes:** Wrap in adapter, inject via Composition Root.
3. **If unsure:** Ask in PR comments or GitHub Discussion.

**Remember:** The Dependency Rule is not negotiable. It's the foundation of testable, maintainable, and performant security code.

---

**Last Updated:** 2025-12-01
**Version:** 1.0
