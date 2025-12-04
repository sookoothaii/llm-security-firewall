# Architecture Evolution - Pragmatic Hexagonal Implementation

**Date:** 2025-12-01
**Status:** Active - Dependency Rule Enforcement
**Purpose:** Document pragmatic evolution toward hexagonal architecture

---

## Overview

This document describes the pragmatic approach to hexagonal architecture evolution, focusing on enforcing the **Dependency Rule** (all dependencies point inward) without the overhead of strict interface contracts.

**Core Principle:** Domain layer must not import from infrastructure (cache, UI, HTTP, etc.). All infrastructure dependencies are injected via protocols (Python Protocols, not abstract base classes).

---

## Problem Statement

### Original Architecture Drift

**Issue:** `firewall_engine_v2.py` (domain core) directly imported from infrastructure:
```python
from llm_firewall.cache.decision_cache import get_cached, set_cached  # ❌ Violation
```

**Impact:**
- Violates Dependency Rule (domain depends on infrastructure)
- Makes testing harder (requires mocking infrastructure)
- Tightly couples domain to Redis implementation
- Difficult to swap cache implementations

### Why Not Strict Interfaces?

**Analysis:** Strict hexagonal architecture (abstract base classes, full interface contracts) was evaluated but rejected because:

1. **Performance Overhead:** More indirection = slower (P99 < 200ms is critical)
2. **Code Complexity:** Too much boilerplate for current phase (Alpha)
3. **Iteration Speed:** Need fast adapter changes during development
4. **Team Onboarding:** Simpler code = easier contributions

**Decision:** Use **pragmatic hexagonal** with Python Protocols for type hints and dependency injection, but without strict compile-time enforcement.

---

## Solution: Pragmatic Hexagonal Evolution

### 1. Protocol Definitions (`core/ports.py`)

**Purpose:** Define contracts using Python Protocols (structural subtyping, no runtime overhead).

**Implementation:**
```python
from typing import Protocol, Optional, Dict, Any

@runtime_checkable
class DecisionCachePort(Protocol):
    """Port for firewall decision caching."""

    def get(self, tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
        """Get cached decision."""
        ...

    def set(self, tenant_id: str, text: str, decision: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Cache decision."""
        ...
```

**Benefits:**
- Type hints provide clear intent
- No runtime overhead (type checking only)
- Duck typing: "If it quacks like a duck, it's a duck"
- Easy to mock in tests

### 2. Adapter Implementation (`cache/cache_adapter.py`)

**Purpose:** Wrap infrastructure functions to implement Protocol.

**Implementation:**
```python
from llm_firewall.core.ports import DecisionCachePort

class DecisionCacheAdapter(DecisionCachePort):
    """Adapter that wraps decision_cache functions."""

    def get(self, tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
        return get_cached(tenant_id, text)  # Delegates to infrastructure

    def set(self, tenant_id: str, text: str, decision: Dict[str, Any], ttl: Optional[int] = None) -> None:
        set_cached(tenant_id, text, decision, ttl)
```

**Benefits:**
- Infrastructure stays unchanged
- Protocol contract fulfilled
- Easy to swap implementations (e.g., `NullCacheAdapter` for tests)

### 3. Composition Root (`app/composition_root.py`)

**Purpose:** Central place to assemble system components and inject dependencies.

**Implementation:**
```python
class CompositionRoot:
    def create_firewall_engine(...) -> FirewallEngineV2:
        cache_adapter = self.create_cache_adapter()  # Create adapter
        engine = FirewallEngineV2(
            cache_adapter=cache_adapter,  # Inject via constructor
            ...
        )
        return engine
```

**Benefits:**
- Architecture is explicit and visible
- Easy to swap adapters (Redis → InMemory for tests)
- Single place to configure system

### 4. Domain Layer Refactoring (`core/firewall_engine_v2.py`)

**Change:** Remove direct import, accept cache via constructor.

**Before:**
```python
from llm_firewall.cache.decision_cache import get_cached, set_cached  # ❌

class FirewallEngineV2:
    def process_input(...):
        cached = get_cached(tenant_id, text)  # Direct call
```

**After:**
```python
# No direct import - only Protocol type hint
from llm_firewall.core.ports import DecisionCachePort  # ✅ (optional, for type hints)

class FirewallEngineV2:
    def __init__(self, cache_adapter: Optional[DecisionCachePort] = None, ...):
        self.cache_adapter = cache_adapter  # Injected

    def process_input(...):
        if self.cache_adapter:
            cached = self.cache_adapter.get(tenant_id, text)  # Protocol method
```

**Benefits:**
- Dependency Rule enforced (domain doesn't import infrastructure)
- Backward compatible (legacy import fallback if adapter is None)
- Easy to test (inject `NullCacheAdapter`)

---

## Usage Examples

### Production Usage (with Composition Root)

```python
from llm_firewall.app.composition_root import create_default_firewall_engine

# Uses Redis cache adapter (default)
engine = create_default_firewall_engine()

decision = engine.process_input("user123", "user input")
```

### Custom Configuration

```python
from llm_firewall.app.composition_root import CompositionRoot
from llm_firewall.cache.cache_adapter import NullCacheAdapter

# Disable cache
root = CompositionRoot(enable_cache=False)
engine = root.create_firewall_engine()
```

### Testing

```python
from llm_firewall.cache.cache_adapter import NullCacheAdapter
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

# Inject null cache (no external dependencies)
engine = FirewallEngineV2(cache_adapter=NullCacheAdapter())
```

---

## Enforcement Strategy

### Current: Manual Discipline

- Code review checks for infrastructure imports in domain layer
- Protocol type hints provide clear intent
- Composition Root makes architecture explicit

### Future: Static Analysis (Recommended)

**Tool:** `import-linter` or custom pylint rule

**Rule:** Files in `src/llm_firewall/core/` must NOT import from:
- `llm_firewall.cache.*` (except `core.ports`)
- `llm_firewall.ui.*`
- `redis`, `requests`, `flask`, etc.

**CI/CD Integration:**
```yaml
# .github/workflows/ci.yml
- name: Check Dependency Rule
  run: |
    import-linter --config .importlinter
```

---

## Migration Status

### ✅ Completed

- [x] Protocol definitions (`ports.py`)
- [x] Cache adapter (`cache_adapter.py`)
- [x] Composition root (`composition_root.py`)
- [x] Domain layer refactoring (`firewall_engine_v2.py`)
- [x] Backward compatibility (legacy import fallback)

### 🔄 In Progress

- [ ] Static analysis enforcement (import-linter setup)
- [ ] Documentation updates (README, contributing guide)
- [ ] Example usage in tests

### 📋 Future (When Needed)

- [ ] Additional port definitions (DecoderPort, ValidatorPort integration)
- [ ] Full Protocol implementation for all adapters
- [ ] Architecture tests (verify Dependency Rule)

---

## Trade-offs

### ✅ Advantages

1. **Performance:** No runtime overhead (Protocols are type hints only)
2. **Simplicity:** Less boilerplate than strict interfaces
3. **Flexibility:** Easy to swap adapters without changing domain
4. **Testability:** Easy to mock (inject test adapters)
5. **Backward Compatible:** Legacy code still works

### ⚠️ Limitations

1. **No Compile-Time Enforcement:** Static analysis needed for strict checking
2. **Manual Discipline:** Developers must follow Dependency Rule
3. **Type Safety:** Protocols don't enforce at runtime (duck typing)

### 🎯 When to Strengthen

**Consider stricter enforcement if:**
- Repeated violations in code reviews
- Need multiple cache implementations simultaneously
- Team grows and discipline breaks down
- Performance requirements relax

---

## References

- **Handover Document:** `docs/HANDOVER_2025_12_01.md`
- **Critical Issues:** `docs/CRITICAL_ISSUES_REGISTER.md`
- **Architecture Analysis:** External review (pragmatic vs. strict hexagonal)

---

## Conclusion

The pragmatic hexagonal evolution successfully enforces the Dependency Rule while maintaining performance and simplicity. The use of Python Protocols provides clear contracts without overhead, and the Composition Root makes the architecture explicit.

**Status:** ✅ Architecture drift resolved, Dependency Rule enforced
**Next Steps:** Add static analysis enforcement, document in contributing guide

---

**Last Updated:** 2025-12-01
**Version:** 1.0
