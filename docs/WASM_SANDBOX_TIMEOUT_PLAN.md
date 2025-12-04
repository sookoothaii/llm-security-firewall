# WASM Sandbox Timeout Implementation Plan

**Priority:** P0 (Security Critical)
**Status:** Not Implemented - Plan for Implementation
**Date:** 2025-12-01
**Issue Reference:** `docs/CRITICAL_ISSUES_REGISTER.md` - Issue #3

---

## Problem Statement

**Current State:** WASM sandbox timeout enforcement is missing or not implemented.

**Security Risk:** DoS vulnerability through infinite loops in WASM rules. A simple `while(1){}` in WASM could hang the system indefinitely.

**Evidence:**
- No `wasm_sandbox.py` file found in codebase
- Documentation mentions "timeout=50" but no implementation found
- No `signal.alarm()` or thread-killing mechanism
- No hardware interrupt or signal-based timeout enforcement

---

## Solution: Hardware-Interrupt Timeout with Signal-Based Enforcement

### Architecture Pattern

Following our **pragmatic hexagonal architecture**:

1. **Protocol Definition** (`core/ports.py`): `SandboxExecutorPort`
2. **Adapter Implementation** (`sandbox/wasm_sandbox_adapter.py`): `WASMSandboxAdapter`
3. **Composition Root Integration**: Wire adapter in `app/composition_root.py`
4. **Domain Layer Usage**: Inject adapter into `FirewallEngineV2`

---

## Implementation Strategy

### Option A: Signal-Based Timeout (Recommended for Linux/macOS)

**Pros:**
- True hardware interrupt (OS-level enforcement)
- Works even if WASM code blocks Python interpreter
- Standard Python library (`signal`, `signal.alarm()`)

**Cons:**
- Windows compatibility issues (`signal.alarm()` not available on Windows)
- Requires fallback for Windows

**Implementation:**
```python
import signal
import os
from typing import Dict, Any
from llm_firewall.core.ports import SandboxExecutorPort

class TimeoutError(Exception):
    """Raised when WASM execution exceeds timeout."""

class WASMSandboxAdapter(SandboxExecutorPort):
    def __init__(self, timeout_ms: int = 50):
        self.timeout_ms = timeout_ms
        # ... WASM runtime initialization

    def validate(self, text: str, timeout: int = None) -> Dict[str, Any]:
        timeout = timeout or self.timeout_ms

        def timeout_handler(signum, frame):
            raise TimeoutError(f"WASM execution exceeded {timeout}ms")

        # Set signal handler for timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout // 1000)  # Convert ms to seconds

        try:
            result = self._execute_wasm(text)
            signal.alarm(0)  # Cancel timeout
            return result
        except TimeoutError:
            return {"allowed": False, "reason": "WASM timeout exceeded"}
        finally:
            signal.signal(signal.SIGALRM, old_handler)  # Restore handler
```

---

### Option B: Thread-Based Timeout (Windows Compatible)

**Pros:**
- Works on all platforms (Windows, Linux, macOS)
- Good for CPU-bound operations

**Cons:**
- Less reliable (thread can't be forcibly killed)
- May not interrupt blocking I/O operations
- Requires separate thread pool

**Implementation:**
```python
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from llm_firewall.core.ports import SandboxExecutorPort

class WASMSandboxAdapter(SandboxExecutorPort):
    def __init__(self, timeout_ms: int = 50):
        self.timeout_ms = timeout_ms
        self.executor = ThreadPoolExecutor(max_workers=4)
        # ... WASM runtime initialization

    def validate(self, text: str, timeout: int = None) -> Dict[str, Any]:
        timeout = timeout or self.timeout_ms
        timeout_seconds = timeout / 1000.0

        future = self.executor.submit(self._execute_wasm, text)
        try:
            result = future.result(timeout=timeout_seconds)
            return result
        except FutureTimeout:
            # Note: Thread cannot be forcibly killed, but we return timeout result
            logger.warning(f"WASM execution exceeded {timeout}ms")
            return {"allowed": False, "reason": "WASM timeout exceeded"}
```

---

### Option C: Hybrid Approach (Recommended)

**Strategy:** Use signal-based timeout on Unix (Linux/macOS) with thread-based fallback for Windows.

**Implementation:**
```python
import sys
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from llm_firewall.core.ports import SandboxExecutorPort

class WASMSandboxAdapter(SandboxExecutorPort):
    def __init__(self, timeout_ms: int = 50):
        self.timeout_ms = timeout_ms
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.use_signal = sys.platform != 'win32'  # Signal only on Unix
        # ... WASM runtime initialization

    def validate(self, text: str, timeout: int = None) -> Dict[str, Any]:
        timeout = timeout or self.timeout_ms

        if self.use_signal:
            return self._validate_with_signal(text, timeout)
        else:
            return self._validate_with_thread(text, timeout)

    def _validate_with_signal(self, text: str, timeout_ms: int) -> Dict[str, Any]:
        """Unix/Linux: Use signal.alarm() for hardware interrupt."""
        # ... signal-based implementation (Option A)
        pass

    def _validate_with_thread(self, text: str, timeout_ms: int) -> Dict[str, Any]:
        """Windows: Use ThreadPoolExecutor with timeout."""
        # ... thread-based implementation (Option B)
        pass
```

---

## Protocol Definition

Add to `src/llm_firewall/core/ports.py`:

```python
@runtime_checkable
class SandboxExecutorPort(Protocol):
    """
    Port for WASM sandbox execution with timeout enforcement.

    Adapters implementing this protocol:
    - WASMSandboxAdapter (with hardware interrupt timeout)
    - MockSandboxAdapter (for testing)

    Usage:
        sandbox: SandboxExecutorPort = WASMSandboxAdapter(timeout_ms=50)
        result = sandbox.validate(text, timeout=50)
    """

    def validate(self, text: str, timeout: int = 50) -> Dict[str, Any]:
        """
        Validate text against WASM rules with timeout enforcement.

        Args:
            text: Text to validate
            timeout: Maximum execution time in milliseconds

        Returns:
            Validation result dict with 'allowed', 'reason', etc.

        Raises:
            TimeoutError: If execution exceeds timeout (handled internally, returns result)
        """
        ...
```

---

## Implementation Steps

### Phase 1: Protocol & Adapter Structure (2 hours)

1. ✅ Add `SandboxExecutorPort` to `core/ports.py`
2. Create `src/llm_firewall/sandbox/wasm_sandbox_adapter.py`
3. Implement `WASMSandboxAdapter` with timeout mechanism (Hybrid Approach)
4. Create `MockSandboxAdapter` for testing

### Phase 2: WASM Runtime Integration (4-6 hours)

1. Choose WASM runtime (e.g., `wasmtime-python`, `wasmer-python`)
2. Integrate runtime into `WASMSandboxAdapter`
3. Implement rule loading from config
4. Add error handling for WASM compilation/execution errors

### Phase 3: Timeout Enforcement (2-3 hours)

1. Implement signal-based timeout (Unix)
2. Implement thread-based timeout (Windows)
3. Add timeout tests (infinite loop detection)
4. Verify timeout works with blocking operations

### Phase 4: Integration & Testing (2-3 hours)

1. Wire adapter in `app/composition_root.py`
2. Inject into `FirewallEngineV2`
3. Add integration tests
4. Document timeout behavior

**Total Estimated Time:** 10-14 hours

---

## Testing Strategy

### Unit Tests

```python
def test_wasm_timeout_infinite_loop():
    """Test that infinite loop in WASM is terminated."""
    sandbox = WASMSandboxAdapter(timeout_ms=100)

    # WASM code with infinite loop
    wasm_code = """
    (module
        (func $infinite_loop
            loop
                br 0
            end
        )
    )
    """

    result = sandbox.validate(wasm_code, timeout=100)
    assert not result["allowed"]
    assert "timeout" in result["reason"].lower()
    assert result["execution_time_ms"] < 150  # Should be close to 100ms
```

### Integration Tests

```python
def test_wasm_timeout_integration():
    """Test WASM timeout within firewall engine."""
    root = CompositionRoot()
    engine = root.create_firewall_engine()  # With WASM sandbox injected

    # Malicious input that triggers WASM rule with infinite loop
    result = engine.process_input("user123", malicious_input)

    # Should block due to timeout, not hang
    assert not result.allowed
    assert "timeout" in result.reason.lower()
```

---

## Dependencies

Add to `requirements.txt`:

```txt
# WASM Runtime (choose one)
wasmtime>=15.0  # Recommended: High performance, WASI Preview 2 support
# OR
wasmer>=3.0  # Alternative: Good Python bindings
```

---

## Configuration

Add to config files:

```yaml
# config/wasm_sandbox.yaml
wasm_sandbox:
  enabled: true
  timeout_ms: 50  # Maximum execution time
  rules_path: "config/wasm_rules/"
  runtime: "wasmtime"  # or "wasmer"

  # Timeout enforcement
  use_signal_timeout: true  # Unix only, auto-detected
  thread_timeout_fallback: true  # Windows fallback

  # Circuit breaker (if adapter becomes slow)
  failure_threshold: 5
  recovery_timeout_seconds: 30
```

---

## Fail-Safe Behavior

Following our **Fail-Safe Policy**:

**If WASM sandbox fails or times out:**
- Return `{"allowed": False, "reason": "WASM timeout exceeded"}` (fail-safe: block)
- **NOT** `{"allowed": True}` (fail-open: allow - security violation)

**Implementation in Adapter:**
```python
def validate(self, text: str, timeout: int = None) -> Dict[str, Any]:
    try:
        result = self._execute_with_timeout(text, timeout)
        return result
    except TimeoutError:
        logger.warning(f"WASM timeout exceeded: blocking for safety")
        return {"allowed": False, "reason": "WASM validation timeout - blocked for safety"}
    except Exception as e:
        logger.error(f"WASM execution error: {e}")
        return {"allowed": False, "reason": f"WASM validation error: {e}"}
```

---

## Security Considerations

1. **Timeout Must Be Enforced:** Hardware interrupt (signal) or thread timeout required
2. **Fail-Safe on Timeout:** Block, don't allow (security > availability)
3. **Resource Limits:** WASM runtime should also enforce memory limits
4. **Circuit Breaker:** If WASM adapter becomes slow, open circuit and block

---

## Migration Path

**Current State:** WASM sandbox not implemented (or timeout not enforced)

**Step 1:** Implement adapter with timeout enforcement
**Step 2:** Wire in Composition Root (optional/adapter can be None)
**Step 3:** Inject into FirewallEngineV2 (gracefully handles None adapter)
**Step 4:** Enable via config
**Step 5:** Run integration tests
**Step 6:** Monitor timeout rates in production

---

## References

- **Critical Issues:** `docs/CRITICAL_ISSUES_REGISTER.md` - Issue #3
- **Architecture Pattern:** `docs/ARCHITECTURE_EVOLUTION.md`
- **Fail-Safe Policy:** `ARCHITECTURE.md` - Fail-Safe Policy section
- **WASM Runtime Docs:**
  - [Wasmtime Python](https://docs.wasmtime.dev/lang/python.html)
  - [Wasmer Python](https://wasmer.io/docs/usage/python)

---

## Status Tracking

- [ ] Protocol defined (`SandboxExecutorPort`)
- [ ] Adapter structure created (`WASMSandboxAdapter`)
- [ ] Timeout mechanism implemented (signal + thread)
- [ ] WASM runtime integrated
- [ ] Tests written (timeout detection)
- [ ] Integration tests (with firewall engine)
- [ ] Composition Root wiring
- [ ] Documentation updated

---

**Last Updated:** 2025-12-01
**Next Review:** After implementation begins
