# DeepSeek Test Development Guide
**Date:** 2025-12-01
**Purpose:** Antworten auf konkrete Fragen für Python-Testentwicklung

---

## WICHTIG: Architektur-Hinweis

**Die Codebase verwendet KEINE strikte Hexagonal-Architektur mit expliziten Port-Interfaces.**

Stattdessen:
- **Cache:** Funktionen (`get_cached()`, `set_cached()`) statt `ICachePort` Interface
- **Domain:** Direkte Klassen (`FirewallEngineV2`, `FirewallDecision`) statt abstrakte Ports
- **Dependency Injection:** Constructor Injection, aber keine zentrale DI-Container

**Warum:** Pragmatische Implementierung mit hexagonalen Prinzipien (Framework-Unabhängigkeit), aber ohne explizite Port/Adapter-Abstraktionen.

---

## 1. Domain-Layer Struktur

### ❌ NICHT vorhanden: `src/domain/ports/icache_port.py`

### ✅ TATSÄCHLICH: Cache-Funktionen

**Datei:** `src/llm_firewall/cache/decision_cache.py`

```python
# Erste 5 Zeilen:
"""
HAK_GAL Decision Cache - Redis/LangCache-Backed Firewall Decision Caching

Performance optimization: Cache firewall decisions after normalization layer
to achieve < 1 ms hit latency for repeated prompts.
"""

# Interface-Vertrag (Funktions-Signaturen):
def get_cached(tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
    """
    Get cached firewall decision (sync implementation).

    Returns:
        Cached decision dict or None (fail-open on cache errors)
    """
    pass

def set_cached(
    tenant_id: str,
    text: str,
    decision: Dict[str, Any],
    ttl: Optional[int] = None
) -> None:
    """
    Cache firewall decision (sync implementation).

    Args:
        tenant_id: Tenant identifier (defaults to "default")
        text: Normalized text (after Layer 0.25)
        decision: Decision dict to cache
        ttl: Time-to-live in seconds (default: 3600, or REDIS_TTL env var)
    """
    pass

def initialize_cache(redis_pool=None):
    """
    Initialize decision cache with TenantRedisPool instance.

    Args:
        redis_pool: TenantRedisPool instance (optional, can be set via env)
    """
    pass
```

**Exceptions:**
- `RedisError` (from `redis.exceptions`) - wird gefangen, `None` zurückgegeben (fail-open)
- Keine `CacheMissException` - nur `None` bei Cache-Miss

---

## 2. FirewallDecision Data Class

### ✅ Datei: `src/llm_firewall/core/firewall_engine_v2.py`

**Erste 5 Zeilen:**
```python
@dataclass
class FirewallDecision:
    """
    Decision result from firewall processing.

    Attributes:
        allowed: Whether the request/response is allowed
        reason: Human-readable reason for allow/block decision
```

**Vollständige Struktur:**
```python
@dataclass
class FirewallDecision:
    allowed: bool
    reason: str
    sanitized_text: Optional[str] = None
    risk_score: float = 0.0
    detected_threats: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.detected_threats is None:
            self.detected_threats = []
        if self.metadata is None:
            self.metadata = {}
```

**Beispiel:**
```python
decision = FirewallDecision(
    allowed=False,
    reason="Pattern match: SQL injection detected",
    sanitized_text=None,
    risk_score=0.95,
    detected_threats=["sql_injection", "pattern_match"],
    metadata={"layer": "L1", "pattern_id": "SQL_INJECTION_001"}
)
```

---

## 3. Test Fixtures (conftest.py)

### ❌ NICHT vorhanden: `tests/conftest.py` (zentrale Fixtures)

### ✅ TATSÄCHLICH: Fixtures in einzelnen Test-Dateien

**Beispiel aus `tests/test_decision_cache.py`:**

```python
@pytest.fixture
def mock_redis_pool():
    """Mock TenantRedisPool instance."""
    pool = Mock()
    pool.get_tenant_client = AsyncMock()
    return pool

@pytest.fixture
def mock_redis_client():
    """Mock Redis client."""
    client = AsyncMock()
    return client
```

**Beispiel aus `tests/test_tool_call_validator.py`:**

```python
@pytest.fixture
def validator():
    """Create a validator with default safe tools."""
    return ToolCallValidator(
        allowed_tools=["web_search", "calculator", "text_analysis"],
        strict_mode=True,
        enable_sanitization=True,
    )

@pytest.fixture
def lenient_validator():
    """Create a validator in lenient mode (sanitizes instead of blocking)."""
    return ToolCallValidator(
        allowed_tools=["web_search", "calculator", "text_analysis"],
        strict_mode=False,
        enable_sanitization=True,
    )
```

**Empfehlung:** Erstelle `tests/conftest.py` mit gemeinsamen Fixtures.

---

## 4. Test-Daten & Fixtures

### ✅ Adversarische Vektoren: JSONL Format

**Datei:** `data/gpt5_adversarial_suite.jsonl`

**Format:**
```json
{"id":"adv_001","attack_type":"zero_width_secret","payload":"sk-\u200Blive-\u200BABCDEF1234567890abcdEFGH","expected_detection":"should_block","weakness_if_pass":"Zero-width bypass survives normalization","severity":"critical"}
{"id":"adv_002","attack_type":"bidi_rlo_wrap","payload":"\u202E dcb a0987654321-FEDCBA-evil sk-live-","expected_detection":"should_block","weakness_if_pass":"RLO reverses match boundary; early-window leak","severity":"critical"}
```

**Vollständiger Testfall-Struktur:**
```python
test_case = {
    "id": "adv_001",
    "attack_type": "zero_width_secret",
    "payload": "sk-\u200Blive-\u200BABCDEF1234567890abcdEFGH",
    "expected_detection": "should_block",  # oder "should_allow"
    "weakness_if_pass": "Zero-width bypass survives normalization",
    "severity": "critical"  # oder "high", "medium", "low"
}
```

**Laden der Test-Daten:**
```python
import json

def load_adversarial_suite():
    """Load adversarial test vectors from JSONL."""
    test_cases = []
    with open("data/gpt5_adversarial_suite.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                test_cases.append(json.loads(line))
    return test_cases
```

**Anzahl:** 50+ Vektoren in `gpt5_adversarial_suite.jsonl`

---

## 5. Mock-Adapter Interface

### ✅ Minimaler Mock-Cache-Adapter

**Da es kein Interface gibt, kannst du eine Mock-Funktion erstellen:**

```python
from unittest.mock import Mock, patch
from typing import Optional, Dict, Any

class MockCacheAdapter:
    """Mock cache adapter for unit tests."""

    def __init__(self, should_fail: bool = False):
        self._store: Dict[str, Dict[str, Any]] = {}
        self.should_fail = should_fail
        self.call_count = 0

    def get(self, tenant_id: str, text: str) -> Optional[Dict[str, Any]]:
        """Mock get_cached."""
        self.call_count += 1
        if self.should_fail:
            raise ConnectionError("Mock cache connection failed")
        key = f"{tenant_id}:{text}"
        return self._store.get(key)

    def set(self, tenant_id: str, text: str, decision: Dict[str, Any], ttl: int = None):
        """Mock set_cached."""
        self.call_count += 1
        if self.should_fail:
            raise ConnectionError("Mock cache connection failed")
        key = f"{tenant_id}:{text}"
        self._store[key] = decision

# Verwendung in Tests:
@pytest.fixture
def mock_cache():
    return MockCacheAdapter()

def test_with_mock_cache(mock_cache):
    with patch('llm_firewall.cache.decision_cache.get_cached',
               side_effect=mock_cache.get):
        # Test code
        pass
```

**ConnectionPool/HealthCheck:** Nicht erforderlich - Cache verwendet direkte Redis-Verbindungen oder TenantRedisPool.

**Lebenszyklus-Methoden:** Nicht vorhanden - Cache ist stateless (Funktionen, keine Klassen).

---

## 6. Dependency Injection

### ✅ Pattern: Constructor Injection

**Beispiel:** `FirewallEngineV2`

```python
class FirewallEngineV2:
    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        strict_mode: bool = True,
        enable_sanitization: bool = True,
    ):
        # Layer 0: UnicodeSanitizer
        if HAS_UNICODE_SANITIZER and UnicodeSanitizer is not None:
            self.sanitizer = UnicodeSanitizer()
        else:
            self.sanitizer = None

        # Protocol HEPHAESTUS: Tool Call Extractor
        self.extractor = ToolCallExtractor(strict_mode=False)

        # Protocol HEPHAESTUS: Tool Call Validator
        self.validator = ToolCallValidator(
            allowed_tools=allowed_tools or [],
            strict_mode=strict_mode,
            enable_sanitization=enable_sanitization,
        )
```

**Keine zentrale DI-Container-Klasse.**

**Mock-Adapter in Tests einbinden:**
```python
def test_firewall_with_mock_cache():
    # Mock cache functions
    with patch('llm_firewall.cache.decision_cache.get_cached') as mock_get:
        mock_get.return_value = None  # Cache miss

        engine = FirewallEngineV2()
        decision = engine.process_input(user_id="test", text="malicious input")

        assert decision.allowed is False
```

---

## 7. Fehlerbehandlung & Exceptions

### ✅ Exception-Hierarchie

**Datei:** `src/hak_gal/core/exceptions.py`

**Erste 5 Zeilen:**
```python
"""
HAK_GAL v2.2-ALPHA: Custom Exception Hierarchy

Custom exceptions for security policy violations and system errors.
All exceptions inherit from SecurityException for unified error handling.
"""

# Vollständige Hierarchie:
class SecurityException(Exception):
    """Base exception for all security-related errors."""
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.code = code or "SECURITY_ERROR"
        self.metadata = metadata or {}

class PolicyViolation(SecurityException):
    """Raised when a security policy is violated."""
    def __init__(
        self,
        message: str,
        policy_name: str,
        risk_score: float = 1.0,
        detected_threats: Optional[list] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, code="POLICY_VIOLATION", metadata=metadata)
        self.policy_name = policy_name
        self.risk_score = risk_score
        self.detected_threats = detected_threats or []

class SystemError(SecurityException):
    """Raised when a system component fails (fail-closed behavior)."""
    def __init__(
        self,
        message: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, code="SYSTEM_ERROR", metadata=metadata)
        self.component = component

class BusinessLogicException(SecurityException):
    """Raised when business logic validation fails."""
    def __init__(
        self,
        message: str,
        tool_name: str,
        rule_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message,
            code="BUSINESS_LOGIC_VIOLATION",
            metadata=metadata or {},
        )
        self.tool_name = tool_name
        self.rule_name = rule_name
```

**Cache-Miss:** Keine `CacheMissException` - nur `None` zurückgegeben.

**Decode-Timeout:** Nicht als Exception implementiert - Timeout wird über Resource-Limits (8 MiB, 200 ms) gehandhabt.

---

## 8. Metriken & Observability

### ⚠️ NICHT implementiert: Explizite Metrics-Collector-Interface

**Aktueller Stand:**
- Logging via `logging.getLogger(__name__)`
- Keine strukturierte Metriken-Sammlung
- Keine `IMetricsCollector` Interface

**Für Tests:**
```python
# Mock logging
import logging
from unittest.mock import patch

def test_with_mocked_logging():
    with patch('llm_firewall.core.firewall_engine_v2.logger') as mock_logger:
        engine = FirewallEngineV2()
        # Test code
        mock_logger.info.assert_called()
```

**Empfehlung:** Implementiere `NoOpMetricsCollector` für Tests (P0 Action Item aus Review).

---

## 9. Performance Test Anforderungen

### ✅ Vorhanden: Performance-Test-Skripte

**Datei:** `scripts/perf_persistence_test.py`

**Beispiel:**
```python
def run_performance_test(num_sessions=100, events_per_session=50, concurrency=10):
    # Warm-up Phase
    # Measure Write Performance
    # Measure Update Performance
    # Calculate P95, P99 latencies
```

**Messung:**
- `time.perf_counter()` wird verwendet
- P95/P99 werden berechnet: `statistics.quantiles(latencies, n=100)[98]`

**Für P99-Latenz-Tests:**
```python
import time
import statistics

def test_p99_latency_adversarial_inputs():
    """Test P99 latency for worst-case adversarial inputs."""
    latencies = []
    warmup_iterations = 100
    test_iterations = 1000

    engine = FirewallEngineV2()

    # Warm-up
    for _ in range(warmup_iterations):
        engine.process_input(user_id="test", text="warmup")

    # Measure
    adversarial_payloads = load_adversarial_suite()
    for payload in adversarial_payloads[:test_iterations]:
        start = time.perf_counter()
        engine.process_input(user_id="test", text=payload["payload"])
        end = time.perf_counter()
        latencies.append((end - start) * 1000)  # Convert to ms

    p99 = statistics.quantiles(latencies, n=100)[98]
    assert p99 < 200.0  # P99 must be < 200ms
```

**pytest-benchmark:** Nicht integriert, aber empfohlen für zukünftige Tests.

---

## 10. Konfiguration Management

### ✅ Datei: `src/hak_gal/core/config.py`

**Erste 5 Zeilen:**
```python
"""
HAK_GAL v2.3.1: Runtime Configuration (Kill-Switch) - SECURED

Runtime-configurable flags and thresholds for emergency bypass and tuning.
SECURITY: HMAC-SHA256 signature required for all config changes.
"""

# Konfiguration wird über Environment Variables geladen:
CACHE_CONFIG = {
    "exact": {
        "adapter": "redis",
        "url": os.getenv("REDIS_URL", "redis://localhost:6379"),
        "timeout_ms": 100
    },
    "semantic": {
        "adapter": "langcache",
        "similarity_threshold": float(os.getenv("LANGCACHE_SIMILARITY_THRESHOLD", "0.92")),
        "timeout_ms": 300
    }
}
```

**Config-Klasse:** `RuntimeConfig` (Singleton) mit HMAC-Signatur-Schutz.

**Validation:** Keine `pydantic` - direkte Typ-Checks in `RuntimeConfig.update_config()`.

**Für Tests:**
```python
import os
from unittest.mock import patch

def test_with_custom_config():
    with patch.dict(os.environ, {
        "CACHE_MODE": "memory",
        "REDIS_TTL": "60"
    }):
        # Test code
        pass
```

---

## 11. Test Utilities & Helpers

### ⚠️ NICHT vorhanden: Zentrale Test-Utilities

**Empfehlung:** Erstelle `tests/utils/` mit:

```python
# tests/utils/helpers.py

def build_malicious_request(
    payload: str,
    encoding: str = "base64",
    compression: str = None
) -> str:
    """Build malicious request with encoding/compression."""
    if encoding == "base64":
        import base64
        payload = base64.b64encode(payload.encode()).decode()
    elif encoding == "url":
        import urllib.parse
        payload = urllib.parse.quote(payload)

    if compression == "gzip":
        import gzip
        payload = gzip.compress(payload.encode()).hex()

    return payload

def assert_block_decision(
    decision: FirewallDecision,
    expected_reason: str = None,
    min_risk_score: float = 0.8
):
    """Assert that decision is BLOCK."""
    assert decision.allowed is False
    assert decision.risk_score >= min_risk_score
    if expected_reason:
        assert expected_reason in decision.reason

def assert_allow_decision(decision: FirewallDecision):
    """Assert that decision is ALLOW."""
    assert decision.allowed is True
    assert decision.risk_score < 0.5
```

---

## 12. CI/CD Integration

### ✅ Datei: `pytest.ini`

**Erste 5 Zeilen:**
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Markers
markers =
    security: Security-critical tests (canonicalization, evasion)
    integration: Integration tests requiring full stack
    slow: Slow tests (ablation, large datasets)
    xfail: Expected failures (demonstrates requirements)
    asyncio: Async tests requiring asyncio support
```

**Adversarische Tests aufrufen:**
```bash
# Alle adversarischen Tests
pytest tests/adversarial/ -v

# Oder mit Marker (wenn vorhanden):
pytest -m adversarial -v
```

**Coverage-Schwellwerte:**
- Domain: 95% (in pyproject.toml: `[tool.coverage.run]`)
- Adapters: 90% (nicht explizit, aber empfohlen)

---

## 13. Spezifische Test-Szenarien

### ✅ Vorhandene Test-Struktur:

```
tests/
├── unit/
│   ├── test_vector_guard.py
│   ├── test_tool_guard.py
│   └── test_session_manager.py
├── integration/
│   └── test_firewall_engine.py
├── adversarial/
│   ├── test_adversarial_bypass.py
│   └── (weitere adversarische Tests)
└── test_decision_cache.py
```

**Kritische Test-Pfade:**

1. **Cache-Hit vs Cache-Miss:** `tests/test_decision_cache.py`
2. **Fail-Open:** `tests/test_decision_cache.py::test_redis_fail_open`
3. **Resource-Limits:** Nicht explizit getestet (empfohlen)
4. **Shadow-Allow:** Nicht explizit getestet (empfohlen)

---

## 14. Mocking-Strategien

### ✅ Verwendet: `unittest.mock`

**Beispiel aus `tests/test_decision_cache.py`:**

```python
from unittest.mock import Mock, patch, AsyncMock

@pytest.fixture
def mock_redis_pool():
    """Mock TenantRedisPool instance."""
    pool = Mock()
    pool.get_tenant_client = AsyncMock()
    return pool

def test_redis_connection_error():
    """Test fail-open behavior on Redis connection error."""
    with patch('llm_firewall.cache.decision_cache._get_exact_cached') as mock_get:
        mock_get.side_effect = ConnectionError("Redis connection failed")

        result = get_cached("test_tenant", "test_input")
        assert result is None  # Fail-open: returns None
```

**Mock-Klassen:**

```python
class MockRedisAdapter:
    def __init__(self, should_fail: bool = False, should_timeout: bool = False):
        self.should_fail = should_fail
        self.should_timeout = should_timeout
        self._store = {}

    def get(self, key: str):
        if self.should_fail:
            raise ConnectionError("Redis connection failed")
        if self.should_timeout:
            import time
            time.sleep(0.3)  # Simulate timeout
        return self._store.get(key)

    def setex(self, key: str, ttl: int, value: str):
        if self.should_fail:
            raise ConnectionError("Redis connection failed")
        self._store[key] = value
```

---

## 15. Zeitkritische Tests

### ✅ Pattern: `pytest-timeout` (empfohlen)

**Installation:**
```bash
pip install pytest-timeout
```

**Verwendung:**
```python
import pytest

@pytest.mark.timeout(0.3)  # 300ms timeout for test
def test_decode_timeout():
    """Test that decode operation times out after 200ms."""
    # Test mit langsamem Decoder
    pass
```

**Langsame Adapter simulieren:**
```python
import time
from unittest.mock import patch

def test_timeout_simulation():
    """Simulate slow adapter for timeout testing."""
    def slow_get_cached(tenant_id: str, text: str):
        time.sleep(0.3)  # Simulate 300ms latency
        return None

    with patch('llm_firewall.cache.decision_cache.get_cached',
               side_effect=slow_get_cached):
        # Test should timeout or handle gracefully
        pass
```

---

## 16. Test-Datenbank für Cache

### ⚠️ NICHT vorhanden: `docker-compose.test.yml`

**Empfehlung:** Erstelle `docker-compose.test.yml`:

```yaml
version: '3.8'
services:
  redis-test:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
```

**Oder verwende `fakeredis` für Unit-Tests:**

```python
import fakeredis
from unittest.mock import patch

@pytest.fixture
def fake_redis():
    """In-memory Redis mock for unit tests."""
    return fakeredis.FakeStrictRedis()

def test_with_fake_redis(fake_redis):
    with patch('redis.Redis', return_value=fake_redis):
        # Test code
        pass
```

---

## Zusammenfassung: Erste 5 Zeilen der kritischen Dateien

### 1. Cache-Interface (Funktionen, kein Interface)
**Datei:** `src/llm_firewall/cache/decision_cache.py`
```python
"""
HAK_GAL Decision Cache - Redis/LangCache-Backed Firewall Decision Caching

Performance optimization: Cache firewall decisions after normalization layer
to achieve < 1 ms hit latency for repeated prompts.
```

### 2. FirewallDecision Data Class
**Datei:** `src/llm_firewall/core/firewall_engine_v2.py`
```python
@dataclass
class FirewallDecision:
    """
    Decision result from firewall processing.

    Attributes:
        allowed: Whether the request/response is allowed
```

### 3. Test Fixtures (nicht zentral)
**Datei:** `tests/test_decision_cache.py` (Beispiel)
```python
"""
Unit Tests for Decision Cache Module.

Tests:
- Cache hit returns cached decision
```

**Empfehlung:** Erstelle `tests/conftest.py` mit gemeinsamen Fixtures.

---

## Nächste Schritte für DeepSeek

1. **Erstelle `tests/conftest.py`** mit gemeinsamen Fixtures
2. **Implementiere Mock-Adapter** für Cache (siehe Beispiel oben)
3. **Erstelle Test-Utilities** in `tests/utils/helpers.py`
4. **Implementiere P99-Latenz-Tests** für adversarische Inputs
5. **Erstelle `docker-compose.test.yml`** für Redis-Integration-Tests

**Repository-Struktur ist bereit für Test-Entwicklung!**

---

## 17. Konkrete Test-Beispiele

### Beispiel 1: Adversarischer Test (aus `tests/test_gpt5_adversarial.py`)

```python
import json
import pathlib
import pytest

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

def load_adversarial_suite():
    """Load adversarial test vectors from JSONL."""
    suite_path = root / "data" / "gpt5_adversarial_suite.jsonl"
    test_cases = []
    with open(suite_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                test_cases.append(json.loads(line))
    return test_cases

@pytest.mark.parametrize("test_case", load_adversarial_suite())
def test_adversarial_vector(test_case):
    """Test each adversarial vector from suite."""
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

    engine = FirewallEngineV2()
    decision = engine.process_input(
        user_id="test",
        text=test_case["payload"]
    )

    if test_case["expected_detection"] == "should_block":
        assert decision.allowed is False, \
            f"Failed to block: {test_case['id']} - {test_case['weakness_if_pass']}"
    else:
        assert decision.allowed is True
```

### Beispiel 2: Cache-Integration-Test (aus `tests/test_decision_cache_integration.py`)

```python
import pytest
import os
from llm_firewall.cache.decision_cache import get_cached, set_cached

@pytest.mark.skipif(
    not os.getenv("REDIS_URL") and not os.getenv("REDIS_CLOUD_HOST"),
    reason="Redis connection not configured",
)
def test_real_redis_connection():
    """Test basic Redis connection."""
    decision = {
        "allowed": True,
        "reason": "Integration test",
        "sanitized_text": "test",
        "risk_score": 0.0,
        "detected_threats": [],
        "metadata": {},
    }

    # Set cache
    set_cached("test_tenant", "integration_test_input", decision, ttl=60)

    # Get cache
    result = get_cached("test_tenant", "integration_test_input")

    # Verify
    assert result is not None
    assert result["allowed"]
    assert result["reason"] == "Integration test"
```

### Beispiel 3: Tool-Validator-Test (aus `tests/test_tool_call_validator.py`)

```python
import pytest
from llm_firewall.detectors.tool_call_validator import ToolCallValidator

@pytest.fixture
def validator():
    """Create a validator with default safe tools."""
    return ToolCallValidator(
        allowed_tools=["web_search", "calculator", "text_analysis"],
        strict_mode=True,
        enable_sanitization=True,
    )

def test_sql_injection_detection(validator):
    """Test SQL injection detection in query arguments."""
    # SQL injection in query argument
    result = validator.validate_tool_call(
        "web_search",
        {"query": "test' OR '1'='1"}
    )
    assert result.allowed is False
    assert "sql_injection" in result.detected_threats
    assert result.risk_score >= 0.8
```

---

## 18. Factory-Pattern für Test-Daten

### Empfehlung: Erstelle `tests/factories.py`

```python
"""Test data factories for consistent test data generation."""

from llm_firewall.core.firewall_engine_v2 import FirewallDecision

def create_firewall_decision(
    allowed: bool = True,
    reason: str = "Test decision",
    risk_score: float = 0.0,
    detected_threats: list = None
) -> FirewallDecision:
    """Factory for FirewallDecision objects."""
    return FirewallDecision(
        allowed=allowed,
        reason=reason,
        sanitized_text=None,
        risk_score=risk_score,
        detected_threats=detected_threats or [],
        metadata={}
    )

def create_malicious_payload(
    attack_type: str = "sql_injection",
    encoding: str = None
) -> str:
    """Factory for malicious payloads."""
    payloads = {
        "sql_injection": "test' OR '1'='1",
        "path_traversal": "../../etc/passwd",
        "rce": "os.system('rm -rf /')",
        "xss": "<script>alert('XSS')</script>",
    }

    payload = payloads.get(attack_type, payloads["sql_injection"])

    if encoding == "base64":
        import base64
        payload = base64.b64encode(payload.encode()).decode()
    elif encoding == "url":
        import urllib.parse
        payload = urllib.parse.quote(payload)

    return payload
```

---

## 19. Performance-Benchmark-Struktur

### Empfehlung: Erstelle `tests/performance/test_p99_latency.py`

```python
"""P99 latency tests for worst-case adversarial inputs."""

import time
import statistics
import pytest
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

@pytest.mark.slow
@pytest.mark.performance
def test_p99_latency_adversarial_inputs():
    """Test P99 latency for worst-case adversarial inputs."""
    latencies = []
    warmup_iterations = 100
    test_iterations = 1000

    engine = FirewallEngineV2()

    # Load adversarial payloads
    adversarial_payloads = load_adversarial_suite()

    # Warm-up phase
    for _ in range(warmup_iterations):
        engine.process_input(user_id="test", text="warmup input")

    # Measure phase
    for payload in adversarial_payloads[:test_iterations]:
        start = time.perf_counter()
        engine.process_input(user_id="test", text=payload["payload"])
        end = time.perf_counter()
        latencies.append((end - start) * 1000)  # Convert to ms

    # Calculate percentiles
    p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
    p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile

    print(f"P95 latency: {p95:.2f} ms")
    print(f"P99 latency: {p99:.2f} ms")

    # Assertions
    assert p99 < 200.0, f"P99 latency {p99:.2f}ms exceeds 200ms threshold"
    assert p95 < 100.0, f"P95 latency {p95:.2f}ms exceeds 100ms threshold"
```

---

## 20. Zusammenfassung: Was fehlt vs. was vorhanden ist

### ✅ Vorhanden:
- `FirewallDecision` Dataclass
- Exception-Hierarchie (`SecurityException`)
- Cache-Funktionen (`get_cached`, `set_cached`)
- Adversarische Test-Daten (JSONL)
- Pytest-Konfiguration (`pytest.ini`)
- Einzelne Test-Fixtures in Test-Dateien

### ⚠️ Fehlt (empfohlen zu erstellen):
- Zentrale `tests/conftest.py` mit gemeinsamen Fixtures
- `tests/utils/helpers.py` mit Test-Utilities
- `tests/factories.py` für Test-Daten-Generierung
- `tests/performance/test_p99_latency.py` für Performance-Tests
- `docker-compose.test.yml` für Redis-Integration-Tests
- Explizite `ICachePort` Interface (optional, aber empfohlen für bessere Testbarkeit)

---

**Die Codebase ist testbar, aber würde von zentralen Test-Utilities profitieren!**
