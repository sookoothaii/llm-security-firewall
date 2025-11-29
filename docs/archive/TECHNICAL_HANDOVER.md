# HAK_GAL v2.3.1 Technical Handover

**Version:** 2.3.1 (Security-Hardened)
**Date:** 2025-01-15
**Status:** Production-Ready Alpha
**Creator:** Joerg Bollwahn

---

## Executive Summary

HAK_GAL v2.3.1 is a defensive middleware framework for LLM Agents with a focus on **low latency**, **type safety**, **async I/O**, and **defense-in-depth**. The system provides bidirectional security (Inbound: User → LLM, Outbound: LLM → Tool) with privacy-first design and runtime-configurable kill-switches.

**Key Achievements:**
- Complete implementation of layered defense architecture
- Privacy-by-design: No raw user IDs stored
- Runtime configuration with HMAC signature + replay protection
- Async ToolGuard framework with priority-based execution
- SessionTrajectory with EMA for gradual drift prevention
- Timing attack mitigation via jitter injection

---

## Architecture Overview

### Directory Structure

```
src/hak_gal/
├── core/
│   ├── engine.py              # Main orchestrator (FirewallEngine)
│   ├── config.py              # RuntimeConfig (Kill-Switch + Replay Protection)
│   ├── session_manager.py     # Unified state management (Pydantic)
│   └── exceptions.py           # Exception hierarchy
├── layers/
│   ├── inbound/
│   │   ├── sanitizer.py       # UnicodeSanitizer (NFKC normalization)
│   │   ├── regex_gate.py      # RegexGate (Fast-fail patterns)
│   │   └── vector_guard.py    # SemanticVectorCheck + SessionTrajectory (EMA)
│   └── outbound/
│       └── tool_guard.py      # BaseToolGuard + Registry (Priority-based)
└── utils/
    └── crypto.py              # CryptoUtils (HMAC, PII redaction)
```

### Component Diagram

```
User Input
    ↓
[UnicodeSanitizer] → NFKC normalization
    ↓
[RegexGate] → Fast-fail pattern matching (jailbreak detection)
    ↓
[SemanticVectorCheck] → Drift detection via SessionTrajectory (EMA)
    ↓
LLM Processing
    ↓
[ToolGuardRegistry] → Priority-based validation (async + jitter)
    ↓
Tool Execution
```

---

## Core Components

### 1. FirewallEngine (`core/engine.py`)

**Main orchestrator** for Inbound and Outbound pipelines.

**Initialization:**
```python
from hak_gal.core.engine import FirewallEngine

engine = FirewallEngine(
    drift_threshold=0.6,  # Cosine distance threshold
    embedding_model="all-MiniLM-L6-v2"  # SentenceTransformer model
)
```

**Methods:**
- `async process_inbound(user_id: str, text: str) -> bool`
  - Pipeline: UnicodeSanitizer → RegexGate → SemanticVectorCheck
  - Respects `RuntimeConfig` flags (ENABLE_INBOUND_REGEX, ENABLE_INBOUND_VECTOR)
  - Stores embeddings in SessionTrajectory

- `async process_outbound(user_id: str, tool_name: str, tool_args: dict) -> bool`
  - Pipeline: Session Context → ToolGuardRegistry.validate() → Context Update
  - Respects `RuntimeConfig.ENABLE_OUTBOUND_TOOLS` flag
  - Updates stateful context (e.g., tx_count_1h)

**Features:**
- Privacy-first: All user IDs hashed via CryptoUtils
- Fail-closed: Any error blocks the request
- Runtime-configurable: Layer bypass via RuntimeConfig

---

### 2. RuntimeConfig (`core/config.py`)

**Singleton runtime configuration** with kill-switch and replay protection.

**Security Features:**
- HMAC-SHA256 signature required for all updates
- Timestamp validation (within 30 seconds)
- Nonce validation (prevents replay attacks)
- Thread-safe: All writes protected by Lock

**Usage:**
```python
from hak_gal.core.config import RuntimeConfig
import time
import uuid

config = RuntimeConfig()

# Get signature (for authorized clients)
timestamp = int(time.time())
nonce = str(uuid.uuid4())
signature = config.get_signature("ENABLE_INBOUND_VECTOR", False, timestamp, nonce)

# Update config (with replay protection)
config.update_config("ENABLE_INBOUND_VECTOR", False, signature, timestamp, nonce)
```

**Configuration Flags:**
- `ENABLE_INBOUND_REGEX: bool` - Enable/disable RegexGate
- `ENABLE_INBOUND_VECTOR: bool` - Enable/disable SemanticVectorCheck
- `ENABLE_OUTBOUND_TOOLS: bool` - Enable/disable ToolGuard validation
- `DRIFT_THRESHOLD: float` - Cosine distance threshold (default: 0.6)

**Replay Protection:**
- Nonce cache: Thread-safe Set with 60-second expiry
- Automatic cleanup: Prevents memory leaks
- Timestamp window: ±30 seconds from current time

---

### 3. SessionManager (`core/session_manager.py`)

**Unified state management** for Inbound (Trajectory) and Outbound (Context).

**Privacy-First Design:**
- All user IDs hashed via CryptoUtils (HMAC-SHA256 with daily salt)
- No raw user IDs stored in memory
- Daily salt rotation: Same user, different day → different hash

**SessionState (Pydantic Model):**
```python
class SessionState(BaseModel):
    trajectory_buffer: List[List[float]]  # Embeddings for drift detection
    context_data: Dict[str, Any]           # State for ToolGuard (e.g., tx_count_1h)
    created_at: datetime
```

**Key Methods:**
- `get_or_create_session(raw_user_id: str) -> SessionState` - Transparent hashing
- `update_context(raw_user_id: str, key: str, value: Any)` - Update ToolGuard state
- `add_vector(raw_user_id: str, vector: List[float])` - Update trajectory

---

### 4. Inbound Pipeline

#### UnicodeSanitizer (`layers/inbound/sanitizer.py`)
- NFKC normalization (neutralizes homoglyphs)
- Removes zero-width characters
- Fast: < 1ms

#### RegexGate (`layers/inbound/regex_gate.py`)
- Fast-fail pattern matching
- Patterns: Jailbreak ("ignore previous instructions", "system prompt"), Command Injection, SQLi, XSS
- Fast: < 1ms

#### SemanticVectorCheck (`layers/inbound/vector_guard.py`)
- **SessionTrajectory**: Rolling window buffer with EMA (Exponential Moving Average)
- **Drift Detection**: Cosine distance to session centroid
- **EMA Formula**: `NewCentroid = Alpha * NewVector + (1 - Alpha) * OldCentroid`
  - Alpha = 0.3 (30% weight to new vector, 70% to old centroid)
  - Makes system slower to drift (resistant to gradual poisoning attacks)
- **Embedding Model**: sentence-transformers/all-MiniLM-L6-v2 (real, lightweight)
- Slower: 50-200ms (embedding computation)

---

### 5. Outbound Pipeline

#### ToolGuard Framework (`layers/outbound/tool_guard.py`)

**BaseToolGuard (Abstract Base Class):**
```python
class BaseToolGuard(ABC):
    def __init__(self, tool_name: str, priority: int = 50):
        self.tool_name = tool_name
        self.priority = priority  # 0 = Highest, 100 = Lowest

    @abstractmethod
    async def validate(tool_name: str, args: dict, context: SessionContext) -> bool:
        # Raises BusinessLogicException on violation
        pass
```

**ToolGuardRegistry:**
- Priority-based execution: Guards sorted by priority (0 = highest first)
- Short-circuit: High-priority guard failure stops execution immediately
- **Timing Attack Mitigation**: Jitter after each guard (5-15ms random delay)
- Async: All guards executed with `await`

**Example: FinancialToolGuard**
- Priority: 30 (High priority for financial tools)
- Rules:
  1. Micro-Transaction Spam: Block if `amount < 1.0 AND tx_count_1h > 50`
  2. Forbidden Keywords: Block if `reason` contains "admin"

---

### 6. CryptoUtils (`utils/crypto.py`)

**Session ID Hashing:**
- `hash_session_id(raw_id: str) -> str`: HMAC-SHA256(raw_id + daily_salt, secret_key)
- Daily salt rotation: `get_daily_salt(date_str)` - HMAC(date_str, secret_key)
- Privacy: Never stores raw IDs

**PII Redaction:**
- `redact_pii(text: str) -> str`: Redacts emails, phone numbers, credit cards, IPs
- Only logs redacted text unless `LOG_LEVEL=FORENSIC`

---

## Security Features

### 1. Privacy-by-Design
- **No Raw IDs**: All user IDs hashed via CryptoUtils
- **Daily Salt Rotation**: Same user, different day → different hash
- **PII Redaction**: Automatic redaction in logs (unless FORENSIC mode)

### 2. Replay Protection
- **Timestamp Validation**: Requests must be within ±30 seconds
- **Nonce Validation**: Each request requires unique nonce (UUID)
- **Nonce Cache**: Thread-safe Set with 60-second expiry and automatic cleanup

### 3. Timing Attack Mitigation
- **Jitter Injection**: Random delay (5-15ms) after each ToolGuard execution
- **Obscures Timing**: Prevents side-channel analysis of guard execution time

### 4. Gradual Drift Prevention
- **EMA Centroid**: Exponential Moving Average instead of simple mean
- **Alpha = 0.3**: Gives newer vectors less weight (70% to old centroid)
- **Resistant to Slow Poisoning**: System adapts slowly to gradual topic shifts

### 5. Runtime Kill-Switch
- **HMAC Signature**: All config updates require valid signature
- **Layer Bypass**: Each security layer can be disabled at runtime (with signature)
- **Emergency Response**: Allows rapid response to operational issues

---

## Dependencies

### Required
```txt
sentence-transformers>=2.2.0  # Embedding model (all-MiniLM-L6-v2)
numpy>=1.24.0                  # Vector calculations
pydantic>=2.0.0                # Data models (SessionState)
```

### Optional
```txt
# For production deployment
fastapi>=0.100.0               # API framework (see examples/quickstart_fastapi.py)
uvicorn>=0.23.0                # ASGI server
```

---

## Testing

### Unit Tests
```bash
pytest tests/unit/
```

**Coverage:**
- SessionTrajectory: Normal flow, topic switch detection, rolling window
- ToolGuard: State-check, semantic-check, registry pattern
- SessionManager: Hashing, state persistence, salt rotation
- CryptoUtils: Daily salt, session ID hashing, PII redaction

### Integration Tests
```bash
pytest tests/integration/
```

**Coverage:**
- Complete agent loop: Inbound → Outbound
- Emergency kill-switch: Layer bypass
- Replay attack prevention
- Expired timestamp rejection
- Multi-user isolation

---

## Configuration

### Environment Variables

```bash
# Required for persistent config updates (recommended for production)
export HAKGAL_ADMIN_SECRET="your-32-byte-secret-key-here"

# Optional: Enable forensic logging (logs raw payloads)
export LOG_LEVEL=FORENSIC
```

### Runtime Configuration

```python
from hak_gal.core.config import RuntimeConfig

config = RuntimeConfig()

# Update drift threshold (requires signature + timestamp + nonce)
import time
import uuid
timestamp = int(time.time())
nonce = str(uuid.uuid4())
signature = config.get_signature("DRIFT_THRESHOLD", 0.7, timestamp, nonce)
config.update_config("DRIFT_THRESHOLD", 0.7, signature, timestamp, nonce)
```

---

## Performance Characteristics

### Latency (p99)
- **UnicodeSanitizer**: < 1ms
- **RegexGate**: < 1ms
- **SemanticVectorCheck**: 50-200ms (embedding computation dominates)
- **ToolGuard**: < 5ms (with jitter: +5-15ms)

### Total Pipeline Latency
- **Inbound**: ~50-200ms (dominated by Vector Check)
- **Outbound**: ~10-20ms (ToolGuard + jitter)

### Memory
- **SessionState**: ~1KB per session (trajectory + context)
- **Nonce Cache**: ~100 bytes per nonce, auto-cleanup after 60s
- **Embedding Model**: ~90MB (all-MiniLM-L6-v2, loaded once)

---

## Known Limitations & Trade-offs

### 1. False Positives
- **Semantic Drift Detection**: May block legitimate topic switches
- **Mitigation**: Tune `DRIFT_THRESHOLD` based on use case (higher = more lenient)

### 2. False Negatives
- **RegexGate**: Only catches known patterns
- **Vector Check**: May miss subtle attacks
- **No "100% Protection" Claim**: Layered defense with real cost/benefit trade-offs

### 3. Latency
- **Vector Check**: 50-200ms per request (embedding computation)
- **Mitigation**: Can be disabled via `ENABLE_INBOUND_VECTOR=False` (emergency bypass)

### 4. Concurrency
- **In-Memory Storage**: Current SessionManager uses dict (single-process)
- **Production**: Replace with Redis adapter for multi-pod deployments (see ROADMAP_BETA.md)

---

## Security Considerations

### 1. Admin Secret Management
- **Production**: MUST set `HAKGAL_ADMIN_SECRET` environment variable
- **Development**: Random secret generated (not persistent across restarts)
- **Rotation**: Change secret periodically, invalidates all existing signatures

### 2. Nonce Management
- **Uniqueness**: Clients must generate unique UUIDs for each request
- **Expiry**: Nonces expire after 60 seconds (automatic cleanup)
- **Memory**: Nonce cache bounded by cleanup interval (no unbounded growth)

### 3. Timestamp Validation
- **Clock Skew**: ±30 second window accounts for reasonable clock differences
- **NTP Sync**: Ensure server clocks are synchronized (NTP recommended)

### 4. Embedding Model Security
- **Model Loading**: Lazy-loaded on first use (may cause first request delay)
- **Timeout**: 5-second timeout for embedding computation (fail-closed)
- **Model Updates**: Update sentence-transformers for security patches

---

## Integration Example

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from hak_gal.core.engine import FirewallEngine
from hak_gal.core.exceptions import SecurityException

app = FastAPI()
firewall = FirewallEngine()

@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    try:
        await firewall.process_inbound(req.user_id, req.message)
        # ... LLM inference ...
        return {"status": "allowed"}
    except SecurityException as e:
        raise HTTPException(status_code=403, detail=str(e))
```

See `examples/quickstart_fastapi.py` for complete example.

---

## Roadmap (Beta)

See `ROADMAP_BETA.md` for:
- Adversarial hardening (HarmBench integration)
- Redis persistence (multi-pod support)
- OpenTelemetry observability

---

## Troubleshooting

### Issue: Config updates fail with "Unauthorized config change attempt"
**Solution**: Ensure `HAKGAL_ADMIN_SECRET` is set and signature includes timestamp + nonce.

### Issue: High latency in Inbound pipeline
**Solution**: Check if SemanticVectorCheck is enabled. Consider disabling via `ENABLE_INBOUND_VECTOR=False` (with signature) for emergency bypass.

### Issue: Replay attacks succeed
**Solution**: Verify nonce uniqueness (each request must use new UUID) and timestamp freshness (within ±30 seconds).

### Issue: Memory growth over time
**Solution**: Check nonce cleanup (should auto-cleanup after 60s). Verify SessionManager session expiration.

---

## Contact & Support

**Creator:** Joerg Bollwahn
**Version:** 2.3.1
**License:** MIT

For issues or questions, refer to:
- `README_V2_2_ALPHA.md` - User documentation
- `ROADMAP_BETA.md` - Future enhancements
- `tests/` - Test suite for usage examples

---

**Last Updated:** 2025-01-15
**Status:** Production-Ready Alpha (Security-Hardened)
