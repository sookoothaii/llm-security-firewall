# HAK_GAL v2.2-ALPHA → Beta Roadmap

**Status:** v2.2-ALPHA Complete | **Target:** Beta Release

---

## Current State (v2.2-ALPHA)

### ✅ Completed

- **Inbound Defense:**
  - Layer 0: UnicodeSanitizer (NFKC) gegen Homoglyphen-Obfuskation
  - Layer 1: RegexGate (Fail-Fast) für bekannte Jailbreak-Patterns
  - Layer 2: SemanticVectorCheck mit SessionTrajectory (Drift Detection)

- **Outbound Defense:**
  - ToolGuard Framework (Pure Python, NO OPA)
  - FinancialToolGuard mit State-Check (tx_count_1h) und Semantic-Check (forbidden keywords)

- **Core:**
  - Privacy-by-Design: HMAC(id + daily_salt), keine Raw-IDs im RAM
  - Stateful: Context und Trajectory teilen sich Session
  - Unified State Management via SessionManager

---

## Next Steps (Beta Roadmap)

### 1. Adversarial Hardening

**Goal:** Tune `drift_threshold` based on real-world attack datasets.

**Tasks:**
- [ ] Create `tests/adversarial/run_harmbench.py`
- [ ] Integrate HarmBench dataset (or similar adversarial dataset)
- [ ] Run systematic tests against:
  - Jailbreak attempts (various techniques)
  - Semantic drift attacks (topic switching)
  - Tool call injection attempts
- [ ] Measure:
  - False Positive Rate (FPR) at different thresholds
  - False Negative Rate (FNR) at different thresholds
  - Latency impact of vector checks
- [ ] Tune `drift_threshold` in `vector_guard.py` based on results
- [ ] Document optimal threshold range for different use cases

**Deliverable:** `docs/ADVERSARIAL_TUNING.md` with threshold recommendations

---

### 2. Persistence Layer

**Goal:** Replace in-memory `self._sessions = {}` with Redis for multi-pod deployments.

**Tasks:**
- [ ] Create `hak_gal/infrastructure/storage/redis_adapter.py`
- [ ] Implement `SessionStorage` interface (abstract base class)
- [ ] Redis adapter:
  - `get_session(hashed_id) -> Optional[SessionState]`
  - `save_session(hashed_id, session_state) -> None`
  - `delete_session(hashed_id) -> bool`
  - TTL handling (session expiration)
- [ ] Update `SessionManager` to use storage adapter (dependency injection)
- [ ] Add configuration for Redis connection (env vars)
- [ ] Migration guide: In-Memory → Redis
- [ ] Performance benchmarks: In-Memory vs Redis latency

**Deliverable:** `docs/PERSISTENCE_MIGRATION.md` and Redis adapter implementation

---

### 3. Observability

**Goal:** Add OpenTelemetry spans to track latency spikes in Vector-Check.

**Tasks:**
- [ ] Add `opentelemetry` dependency
- [ ] Instrument `engine.py`:
  - Span for `process_inbound()` (total latency)
  - Span for `process_outbound()` (total latency)
  - Nested spans:
    - `unicode_sanitizer` (usually < 1ms)
    - `regex_gate` (usually < 1ms)
    - `semantic_vector_check` (can be 50-200ms, critical to monitor)
    - `tool_guard_validation` (usually < 5ms)
- [ ] Add metrics:
  - `hak_gal_inbound_latency_seconds` (histogram)
  - `hak_gal_outbound_latency_seconds` (histogram)
  - `hak_gal_vector_check_latency_seconds` (histogram, critical)
  - `hak_gal_blocks_total` (counter, by reason)
- [ ] Export to Prometheus (or compatible)
- [ ] Dashboard example (Grafana) for monitoring

**Deliverable:** `docs/OBSERVABILITY.md` with dashboard configs

---

### 4. Additional Enhancements (Optional for Beta)

**Outbound Pipeline Completion:**
- [ ] `RecursiveDeobfuscator`: Base64/Hex recursion detection
- [ ] `JsonASTParser`: Parse and validate JSON AST before ToolGuard

**Performance Optimizations:**
- [ ] Embedding model caching (avoid reload on every request)
- [ ] Batch embedding computation (if multiple requests)
- [ ] Async session storage operations

**Documentation:**
- [ ] API Reference (Sphinx or similar)
- [ ] Architecture diagrams (Mermaid)
- [ ] Security model documentation

---

## Success Criteria for Beta

1. ✅ Adversarial testing completed, thresholds tuned
2. ✅ Redis persistence working in multi-pod setup
3. ✅ Observability metrics exported and dashboard available
4. ✅ Performance: < 200ms p99 latency for Inbound pipeline
5. ✅ False Positive Rate: < 1% on benign dataset
6. ✅ False Negative Rate: < 5% on adversarial dataset

---

## Notes

- **No "100% Protection" Marketing:** Beta will document real costs/benefits, not marketing claims
- **Layered Defense:** Each layer has trade-offs (latency vs. security)
- **Privacy-First:** All user IDs remain hashed, no raw IDs in logs/metrics

---

**Last Updated:** 2025-01-15
**Version:** v2.2-ALPHA → Beta Roadmap
