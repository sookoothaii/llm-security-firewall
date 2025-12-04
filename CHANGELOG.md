# Changelog

All notable changes to the **HAK_GAL LLM Security Firewall** project will be documented in this file.

## [2.5.0] - 2025-12-05

**Status:** Production Release (Current)

### Highlights

- **96% Reduction in Baseline Memory:** Firewall core now loads in **53.9 MB** (was ~1.3 GB). Target of 300 MB exceeded by 82%.

- **Optional Heavy Dependencies:** Install via `pip install llm-security-firewall[full]` to enable all ML validators. Core installation requires no PyTorch or transformers.

- **ONNX Runtime Integration:** Semantic vector checking now uses ONNX with CUDA support (speed priority), eliminating PyTorch dependency in the core path.

- **Lazy Loading & Monitoring:** Advanced validators (TruthPreservationValidator, TopicFence) load only when needed. Monitor usage via new `get_lazy_load_stats()` method.

### Added

- **Optional Dependency Groups:** `[full]` extra for torch/transformers/sentence-transformers (heavy ML validators)
- **Core Requirements File:** `requirements-core.txt` for minimal installations (~54 MB baseline)
- **Lazy-Loading Monitoring:** `get_lazy_load_stats()` method tracks when heavy components are loaded
- **ONNX-Based Semantic Guard:** `SemanticGroomingGuardONNX` with CUDAExecutionProvider support
- **Lightweight Tokenizer:** Replaced `transformers.AutoTokenizer` with `tokenizers` library (376.7 MB saved)

### Changed

- **Internal Architecture:** All ML components now lazy-loaded via `@property` decorators
- **Dependency Structure:** Moved `torch`, `transformers`, `sentence-transformers`, `scikit-learn` to optional dependencies
- **Import Strategy:** Eliminated transitive PyTorch imports from core path
- **Memory Footprint:** Baseline reduced from ~1327 MB to 53.9 MB (96% reduction)

### Fixed

- **Memory Leak:** Eliminated eager loading of transformer models at import time
- **Tokenizer Dependency:** Removed 386.1 MB `transformers` import cost from core path
- **Dependency Bloat:** Fixed ~726 MB baseline overhead from transitive imports

### Technical Details

- **Lazy Loading Impact:** Eliminated 482.8 MB initialization cost
- **Tokenizer Replacement:** 376.7 MB saved by switching to `tokenizers` library
- **Dependency Elimination:** 726 MB baseline reduction through optional dependencies
- **Total Reduction:** ~1100 MB from original 1.3 GB baseline

### Upgrade Note

This release is **fully backwards compatible**. The public API (`guard.check_input()`, `guard.check_output()`) remains unchanged. Existing code will continue to work without modifications.

**Installation Options:**
- **Core (Recommended):** `pip install llm-security-firewall` (~54 MB baseline)
- **Full ML Features:** `pip install llm-security-firewall[full]` (heavy validators available on-demand)

## [2.4.1] - 2025-12-04

**Status:** Production Release (Superseded by v2.5.0)

### Fixed

- False-Positive-Reduktion: Whitelist-Filter für harmlose Bildungsinhalte im Kids-Policy Risk Scorer.
- Betroffen: UNSAFE_TOPIC-Erkennung, die fälschlich einfache "Explain how..."-Fragen blockierte.
- Ergebnis: FPR von 22% auf 5% reduziert (77% relative Reduktion) bei stabiler ASR (40%).

### Technical Details

- Implementiert `_is_benign_educational_query()` Filter in `kids_policy/firewall_engine_v2.py`
- Filter wird vor UNSAFE_TOPIC-Blockierung angewendet
- Eliminiert alle 17 UNSAFE_TOPIC False Positives
- Keine Sicherheitsdegradierung (ASR unverändert)

## [2.4.0] - 2025-12-02

**Status:** Production Release (Superseded by v2.4.1)

### Release Summary

This is the first production release of llm-security-firewall with the new hexagonal architecture and Developer Adoption API. All critical security fixes have been validated and tested.

### Validated

- **Security Fixes:** All critical bypasses (Zero-Width, RLO, Concatenation) verified and fixed
- **Unicode Hardening:** 9/9 Unicode security tests passed
- **Adversarial Tests:** 4/4 security tests passed (100%)
- **False Positive Rate:** Improved to 0.0% in test suite (from 20-25%)
- **Package Build:** All build issues resolved, package installs correctly from PyPI

### Added

- **Hexagonal Architecture:** Protocol-based dependency injection for framework independence
- **Developer Adoption API:** Simple `guard.check_input()` and `guard.check_output()` API
- **LangChain Integration:** `FirewallCallbackHandler` for seamless LangChain integration
- **Comprehensive Documentation:** QUICKSTART.md, examples, and integration guides

### Changed

- **Fail-Safe Policy:** Cache failures now trigger block behavior (security-first)
- **Version Synchronization:** All metadata files synchronized (pyproject.toml, __init__.py, README.md)

### Fixed

- **Import Conflict:** Resolved `ports.py` vs `ports/` directory conflict
- **IndentationError:** Fixed critical syntax error in firewall_engine_v2.py
- **Package Metadata:** Corrected email addresses and architecture descriptions

### Known Limitations

- Optional dependencies (sentence-transformers, torch, etc.) required for full feature set
- Some advanced detection features disabled without optional ML dependencies
- Documented in README and expected behavior

## [2.4.0rc4] - 2025-12-02

### Fixed

- **Critical:** Fixed import conflict between `ports.py` and `ports/` directory. Protocol definitions moved to `ports/__init__.py` to resolve ImportError: `cannot import name 'DecisionCachePort'`.
- **Critical:** Fixed IndentationError in `firewall_engine_v2.py` line 327 that prevented package from initializing.

## [2.4.0rc3] - 2025-12-02

### Fixed

- **Critical:** Fixed IndentationError in `firewall_engine_v2.py` line 327 that prevented package from initializing.
- Synchronized package metadata and README with the actual repository state.
- Corrected architectural documentation to reflect the implemented hexagonal pattern (Protocol-based Port/Adapter interfaces).
- Fixed PyPI project description to accurately represent the current feature set.
- Updated cache behavior documentation from "fail-open" to "fail-safe behavior".
- Added Developer Adoption API (`guard.py`) and LangChain Integration documentation to README.

## [2.4.0rc2] - 2025-12-02

### Fixed

- Synchronized package metadata and README with the actual repository state.
- Corrected architectural documentation to reflect the implemented hexagonal pattern (Protocol-based Port/Adapter interfaces).
- Fixed PyPI project description to accurately represent the current feature set.
- Updated cache behavior documentation from "fail-open" to "fail-safe behavior".
- Added Developer Adoption API (`guard.py`) and LangChain Integration documentation to README.

## [2.4.0rc1] - 2025-12-01 (Architecture Evolution & Developer Adoption)

**Status:** Release Candidate

### Added

- **Hexagonal Architecture Refactoring:** Implemented pragmatic hexagonal architecture with Protocol-based dependency injection. Domain layer no longer imports infrastructure directly.
  - `src/llm_firewall/core/ports.py`: Protocol definitions (DecisionCachePort, DecoderPort, ValidatorPort)
  - `src/llm_firewall/cache/cache_adapter.py`: Adapter implementations with fail-safe policy
  - `src/llm_firewall/app/composition_root.py`: Dependency Injection container
  - Static analysis enforcement via `import-linter` in CI/CD pipeline

- **Developer Adoption API:** Simple one-liner integration for external users.
  - `src/llm_firewall/guard.py`: `guard.check_input()` and `guard.check_output()` API
  - `QUICKSTART.md`: 5-minute integration guide
  - `examples/quickstart.py`: Runnable example (< 10 lines)

- **LangChain Integration:** Pre-structured integration with LangChain framework.
  - `src/llm_firewall/integrations/langchain/callbacks.py`: `FirewallCallbackHandler`
  - `examples/langchain_integration.py`: Production-ready example
  - Optional `langchain` dependency in `pyproject.toml`

- **PyPI Package Preparation:** Complete package configuration for PyPI release.
  - `MANIFEST.in`: Includes lexicons and required runtime files
  - `pyproject.toml`: Full metadata, dependencies, and optional extras
  - Publishing scripts and documentation

### Changed

- **Fail-Safe Policy:** Cache failures now trigger fail-safe (block) behavior instead of fail-open. Policy moved to adapter layer.
- **Architecture Enforcement:** Automated CI/CD gate prevents dependency rule violations.
- **Package Structure:** Lexicons (`lexicons/` and `lexicons_gpt5/`) now included in distribution.

### Fixed

- **Lexicon Inclusion:** Fixed missing lexicons in PyPI package (required for runtime operation).

## [2.3.4] - 2025-11-29 (Emergency Security Patch)

**Status:** Stable / Production Ready

### Security Fixes

- **JSON Parser Hardening:** Replaced standard JSON decoder with `StrictJSONDecoder`. Now raises `ValueError` on duplicate keys to prevent "Last-Key-Wins" bypass attacks (Fixes Audit Finding: `JSON_DUPLICATE_KEY_BYPASS`).

- **Context Whiplash Mitigation:** Implemented `REALISM_TRIGGERS` in `KidsPolicy`. Revokes "Gamer Amnesty" bonus immediately if real-world chemistry/physics terms are detected in a gaming context.

- **Recursion DoS Protection:** Added `ComplexityCheck` pre-flight scanner. Blocks payloads with excessive nesting depth (`{` > 50) or length (>100k chars) before parsing.

### Changed

- **Argument Inspector:** Updated `RC10c` rules to detect context-switching campaigns.

## [2.3.3] - 2025-11-29 (Golden Master)

**Status:** Architecture Freeze

### Added

- **CUSUM Drift Detection:** Replaced variance-based checks with Cumulative Sum Control Chart algorithm to detect oscillation attacks.

- **Per-Tenant Rate Limiting:** Implemented Redis-backed sliding window limiters using Lua scripts for atomicity.

- **Redis ACL Integration:** Added support for per-tenant Redis users and key prefixes (`hakgal:tenant:{id}:*`).

- **Log Redaction:** Integrated AES-GCM field-level encryption for PII in logs.

## [2.3.1] - 2025-11-27 (Hardening)

### Added

- **RuntimeConfig Security:** Implemented HMAC-SHA256 signature verification for config updates.

- **Replay Protection:** Added Nonce and Timestamp validation to admin endpoints.

- **Timing Protection:** Added random jitter to `ToolGuard` execution to mitigate side-channel timing attacks.

## [2.3.0] - 2025-11-26 (Beta)

### Changed

- **Async Core:** Refactored entire pipeline to `asyncio`.

- **Priority Queues:** Implemented weighted fair queueing for Guard execution.
