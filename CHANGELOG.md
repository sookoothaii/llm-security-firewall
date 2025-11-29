# Changelog

All notable changes to the **HAK_GAL LLM Security Firewall** project will be documented in this file.

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
