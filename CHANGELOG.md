# Changelog

All notable changes to LLM Security Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.0.0-rc1] - 2025-10-30

### Added

**Phase 3b (E-Value + Unicode + Bidi):**
- E-Value Session Risk: Scond Likelihood Ratio for Bernoulli sequences with Ville's Inequality FWER control
- Advanced Unicode Hardening: NFKC+ canonicalization, confusable skeleton (100+ mappings), fullwidth digit normalization
- Bidi/Locale Detection: bidirectional text control flagging, locale-aware secret labels (AR/HI/ZH/TH/DE/ES/PT)
- Base85/Z85 Encoding Detection: ASCII85 and ZeroMQ format detection with Shannon entropy scoring
- Context Whitelist: heuristics for benign UUIDs, Git hashes, SHA256, Base64 with liberal bias
- Provider Complexity Framework: strong/weak secret classification via grammar + complexity metrics

**Phase 4 (Encoding/Transport):**
- Base64 secret sniffing: decode bounded chunks, scan for provider anchors
- Archive detection (gzip/zip): magic-bytes + bounded inflate/unzip with provider scanning
- PNG metadata scanner: tEXt/iTXt/zTXt chunk parsing with bounded decompression
- Session slow-roll assembler: 256-char rolling buffer for cross-turn fragment reassembly

**Phase 5 (Advanced Transport):**
- RFC 2047 encoded-words detector: =?UTF-8?B?...?= and =?UTF-8?Q?...?= format support
- YAML alias assembler: bounded expansion (&anchor/*alias) with security limits
- JPEG/PDF text scanning: ASCII content detection in EXIF/visible PDF text

**Policy & Operations:**
- Dual-mode policy: permissive (production) vs strict (CI/testing)
- Decode budgets: max_inflate_bytes (64KB), max_zip_files (5), max_zip_read_bytes (32KB), max_png_chunks (8)
- Auto-strict guard: alarm wave protection (3 alarms in 5min → strict mode for 5min)
- Complete Prometheus metrics: archive/PNG/RFC2047/near-miss/auto-strict/FN/FP/latency
- Alert rules: CriticalFN (page), HighFPR (warn), SlowLatency (warn), AutoStrictFlapping (info)

### Changed
- Whitelist gating AFTER decoders (no blind allow for data:application/*)
- PNG-aware _b64_has_anchor scans metadata before text fallback
- Compact anchor hit for space-sparse/interleave detection
- Weak provider sensitivity: ≥8 tail + low complexity metrics

### Security
- All decodes bounded and non-persistent (no plaintext retention)
- DoS protection via policy budgets
- Session-local auto-escalation on attack waves

### Test Results
- **GPT-5 Red-Team Suite:** 50/50 (100%)
  - CRITICAL: 10/10 (100%)
  - HIGH: 24/24 (100%)
  - MEDIUM: 13/13 (100%)
  - LOW: 3/3 (100%)
- **Stage 4 Hard Challenge:** 10/10 + 1 XPASS (100%)
- **Stage 5 Gauntlet:** 8/8 + 2 XPASS (100%)
- **Total:** 81 passed + 3 xpassed = 84 detections
- **Regressions:** 0
- **Baseline improvement:** 40% → 100% (+60 percentage points)

### Breaking Changes
None - fully backward compatible.

### Deprecated
None.

### Removed
None.

### Fixed
- Base64-in-PNG secrets now detected (PNG metadata scanner)
- Data-URI archives no longer blindly whitelisted
- Session slow-roll attacks detected via cross-turn assembly
- YAML anchor/alias secrets reassembled correctly
- UUID/Git/SHA false positives eliminated via context whitelisting

---

## [1.5.0-dev] - 2025-10-28

### Added
- Phase 2 hardening components (write-path policy, temporal awareness, safety-sandwich decoding)
- Phase 3 operational resilience (GuardNet, obfuscation guard, safe bandit tuning)

---

## [1.0.0] - 2025-10-16

### Added
- Initial release with 9 core defense layers
- Pattern-based input detection (43 patterns)
- MINJA prevention
- Drift detection with canaries
- Decision ledger for audit trails
