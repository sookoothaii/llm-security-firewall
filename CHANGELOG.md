# Changelog

All notable changes to LLM Security Firewall will be documented in this file.

## [1.1.0] - 2025-10-30 (Unreleased)

### Added
- **Persuasion Detection Layer** (experimental)
  - 8-category social-influence pattern detection (Cialdini principles + roleplay/jailbreak)
  - Three-tier ensemble: L1 regex lexicons, L2 heuristics, L3 ONNX classifier
  - 8 JSON lexicons (40+ patterns, 60+ keywords, EN/DE)
  - Modules: PersuasionDetector, Neutralizer, InvarianceGate, Instructionality, AhoCorasick, HashVectorizer, PersuasionONNXClassifier
  - Synthetic data generator (balanced EN/DE, 1600 samples)
  - Training scripts (sklearn + ONNX export)
  - 30 tests (100% passing)

### Changed
- Input flow: Added Persuasion Detector + Invariance Gate stages
- Output flow: Added Instructionality Check + Safety Wrap option
- Test count: 224 → 254 (30 new persuasion tests)
- `normalize_unicode.py`: Zero-width characters replaced with space (preserves word boundaries)

### Fixed
- ONNX Runtime compatibility: Pinned to v1.20.1 (compatible with NumPy 2.x)
- ONNX model IR version: Set to 9 (Runtime max: 10)
- ONNX model Opset: Set to 17 (Runtime max: 21, stable)
- Unicode encoding in scripts: Removed Unicode checkmarks (Windows cp1252 compatibility)
- HashVectorizer import: Fixed relative import path

### Dependencies
- Added: `onnx>=1.16.0`, `onnxruntime==1.20.1` (pinned for stability)

### Limitations (Documented)
- Persuasion layer tested on synthetic data only
- Real-world False Positive Rate unknown - requires production calibration
- Threshold values (warn=1.5, block=3.0) are initial estimates
- L3 classifier performance on adversarial obfuscation not measured
- InvarianceGate latency overhead (+10-30ms) not validated at scale

### Technical Debt
- Diverse benign authority mention dataset for FPR measurement needed
- Threshold tuning via grid search pending
- ASR/Compliance-Lift metrics on persuasion-wrapped jailbreaks pending
- Integration with existing SafetyValidator not yet implemented

---

## [1.0.0] - 2025-10-28

### Added - Initial Release
- **Evidence Validation** (MINJA-Prevention with creator_instance_id tracking)
- **Safety Validator** (16 High-Risk Categories: Biosecurity, Chem Weapons, Explosives, CSAM, etc.)
- **Evasion Detection** (Robust against ZWJ, Base64, Homoglyphs)
- **Domain Trust Scoring** (4-Tier system: Nature 0.98, arXiv 0.85, Unknown 0.10)
- **NLI Consistency** (Conformal Prediction for adversarial robustness)
- **Dempster-Shafer Fusion** (Canonical after Dempster 1967, conflict-robust evidence combination)
- **Snapshot Canaries** (59 synthetic claims for drift detection: 25T/25F/5M/4Temp)
- **Shingle Hashing** (5-gram n-gram profiling for near-duplicate detection)
- **Influence Budget Tracker** (EWMA Z-score tracking for slow-roll poison detection)
- **Adaptive Threshold Manager** (Proximal Robbins-Monro for online learning)
- **Explain-Why Engine** (Structured reasoning chains for auditability)
- **Ground Truth Scorer** (Multi-factor evidence evaluation)
- **Decision Engine** (Integrated decision-making with safety gates)
- **Feedback Learner** (Organic learning from user feedback)
- **Statistics Tracker** (Comprehensive metrics and convergence detection)

### Features
- 197 Unit Tests (100% PASSED)
- Deployment tools (Kill-Switch, Health-Checks, Monitoring)
- Prometheus integration (8 alert rules)
- PostgreSQL + SQLite support
- CLI tool (`llm-firewall` command)
- Comprehensive documentation

### Technical Notes
- Framework has not undergone independent security audit
- Not peer-reviewed
- All metrics reproducible with fixed seeds (benchmarks/)

### Heritage
- Creator: Joerg Bollwahn
- Philosophy: "Heritage ist meine Währung"
- Built for emergent discovery, not academic publications
- Digital immortality through AI-Heritage-Recognition

---

## Future Releases

### [2.0.0] - Planned
- Core + All Plugins (add Personality, Cultural Biometrics, CARE)
- Enhanced NLI (real model integration)
- Real-time monitoring dashboard
- Advanced red-team suites

