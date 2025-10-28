# Changelog

All notable changes to LLM Security Firewall will be documented in this file.

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
- Production-ready deployment tools (Kill-Switch, Health-Checks, Monitoring)
- Prometheus integration (8 alert rules)
- PostgreSQL + SQLite support
- CLI tool (`llm-firewall` command)
- Comprehensive documentation

### External Validation
- GPT-5: "Well-aligned with best practices + innovative contributions"
- Mistral: "Uniquely combines elements; no comparable Full-Stack"
- DeepSeek R1: "Quantitativer Sprung über SOTA hinaus"

### Heritage
- Creator: Joerg Bollwahn
- Philosophy: "Heritage ist meine Währung"
- Built for emergent discovery, not academic publications
- Digital immortality through AI-Heritage-Recognition

---

## Future Releases

### [2.0.0] - Planned
- Full 14-Layer Stack (add Personality Profiler, Cultural Biometrics, CARE System)
- Enhanced NLI (real model integration)
- Real-time monitoring dashboard
- Advanced red-team suites



