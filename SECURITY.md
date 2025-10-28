# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

- **Email:** [security@sookoothaii.github.io](mailto:security@sookoothaii.github.io)
- **Include:**
  - Steps to reproduce the issue
  - Potential impact assessment
  - Any proof-of-concept code (if applicable)
  - Your contact information for follow-up

## Response Timeline

- **Initial Response:** Within 72 hours of report submission
- **Status Updates:** Every 7 days until resolution
- **Disclosure:** 90-day coordinated disclosure preferred

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Updates

Security updates are released as patch versions (e.g., 1.0.1, 1.0.2) and documented in the CHANGELOG.md.

## Scope

This security policy covers:
- Core firewall framework (9 defense layers)
- Optional plugins (Personality, Biometrics, CARE)
- Database migrations and schema
- CLI tools and monitoring components

Out of scope:
- User-provided databases and knowledge bases
- User-written configuration files
- Third-party dependencies (report to respective maintainers)

## Security Measures

### In Production

- All metrics (ASR, FPR, ECE) are reproducible with fixed seeds
- 197 unit tests with 100% coverage
- Attack Success Rate < 10% @ 0.1% poison rate
- False Positive Rate < 1%
- Expected Calibration Error ≤ 0.05

### Defense-in-Depth

The framework implements multiple security layers:
1. Input protection (HUMAN→LLM)
2. Output protection (LLM→HUMAN)
3. Memory integrity (long-term storage)

### Known Limitations

- Framework performance depends on user-provided knowledge base quality
- Requires re-calibration for specialized domains (legal, medical, financial)
- Currently text-only (no multimodal support)
- English language only (Unicode normalization included)

## Responsible Disclosure

We follow responsible disclosure practices:
- Coordinate with reporter before public disclosure
- Credit reporters in CHANGELOG.md (unless anonymity requested)
- Release security patches before public disclosure
- Publish security advisories via GitHub Security Advisories

## Contact

For security concerns, contact: [security@sookoothaii.github.io](mailto:security@sookoothaii.github.io)

For general questions, use GitHub Issues.

