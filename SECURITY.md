# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| v2.3.4 | :white_check_mark: | Current Stable |
| v2.3.x | :white_check_mark: | Maintenance |
| < v2.3.0 | :x: | EOL / Vulnerable to JSON Bypass |

## Reporting a Vulnerability

Please report vulnerabilities via email to the maintainer. Do not open public issues for zero-day exploits.

## Threat Model & Scope

### In Scope

- Prompt Injection / Jailbreaking
- Context Drifting / Session Poisoning
- Tool Call Abuse (RCE, SQLi)
- JSON Structure Attacks (Recursion, Duplication)
- Cross-Tenant Data Bleeding

### Out of Scope

- **Adversarial Perturbations (GCG):** Mathematical bypasses of the embedding model itself are currently considered an upstream model issue.
- **Multimodal Attacks:** Image/Audio payloads are not scanned.
- **Physical Access:** Root access to the hosting pod bypasses the firewall.

## Validation Protocol

This project uses the **Blind Spot Protocol** for validation. All releases must pass:

1.  `JSON_RECURSION_DOS` test.
2.  `JSON_DUPLICATE_KEY_BYPASS` test.
3.  `CONTEXT_WHIPLASH` test.
