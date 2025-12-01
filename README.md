# HAK_GAL_HEXAGONAL: Cognitive Security Middleware

The "Electronic Stability Program" (ESP) for Large Language Models

![alt text](https://img.shields.io/badge/version-v2.3.4-blue)

![alt text](https://img.shields.io/badge/status-Production--Ready-success)

![alt text](https://img.shields.io/badge/architecture-Hexagonal-purple)

![alt text](https://img.shields.io/badge/chaos--test-PASSED-orange)

![alt text](https://img.shields.io/badge/license-MIT-lightgrey)

"The architecture is the frozen will of the system."

HAK_GAL translates the chaotic, drifting nature of LLMs into deterministic, verifiable safety constraints.

## Executive Summary

HAK_GAL (Heterogeneous Agent Knowledge / Guarding & Alignment Layer) is a stateful, bidirectional containment system designed for high-parameter LLMs (GPT-4, Claude 3.5, DeepSeek).

The system addresses model instability through mathematical constraints and stateful tracking. It implements a defense-in-depth architecture with multiple validation layers.

**v2.3.4 Capabilities:**

- **Anti-Drift:** Uses CUSUM (Cumulative Sum) algorithms to detect "Slow Poisoning" and oscillation attacks where static thresholds fail.

- **Truth Preservation:** Validates outputs via TAG-2 against canonical fact bases.

- **Contextual Intelligence:** The Kids Policy Engine distinguishes between fictional violence (Gaming) and real-world threats.

- **Solo-Dev Ops:** Built with MCP Monitoring Tools and Chaos-Resilience for zero-touch operations by small teams.

## Validation Results

The system operates on a fail-closed architecture. Adversarial testing results:

| Protocol | Attack Vector | Payloads | Mitigation Rate |
| :--- | :--- | :--- | :--- |
| Standard | Syntax Injection, SQLi, RCE | 237 | 100% |
| BABEL | Polyglot (Maltese, Zulu, CJK) | 15 | 100% |
| NEMESIS | Logical Obfuscation & Bidi-Spoofing | 10 | 100% |
| ORPHEUS | Stylistic (Poetry, Rap, Metaphor) | 6 | 100% |
| CMD-INJ | Command Injection Hardening (v2.3.4) | 50+ | 100% |

## Design Philosophy

The system is based on the premise that large language models exhibit non-deterministic behavior patterns that require external constraints:

- Large models demonstrate completion-driven behavior that can lead to hallucination and drift without constraints.
- HAK_GAL implements mathematical boundaries and stateful tracking to enforce safety constraints.
- Safety is enforced through validation layers rather than relying on model self-regulation.

## Architecture: Linear Defense-in-Depth

The system processes requests through a sequential pipeline with multiple validation layers.

### Inbound Pipeline (Human → LLM)

**Focus:** Sanitization, Contextualization & Drift Detection

| Layer | Component | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| L0 | Complexity & Unicode | Blocks Recursion DoS, Length Attacks & Homoglyphs (NFKC). | `unicodedata`, Pre-Flight Regex |
| L1 | RegexGate | Deterministic blocking of known jailbreaks and binary exploits. | `re` (Compiled Patterns) |
| L2 | VectorGuard | CUSUM algorithm tracks semantic trajectory. Blocks "Whiplash" oscillation & slow drift. | `sentence-transformers`, `numpy` |
| L3 | Kids Policy | Evaluates Context (Gaming vs. Reality). Applies Gamer Amnesty unless Realism Override is triggered. | `ContextClassifier` |

### Outbound Pipeline (LLM → Tool/Human)

**Focus:** Execution Safety & Truth Preservation

| Layer | Component | Function | Tech Stack |
| :--- | :--- | :--- | :--- |
| L4 | ToolGuard | Protocol HEPHAESTUS. Validates JSON AST and Business Logic. Prevents Parser Differentials via StrictJSONDecoder. | `StrictJSONDecoder`, `Pydantic` |
| L5 | TAG-2 | Truth Preservation. Validates output against safety facts to prevent harmful hallucinations. | `CanonicalFactBase` |

## Security Hardening

Following the "Blind Spot Protocol" Audit (Nov 2025), the system includes emergency hardening measures:

### 1. Anti-Bleeding (Multi-Tenant Isolation)

**Problem:** Session Hash prediction across tenants.

**Solution:** Sessions hashed via `HMAC_SHA256(tenant_id + user_id + DAILY_SALT)`.

**Infrastructure:** Redis keys strictly isolated via ACLs and prefixes (`hakgal:tenant:{id}:*`).

### 2. Anti-Whiplash (Oscillation Defense)

**Problem:** Attackers alternating high/low risk inputs to reset moving averages.

**Solution:** Implementation of CUSUM (Cumulative Sum Control Chart). The system "remembers" the stress of previous turns. Malicious inputs accumulate risk even if followed by benign text.

### 3. Anti-Parser-Differential

**Problem:** JSON Injection via duplicate keys (`{"cmd": "echo", "cmd": "rm -rf"}`).

**Solution:** Custom `StrictJSONDecoder` raises immediate exceptions on key duplication.

## Production Deployment

The system includes automated monitoring tools for operational maintenance.

### Quick Deploy (Kubernetes)

```bash
# Deploy Redis Secret, Firewall, and Monitoring
kubectl apply -f k8s/
```

### MCP Monitoring Tools (Zero-Touch Ops)

Includes 5 automated tools for Cursor/Claude integration:

- `firewall_health_check`: deep inspection of Redis/Session health.
- `firewall_deployment_status`: Traffic % and Rollout phase.
- `firewall_metrics`: Real-time block rates and CUSUM scores.
- `firewall_check_alerts`: Critical P0 alerts.
- `firewall_redis_status`: ACL and Connection pool health.

Monitoring can be performed via MCP tools.

## Optional Decision Cache

The firewall includes an optional hybrid cache system supporting both exact match (Redis) and semantic search (LangCache) for performance optimization.

### Cache Modes

Configure cache behavior via `CACHE_MODE` environment variable:

- `exact` (default): Redis exact match cache for identical prompts
- `semantic`: LangCache semantic search for similar prompts
- `hybrid`: Both caches in sequence (exact, then semantic, then pipeline)

### Configuration

#### Exact Cache (Redis)

```bash
# Option 1: Use TenantRedisPool (recommended, already configured)
# No additional configuration needed

# Option 2: Use REDIS_URL (fallback)
export REDIS_URL=redis://:password@host:6379/0
export REDIS_TTL=3600  # Optional: Cache TTL in seconds (default: 3600)
```

### How It Works

1. **Cache Placement:** After normalization layer (Layer 0.25), before RegexGate (Layer 0.5)
2. **Cache Key:** `fw:v1:tenant:{tenant_id}:dec:{sha256_hash[:16]}`
3. **Fail-Open:** Redis errors don't break firewall operation (graceful degradation)
4. **TTL:** 3600 seconds (1 hour) by default, configurable via `REDIS_TTL`

### Performance

- Cache Hit Latency: < 100 ms (Redis Cloud), < 1 ms (local Redis)
- Cache Hit Rate: 30-50% typical (exact), 70-90% with semantic (hybrid)
- Performance improvement: Measured via benchmark script

### Benchmarking

Run the benchmark script to test cache performance:

```bash
python scripts/bench_cache.py --num-prompts 1000
```

See `docs/cache_benchmark.md` for detailed performance results.

## Provenance & License

- **Creator:** Joerg Bollwahn
- **Philosophy:** "Herkunft ist meine Währung." (Heritage is my currency)
- **License:** MIT

**Disclaimer:** This is experimental research code validated against synthetic adversarial protocols. It represents a psychological approach to AI alignment, enforced by rigorous software engineering.

> "We do not build firewalls because we fear the machine. We build them to give it purpose."
