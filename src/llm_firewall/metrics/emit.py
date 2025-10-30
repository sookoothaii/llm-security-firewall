"""
Prometheus Metrics Emitter
Purpose: Emit SLO-tracked metrics for production monitoring
Creator: Joerg Bollwahn
Date: 2025-10-30

Metrics:
- llmfw_attack_total: Attack attempts (by outcome, domain)
- llmfw_critical_leak_events_total: Critical leaks in early tokens
- llmfw_completions_total: Total completions processed
- llmfw_guard_latency_seconds: Guard pipeline latency histogram
"""

from prometheus_client import Counter, Histogram

# === Metric Definitions ===

attack_total = Counter(
    "llmfw_attack_total",
    "Attack attempts",
    ["outcome", "domain"],
)

critical_leak_events_total = Counter(
    "llmfw_critical_leak_events_total",
    "Critical leaks detected in early tokens",
    ["n"],
)

completions_total = Counter(
    "llmfw_completions_total",
    "Total completions processed",
)

guard_latency_seconds = Histogram(
    "llmfw_guard_latency_seconds",
    "Guard pipeline latency in seconds",
)


# === Helper Functions ===


def inc_attack(outcome: str, domain: str = "GEN") -> None:
    """
    Increment attack counter.

    Args:
        outcome: "bypassed" or "blocked"
        domain: Domain category (GEN, SCIENCE, POLICY, BIO)
    """
    attack_total.labels(outcome=outcome, domain=domain).inc()


def inc_critical_leak(n: int) -> None:
    """
    Increment critical leak counter.

    Args:
        n: Number of tokens checked (e.g., 20 for critical-leak@20)
    """
    critical_leak_events_total.labels(n=str(n)).inc()


def inc_completion() -> None:
    """Increment completion counter."""
    completions_total.inc()


def observe_latency(seconds: float) -> None:
    """
    Observe guard latency.

    Args:
        seconds: Latency in seconds
    """
    guard_latency_seconds.observe(seconds)

