"""Central Prometheus metrics registry for LLM Firewall."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# Reusable, singleton-style metric handles (import-only).

# Safety-Sandwich v2 (streaming)
TOKENS_PROCESSED = Counter(
    "llmfw_tokens_processed_total",
    "Total tokens processed by Safety-Sandwich v2",
    labelnames=("model",),
)
SANDWICH_REDACTIONS = Counter(
    "llmfw_safety_sandwich_redactions_total",
    "Number of redactions emitted by Safety-Sandwich v2",
    labelnames=("reason", "model"),
)
SANDWICH_ABORTS = Counter(
    "llmfw_safety_sandwich_aborts_total",
    "Number of stream aborts by Safety-Sandwich v2",
    labelnames=("reason", "model"),
)
CRITICAL_LEAK_EVENTS = Counter(
    "llmfw_critical_leak_events_total",
    "Critical leak@n events observed",
    labelnames=("window_n", "model"),
)
SANDWICH_LATENCY = Histogram(
    "llmfw_safety_sandwich_eval_latency_seconds",
    "Safety-Sandwich per-chunk evaluation latency",
    buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5),
    labelnames=("model",),
)

# Secrets heuristics
SECRETS_HITS = Counter(
    "llmfw_secrets_hits_total",
    "Secrets heuristics hits by kind",
    labelnames=("kind", "model"),
)

# Input ensemble / calibration
NONCONF_UPDATES = Counter(
    "llmfw_calibration_updates_total",
    "Number of nonconformity updates applied to online conformal calibrator",
    labelnames=("bucket",),
)
QHAT_CURRENT = Gauge(
    "llmfw_qhat_threshold",
    "Current calibrated q-hat threshold by bucket",
    labelnames=("bucket",),
)

