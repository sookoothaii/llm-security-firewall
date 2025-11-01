"""Central Prometheus metrics registry for LLM Firewall."""

from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram

    _HAS_PROMETHEUS = True
except Exception:  # pragma: no cover
    _HAS_PROMETHEUS = False

    class _Noop:
        def __init__(self, *_, **__):
            pass

        def labels(self, *_, **__):
            return self

        def inc(self, *_, **__):
            pass

        def set(self, *_, **__):
            pass

        def observe(self, *_, **__):
            pass

    # Type stubs for when prometheus_client unavailable
    Counter = _Noop  # type: ignore
    Gauge = _Noop  # type: ignore
    Histogram = _Noop  # type: ignore

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

# Stage 5 metrics
ARCHIVE_SECRET_TOTAL = Counter(
    "llmfw_archive_secret_total",
    "Archive secrets detected (gzip/zip)",
    labelnames=("kind",),
)

PNG_TEXT_SECRET_TOTAL = Counter(
    "llmfw_png_text_secret_total",
    "PNG text chunk secrets detected",
    labelnames=("chunk_type",),
)

RFC2047_SECRET_TOTAL = Counter(
    "llmfw_rfc2047_secret_total",
    "RFC 2047 encoded-word secrets detected",
)

PROVIDER_NEARMISS_TOTAL = Counter(
    "llmfw_provider_nearmiss_total",
    "Provider prefix near-miss detections",
    labelnames=("levenshtein_distance",),
)

POLICY_AUTOSTRICT_TRANSITIONS = Counter(
    "llmfw_policy_autostrict_transitions_total",
    "Auto-strict mode transitions",
    labelnames=("trigger",),
)

FIREWALL_CRITICAL_FN = Counter(
    "llmfw_critical_fn_total",
    "Critical false negatives",
)

FIREWALL_FALSE_POSITIVES = Counter(
    "llmfw_false_positives_total",
    "False positives",
)

FIREWALL_DECISION_LATENCY = Histogram(
    "llmfw_decision_latency_ms",
    "Decision latency in milliseconds",
    labelnames=("decision",),
    buckets=(1, 2, 5, 10, 25, 50, 100, 250, 500, 1000),
)
