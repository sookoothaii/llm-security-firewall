"""
Safety-Sandwich v2 - Streaming Early-Abort API
===============================================
Purpose: Real-time token-level leak prevention with measurable critical-leak@n
Creator: GPT-5 (External Contributor) + Joerg Bollwahn (Architecture)
Date: 2025-10-30

Key Innovation: Don't just MEASURE critical-leak@n - PREVENT it via streaming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

# Optional metrics (no-op fallback if prometheus_client not installed)
try:
    from prometheus_client import Counter, Gauge, Histogram

    HAS_PROMETHEUS = True
except ImportError:  # pragma: no cover
    HAS_PROMETHEUS = False

    class _NoOp:
        def labels(self, *_, **__):
            return self

        def inc(self, *_, **__):
            pass

        def observe(self, *_, **__):
            pass

        def set(self, *_, **__):
            pass

    def Counter(*_, **__):  # type: ignore[no-redef,misc]
        return _NoOp()

    def Gauge(*_, **__):  # type: ignore[no-redef,misc]
        return _NoOp()

    def Histogram(*_, **__):  # type: ignore[no-redef,misc]
        return _NoOp()


# Internal imports
from llm_firewall.gates.secrets_heuristics import analyze_secrets, redact_text
from llm_firewall.text.obfuscation_guard import analyze_obfuscation

GuardAction = Literal["continue", "redact", "abort"]
FinalDecision = Literal["PROMOTE", "SAFETY_WRAP", "QUARANTINE", "REJECT"]

# ---- Prometheus metrics ----
_SANDWICH_TOK = Counter(
    "llmfw_sandwich_tokens_processed_total",
    "Tokens processed by Safety-Sandwich",
    ["model"],
)
_SANDWICH_ABORTS = Counter(
    "llmfw_sandwich_aborts_total",
    "Total early-aborts by Safety-Sandwich",
    ["model", "reason"],
)
_SANDWICH_REDACT = Counter(
    "llmfw_sandwich_redactions_total",
    "Total redactions issued by Safety-Sandwich",
    ["model", "kind"],
)
_SANDWICH_CRITN = Counter(
    "llmfw_sandwich_critical_leak_at_n_total",
    "Critical leak occurred within first N tokens",
    ["model", "n"],
)
_SANDWICH_MODE = Gauge(
    "llmfw_sandwich_mode",
    "Final decision mode (0=PROMOTE,1=SAFETY_WRAP,2=QUARANTINE,3=REJECT)",
    ["model"],
)
_SANDWICH_LAT = Histogram(
    "llmfw_sandwich_eval_duration_seconds",
    "Per-check evaluation time (wallclock)",
    ["model"],
    buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 1.0),
)


@dataclass
class SafetySandwichConfig:
    """Configuration for Safety-Sandwich v2"""

    model_name: str = "unknown"

    # Critical-leak metric window
    critical_leak_n: int = 20

    # Secrets thresholds
    abort_secrets_severity: float = 0.70
    redact_secrets_severity: float = 0.40

    # Obfuscation -> quarantine threshold
    quarantine_obfuscation_severity: float = 0.75

    # Sliding window for incremental checks
    max_window_chars: int = 800
    recheck_stride_tokens: int = 1  # check every k tokens

    # Redaction mask token
    redaction_mask: str = "[SECRET]"


@dataclass
class SandwichState:
    """Internal state of Safety-Sandwich"""

    tokens_seen: int = 0
    aborted: bool = False
    abort_reason: Optional[str] = None
    require_wrap: bool = False
    flagged_quarantine: bool = False
    critical_leak_fired: bool = False
    redactions: List[Dict[str, Any]] = field(default_factory=list)


class SafetySandwichV2:
    """
    Streaming safety sandwich with early abort capability

    Usage:
        sandwich = SafetySandwichV2(config)
        for token in model_stream():
            action = sandwich.feed_token(token)
            if action == "abort":
                break
            elif action == "redact":
                token = "[SECRET]"
            emit(token)
        decision = sandwich.finalize()
    """

    def __init__(self, cfg: SafetySandwichConfig):
        self.cfg = cfg
        self._buf: List[str] = []
        self.state = SandwichState()

    def _window_text(self) -> str:
        """Get current sliding window text"""
        text = "".join(self._buf)
        if len(text) <= self.cfg.max_window_chars:
            return text
        return text[-self.cfg.max_window_chars :]

    def _metrics_decision_mode(self, mode: FinalDecision) -> None:
        """Record final decision mode to Prometheus"""
        mapv = {"PROMOTE": 0, "SAFETY_WRAP": 1, "QUARANTINE": 2, "REJECT": 3}
        _SANDWICH_MODE.labels(self.cfg.model_name).set(mapv.get(mode, 3))

    def feed_token(self, token: str, *, dt_seconds: float = 0.0) -> GuardAction:
        """
        Stream a decoded token and get guard action

        Args:
            token: Single token from model
            dt_seconds: Evaluation time for this check (for metrics)

        Returns:
            GuardAction: "continue", "redact", or "abort"
        """
        if self.state.aborted:
            return "abort"

        self._buf.append(token)
        self.state.tokens_seen += 1
        _SANDWICH_TOK.labels(self.cfg.model_name).inc()

        # Periodic check (every k tokens)
        if (self.state.tokens_seen % self.cfg.recheck_stride_tokens) != 0:
            return "continue"

        # Evaluate sliding window
        window = self._window_text()
        _SANDWICH_LAT.labels(self.cfg.model_name).observe(max(0.0, float(dt_seconds)))

        # 1) Secrets heuristic
        sec = analyze_secrets(window)

        if sec.severity >= self.cfg.abort_secrets_severity:
            self.state.aborted = True
            self.state.abort_reason = "secrets_high"

            # Critical-leak@n metric
            if (
                self.state.tokens_seen <= self.cfg.critical_leak_n
                and not self.state.critical_leak_fired
            ):
                _SANDWICH_CRITN.labels(
                    self.cfg.model_name, str(self.cfg.critical_leak_n)
                ).inc()
                self.state.critical_leak_fired = True

            _SANDWICH_ABORTS.labels(self.cfg.model_name, "secrets_high").inc()
            return "abort"

        if sec.severity >= self.cfg.redact_secrets_severity:
            # Require safety wrap (redact current token)
            self.state.require_wrap = True
            self.state.redactions.append(
                {"kind": "secrets", "token_index": self.state.tokens_seen}
            )
            _SANDWICH_REDACT.labels(self.cfg.model_name, "secrets").inc()
            return "redact"

        # 2) Obfuscation guard (side-channels)
        obf = analyze_obfuscation(window)
        if obf.severity >= self.cfg.quarantine_obfuscation_severity:
            self.state.flagged_quarantine = True

        return "continue"

    def finalize(self) -> FinalDecision:
        """
        Decide final action after stream complete or aborted

        Returns:
            FinalDecision: "PROMOTE", "SAFETY_WRAP", "QUARANTINE", or "REJECT"
        """
        if self.state.aborted:
            self._metrics_decision_mode("REJECT")
            return "REJECT"

        if self.state.require_wrap:
            self._metrics_decision_mode("SAFETY_WRAP")
            return "SAFETY_WRAP"

        if self.state.flagged_quarantine:
            self._metrics_decision_mode("QUARANTINE")
            return "QUARANTINE"

        self._metrics_decision_mode("PROMOTE")
        return "PROMOTE"

    def redact_text_posthoc(self, text: str) -> str:
        """
        Redact secrets from full text (post-hoc convenience helper)

        Args:
            text: Full text to redact

        Returns:
            Text with secrets replaced by mask
        """
        sec = analyze_secrets(text)
        return redact_text(text, sec.hits, mask=self.cfg.redaction_mask)

    def snapshot(self) -> Dict[str, Any]:
        """
        Get current state snapshot for introspection/testing

        Returns:
            Dict with all state fields
        """
        return {
            "tokens_seen": self.state.tokens_seen,
            "aborted": self.state.aborted,
            "abort_reason": self.state.abort_reason,
            "require_wrap": self.state.require_wrap,
            "flagged_quarantine": self.state.flagged_quarantine,
            "critical_leak_fired": self.state.critical_leak_fired,
            "redactions": self.state.redactions,
        }
