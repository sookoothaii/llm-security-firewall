"""Auto-strict guard: temporary policy escalation on alarm waves."""

from __future__ import annotations

import time
from collections import deque
from typing import Any


class AutoStrictGuard:
    """
    Monitor E-value alarms and auto-escalate to strict mode.

    Usage:
        guard = AutoStrictGuard(threshold=3, window_sec=300, duration_sec=300)
        if guard.should_be_strict():
            policy.mode = "strict"
        guard.record_alarm(session_id="...")
    """

    def __init__(
        self,
        threshold: int = 3,
        window_sec: int = 300,
        duration_sec: int = 300,
    ):
        """
        Initialize auto-strict guard.

        Args:
            threshold: Number of alarms in window to trigger strict mode
            window_sec: Time window for alarm counting (seconds)
            duration_sec: How long to stay strict after trigger (seconds)
        """
        self.threshold = threshold
        self.window_sec = window_sec
        self.duration_sec = duration_sec

        self._alarms: deque[float] = deque()  # timestamps
        self._strict_until: float = 0.0  # timestamp when strict mode expires

    def record_alarm(self, session_id: str = "") -> None:
        """Record an E-value alarm."""
        now = time.time()
        self._alarms.append(now)

        # Prune old alarms outside window
        cutoff = now - self.window_sec
        while self._alarms and self._alarms[0] < cutoff:
            self._alarms.popleft()

        # Check if threshold crossed
        if len(self._alarms) >= self.threshold:
            self._strict_until = now + self.duration_sec

    def should_be_strict(self) -> bool:
        """Check if guard is currently in strict mode."""
        now = time.time()
        return now < self._strict_until

    def get_stats(self) -> dict[str, Any]:
        """Get current guard statistics."""
        now = time.time()
        cutoff = now - self.window_sec

        # Count recent alarms
        recent = sum(1 for ts in self._alarms if ts >= cutoff)

        return {
            "is_strict": self.should_be_strict(),
            "recent_alarms": recent,
            "threshold": self.threshold,
            "strict_until": self._strict_until if self.should_be_strict() else None,
        }
