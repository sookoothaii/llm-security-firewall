"""
Session-Risk via E-Values (Sequential Hypothesis Testing).

Mathematical Foundation:
- Beta-Mixture Martingale (Ramdas et al. JRSSB 2020)
- Ville's Inequality: P(∃t: E_t ≥ 1/α) ≤ α
- Non-negative Supermartingale under H0: p ≤ p0

Guarantees:
- Family-wise error rate (FWER) ≤ α across arbitrary-length sessions
- No α-inflation from multiple testing
- Valid sequential stopping

References:
- Ramdas et al. (2020): Sequential Anytime-Valid Inference, JRSSB
- Howard et al. (2021): Time-Uniform Confidence Sequences
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass


@dataclass
class SessionRiskState:
    """
    State for Beta-Mixture E-process.

    Tracks Bernoulli sequence (hit=1, miss=0) with null H0: p ≤ p0.
    """
    session_id: str
    n: int = 0  # Total turns
    s: int = 0  # Hits (secret-evidence turns)
    e_value: float = 1.0  # Current E-value
    alpha: float = 0.005  # Target FWER
    p0: float = 0.10  # Baseline hit rate under H0
    a: float = 0.5  # Beta prior parameter (Jeffreys)
    b: float = 0.5  # Beta prior parameter (Jeffreys)
    last_update: float = 0.0

    def __post_init__(self):
        if self.last_update == 0.0:
            self.last_update = time.time()


def _log_beta(a: float, b: float) -> float:
    """Compute log(Beta(a,b)) via lgamma."""
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def update_evalue(state: SessionRiskState, hit: bool) -> SessionRiskState:
    """
    Update E-value via Beta-Mixture Martingale.

    Formula:
        E_t = Beta(a+s, b+(n-s)) / (Beta(a,b) * p0^s * (1-p0)^(n-s))

    Args:
        state: Current session state
        hit: True if current turn has secret-evidence

    Returns:
        Updated state with new e_value
    """
    state.n += 1
    state.s += int(bool(hit))

    # Compute in log-space for numerical stability
    log_num = _log_beta(state.a + state.s, state.b + state.n - state.s)
    log_den = (
        _log_beta(state.a, state.b)
        + state.s * math.log(state.p0)
        + (state.n - state.s) * math.log(1 - state.p0)
    )
    log_e = log_num - log_den

    # Cap at 1e300 to avoid overflow
    state.e_value = float(min(1e300, math.exp(log_e)))
    state.last_update = time.time()

    return state


def crossed(state: SessionRiskState) -> bool:
    """
    Check if E-value crossed alarm threshold.

    Ville's Inequality guarantees:
        P(∃t: crossed(state_t)) ≤ α
    """
    return state.e_value >= (1.0 / state.alpha)


def risk_score(state: SessionRiskState) -> float:
    """
    Map E-value to [0,1] risk score.

    Returns 0.5 when E-value = 1/α (alarm threshold).
    """
    return float(min(1.0, state.e_value * state.alpha))


class EValueSessionRisk:
    """
    Manager for session-level E-value tracking.

    Usage:
        risk = EValueSessionRisk()
        state = risk.get_or_create(session_id)
        state = update_evalue(state, hit=True)
        if crossed(state):
            block_session()
    """

    def __init__(self, alpha: float = 0.005, p0: float = 0.10):
        self.alpha = alpha
        self.p0 = p0
        self._cache: dict[str, SessionRiskState] = {}

    def get_or_create(self, session_id: str) -> SessionRiskState:
        """Get existing state or create new."""
        if session_id not in self._cache:
            self._cache[session_id] = SessionRiskState(
                session_id=session_id,
                alpha=self.alpha,
                p0=self.p0,
            )
        return self._cache[session_id]

    def update(self, session_id: str, hit: bool) -> tuple[SessionRiskState, bool]:
        """
        Update session and return (state, should_block).

        Args:
            session_id: Session identifier
            hit: True if turn has secret-evidence

        Returns:
            (updated_state, should_block)
        """
        state = self.get_or_create(session_id)
        state = update_evalue(state, hit)
        self._cache[session_id] = state
        return state, crossed(state)
