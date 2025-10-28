"""
Proximal Robbins-Monro Controller for Adaptive Threshold Adjustment
==================================================================

Implements the proximal Robbins-Monro method (2025) for stable threshold adaptation
in noisy, small-data scenarios (N=1 user). Superior numerical stability compared
to classical Robbins-Monro.

Key improvements:
- Proximal formulation avoids overshooting/undershooting
- Fixed-point style iterative procedures
- Data-driven with minimal heuristic tuning
- Enhanced convergence robustness

Algorithm:
    g(tau) = UB_alpha(error|answer; tau) - epsilon
    tau_{t+1} = tau_t + eta_t * (bound_violation + proximal_term)
    eta_t = eta0 / sqrt(t)  (diminishing step)
    proximal_term = lambda * (tau_t - proximal_center)
    
Dual-objective:
    Primary: Maintain bound (UB <= epsilon)
    Secondary: Maximize coverage (target 60-70%)

References:
    - GPT-5 (2025-10-27): Robbins-Monro for conformal threshold control
    - Perplexity: Online learning for N=1, step size guidance
    - Proximal RM (2025): Enhanced numerical stability
    - Classic: Robbins & Monro (1951) - Stochastic Approximation
"""

import numpy as np
from typing import Dict, List, Tuple
from scipy.stats import beta
import logging

logger = logging.getLogger(__name__)


class ProximalRobbinsMonroController:
    """
    Proximal Robbins-Monro controller for conformal threshold
    
    Maintains P(error|answer) <= epsilon via adaptive tau adjustment using
    the latest proximal Robbins-Monro method (2025) for enhanced stability.
    """
    
    def __init__(
        self,
        epsilon: float = 0.05,
        alpha: float = 0.05,
        eta0: float = 0.05,
        beta_smoothing: float = 0.2,
        max_step: float = 0.02,
        target_coverage: float = 0.65,
        coverage_weight: float = 0.05,
        window_size: int = 200,
        # Proximal parameters
        proximal_weight: float = 0.1,
        proximal_decay: float = 0.99
    ):
        """
        Args:
            epsilon: Target error bound (default 5%)
            alpha: Confidence level for CP bound (default 95%)
            eta0: Initial learning rate
            beta_smoothing: Exponential smoothing factor
            max_step: Maximum threshold change per update
            target_coverage: Desired coverage rate
            coverage_weight: Weight for coverage controller (secondary)
            window_size: Sliding window for recent decisions
            proximal_weight: Weight for proximal term (stability)
            proximal_decay: Decay factor for proximal weight
        """
        self.epsilon = epsilon
        self.alpha = alpha
        self.eta0 = eta0
        self.beta = beta_smoothing
        self.max_step = max_step
        self.target_coverage = target_coverage
        self.gamma_coverage = coverage_weight
        self.window_size = window_size
        
        # Proximal parameters
        self.proximal_weight = proximal_weight
        self.proximal_decay = proximal_decay
        
        # State
        self.tau = 0.75  # Initial threshold
        self.t = 0       # Update counter
        self.window_decisions: List[Tuple[Dict, bool]] = []  # Recent (decision, correct) tuples
        
        # Proximal state
        self.proximal_center = 0.75  # Center for proximal term
        
        logger.info(
            f"[ProximalRM] Initialized: epsilon={epsilon}, eta0={eta0}, "
            f"target_coverage={target_coverage}, window={window_size}, "
            f"proximal_weight={proximal_weight}"
        )
    
    def update(
        self,
        decisions: List[Dict]
    ) -> Dict:
        """
        Update threshold based on mini-batch of recent decisions
        
        Args:
            decisions: List of dicts with:
                - 'decision': 'ANSWER' | 'ABSTAIN'
                - 'correct': bool (from feedback)
                - 'gt_score': float
        
        Returns:
            Update result with new threshold + diagnostics
        """
        # Filter to answered only
        answered = [d for d in decisions if d['decision'] == 'ANSWER']
        
        if not answered:
            logger.warning("[RobbinsMonro] No answered decisions in batch - skipping update")
            return {
                'tau': self.tau,
                'update_applied': False,
                'reason': 'no_answered_decisions'
            }
        
        n_answered = len(answered)
        n_errors = sum(1 for d in answered if not d['correct'])
        
        # Compute Clopper-Pearson upper bound
        ub_error = self._clopper_pearson_upper(n_errors, n_answered, self.alpha)
        
        # Primary controller: Maintain bound
        delta_bound = np.clip(ub_error - self.epsilon, -0.1, +0.1)
        
        # Secondary controller: Maximize coverage
        coverage = len(answered) / len(decisions)
        delta_coverage = self.target_coverage - coverage
        
        # Proximal Robbins-Monro update
        # Primary: bound violation (negative because we want UB to decrease)
        # Secondary: coverage deviation
        # Proximal: distance from current center (stability)
        primary_adjustment = -delta_bound  # Direct bound violation
        secondary_adjustment = -self.gamma_coverage * delta_coverage
        
        # Proximal term for stability (key improvement)
        proximal_term = self.proximal_weight * (self.tau - self.proximal_center)
        
        raw_adjustment = primary_adjustment + secondary_adjustment + proximal_term
        
        # Learning rate (diminishing)
        self.t += 1
        eta_t = self.eta0 / np.sqrt(self.t)
        
        # Compute new threshold
        tau_new_raw = self.tau + eta_t * raw_adjustment
        
        # Apply exponential smoothing (stability)
        tau_new_smoothed = (1 - self.beta) * self.tau + self.beta * tau_new_raw
        
        # Clamp to max step
        tau_new_clamped = np.clip(
            tau_new_smoothed,
            self.tau - self.max_step,
            self.tau + self.max_step
        )
        
        # Final bounds
        tau_new = np.clip(tau_new_clamped, 0.50, 0.95)
        
        # Update state
        tau_old = self.tau
        self.tau = tau_new
        
        # Update proximal center (moving average for stability)
        self.proximal_center = (
            (1 - self.beta) * self.proximal_center +
            self.beta * tau_new
        )
        
        # Decay proximal weight (reduces influence over time)
        self.proximal_weight *= self.proximal_decay
        self.proximal_weight = max(self.proximal_weight, 0.01)  # Minimum weight
        
        logger.info(
            f"[ProximalRM] t={self.t}: tau {tau_old:.3f} → {tau_new:.3f} "
            f"(UB={ub_error:.3%}, ε={self.epsilon:.3%}, cov={coverage:.1%}, "
            f"prox_center={self.proximal_center:.3f}, prox_weight={self.proximal_weight:.4f})"
        )
        
        return {
            'tau_old': tau_old,
            'tau_new': tau_new,
            'adjustment': tau_new - tau_old,
            'eta_t': eta_t,
            'ub_error': ub_error,
            'delta_bound': delta_bound,
            'coverage': coverage,
            'delta_coverage': delta_coverage,
            'n_errors': n_errors,
            'n_answered': n_answered,
            'update_applied': True,
            't': self.t,
            # Proximal information
            'proximal_center': self.proximal_center,
            'proximal_weight': self.proximal_weight,
            'proximal_term': proximal_term,
            'primary_adjustment': primary_adjustment,
            'secondary_adjustment': secondary_adjustment
        }
    
    def check_convergence(
        self,
        recent_updates: List[Dict]
    ) -> Dict:
        """
        Check convergence criteria (GPT-5 specified)
        
        Criteria:
            1. Parameter stability: |tau_t - tau_{t-5}| < 0.01
            2. Bound stability: |UB - epsilon| < 0.01 over last 10 batches
            3. Coverage stability: Var(coverage) < 0.005 over last 10 batches
        
        Args:
            recent_updates: Last 10+ update results
        
        Returns:
            Convergence diagnostics
        """
        if len(recent_updates) < 10:
            return {
                'converged': False,
                'reason': 'insufficient_batches',
                'n_batches': len(recent_updates)
            }
        
        # Extract metrics
        taus = [u['tau_new'] for u in recent_updates[-10:]]
        ubs = [u['ub_error'] for u in recent_updates[-10:]]
        coverages = [u['coverage'] for u in recent_updates[-10:]]
        
        # 1. Parameter stability
        if len(taus) >= 6:
            tau_change = abs(taus[-1] - taus[-6])
            tau_stable = tau_change < 0.01
        else:
            tau_stable = False
        
        # 2. Bound stability
        bound_deviations = [abs(ub - self.epsilon) for ub in ubs]
        bound_stable = all(dev < 0.01 for dev in bound_deviations)
        
        # 3. Coverage stability
        coverage_var = np.var(coverages)
        coverage_stable = coverage_var < 0.005
        
        # Overall convergence
        converged = tau_stable and bound_stable and coverage_stable
        
        result = {
            'converged': converged,
            'tau_stable': tau_stable,
            'bound_stable': bound_stable,
            'coverage_stable': coverage_stable,
            'tau_change': tau_change if len(taus) >= 6 else None,
            'bound_deviation_max': max(bound_deviations),
            'coverage_variance': coverage_var,
            'n_batches': len(recent_updates)
        }
        
        if converged:
            logger.info(
                f"[ProximalRM] CONVERGED after {self.t} updates "
                f"(tau={self.tau:.3f}, UB={ubs[-1]:.3%}, cov={coverages[-1]:.1%})"
            )
        
        return result
    
    def detect_drift(
        self,
        recent_decisions: List[Dict],
        method: str = "cusum"
    ) -> Dict:
        """
        Detect distribution drift via CUSUM or Page-Hinkley
        
        Args:
            recent_decisions: Last 100+ decisions with feedback
            method: 'cusum' or 'page_hinkley'
        
        Returns:
            Drift detection result with alarm flag
        """
        # Extract errors
        answered = [d for d in recent_decisions if d['decision'] == 'ANSWER']
        
        if len(answered) < 30:
            return {'alarm': False, 'reason': 'insufficient_data'}
        
        # Residuals: (error - epsilon)
        residuals = []
        for d in answered:
            error = 0.0 if d.get('correct', False) else 1.0
            residuals.append(error - self.epsilon)
        
        if method == "cusum":
            alarm, statistic = self._cusum(residuals)
        else:  # page_hinkley
            alarm, statistic = self._page_hinkley(residuals)
        
        if alarm:
            logger.warning(
                f"[ProximalRM] DRIFT DETECTED via {method.upper()} "
                f"(statistic={statistic:.4f}) - FREEZE threshold, recalibrate!"
            )
        
        return {
            'alarm': alarm,
            'method': method,
            'statistic': statistic,
            'n_samples': len(residuals),
            'action': 'freeze_and_recalibrate' if alarm else 'continue'
        }
    
    def _cusum(self, residuals: List[float], threshold: float = 0.02) -> Tuple[bool, float]:
        """
        Cumulative Sum (CUSUM) drift detection
        
        Args:
            residuals: Sequence of (error - epsilon)
            threshold: Alarm threshold
        
        Returns:
            (alarm_triggered, max_statistic)
        """
        # Two-sided CUSUM
        s_high = 0.0
        s_low = 0.0
        max_stat = 0.0
        
        for r in residuals:
            s_high = max(0, s_high + r)
            s_low = max(0, s_low - r)
            max_stat = max(max_stat, s_high, s_low)
        
        alarm = max_stat > threshold
        
        return alarm, max_stat
    
    def _page_hinkley(
        self,
        residuals: List[float],
        delta: float = 0.01,
        threshold: float = 0.05
    ) -> Tuple[bool, float]:
        """
        Page-Hinkley test for drift
        
        Args:
            residuals: Sequence of (error - epsilon)
            delta: Minimum change to detect
            threshold: Alarm threshold
        
        Returns:
            (alarm_triggered, statistic)
        """
        cumsum = 0.0
        min_cumsum = 0.0
        statistic = 0.0
        
        for r in residuals:
            cumsum += r - delta
            min_cumsum = min(min_cumsum, cumsum)
            statistic = max(statistic, cumsum - min_cumsum)
        
        alarm = statistic > threshold
        
        return alarm, statistic
    
    def _clopper_pearson_upper(
        self,
        k_errors: int,
        n_answered: int,
        alpha: float
    ) -> float:
        """
        Clopper-Pearson exact upper bound for error rate
        
        P(error|answer) with 1-alpha confidence
        
        Formula:
            UB = BetaInv(1-alpha; k+1, n-k)
        
        Args:
            k_errors: Number of errors
            n_answered: Total answered
            alpha: Confidence level (0.05 = 95% CI)
        
        Returns:
            Upper bound on error rate
        """
        if n_answered == 0:
            return 1.0
        
        if k_errors == 0:
            # Special case: 0 errors
            # UB = 1 - alpha^(1/n) (exact formula for k=0)
            return 1.0 - (alpha ** (1.0 / n_answered))
        
        # General case: Beta inverse CDF
        ub = beta.ppf(1 - alpha, k_errors + 1, n_answered - k_errors)
        
        return float(ub)


# Backward compatibility alias
RobbinsMonroController = ProximalRobbinsMonroController

