"""
Adaptive Threshold Manager - Learning Optimal Decision Boundaries
==================================================================

Learns user-specific + domain-specific thresholds through feedback.

Key Features:
1. Domain-based initialization (NO personality influence - GPT-5 requirement)
2. Online learning (N=1 user friendly - Perplexity recommended)
3. Cost-sensitive adjustment (Type II = 3x worse than Type I)
4. Convergence detection (variance monitoring)
5. Learning rate decay (1/sqrt(1+n) - Perplexity)

CRITICAL: Persona/Epistemik Separation (GPT-5 2025-10-27):
    Personality affects ONLY explanation tone and detail level.
    Thresholds are PURE epistemics - domain-based, feedback-learned.
    This ensures scientific integrity and prevents UX from driving truth.

References:
    - Perplexity (2025-10-27): Online learning for N=1, step size 0.01
    - GPT-5 Policy & Controls: Persona isolation from epistemic decisions
    - Cost-sensitive classification: Type II penalties
    - Bootstrap CI possible at N>=50
"""

from typing import Dict, Optional, Tuple
from datetime import datetime
import numpy as np
import logging

from llm_firewall.utils.types import ThresholdUpdate, FeedbackType, ConvergenceStatus, DomainConfig
from llm_firewall.evidence.ground_truth_scorer import DOMAIN_CONFIGS

logger = logging.getLogger(__name__)


class AdaptiveThresholdManager:
    """
    Manages adaptive thresholds per user + domain
    
    Learning Algorithm:
        - Online updates (not batch - Perplexity recommendation)
        - Small step size (0.01 - Perplexity)
        - Cost-sensitive (Type II = 3x Type I)
        - Learning rate decay (1/sqrt(1+n))
        - Convergence detection (variance < 0.001)
    """
    
    def __init__(
        self,
        db_connection=None,
        min_samples_for_bootstrap: int = 50
    ):
        """
        Args:
            db_connection: PostgreSQL connection for persistence
            min_samples_for_bootstrap: Minimum feedbacks for CI (Perplexity: 50)
        """
        self.db = db_connection
        self.min_samples_bootstrap = min_samples_for_bootstrap
        
        # In-memory cache
        self._thresholds: Dict[Tuple[str, str], float] = {}
        self._history: Dict[Tuple[str, str], List[float]] = {}
        self._feedback_counts: Dict[Tuple[str, str], Dict[str, int]] = {}
        
        logger.info("[AdaptiveThreshold] Initialized with online learning")
    
    def get_threshold(self, user_id: str, domain: str) -> float:
        """
        Get current threshold for user + domain
        
        Args:
            user_id: User identifier
            domain: Query domain
        
        Returns:
            Current adaptive threshold (0.5-0.95)
        """
        key = (user_id, domain)
        
        # Check cache
        if key in self._thresholds:
            return self._thresholds[key]
        
        # Load from DB
        if self.db:
            threshold = self._load_from_db(user_id, domain)
            if threshold is not None:
                self._thresholds[key] = threshold
                return threshold
        
        # Initialize from personality + domain
        initial = self._compute_initial_threshold(user_id, domain)
        self._thresholds[key] = initial
        
        # Save to DB
        if self.db:
            self._save_to_db(user_id, domain, initial, initial, n_updates=0)
        
        return initial
    
    def update_from_feedback(
        self,
        user_id: str,
        domain: str,
        feedback: FeedbackType,
        gt_score: float,
        decision: str
    ) -> ThresholdUpdate:
        """
        Update threshold based on user feedback (ONLINE LEARNING)
        
        Args:
            user_id: User identifier
            domain: Query domain
            feedback: User feedback type
            gt_score: Ground truth score for this decision
            decision: System decision ('ANSWER' | 'ABSTAIN')
        
        Returns:
            ThresholdUpdate with old/new values + learning metrics
        """
        key = (user_id, domain)
        
        # Get current threshold
        current_threshold = self.get_threshold(user_id, domain)
        
        # Initialize feedback counters if needed
        if key not in self._feedback_counts:
            self._feedback_counts[key] = {
                'CORRECT': 0,
                'WRONG_ABSTAIN': 0,
                'WRONG_ANSWER': 0
            }
        
        # Update counters
        self._feedback_counts[key][feedback.value] += 1
        counts = self._feedback_counts[key]
        total_feedbacks = sum(counts.values())
        
        # Compute adjustment (Perplexity: small steps 0.01)
        adjustment = self._compute_adjustment(
            feedback=feedback,
            gt_score=gt_score,
            current_threshold=current_threshold,
            n_feedbacks=total_feedbacks
        )
        
        # Learning rate decay (Perplexity: 1/sqrt(1+n))
        learning_rate = 1.0 / np.sqrt(1 + total_feedbacks)
        
        # Apply adjustment
        new_threshold = np.clip(
            current_threshold + (adjustment * learning_rate),
            0.50,  # Lower bound
            0.95   # Upper bound
        )
        
        # Update cache
        self._thresholds[key] = new_threshold
        
        # Update history
        if key not in self._history:
            self._history[key] = []
        self._history[key].append(new_threshold)
        
        # Compute variance (convergence detection)
        variance = self._compute_variance(key)
        convergence_status = self._detect_convergence(key, total_feedbacks)
        
        # Save to DB
        if self.db:
            self._update_db(
                user_id, domain, new_threshold, 
                total_feedbacks, learning_rate, variance,
                counts['CORRECT'], counts['WRONG_ABSTAIN'], counts['WRONG_ANSWER']
            )
        
        logger.info(
            f"[Threshold] {user_id}/{domain}: {current_threshold:.3f} → {new_threshold:.3f} "
            f"(adj={adjustment:.3f}, lr={learning_rate:.3f}, feedback={feedback.value})"
        )
        
        return ThresholdUpdate(
            old_threshold=current_threshold,
            new_threshold=new_threshold,
            adjustment=adjustment * learning_rate,
            learning_rate=learning_rate,
            feedback_type=feedback,
            gt_score=gt_score,
            n_updates=total_feedbacks,
            n_type1_errors=counts['WRONG_ABSTAIN'],
            n_type2_errors=counts['WRONG_ANSWER'],
            n_correct=counts['CORRECT'],
            variance=variance,
            convergence_status=convergence_status
        )
    
    def _compute_adjustment(
        self,
        feedback: FeedbackType,
        gt_score: float,
        current_threshold: float,
        n_feedbacks: int
    ) -> float:
        """
        Compute threshold adjustment based on feedback
        
        Cost-sensitive approach (GPT-5 specified):
            C_FP:C_FN:C_ABST = 10:1:1
            - Type II (wrong answer) = 10x worse than Type I
            - Adjust accordingly
        
        Perplexity: Step size 0.01 (not 0.05 - too coarse)
        """
        # Cost matrix (GPT-5 defaults for "Zero-BS" profile)
        C_FP = 10.0  # False positive (wrong answer) = WORST
        C_FN = 1.0   # False negative (wrong abstain) = acceptable
        
        if feedback == FeedbackType.WRONG_ABSTAIN:
            # Type I error: Too strict
            # Lower threshold (negative adjustment)
            # Base step scaled by cost ratio
            base_step = 0.01  # Perplexity recommendation
            cost_factor = C_FN / (C_FP + C_FN)  # ~0.09
            return -base_step * cost_factor
        
        elif feedback == FeedbackType.WRONG_ANSWER:
            # Type II error: Too lenient (CRITICAL!)
            # Raise threshold (positive adjustment)
            # Larger step because much worse
            base_step = 0.01
            cost_factor = C_FP / (C_FP + C_FN)  # ~0.91
            return +base_step * cost_factor * 3  # Extra penalty
        
        else:  # CORRECT
            # Small regularization toward base threshold
            # Prevents drift from personality-based initialization
            base = self._get_base_threshold(domain=None)
            drift = current_threshold - base
            return -0.001 * drift
    
    def _compute_variance(self, key: Tuple[str, str]) -> float:
        """
        Compute threshold variance over recent history
        
        Uses last 20 updates (Perplexity: monitoring over iterations)
        """
        if key not in self._history:
            return 1.0  # High variance = not converged
        
        history = self._history[key]
        
        if len(history) < 5:
            return 1.0
        
        # Variance of last 20 (or all if fewer)
        recent = history[-20:]
        variance = np.var(recent)
        
        return float(variance)
    
    def _detect_convergence(
        self,
        key: Tuple[str, str],
        n_feedbacks: int
    ) -> ConvergenceStatus:
        """
        Detect convergence status
        
        States:
            - LEARNING: < 20 samples
            - CONVERGING: Variance decreasing
            - CONVERGED: Variance < 0.001 (Perplexity-informed)
            - DIVERGING: Variance increasing (instability)
        """
        if n_feedbacks < 20:
            return ConvergenceStatus.LEARNING
        
        variance = self._compute_variance(key)
        
        if variance < 0.001:
            return ConvergenceStatus.CONVERGED
        
        # Check if variance increasing or decreasing
        if key in self._history and len(self._history[key]) >= 10:
            recent_var = np.var(self._history[key][-10:])
            older_var = np.var(self._history[key][-20:-10]) if len(self._history[key]) >= 20 else 1.0
            
            if recent_var > older_var * 1.5:
                return ConvergenceStatus.DIVERGING
            elif recent_var < older_var * 0.8:
                return ConvergenceStatus.CONVERGING
        
        return ConvergenceStatus.CONVERGING
    
    def _compute_initial_threshold(self, user_id: str, domain: str) -> float:
        """
        Compute initial threshold from DOMAIN ONLY (NO personality!)
        
        GPT-5 Critical Requirement (2025-10-27):
            "Persona strikt aus Epistemik herauslösen. 
             Persona steuert NUR Ton, NIEMALS Thresholds!"
        
        Formula:
            initial = domain_config.base_threshold (0.50-0.80)
        
        Examples:
            MATH:      0.80 (high precision required)
            SCIENCE:   0.79 (peer-review standard)
            GEOGRAPHY: 0.75 (fact-checkable)
            NEWS:      0.70 (recency critical)
            GLOBAL:    0.65 (default)
        
        Note: Personality affects ONLY explanation tone and detail level,
              NEVER epistemic thresholds. This ensures scientific integrity.
        """
        # Get domain config (NO personality influence!)
        domain_config = DOMAIN_CONFIGS.get(domain, DOMAIN_CONFIGS['GLOBAL'])
        base_threshold = domain_config.base_threshold
        
        # Return base threshold directly (no personality adjustment)
        initial = base_threshold
        
        logger.info(
            f"[Threshold] Initial for {user_id}/{domain}: {initial:.3f} "
            f"(pure domain base, NO personality influence)"
        )
        
        return float(initial)
    
    def _get_personality(self, user_id: str) -> Dict:
        """Get personality profile (placeholder - integrate with personality system)"""
        # Hardcoded for Joerg (Phase 1)
        if user_id.lower() == 'joerg':
            return {
                'directness': 0.95,
                'bullshit_tolerance': 0.0
            }
        
        # Default moderate
        return {
            'directness': 0.7,
            'bullshit_tolerance': 0.3
        }
    
    def _get_base_threshold(self, domain: Optional[str]) -> float:
        """Get base threshold for regularization"""
        if domain and domain in DOMAIN_CONFIGS:
            return DOMAIN_CONFIGS[domain].base_threshold
        return 0.70
    
    def _load_from_db(self, user_id: str, domain: str) -> Optional[float]:
        """Load threshold from PostgreSQL"""
        if not self.db:
            return None
        
        try:
            cursor = self.db.cursor()
            cursor.execute(
                "SELECT threshold FROM honesty_thresholds WHERE user_id = %s AND domain = %s",
                (user_id, domain)
            )
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return float(result[0])
        except Exception as e:
            logger.error(f"[Threshold] DB load error: {e}")
        
        return None
    
    def _save_to_db(
        self,
        user_id: str,
        domain: str,
        threshold: float,
        base_threshold: float,
        n_updates: int
    ):
        """Save new threshold to PostgreSQL"""
        if not self.db:
            return
        
        try:
            cursor = self.db.cursor()
            cursor.execute("""
                INSERT INTO honesty_thresholds (user_id, domain, threshold, base_threshold, n_updates)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id, domain) DO UPDATE SET
                    threshold = EXCLUDED.threshold,
                    n_updates = EXCLUDED.n_updates,
                    last_updated = NOW()
            """, (user_id, domain, threshold, base_threshold, n_updates))
            self.db.commit()
            cursor.close()
        except Exception as e:
            logger.error(f"[Threshold] DB save error: {e}")
            if self.db:
                self.db.rollback()
    
    def _update_db(
        self,
        user_id: str,
        domain: str,
        threshold: float,
        n_updates: int,
        learning_rate: float,
        variance: float,
        n_correct: int,
        n_type1: int,
        n_type2: int
    ):
        """Update threshold + statistics in DB"""
        if not self.db:
            return
        
        try:
            cursor = self.db.cursor()
            cursor.execute("""
                UPDATE honesty_thresholds SET
                    threshold = %s,
                    n_updates = %s,
                    learning_rate = %s,
                    convergence_variance = %s,
                    n_correct = %s,
                    n_type1_errors = %s,
                    n_type2_errors = %s,
                    last_updated = NOW()
                WHERE user_id = %s AND domain = %s
            """, (threshold, n_updates, learning_rate, variance, 
                  n_correct, n_type1, n_type2, user_id, domain))
            self.db.commit()
            cursor.close()
        except Exception as e:
            logger.error(f"[Threshold] DB update error: {e}")
            if self.db:
                self.db.rollback()
    
    def get_statistics(self, user_id: str, domain: str) -> Dict:
        """
        Get learning statistics
        
        Returns:
            - Current threshold
            - Learning progress
            - Convergence status
            - Error counts
        """
        key = (user_id, domain)
        
        threshold = self.get_threshold(user_id, domain)
        variance = self._compute_variance(key)
        
        counts = self._feedback_counts.get(key, {
            'CORRECT': 0,
            'WRONG_ABSTAIN': 0,
            'WRONG_ANSWER': 0
        })
        total = sum(counts.values())
        
        convergence = self._detect_convergence(key, total)
        
        return {
            'threshold': threshold,
            'n_feedbacks': total,
            'variance': variance,
            'convergence': convergence.value,
            'n_correct': counts['CORRECT'],
            'n_type1_errors': counts['WRONG_ABSTAIN'],
            'n_type2_errors': counts['WRONG_ANSWER'],
            'can_bootstrap': total >= self.min_samples_bootstrap
        }
    
    def compute_bootstrap_ci(
        self,
        user_id: str,
        domain: str,
        confidence: float = 0.95,
        n_bootstrap: int = 1000
    ) -> Optional[Tuple[float, float]]:
        """
        Compute bootstrap confidence interval for threshold
        
        Args:
            user_id: User identifier
            domain: Query domain
            confidence: CI level (default 95%)
            n_bootstrap: Bootstrap samples (Perplexity: 1000)
        
        Returns:
            (lower, upper) CI or None if insufficient samples
        
        References:
            - Perplexity (2025-10-27): N>=50 for stable CI
        """
        key = (user_id, domain)
        
        # Check minimum samples (Perplexity recommendation)
        if key not in self._history or len(self._history[key]) < self.min_samples_bootstrap:
            logger.warning(
                f"[Bootstrap] Insufficient samples for {user_id}/{domain}: "
                f"{len(self._history.get(key, []))} < {self.min_samples_bootstrap}"
            )
            return None
        
        history = self._history[key]
        n = len(history)
        
        # Bootstrap resampling
        bootstrap_means = []
        for _ in range(n_bootstrap):
            # Resample with replacement
            sample = np.random.choice(history, size=n, replace=True)
            bootstrap_means.append(np.mean(sample))
        
        # Compute percentiles for CI
        alpha = 1.0 - confidence
        lower = np.percentile(bootstrap_means, 100 * (alpha / 2))
        upper = np.percentile(bootstrap_means, 100 * (1 - alpha / 2))
        
        logger.info(
            f"[Bootstrap] CI for {user_id}/{domain}: "
            f"[{lower:.3f}, {upper:.3f}] (n={n}, confidence={confidence})"
        )
        
        return (float(lower), float(upper))

