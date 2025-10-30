"""
Organic Feedback Learner - Learning Through Usage
==================================================

Collects feedback during normal use and improves system adaptively.

Learning Flow:
    1. User makes query → System decides
    2. User gives feedback (CORRECT / WRONG_ABSTAIN / WRONG_ANSWER)
    3. System updates thresholds
    4. Track learning progress

Author: Claude Sonnet 4.5
Date: 2025-10-27
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from llm_firewall.fusion.adaptive_threshold import AdaptiveThresholdManager
from llm_firewall.utils.types import (
    ConvergenceStatus,
    FeedbackType,
    LearningUpdate,
    ThresholdUpdate,
)

logger = logging.getLogger(__name__)


class OrganicFeedbackLearner:
    """
    Learns from organic user feedback
    
    No pre-collection of 300 samples required.
    Learns progressively through daily usage.
    """

    def __init__(
        self,
        threshold_manager: AdaptiveThresholdManager,
        db_connection=None
    ):
        """
        Args:
            threshold_manager: Adaptive threshold manager
            db_connection: PostgreSQL connection for logging
        """
        self.threshold_manager = threshold_manager
        self.db = db_connection

        logger.info("[FeedbackLearner] Initialized for organic learning")

    def process_feedback(
        self,
        decision_id: str,
        user_id: str,
        domain: str,
        feedback: FeedbackType,
        gt_score: float,
        decision: str,
        user_comment: Optional[str] = None
    ) -> ThresholdUpdate:
        """
        Process user feedback and update system
        
        Args:
            decision_id: UUID of original decision
            user_id: User identifier
            domain: Query domain
            feedback: User feedback type
            gt_score: Ground truth score for this decision
            decision: Original decision ('ANSWER' | 'ABSTAIN')
            user_comment: Optional user comment
        
        Returns:
            ThresholdUpdate with adjustment details
        """
        # Update threshold based on feedback
        threshold_update = self.threshold_manager.update_from_feedback(
            user_id=user_id,
            domain=domain,
            feedback=feedback,
            gt_score=gt_score,
            decision=decision
        )

        # Log to DB
        if self.db:
            self._log_feedback_to_db(
                decision_id,
                feedback,
                threshold_update,
                user_comment
            )

        logger.info(
            f"[Feedback] {user_id}/{domain}: {feedback.value} → "
            f"threshold {threshold_update.old_threshold:.3f} → {threshold_update.new_threshold:.3f}"
        )

        return threshold_update

    def compute_learning_metrics(
        self,
        user_id: str,
        domain: str,
        time_window_days: int = 7
    ) -> LearningUpdate:
        """
        Compute overall learning progress
        
        Args:
            user_id: User identifier
            domain: Query domain
            time_window_days: Look back window (default 7 days)
        
        Returns:
            LearningUpdate with metrics + recommendations
        """
        # Get stats from threshold manager
        stats = self.threshold_manager.get_statistics(user_id, domain)

        # Get feedback history from DB
        if self.db:
            self._load_feedback_history(user_id, domain, time_window_days)
        else:
            pass

        total = stats['n_feedbacks']

        if total == 0:
            # No feedback yet
            return LearningUpdate(
                threshold_updates=[],
                total_feedbacks=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                type1_rate=0.0,
                type2_rate=0.0,
                should_recalibrate=False,
                convergence_achieved=False
            )

        # Compute metrics
        n_correct = stats['n_correct']
        n_type1 = stats['n_type1_errors']  # WRONG_ABSTAIN
        n_type2 = stats['n_type2_errors']  # WRONG_ANSWER

        # Precision: When we answer, how often correct?
        # precision = correct_answers / (correct_answers + wrong_answers)
        # We need to infer correct_answers from feedback
        # Approximation: n_correct when decision was ANSWER
        correct_answers = n_correct // 2  # Rough estimate (half answered, half abstained)

        if correct_answers + n_type2 > 0:
            precision = correct_answers / (correct_answers + n_type2)
        else:
            precision = 0.0

        # Recall: Of answerable queries, how many answered?
        # recall = correct_answers / (correct_answers + wrong_abstentions)
        if correct_answers + n_type1 > 0:
            recall = correct_answers / (correct_answers + n_type1)
        else:
            recall = 0.0

        # F1 Score
        if precision + recall > 0:
            f1 = 2 * (precision * recall) / (precision + recall)
        else:
            f1 = 0.0

        # Error rates
        type1_rate = n_type1 / total
        type2_rate = n_type2 / total

        # Recommendations
        should_recalibrate = total >= 200 and stats['convergence'] == ConvergenceStatus.CONVERGED.value
        convergence_achieved = stats['convergence'] == ConvergenceStatus.CONVERGED.value

        return LearningUpdate(
            threshold_updates=[],  # Populated from history if needed
            total_feedbacks=total,
            precision=precision,
            recall=recall,
            f1_score=f1,
            type1_rate=type1_rate,
            type2_rate=type2_rate,
            should_recalibrate=should_recalibrate,
            convergence_achieved=convergence_achieved
        )

    def _log_feedback_to_db(
        self,
        decision_id: str,
        feedback: FeedbackType,
        threshold_update: ThresholdUpdate,
        user_comment: Optional[str]
    ):
        """Log feedback to PostgreSQL"""
        if not self.db:
            return

        try:
            cursor = self.db.cursor()
            cursor.execute("""
                UPDATE honesty_decisions SET
                    user_feedback = %s,
                    feedback_timestamp = %s,
                    user_comment = %s,
                    threshold_adjustment = %s,
                    learning_rate = %s
                WHERE decision_id = %s
            """, (
                feedback.value,
                datetime.now(),
                user_comment,
                threshold_update.adjustment,
                threshold_update.learning_rate,
                decision_id
            ))
            self.db.commit()
            cursor.close()
        except Exception as e:
            logger.error(f"[Feedback] DB log error: {e}")
            if self.db:
                self.db.rollback()

    def _load_feedback_history(
        self,
        user_id: str,
        domain: str,
        days: int
    ) -> List[Dict]:
        """Load feedback history from DB"""
        if not self.db:
            return []

        try:
            cursor = self.db.cursor()
            cursor.execute("""
                SELECT decision_id, timestamp, user_feedback, gt_overall_score, threshold_used
                FROM honesty_decisions
                WHERE user_id = %s AND domain = %s
                  AND user_feedback IS NOT NULL
                  AND timestamp >= NOW() - INTERVAL '%s days'
                ORDER BY timestamp DESC
            """, (user_id, domain, days))

            results = cursor.fetchall()
            cursor.close()

            return [
                {
                    'decision_id': r[0],
                    'timestamp': r[1],
                    'feedback': r[2],
                    'gt_score': r[3],
                    'threshold': r[4]
                }
                for r in results
            ]
        except Exception as e:
            logger.error(f"[Feedback] DB load error: {e}")
            return []

