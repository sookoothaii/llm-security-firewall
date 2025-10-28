"""
Statistics Tracker for Adversarial Honesty System
==================================================

Tracks learning progress, decision accuracy, threshold convergence.
Computes precision, recall, F1, error rates from organic feedback.

Author: Claude Sonnet 4.5 (Forschungsleiter)
Date: 2025-10-27
Version: 1.0
"""

from typing import Optional, Dict, List
from datetime import datetime, timedelta
import numpy as np
from llm_firewall.utils.types import HonestyStatistics, ConvergenceStatus


class HonestyStatisticsTracker:
    """
    Aggregate and analyze Honesty system performance over time.
    
    Reads from:
        - honesty_decisions: All decisions + feedback
        - honesty_thresholds: Current thresholds per user/domain
        
    Computes:
        - Decision counts (answered vs abstained)
        - Accuracy metrics (precision, recall, F1)
        - Error rates (Type I: wrong abstain, Type II: wrong answer)
        - Threshold evolution and convergence
        - GT score distributions
    """
    
    def __init__(self, db_connection: Optional[object] = None):
        """
        Initialize tracker.
        
        Args:
            db_connection: PostgreSQL connection (optional for testing)
        """
        self.db = db_connection
        
    def get_statistics(
        self,
        user_id: str,
        time_window: str = 'last_7_days',
        domain: Optional[str] = None
    ) -> HonestyStatistics:
        """
        Compute comprehensive statistics for user over time window.
        
        Args:
            user_id: User identifier
            time_window: 'last_7_days' | 'last_30_days' | 'all_time'
            domain: Optional domain filter
            
        Returns:
            HonestyStatistics dataclass with all metrics
        """
        # Determine time range
        cutoff = self._get_time_cutoff(time_window)
        
        # Query decisions
        decisions = self._fetch_decisions(user_id, cutoff, domain)
        thresholds = self._fetch_thresholds(user_id, domain)
        
        if not decisions:
            return self._empty_statistics(user_id, time_window)
        
        # Compute metrics
        decision_counts = self._compute_decision_counts(decisions)
        accuracy_metrics = self._compute_accuracy_metrics(decisions)
        learning_metrics = self._compute_learning_metrics(decisions, thresholds)
        distribution_metrics = self._compute_distribution_metrics(decisions)
        
        return HonestyStatistics(
            user_id=user_id,
            time_window=time_window,
            **decision_counts,
            **accuracy_metrics,
            **learning_metrics,
            **distribution_metrics,
            first_decision=decisions[0]['timestamp'] if decisions else None,
            last_decision=decisions[-1]['timestamp'] if decisions else None
        )
    
    def _get_time_cutoff(self, time_window: str) -> Optional[datetime]:
        """Convert time window string to datetime cutoff."""
        if time_window == 'all_time':
            return None
        elif time_window == 'last_7_days':
            return datetime.now() - timedelta(days=7)
        elif time_window == 'last_30_days':
            return datetime.now() - timedelta(days=30)
        else:
            raise ValueError(f"Unknown time window: {time_window}")
    
    def _fetch_decisions(
        self,
        user_id: str,
        cutoff: Optional[datetime],
        domain: Optional[str]
    ) -> List[Dict]:
        """Fetch decisions from database (or return mock data for tests)."""
        if self.db is None:
            return []  # Testing mode
        
        query = """
            SELECT decision_id, timestamp, query, domain,
                   gt_overall_score, decision, threshold_used,
                   confidence, margin, user_feedback, feedback_timestamp
            FROM honesty_decisions
            WHERE user_id = %s
        """
        params = [user_id]
        
        if cutoff:
            query += " AND timestamp >= %s"
            params.append(cutoff)
        
        if domain:
            query += " AND domain = %s"
            params.append(domain)
        
        query += " ORDER BY timestamp ASC"
        
        cursor = self.db.cursor()
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        decisions = [dict(zip(columns, row)) for row in cursor.fetchall()]
        cursor.close()
        
        return decisions
    
    def _fetch_thresholds(
        self,
        user_id: str,
        domain: Optional[str]
    ) -> Dict[str, float]:
        """Fetch current thresholds per domain."""
        if self.db is None:
            return {}  # Testing mode
        
        query = """
            SELECT domain, threshold, convergence_variance
            FROM honesty_thresholds
            WHERE user_id = %s
        """
        params = [user_id]
        
        if domain:
            query += " AND domain = %s"
            params.append(domain)
        
        cursor = self.db.cursor()
        cursor.execute(query, params)
        
        thresholds = {row[0]: {'threshold': row[1], 'variance': row[2]} 
                     for row in cursor.fetchall()}
        cursor.close()
        
        return thresholds
    
    def _compute_decision_counts(self, decisions: List[Dict]) -> Dict:
        """Count answered vs abstained."""
        total = len(decisions)
        answered = sum(1 for d in decisions if d['decision'] == 'ANSWER')
        abstained = total - answered
        
        return {
            'total_decisions': total,
            'answered': answered,
            'abstained': abstained,
            'abstention_rate': abstained / total if total > 0 else 0.0
        }
    
    def _compute_accuracy_metrics(self, decisions: List[Dict]) -> Dict:
        """Compute precision, recall, F1 from feedback."""
        # Filter decisions with feedback
        with_feedback = [d for d in decisions if d['user_feedback']]
        n_with_feedback = len(with_feedback)
        
        if n_with_feedback == 0:
            return {
                'n_with_feedback': 0,
                'correct_answers': 0,
                'correct_abstentions': 0,
                'wrong_answers': 0,
                'wrong_abstentions': 0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'type1_error_rate': 0.0,
                'type2_error_rate': 0.0
            }
        
        # Count feedback types
        correct_answers = sum(1 for d in with_feedback 
                            if d['decision'] == 'ANSWER' and d['user_feedback'] == 'CORRECT')
        wrong_answers = sum(1 for d in with_feedback 
                          if d['user_feedback'] == 'WRONG_ANSWER')
        correct_abstentions = sum(1 for d in with_feedback 
                                if d['decision'] == 'ABSTAIN' and d['user_feedback'] == 'CORRECT')
        wrong_abstentions = sum(1 for d in with_feedback 
                              if d['user_feedback'] == 'WRONG_ABSTAIN')
        
        # Compute metrics
        precision = correct_answers / (correct_answers + wrong_answers) if (correct_answers + wrong_answers) > 0 else 0.0
        recall = correct_answers / (correct_answers + wrong_abstentions) if (correct_answers + wrong_abstentions) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        type1_rate = wrong_abstentions / n_with_feedback
        type2_rate = wrong_answers / n_with_feedback
        
        return {
            'n_with_feedback': n_with_feedback,
            'correct_answers': correct_answers,
            'correct_abstentions': correct_abstentions,
            'wrong_answers': wrong_answers,
            'wrong_abstentions': wrong_abstentions,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'type1_error_rate': type1_rate,
            'type2_error_rate': type2_rate
        }
    
    def _compute_learning_metrics(
        self,
        decisions: List[Dict],
        thresholds: Dict[str, Dict]
    ) -> Dict:
        """Analyze threshold evolution and convergence."""
        # Extract thresholds from decisions (chronological)
        threshold_history = [d['threshold_used'] for d in decisions]
        
        if not threshold_history:
            return {
                'avg_threshold': 0.0,
                'threshold_variance': 0.0,
                'convergence_status': ConvergenceStatus.LEARNING
            }
        
        avg_threshold = np.mean(threshold_history)
        threshold_variance = np.var(threshold_history)
        
        # Determine convergence status
        n_decisions = len(decisions)
        if n_decisions < 20:
            convergence = ConvergenceStatus.LEARNING
        elif threshold_variance < 0.001:
            convergence = ConvergenceStatus.CONVERGED
        elif threshold_variance < 0.01:
            convergence = ConvergenceStatus.CONVERGING
        else:
            # Check if variance increasing (last 20 vs previous 20)
            if n_decisions >= 40:
                var_recent = np.var(threshold_history[-20:])
                var_older = np.var(threshold_history[-40:-20])
                if var_recent > var_older * 1.5:
                    convergence = ConvergenceStatus.DIVERGING
                else:
                    convergence = ConvergenceStatus.CONVERGING
            else:
                convergence = ConvergenceStatus.CONVERGING
        
        return {
            'avg_threshold': avg_threshold,
            'threshold_variance': threshold_variance,
            'convergence_status': convergence
        }
    
    def _compute_distribution_metrics(self, decisions: List[Dict]) -> Dict:
        """Analyze GT score distribution."""
        gt_scores = [d['gt_overall_score'] for d in decisions]
        
        if not gt_scores:
            return {
                'gt_score_mean': 0.0,
                'gt_score_std': 0.0,
                'gt_score_histogram': {}
            }
        
        gt_mean = np.mean(gt_scores)
        gt_std = np.std(gt_scores)
        
        # Histogram (bins: 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0)
        bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
        histogram = {}
        for i in range(len(bins) - 1):
            bin_label = f"{bins[i]:.1f}-{bins[i+1]:.1f}"
            count = sum(1 for s in gt_scores if bins[i] <= s < bins[i+1])
            histogram[bin_label] = count
        
        # Include edge case for exactly 1.0
        if gt_scores and max(gt_scores) == 1.0:
            histogram['0.8-1.0'] += sum(1 for s in gt_scores if s == 1.0)
        
        return {
            'gt_score_mean': gt_mean,
            'gt_score_std': gt_std,
            'gt_score_histogram': histogram
        }
    
    def _empty_statistics(self, user_id: str, time_window: str) -> HonestyStatistics:
        """Return empty statistics object."""
        return HonestyStatistics(
            user_id=user_id,
            time_window=time_window,
            total_decisions=0,
            answered=0,
            abstained=0,
            abstention_rate=0.0,
            n_with_feedback=0,
            correct_answers=0,
            correct_abstentions=0,
            wrong_answers=0,
            wrong_abstentions=0,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            type1_error_rate=0.0,
            type2_error_rate=0.0,
            avg_threshold=0.0,
            threshold_variance=0.0,
            convergence_status=ConvergenceStatus.LEARNING,
            gt_score_mean=0.0,
            gt_score_std=0.0,
            gt_score_histogram={},
            first_decision=None,
            last_decision=None
        )

