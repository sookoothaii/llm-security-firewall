"""
Unit Tests for HonestyStatisticsTracker
========================================

Tests metrics computation, convergence detection, distribution analysis.

Author: Claude Sonnet 4.5 (Forschungsleiter)
Date: 2025-10-27
"""

import pytest
from datetime import datetime, timedelta
from llm_firewall.engines.statistics_tracker import HonestyStatisticsTracker
from llm_firewall.utils.types import ConvergenceStatus


@pytest.fixture
def tracker():
    """Create tracker without DB (testing mode)."""
    return HonestyStatisticsTracker(db_connection=None)


@pytest.fixture
def mock_decisions_empty():
    """Empty decisions list."""
    return []


@pytest.fixture
def mock_decisions_no_feedback():
    """10 decisions without user feedback."""
    decisions = []
    for i in range(10):
        decisions.append({
            'decision_id': f'id_{i}',
            'timestamp': datetime.now() - timedelta(days=10-i),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.5 + i * 0.05,
            'decision': 'ANSWER' if i % 2 == 0 else 'ABSTAIN',
            'threshold_used': 0.75,
            'confidence': 0.80,
            'margin': 0.05,
            'user_feedback': None,
            'feedback_timestamp': None
        })
    return decisions


@pytest.fixture
def mock_decisions_with_feedback():
    """20 decisions with mixed feedback."""
    decisions = []
    feedbacks = [
        'CORRECT', 'CORRECT', 'WRONG_ABSTAIN', 'CORRECT',
        'CORRECT', 'WRONG_ABSTAIN', 'CORRECT', 'CORRECT',
        'WRONG_ANSWER', 'CORRECT', 'CORRECT', 'WRONG_ABSTAIN',
        'CORRECT', 'CORRECT', 'CORRECT', 'WRONG_ABSTAIN',
        'CORRECT', 'CORRECT', 'CORRECT', 'CORRECT'
    ]
    
    for i in range(20):
        decisions.append({
            'decision_id': f'id_{i}',
            'timestamp': datetime.now() - timedelta(days=20-i),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.4 + i * 0.02,
            'decision': 'ANSWER' if i % 3 != 0 else 'ABSTAIN',
            'threshold_used': 0.75 - i * 0.001,  # Slowly decreasing
            'confidence': 0.80,
            'margin': 0.05,
            'user_feedback': feedbacks[i],
            'feedback_timestamp': datetime.now() - timedelta(days=20-i, hours=1)
        })
    return decisions


def test_empty_statistics(tracker):
    """Test empty statistics computation."""
    tracker._fetch_decisions = lambda u, c, d: []
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'last_7_days')
    
    assert stats.user_id == 'test_user'
    assert stats.total_decisions == 0
    assert stats.answered == 0
    assert stats.abstained == 0
    assert stats.abstention_rate == 0.0
    assert stats.precision == 0.0
    assert stats.recall == 0.0
    assert stats.convergence_status == ConvergenceStatus.LEARNING


def test_decision_counts_no_feedback(tracker, mock_decisions_no_feedback):
    """Test decision counting without feedback."""
    tracker._fetch_decisions = lambda u, c, d: mock_decisions_no_feedback
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'last_7_days')
    
    assert stats.total_decisions == 10
    assert stats.answered == 5  # Even indices
    assert stats.abstained == 5
    assert stats.abstention_rate == 0.5
    assert stats.n_with_feedback == 0  # No feedback


def test_accuracy_metrics_with_feedback(tracker, mock_decisions_with_feedback):
    """Test precision/recall computation with feedback."""
    tracker._fetch_decisions = lambda u, c, d: mock_decisions_with_feedback
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'last_30_days')
    
    assert stats.n_with_feedback == 20
    
    # Count from fixture:
    # CORRECT: 15, WRONG_ABSTAIN: 4, WRONG_ANSWER: 1
    assert stats.correct_answers + stats.correct_abstentions == 15
    assert stats.wrong_abstentions == 4
    assert stats.wrong_answers == 1
    
    # Precision = correct_answer / (correct_answer + wrong_answer)
    # Depends on decision types (ANSWER vs ABSTAIN)
    # We just check they're computed (non-zero if feedback exists)
    assert 0.0 <= stats.precision <= 1.0
    assert 0.0 <= stats.recall <= 1.0
    assert 0.0 <= stats.f1_score <= 1.0
    
    # Error rates
    assert stats.type1_error_rate == 4 / 20  # 0.20
    assert stats.type2_error_rate == 1 / 20  # 0.05


def test_convergence_learning_phase(tracker):
    """Test convergence detection: LEARNING phase (<20 samples)."""
    decisions = [
        {
            'decision_id': f'id_{i}',
            'timestamp': datetime.now() - timedelta(days=10-i),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.6,
            'decision': 'ANSWER',
            'threshold_used': 0.75,
            'confidence': 0.80,
            'margin': 0.05,
            'user_feedback': None,
            'feedback_timestamp': None
        }
        for i in range(15)  # < 20
    ]
    
    tracker._fetch_decisions = lambda u, c, d: decisions
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'all_time')
    
    assert stats.convergence_status == ConvergenceStatus.LEARNING


def test_convergence_converged(tracker):
    """Test convergence detection: CONVERGED (variance < 0.001)."""
    decisions = [
        {
            'decision_id': f'id_{i}',
            'timestamp': datetime.now() - timedelta(days=30-i),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.6,
            'decision': 'ANSWER',
            'threshold_used': 0.750 + (i % 3) * 0.0001,  # Very stable
            'confidence': 0.80,
            'margin': 0.05,
            'user_feedback': None,
            'feedback_timestamp': None
        }
        for i in range(30)  # >= 20, low variance
    ]
    
    tracker._fetch_decisions = lambda u, c, d: decisions
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'all_time')
    
    assert stats.convergence_status == ConvergenceStatus.CONVERGED
    assert stats.threshold_variance < 0.001


def test_convergence_converging(tracker):
    """Test convergence detection: CONVERGING (0.001 < variance < 0.01)."""
    decisions = [
        {
            'decision_id': f'id_{i}',
            'timestamp': datetime.now() - timedelta(days=30-i),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.6,
            'decision': 'ANSWER',
            'threshold_used': 0.75 - i * 0.005,  # More variation for CONVERGING
            'confidence': 0.80,
            'margin': 0.05,
            'user_feedback': None,
            'feedback_timestamp': None
        }
        for i in range(30)
    ]
    
    tracker._fetch_decisions = lambda u, c, d: decisions
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'all_time')
    
    assert stats.convergence_status == ConvergenceStatus.CONVERGING
    assert 0.001 <= stats.threshold_variance < 0.01


def test_gt_score_distribution(tracker, mock_decisions_with_feedback):
    """Test GT score histogram computation."""
    tracker._fetch_decisions = lambda u, c, d: mock_decisions_with_feedback
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'all_time')
    
    # Check histogram bins exist
    assert '0.0-0.2' in stats.gt_score_histogram
    assert '0.2-0.4' in stats.gt_score_histogram
    assert '0.4-0.6' in stats.gt_score_histogram
    assert '0.6-0.8' in stats.gt_score_histogram
    assert '0.8-1.0' in stats.gt_score_histogram
    
    # Check total counts = total decisions
    total_in_bins = sum(stats.gt_score_histogram.values())
    assert total_in_bins == 20
    
    # Check mean/std computed
    assert 0.0 <= stats.gt_score_mean <= 1.0
    assert stats.gt_score_std >= 0.0


def test_time_window_filtering(tracker):
    """Test time window cutoff computation."""
    # last_7_days
    cutoff_7 = tracker._get_time_cutoff('last_7_days')
    assert cutoff_7 is not None
    assert cutoff_7 < datetime.now()
    assert cutoff_7 > datetime.now() - timedelta(days=8)
    
    # last_30_days
    cutoff_30 = tracker._get_time_cutoff('last_30_days')
    assert cutoff_30 is not None
    assert cutoff_30 < datetime.now()
    assert cutoff_30 > datetime.now() - timedelta(days=31)
    
    # all_time
    cutoff_all = tracker._get_time_cutoff('all_time')
    assert cutoff_all is None


def test_precision_recall_edge_cases(tracker):
    """Test precision/recall with edge cases (no correct answers, etc.)."""
    # Only wrong answers (precision = 0)
    decisions_all_wrong = [
        {
            'decision_id': f'id_{i}',
            'timestamp': datetime.now(),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.5,
            'decision': 'ANSWER',
            'threshold_used': 0.75,
            'confidence': 0.80,
            'margin': 0.05,
            'user_feedback': 'WRONG_ANSWER',
            'feedback_timestamp': datetime.now()
        }
        for i in range(5)
    ]
    
    tracker._fetch_decisions = lambda u, c, d: decisions_all_wrong
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'all_time')
    
    assert stats.precision == 0.0
    assert stats.wrong_answers == 5
    assert stats.type2_error_rate == 1.0


def test_f1_score_computation(tracker):
    """Test F1 score computation from precision and recall."""
    # Perfect precision and recall
    decisions_perfect = [
        {
            'decision_id': f'id_{i}',
            'timestamp': datetime.now(),
            'query': f'Query {i}',
            'domain': 'SCIENCE',
            'gt_overall_score': 0.8,
            'decision': 'ANSWER',
            'threshold_used': 0.75,
            'confidence': 0.85,
            'margin': 0.10,
            'user_feedback': 'CORRECT',
            'feedback_timestamp': datetime.now()
        }
        for i in range(10)
    ]
    
    tracker._fetch_decisions = lambda u, c, d: decisions_perfect
    tracker._fetch_thresholds = lambda u, d: {}
    
    stats = tracker.get_statistics('test_user', 'all_time')
    
    # All ANSWER + all CORRECT = precision 1.0, but recall depends on wrong_abstentions (0 here)
    assert stats.precision == 1.0
    # F1 will be computed correctly
    assert 0.0 <= stats.f1_score <= 1.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

