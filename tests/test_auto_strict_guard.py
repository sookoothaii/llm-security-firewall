"""Tests for auto-strict guard."""

import time

from llm_firewall.session.auto_strict_guard import AutoStrictGuard


def test_auto_strict_triggers_on_threshold():
    """Test that guard triggers strict mode after threshold alarms."""
    guard = AutoStrictGuard(threshold=3, window_sec=60, duration_sec=120)

    assert guard.should_be_strict() is False

    # Record 3 alarms
    guard.record_alarm("session1")
    guard.record_alarm("session2")
    assert guard.should_be_strict() is False  # Not yet

    guard.record_alarm("session3")
    assert guard.should_be_strict() is True  # Now triggered


def test_auto_strict_expires_after_duration():
    """Test that strict mode expires after duration."""
    guard = AutoStrictGuard(threshold=2, window_sec=60, duration_sec=1)

    guard.record_alarm("s1")
    guard.record_alarm("s2")
    assert guard.should_be_strict() is True

    # Wait for expiration
    time.sleep(1.1)
    assert guard.should_be_strict() is False


def test_auto_strict_prunes_old_alarms():
    """Test that old alarms outside window don't count."""
    guard = AutoStrictGuard(threshold=3, window_sec=2, duration_sec=60)

    guard.record_alarm("s1")
    guard.record_alarm("s2")

    # Wait for window to expire
    time.sleep(2.1)

    guard.record_alarm("s3")  # Only 1 alarm in window now

    assert guard.should_be_strict() is False


def test_auto_strict_stats():
    """Test get_stats method."""
    guard = AutoStrictGuard(threshold=3, window_sec=60, duration_sec=120)

    guard.record_alarm("s1")
    guard.record_alarm("s2")

    stats = guard.get_stats()
    assert stats["is_strict"] is False
    assert stats["recent_alarms"] == 2
    assert stats["threshold"] == 3

    guard.record_alarm("s3")
    stats = guard.get_stats()
    assert stats["is_strict"] is True
    assert stats["strict_until"] is not None
