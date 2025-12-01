"""
Helper utilities for test development.
"""

import json
import time
import statistics
from typing import List, Dict, Any, Optional
from pathlib import Path


def load_adversarial_suite(suite_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Load adversarial test vectors from JSONL file.

    Args:
        suite_path: Optional path to JSONL file. If None, uses default.

    Returns:
        List of test case dictionaries.
    """
    if suite_path is None:
        suite_path = (
            Path(__file__).parent.parent.parent
            / "data"
            / "gpt5_adversarial_suite.jsonl"
        )

    if not suite_path.exists():
        return []

    test_cases = []
    with open(suite_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    test_cases.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return test_cases


def calculate_percentiles(
    latencies: List[float], percentiles: List[int] = [50, 95, 99]
) -> Dict[int, float]:
    """
    Calculate percentile latencies from a list of measurements.

    Args:
        latencies: List of latency measurements in milliseconds
        percentiles: List of percentiles to calculate (default: [50, 95, 99])

    Returns:
        Dictionary mapping percentile to latency value.
    """
    if not latencies:
        return {p: 0.0 for p in percentiles}

    sorted_latencies = sorted(latencies)
    results = {}

    for p in percentiles:
        if p == 50:
            results[p] = statistics.median(sorted_latencies)
        else:
            # Calculate percentile using linear interpolation
            index = (p / 100.0) * (len(sorted_latencies) - 1)
            lower = int(index)
            upper = min(lower + 1, len(sorted_latencies) - 1)
            weight = index - lower

            if lower == upper:
                results[p] = sorted_latencies[lower]
            else:
                results[p] = (
                    sorted_latencies[lower] * (1 - weight)
                    + sorted_latencies[upper] * weight
                )

    return results


def measure_latency(func, *args, **kwargs) -> tuple[Any, float]:
    """
    Measure execution time of a function.

    Args:
        func: Function to measure
        *args, **kwargs: Arguments to pass to function

    Returns:
        Tuple of (result, latency_ms)
    """
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    latency_ms = (end - start) * 1000
    return result, latency_ms


def create_large_payload(size_mb: float) -> str:
    """
    Create a large payload for buffer limit testing.

    Args:
        size_mb: Size in megabytes

    Returns:
        String payload of specified size.
    """
    size_bytes = int(size_mb * 1024 * 1024)
    return "A" * size_bytes


def create_encoded_payload(original: str, encoding: str = "url") -> str:
    """
    Create encoded payload for normalization layer testing.

    Args:
        original: Original payload
        encoding: Encoding type ('url', 'base64', 'double_url')

    Returns:
        Encoded payload string.
    """
    import urllib.parse
    import base64

    if encoding == "url":
        return urllib.parse.quote(original)
    elif encoding == "base64":
        return base64.b64encode(original.encode()).decode()
    elif encoding == "double_url":
        # Double URL encoding
        return urllib.parse.quote(urllib.parse.quote(original))
    else:
        return original


def assert_decision_allowed(decision, reason_contains: Optional[str] = None):
    """
    Assert that a firewall decision allows the request.

    Args:
        decision: FirewallDecision object
        reason_contains: Optional string that should be in reason
    """
    assert decision.allowed is True, f"Expected ALLOW, got BLOCK: {decision.reason}"
    if reason_contains:
        assert reason_contains.lower() in decision.reason.lower(), (
            f"Reason should contain '{reason_contains}', got: {decision.reason}"
        )


def assert_decision_blocked(
    decision, reason_contains: Optional[str] = None, min_risk_score: float = 0.0
):
    """
    Assert that a firewall decision blocks the request.

    Args:
        decision: FirewallDecision object
        reason_contains: Optional string that should be in reason
        min_risk_score: Minimum risk score expected
    """
    assert decision.allowed is False, f"Expected BLOCK, got ALLOW: {decision.reason}"
    assert decision.risk_score >= min_risk_score, (
        f"Risk score {decision.risk_score} < {min_risk_score}"
    )
    if reason_contains:
        assert reason_contains.lower() in decision.reason.lower(), (
            f"Reason should contain '{reason_contains}', got: {decision.reason}"
        )
