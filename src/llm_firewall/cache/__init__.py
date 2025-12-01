"""
Decision Cache Module for Firewall Performance Optimization.

Provides Redis-backed caching of firewall decisions to achieve < 1 ms hit latency.
"""

from llm_firewall.cache.decision_cache import get_cached, set_cached

__all__ = ["get_cached", "set_cached"]
