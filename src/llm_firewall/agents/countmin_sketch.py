# -*- coding: utf-8 -*-
"""
Count-Min Sketch Implementation for Fragment Memory Tracking
============================================================

Production-ready CountMinSketch for RC10c DLP Lite fragment tracking.
Fixed memory footprint (~10KB), O(1) operations.

Based on recommendations from:
- Kimi K2 Thinking: probables library (preferred)
- DeepSeek v3.1: Custom implementation with mmh3 (fallback)

Creator: Joerg Bollwahn (with Kimi K2 + DeepSeek collaboration)
License: MIT
"""

import hashlib


class CountMinSketch:
    """
    Simple Count-Min Sketch implementation for fragment memory tracking.

    Fixed memory footprint: ~10KB with default parameters (width=512, depth=4).
    O(1) insert and estimate operations.
    """

    def __init__(self, width: int = 512, depth: int = 4, seed: int = 42):
        """Initialize CountMinSketch.

        Args:
            width: Number of counters per hash function (default: 512)
            depth: Number of hash functions (default: 4)
            seed: Random seed for hash function generation

        Memory: width * depth * 4 bytes (32-bit integers)
        Example: 512 * 4 * 4 = 8,192 bytes (~8KB)
        """
        self.width = width
        self.depth = depth
        self.seed = seed

        # Initialize counter matrix: depth x width
        # Using 32-bit integers (4 bytes each)
        self.counters = [[0] * width for _ in range(depth)]

        # Generate unique seeds for each hash function
        self.hash_seeds = [seed + i * 1000 for i in range(depth)]

    def _hash(self, item: bytes, seed: int) -> int:
        """Hash function using SHA-256 with seed mixing."""
        # Use SHA-256 for good distribution
        combined = item + str(seed).encode()
        hash_digest = hashlib.sha256(combined).digest()
        # Convert to integer and modulo width
        hash_int = int.from_bytes(hash_digest[:4], byteorder="big")
        return hash_int % self.width

    def add(self, item: bytes, count: int = 1) -> None:
        """Add an item to the sketch.

        Args:
            item: Item to add (bytes)
            count: Number of occurrences to add (default: 1)
        """
        for i in range(self.depth):
            idx = self._hash(item, self.hash_seeds[i])
            self.counters[i][idx] += count

    def check(self, item: bytes) -> int:
        """Estimate frequency of an item.

        Args:
            item: Item to query (bytes)

        Returns:
            Estimated count (always >= true count due to CMS properties)
        """
        min_count = float("inf")
        for i in range(self.depth):
            idx = self._hash(item, self.hash_seeds[i])
            min_count = min(min_count, self.counters[i][idx])
        return int(min_count)

    def __getitem__(self, item: bytes) -> int:
        """Allow dict-like access: sketch[item]"""
        return self.check(item)

    def __setitem__(self, item: bytes, value: int) -> None:
        """Allow dict-like assignment: sketch[item] += 1"""
        current = self.check(item)
        diff = value - current
        if diff > 0:
            self.add(item, diff)
        # Note: CMS doesn't support decrement, so we only handle increments

    def memory_usage(self) -> int:
        """Return approximate memory usage in bytes."""
        return self.depth * self.width * 4  # 4 bytes per counter


# Note: probables library not available on PyPI
# Using custom implementation (DeepSeek v3.1 recommendation)
# This implementation is always available (no external dependencies beyond stdlib)


def create_countmin_sketch(width: int = 512, depth: int = 4) -> CountMinSketch:
    """Factory function to create CountMinSketch.

    Uses custom implementation (always available, no external deps).

    Args:
        width: Number of counters per hash function (default: 512)
        depth: Number of hash functions (default: 4)

    Returns:
        CountMinSketch instance
    """
    return CountMinSketch(width=width, depth=depth)
