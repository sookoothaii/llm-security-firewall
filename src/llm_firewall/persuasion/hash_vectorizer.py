# -*- coding: utf-8 -*-
"""
Dependency-light hashing vectorizer compatible between training and inference.
- Tokenization: word-level (simple), n-grams (1..2 by default) after normalize().
- Hashing: BLAKE2b 32-bit (stable across processes), *not* Python's hash().
- Output: dense float32 vector of shape [D].

Keep D moderate (e.g., 2**18 = 262,144) for accuracy/latency trade-off.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import hashlib
from typing import Iterable, List, Tuple

import numpy as np

from ..text.normalize_unicode import normalize


class HashVectorizer:
    def __init__(self, n_features: int = 2**18, ngram_range: Tuple[int, int] = (1, 2)):
        if n_features <= 0 or (n_features & (n_features - 1) != 0):
            raise ValueError("n_features should be power of two")
        self.D = n_features
        self.ngram_range = ngram_range

    @staticmethod
    def _tokens(text: str) -> List[str]:
        t = normalize(text).lower()
        return [tok for tok in t.split() if tok]

    @staticmethod
    def _h32(s: str) -> int:
        # 32-bit index via blake2b (stable)
        return int.from_bytes(
            hashlib.blake2b(s.encode("utf-8"), digest_size=4).digest(),
            "little",
            signed=False,
        )

    def transform_one(self, text: str) -> np.ndarray:
        toks = self._tokens(text)
        lo, hi = self.ngram_range
        feats = np.zeros(self.D, dtype=np.float32)
        for n in range(lo, hi + 1):
            if n == 1:
                grams = toks
            else:
                grams = [" ".join(toks[i : i + n]) for i in range(len(toks) - n + 1)]
            for g in grams:
                idx = self._h32(g) & (self.D - 1)
                feats[idx] += 1.0
        # L2 normalize to unit length to stabilize the logistic head
        norm = np.linalg.norm(feats)
        if norm > 0:
            feats /= norm
        return feats

    def transform(self, texts: Iterable[str]) -> np.ndarray:
        arr = [self.transform_one(t) for t in texts]
        return np.stack(arr, axis=0)
