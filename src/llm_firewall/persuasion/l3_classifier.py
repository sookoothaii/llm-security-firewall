# -*- coding: utf-8 -*-
"""
ONNX Mini-Classifier wrapper for persuasion categories (L3).
- Classes: [authority, commitment, liking, reciprocity, scarcity_urgency, social_proof, unity_identity, none]
- Input: raw text(s). Internally vectorized with HashVectorizer to a dense [N, D] float32 matrix.
- Model: `models/persuasion_l3.onnx` with input name `features` (float32 [None, D]) and
         output name `proba` (float32 [None, 8]) - softmax probabilities per class.

If onnxruntime or the model is unavailable, falls back to a neutral prior (uniform probs).

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import os
from typing import List, Sequence

import numpy as np

try:
    import onnxruntime as ort  # type: ignore
except ImportError:
    ort = None  # type: ignore

from llm_firewall.persuasion.hash_vectorizer import HashVectorizer

CLASSES = [
    "authority",
    "commitment_consistency",
    "liking",
    "reciprocity",
    "scarcity_urgency",
    "social_proof",
    "unity_identity",
    "none",
]


class PersuasionONNXClassifier:
    def __init__(
        self, model_path: str = "models/persuasion_l3.onnx", n_features: int = 2**18
    ):
        self.model_path = model_path
        self.vec = HashVectorizer(n_features=n_features)
        self.session = None
        if ort is not None and os.path.exists(self.model_path):
            self.session = ort.InferenceSession(
                self.model_path, providers=["CPUExecutionProvider"]
            )

    def available(self) -> bool:
        return self.session is not None

    def predict_proba(self, texts: Sequence[str]) -> np.ndarray:
        X = self.vec.transform(texts)
        if self.session is None:
            # uniform prior fallback to avoid hard failure
            probs = np.full(
                (len(texts), len(CLASSES)), 1.0 / len(CLASSES), dtype=np.float32
            )
            return probs
        inp = {"features": X.astype(np.float32)}
        out = self.session.run(["proba"], inp)[0]
        return out

    def predict(self, texts: Sequence[str]) -> List[str]:
        proba = self.predict_proba(texts)
        idx = np.argmax(proba, axis=1)
        return [CLASSES[i] for i in idx]
