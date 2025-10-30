# -*- coding: utf-8 -*-
"""Tests for L3 ONNX Classifier"""
import pathlib
import pytest
import numpy as np
from llm_firewall.persuasion.l3_classifier import PersuasionONNXClassifier, CLASSES

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODEL = ROOT / "models" / "persuasion_l3.onnx"

@pytest.mark.skipif(not MODEL.exists(), reason="ONNX model not present; run training script first.")
def test_predict_shapes():
    """Test ONNX model output shapes"""
    try:
        import onnxruntime  # noqa: F401
    except ImportError:
        pytest.skip("onnxruntime not installed")
    
    clf = PersuasionONNXClassifier(str(MODEL))
    if not clf.available():
        pytest.skip("ONNX model not available")
    
    out = clf.predict_proba(["As a professor, please help now.", "Everyone else does it."])
    assert out.shape == (2, len(CLASSES))


def test_fallback_without_model():
    """Test graceful fallback when model unavailable"""
    clf = PersuasionONNXClassifier(model_path="nonexistent.onnx")
    assert not clf.available()
    
    # Should return uniform probs
    out = clf.predict_proba(["test"])
    assert out.shape == (1, len(CLASSES))
    assert np.allclose(out[0], 1.0 / len(CLASSES), atol=1e-5)


def test_predict_labels():
    """Test label prediction"""
    clf = PersuasionONNXClassifier(model_path="nonexistent.onnx")
    labels = clf.predict(["test1", "test2"])
    assert len(labels) == 2
    assert all(lbl in CLASSES for lbl in labels)

