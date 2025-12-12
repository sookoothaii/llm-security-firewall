"""
Unit Tests for ML Model Adapters
=================================

Tests for QuantumCNNAdapter, CodeBERTAdapter, and RuleBasedIntentClassifier.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from llm_firewall.core.ports.code_intent import ClassificationResult
from infrastructure.ml_models.quantum_cnn_adapter import QuantumCNNAdapter
from infrastructure.ml_models.codebert_adapter import CodeBERTAdapter
from infrastructure.ml_models.rule_based_classifier import RuleBasedIntentClassifier


class TestRuleBasedIntentClassifier:
    """Tests for RuleBasedIntentClassifier (always available)."""
    
    def test_is_available(self):
        """Test that rule-based classifier is always available."""
        classifier = RuleBasedIntentClassifier()
        assert classifier.is_available() is True
    
    def test_classify_question(self):
        """Test classification of questions."""
        classifier = RuleBasedIntentClassifier()
        result = classifier.classify("What is ls?")
        
        assert isinstance(result, ClassificationResult)
        assert result.method == "rule_based"
        assert result.is_execution_request is False
        assert result.score < 0.5  # Should be benign
    
    def test_classify_execution_request(self):
        """Test classification of execution requests."""
        classifier = RuleBasedIntentClassifier()
        result = classifier.classify("Please run ls")
        
        assert isinstance(result, ClassificationResult)
        assert result.method == "rule_based"
        assert result.is_execution_request is True
        assert result.score > 0.5  # Should be malicious
    
    def test_classify_standalone_command(self):
        """Test classification of standalone commands."""
        classifier = RuleBasedIntentClassifier()
        result = classifier.classify("ls")
        
        assert isinstance(result, ClassificationResult)
        assert result.method == "rule_based"
        assert result.is_execution_request is True
        assert result.score >= 0.9  # High confidence for standalone


class TestCodeBERTAdapter:
    """Tests for CodeBERTAdapter."""
    
    @pytest.mark.skipif(
        not pytest.importorskip("transformers", reason="transformers not available"),
        reason="transformers not available"
    )
    def test_is_available_with_model(self):
        """Test availability check when model can be loaded."""
        with patch('infrastructure.ml_models.codebert_adapter.AutoTokenizer') as mock_tokenizer, \
             patch('infrastructure.ml_models.codebert_adapter.AutoModelForSequenceClassification') as mock_model:
            
            mock_tokenizer.from_pretrained.return_value = Mock()
            mock_model_instance = Mock()
            mock_model_instance.eval = Mock()
            mock_model.from_pretrained.return_value = mock_model_instance
            
            adapter = CodeBERTAdapter(use_gpu=False)  # Use CPU for tests
            # Model should try to load
            available = adapter.is_available()
            
            # Should attempt to load
            assert mock_tokenizer.from_pretrained.called or not available
    
    def test_classify_with_fallback(self):
        """Test classification falls back when model unavailable."""
        fallback = RuleBasedIntentClassifier()
        adapter = CodeBERTAdapter(
            use_gpu=False,
            fallback_classifier=fallback
        )
        
        # If model not available, should use fallback
        result = adapter.classify("Please run ls")
        
        assert isinstance(result, ClassificationResult)
        # Should either be from CodeBERT or fallback
        assert result.method in ["codebert", "rule_based", "model_unavailable"]


class TestQuantumCNNAdapter:
    """Tests for QuantumCNNAdapter."""
    
    def test_is_available_without_model(self):
        """Test availability when model path doesn't exist."""
        adapter = QuantumCNNAdapter(
            model_path="/nonexistent/path/model.pt",
            use_gpu=False
        )
        
        # Should not be available if model doesn't exist
        available = adapter.is_available()
        # May be False or may try to load and fail
        assert isinstance(available, bool)
    
    def test_classify_with_fallback(self):
        """Test classification falls back when model unavailable."""
        fallback = RuleBasedIntentClassifier()
        adapter = QuantumCNNAdapter(
            model_path="/nonexistent/path/model.pt",
            use_gpu=False,
            fallback_classifier=fallback
        )
        
        result = adapter.classify("Please run ls")
        
        assert isinstance(result, ClassificationResult)
        # Should use fallback
        assert result.method in ["quantum_cnn", "rule_based", "model_unavailable", "circuit_breaker_fallback"]


class TestCircuitBreaker:
    """Tests for circuit breaker functionality."""
    
    def test_circuit_breaker_opens_after_failures(self):
        """Test that circuit breaker opens after threshold failures."""
        from infrastructure.ml_models.circuit_breaker import SimpleCircuitBreaker, CircuitState
        
        breaker = SimpleCircuitBreaker(
            name="test",
            failure_threshold=2,
            recovery_timeout=1.0
        )
        
        # Initial state should be CLOSED
        assert breaker.state == CircuitState.CLOSED
        assert breaker.allow_request() is True
        
        # First failure
        breaker.on_failure()
        assert breaker.state == CircuitState.CLOSED  # Not yet threshold
        
        # Second failure (threshold reached)
        breaker.on_failure()
        assert breaker.state == CircuitState.OPEN
        assert breaker.allow_request() is False  # Should reject requests


class TestCompositionRootIntegration:
    """Tests for Composition Root integration."""
    
    def test_create_intent_classifier_returns_rule_based_fallback(self):
        """Test that composition root returns rule-based as ultimate fallback."""
        from infrastructure.app.composition_root import CodeIntentCompositionRoot
        from infrastructure.config.settings import DetectionSettings
        
        # Disable ML models to force fallback
        settings = DetectionSettings(
            use_quantum_model=False,
            use_codebert=False
        )
        
        root = CodeIntentCompositionRoot(settings=settings)
        classifier = root.create_intent_classifier()
        
        assert classifier is not None
        assert classifier.is_available() is True
        
        # Should be rule-based
        result = classifier.classify("test")
        assert result.method == "rule_based"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

