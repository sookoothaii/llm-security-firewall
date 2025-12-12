"""
ML Module - Quantum-Inspired Architectures
==========================================
"""

from llm_firewall.ml.continual_learning import (
    ElasticWeightConsolidation,
    SynapticIntelligence,
    ContinualLearningTrainer
)

from llm_firewall.ml.quantum_inspired_architectures import (
    HierarchicalBlock,
    QuantumInspiredCNN,
    DeepFeatureTower,
    HybridDetector
)

from llm_firewall.ml.robustness_regularization import (
    OrthogonalRegularizer,
    SpectralNormalization,
    RobustnessTrainer,
    apply_spectral_normalization
)

from llm_firewall.ml.ab_testing import (
    ABTestLogger,
    ABTestMetrics,
    get_ab_logger
)

from llm_firewall.ml.dynamic_hybrid import (
    DynamicHybridDetector,
    RuleEngine
)

from llm_firewall.ml.continual_learning_feedback import (
    ContinualLearningFeedbackLoop,
    FeedbackEntry,
    FeedbackInterface
)

__all__ = [
    # Continual Learning
    "ElasticWeightConsolidation",
    "SynapticIntelligence",
    "ContinualLearningTrainer",
    
    # Quantum-Inspired Architectures
    "HierarchicalBlock",
    "QuantumInspiredCNN",
    "DeepFeatureTower",
    "HybridDetector",
    
    # Robustness
    "OrthogonalRegularizer",
    "SpectralNormalization",
    "RobustnessTrainer",
    "apply_spectral_normalization",
    
    # A/B Testing
    "ABTestLogger",
    "ABTestMetrics",
    "get_ab_logger",
    
    # Dynamic Hybrid
    "DynamicHybridDetector",
    "RuleEngine",
    
    # Feedback Loop
    "ContinualLearningFeedbackLoop",
    "FeedbackEntry",
    "FeedbackInterface"
]
