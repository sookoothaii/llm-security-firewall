"""
Code Intent Service Composition Root

Central place where all adapters are composed and injected into the domain layer.
Extends BaseCompositionRoot from shared components.

Architecture Note:
- Single Responsibility: Assemble system components
- Dependency Rule: All dependencies flow inward (domain ← adapters)
- Testability: Easy to swap adapters for tests

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
Updated: 2025-12-11 (Migrated to use BaseCompositionRoot)
Status: P0 - Dependency Rule Enforcement
License: MIT
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

import sys
from pathlib import Path

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

# Import Base Composition Root
from shared.infrastructure.composition import BaseCompositionRoot

# Domain layer imports (inward dependency)
from domain.services.ports import (
    BenignValidatorPort,
    IntentClassifierPort,
    RuleEnginePort,
    FeedbackRepositoryPort,
)

# Infrastructure imports (adapters)
from infrastructure.config.settings import DetectionSettings
from infrastructure.rule_engines.benign_validator_factory import BenignValidatorFactory
from infrastructure.rule_engines.benign_validator_composite import BenignValidatorComposite

# ML Model imports
from infrastructure.ml_models.quantum_cnn_adapter import QuantumCNNAdapter
from infrastructure.ml_models.codebert_adapter import CodeBERTAdapter
from infrastructure.ml_models.rule_based_classifier import RuleBasedIntentClassifier

# V2.1 Hotfix Adapter (optional)
try:
    from infrastructure.ml_models.v21_hotfix_adapter import V21HotfixAdapter
    HAS_V21_HOTFIX = True
except ImportError:
    HAS_V21_HOTFIX = False
    V21HotfixAdapter = None  # type: ignore

# Repository imports (will be implemented)
# from ..repositories.feedback_buffer_repository import FeedbackBufferRepository


class CodeIntentCompositionRoot(BaseCompositionRoot):
    """
    Composition root for assembling the code intent detection service.
    
    Extends BaseCompositionRoot to inherit common functionality (cache, decoder).
    Adds service-specific components (validators, ML models, rule engine).
    
    Usage:
        settings = DetectionSettings()
        root = CodeIntentCompositionRoot(settings)
        detection_service = root.create_detection_service()
        result = detection_service.detect("user input")
    """
    
    def __init__(
        self,
        settings: Optional[DetectionSettings] = None,
        enable_cache: bool = True,
        enable_normalization: bool = True,
    ):
        """
        Initialize composition root.
        
        Args:
            settings: Detection settings. If None, uses defaults from environment.
            enable_cache: If True, use cache adapter (from BaseCompositionRoot).
            enable_normalization: If True, use normalization (from BaseCompositionRoot).
        """
        # Initialize base composition root
        super().__init__(enable_cache=enable_cache, enable_normalization=enable_normalization)
        
        if settings is None:
            settings = DetectionSettings()
        
        self.settings = settings
        logger.info("CodeIntentCompositionRoot initialized (extends BaseCompositionRoot)")
    
    def create_benign_validator(self) -> BenignValidatorPort:
        """
        Create benign validator composite.
        
        Returns:
            BenignValidatorPort implementation (BenignValidatorComposite)
        """
        composite = BenignValidatorFactory.create_default()
        logger.info("BenignValidatorComposite created")
        return composite
    
    def create_intent_classifier(self) -> IntentClassifierPort:
        """
        Create intent classifier (ML model).
        
        Priority:
        1. V2.1 Hotfix (if enabled - recommended for production)
        2. Quantum-Inspired CNN (if enabled and model available)
        3. CodeBERT (fallback)
        4. Rule-based (ultimate fallback)
        
        Returns:
            IntentClassifierPort implementation
        """
        # Create rule-based fallback (always available)
        rule_based = RuleBasedIntentClassifier()
        
        # Try V2.1 Hotfix first (if enabled and available)
        use_v21_hotfix = getattr(self.settings, 'use_v21_hotfix', False)
        if use_v21_hotfix and HAS_V21_HOTFIX and V21HotfixAdapter:
            try:
                v1_path = getattr(self.settings, 'v1_model_path', None) or "models/code_intent_adversarial_v1/best_model.pt"
                v2_path = getattr(self.settings, 'v2_model_path', None) or "models/code_intent_adversarial_v2/best_model.pt"
                v2_threshold = getattr(self.settings, 'v21_threshold', 0.95)
                v1_fallback_threshold = getattr(self.settings, 'v21_fallback_threshold', 0.7)
                enable_whitelist = getattr(self.settings, 'v21_whitelist_enabled', True)
                
                logger.info(f"Creating V21HotfixAdapter with V1: {v1_path}, V2: {v2_path}")
                v21 = V21HotfixAdapter(
                    v1_model_path=v1_path,
                    v2_model_path=v2_path,
                    v2_threshold=v2_threshold,
                    v1_fallback_threshold=v1_fallback_threshold,
                    enable_whitelist=enable_whitelist,
                    use_gpu=True,
                    fallback_classifier=rule_based
                )
                if v21.is_available():
                    logger.info("✓ V21HotfixAdapter created and available (PRODUCTION READY)")
                    return v21
                else:
                    logger.warning("V21HotfixAdapter not available, falling back to Quantum/CodeBERT")
            except Exception as e:
                logger.warning(f"Failed to create V21HotfixAdapter: {e}, falling back to Quantum/CodeBERT")
        
        # Try Quantum-Inspired CNN (if enabled)
        if self.settings.use_quantum_model:
            quantum_path = self.settings.quantum_model_path
            if quantum_path and quantum_path.exists():
                logger.info(f"Creating QuantumCNNAdapter with model: {quantum_path}")
                quantum = QuantumCNNAdapter(
                    model_path=str(quantum_path),
                    threshold=self.settings.quantum_threshold,
                    enable_shadow=self.settings.shadow_mode,
                    use_gpu=True,  # RTX 3080Ti mit 16GB VRAM
                    fallback_classifier=rule_based
                )
                if quantum.is_available():
                    logger.info("✓ QuantumCNNAdapter created and available")
                    return quantum
                else:
                    logger.warning("QuantumCNNAdapter not available, falling back to CodeBERT")
            else:
                logger.warning(f"Quantum model path not found: {quantum_path}, using CodeBERT")
        
        # Try CodeBERT (fallback)
        if self.settings.use_codebert:
            try:
                logger.info(f"Creating CodeBERTAdapter with model: {self.settings.codebert_model_name}")
                codebert = CodeBERTAdapter(
                    model_name=self.settings.codebert_model_name,
                    threshold=0.5,
                    use_gpu=True,  # RTX 3080Ti mit 16GB VRAM
                    fallback_classifier=rule_based
                )
                if codebert.is_available():
                    logger.info("✓ CodeBERTAdapter created and available")
                    return codebert
                else:
                    logger.warning("CodeBERTAdapter not available, using rule-based fallback")
            except Exception as e:
                logger.warning(f"Failed to create CodeBERTAdapter: {e}, using rule-based fallback")
        
        # Ultimate fallback: Rule-based
        logger.info("Using RuleBasedIntentClassifier as fallback")
        return rule_based
    
    def create_rule_engine(self) -> Optional[RuleEnginePort]:
        """
        Create rule engine for pattern matching.
        
        Returns:
            RuleEnginePort implementation (SimpleRuleEngine als temporäre Lösung)
        """
        if not self.settings.enable_rule_engine:
            logger.info("Rule engine disabled in settings")
            return None
        
        try:
            from infrastructure.rule_engines.simple_rule_engine import SimpleRuleEngine
            engine = SimpleRuleEngine()
            logger.info("SimpleRuleEngine created")
            return engine
        except Exception as e:
            logger.warning(f"Failed to create rule engine: {e}")
            return None
    
    def create_feedback_repository(self) -> Optional[FeedbackRepositoryPort]:
        """
        Create feedback repository based on settings.
        
        Supported types:
        - "memory": In-memory buffer (default fallback)
        - "redis": Redis Cloud repository
        - "postgres": PostgreSQL repository
        - "hybrid": Redis + PostgreSQL (recommended for production)
        
        Returns:
            FeedbackRepositoryPort implementation
        """
        if not self.settings.enable_feedback_collection:
            logger.info("Feedback collection disabled in settings")
            from infrastructure.repositories.feedback_buffer_repository import NullFeedbackRepository
            return NullFeedbackRepository()
        
        repo_type = self.settings.feedback_repository_type.lower()
        
        # Hybrid Repository (Redis + PostgreSQL) - Recommended
        if repo_type == "hybrid":
            try:
                redis_repo = None
                postgres_repo = None
                
                # Try Redis
                try:
                    from infrastructure.repositories.redis_feedback_repository import RedisFeedbackRepository
                    redis_repo = RedisFeedbackRepository(
                        host=self.settings.redis_host,
                        port=self.settings.redis_port,
                        password=self.settings.redis_password,
                        username=self.settings.redis_username,
                        ttl_hours=self.settings.redis_ttl_hours,
                        ssl=self.settings.redis_ssl
                    )
                    logger.info("Redis Feedback Repository created")
                except Exception as e:
                    logger.warning(f"Redis repository creation failed: {e}")
                
                # Try PostgreSQL
                try:
                    from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
                    postgres_repo = PostgresFeedbackRepository(
                        connection_string=self.settings.postgres_connection_string
                    )
                    logger.info("PostgreSQL Feedback Repository created")
                except Exception as e:
                    logger.warning(f"PostgreSQL repository creation failed: {e}")
                
                # Create Hybrid (can work with any combination including memory)
                from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
                from infrastructure.repositories.feedback_buffer_repository import FeedbackBufferRepository
                
                # Always include memory as fallback
                memory_repo = FeedbackBufferRepository(max_size=self.settings.feedback_buffer_size)
                
                hybrid = HybridFeedbackRepository(
                    redis_repo=redis_repo,
                    postgres_repo=postgres_repo,
                    memory_repo=memory_repo
                )
                logger.info("Hybrid Feedback Repository created")
                return hybrid
            
            except Exception as e:
                logger.warning(f"Hybrid repository creation failed: {e}")
        
        # Redis-only Repository
        elif repo_type == "redis":
            try:
                from infrastructure.repositories.redis_feedback_repository import RedisFeedbackRepository
                repo = RedisFeedbackRepository(
                    host=self.settings.redis_host,
                    port=self.settings.redis_port,
                    password=self.settings.redis_password,
                    username=self.settings.redis_username,
                    ttl_hours=self.settings.redis_ttl_hours,
                    ssl=self.settings.redis_ssl
                )
                logger.info("Redis Feedback Repository created")
                return repo
            except Exception as e:
                logger.warning(f"Redis repository creation failed: {e}, falling back to memory")
        
        # PostgreSQL-only Repository
        elif repo_type == "postgres":
            try:
                from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
                repo = PostgresFeedbackRepository(
                    connection_string=self.settings.postgres_connection_string
                )
                logger.info("PostgreSQL Feedback Repository created")
                return repo
            except Exception as e:
                logger.warning(f"PostgreSQL repository creation failed: {e}, falling back to memory")
        
        # Memory Repository (default fallback)
        try:
            from infrastructure.repositories.feedback_buffer_repository import FeedbackBufferRepository
            repo = FeedbackBufferRepository(max_size=self.settings.feedback_buffer_size)
            logger.info(f"FeedbackBufferRepository created (max_size={self.settings.feedback_buffer_size})")
            return repo
        except Exception as e:
            logger.warning(f"Failed to create feedback repository: {e}")
            from infrastructure.repositories.feedback_buffer_repository import NullFeedbackRepository
            return NullFeedbackRepository()
    
    def create_detection_service(self):
        """
        Create detection service with all dependencies injected.
        
        This is the main factory method that composes the entire system.
        
        Returns:
            DetectionService implementation
        """
        # Create adapters
        benign_validator = self.create_benign_validator()
        intent_classifier = self.create_intent_classifier()
        rule_engine = self.create_rule_engine()
        feedback_repo = self.create_feedback_repository()
        
        # Create DetectionService with injected dependencies
        from application.services.detection_service_impl import DetectionServiceImpl
        
        service = DetectionServiceImpl(
            benign_validator=benign_validator,
            intent_classifier=intent_classifier,
            rule_engine=rule_engine,
            feedback_repository=feedback_repo,
            settings=self.settings
        )
        
        logger.info("DetectionService created successfully")
        return service
    
    def create_background_learner(self):
        """
        Create BackgroundLearner for online learning (optional).
        
        Requires:
        - enable_online_learning = True
        - enable_feedback_collection = True
        - A trained model (Quantum-Inspired CNN or CodeBERT)
        
        Returns:
            BackgroundLearner instance or None if not enabled/available
        """
        if not self.settings.enable_online_learning:
            logger.info("Online learning disabled in settings")
            return None
        
        if not self.settings.enable_feedback_collection:
            logger.warning("Online learning requires feedback collection to be enabled")
            return None
        
        try:
            from online_learner import BackgroundLearner
            import torch
            
            # Get feedback repository
            feedback_repo = self.create_feedback_repository()
            if not feedback_repo:
                logger.warning("No feedback repository available for online learning")
                return None
            
            # Try to get model and tokenizer from intent classifier
            intent_classifier = self.create_intent_classifier()
            
            # Check if classifier has model and tokenizer
            model = None
            tokenizer = None
            device = "cuda" if torch.cuda.is_available() else "cpu"
            
            # Try to extract model from QuantumCNNAdapter
            if hasattr(intent_classifier, 'model') and hasattr(intent_classifier, 'tokenizer'):
                model = intent_classifier.model
                tokenizer = intent_classifier.tokenizer
            elif hasattr(intent_classifier, '_model') and hasattr(intent_classifier, '_tokenizer'):
                model = intent_classifier._model
                tokenizer = intent_classifier._tokenizer
            elif hasattr(intent_classifier, 'quantum_model') and hasattr(intent_classifier, 'tokenizer'):
                model = intent_classifier.quantum_model
                tokenizer = intent_classifier.tokenizer
            
            if not model or not tokenizer:
                logger.warning(
                    "Model or tokenizer not available from intent classifier. "
                    "Online learning requires a trained model (Quantum-Inspired CNN or CodeBERT)."
                )
                return None
            
            # Create BackgroundLearner
            background_learner = BackgroundLearner(
                feedback_source=feedback_repo,
                model=model,
                tokenizer=tokenizer,
                batch_size=self.settings.online_learning_batch_size,
                update_interval=self.settings.online_learning_update_interval,
                min_samples=self.settings.online_learning_min_samples,
                learning_rate=self.settings.online_learning_rate,
                device=device
            )
            
            logger.info("BackgroundLearner created successfully")
            return background_learner
            
        except ImportError as e:
            logger.warning(f"Failed to import BackgroundLearner: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create BackgroundLearner: {e}", exc_info=True)
            return None


def create_default_detection_service(
    settings: Optional[DetectionSettings] = None
):
    """
    Convenience function to create a detection service with default configuration.
    
    Args:
        settings: Optional detection settings. If None, uses defaults from environment.
    
    Returns:
        DetectionService instance
    """
    root = CodeIntentCompositionRoot(settings=settings)
    return root.create_detection_service()

