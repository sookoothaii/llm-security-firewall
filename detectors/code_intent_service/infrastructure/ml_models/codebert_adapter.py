"""
CodeBERT Adapter - IntentClassifierPort Implementation
=======================================================

Adapter für CodeBERT Model (microsoft/codebert-base).
Nutzt GPU wenn verfügbar (CUDA).

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
import sys
from pathlib import Path
from typing import Optional

# Add project root src directory to path for imports (wie in main.py)
service_dir = Path(__file__).parent.parent.parent
project_root = service_dir.parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from llm_firewall.core.ports.code_intent import IntentClassifierPort, ClassificationResult
from .circuit_breaker import SimpleCircuitBreaker

logger = logging.getLogger(__name__)

# Try to import transformers
try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    HAS_TRANSFORMERS = True
    # Suppress Dynamo errors if Triton is not available (fallback to eager mode)
    try:
        import torch._dynamo
        torch._dynamo.config.suppress_errors = True
        logger.debug("torch._dynamo error suppression enabled (Triton fallback)")
    except Exception:
        pass  # Dynamo might not be available in older PyTorch versions
except ImportError:
    HAS_TRANSFORMERS = False
    logger.warning("transformers not available. CodeBERTAdapter will use fallback.")


class CodeBERTAdapter(IntentClassifierPort):
    """
    Adapter für CodeBERT Model.
    
    Features:
    - GPU acceleration (CUDA) wenn verfügbar
    - Lazy loading
    - Circuit breaker protection
    - Fallback to rule-based classifier
    """
    
    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        threshold: float = 0.5,
        use_gpu: bool = True,
        fallback_classifier: Optional[IntentClassifierPort] = None
    ):
        """
        Initialize CodeBERT Adapter.
        
        Args:
            model_name: HuggingFace model name
            threshold: Classification threshold (0.0-1.0)
            use_gpu: Use GPU if available (RTX 3080Ti mit 16GB VRAM)
            fallback_classifier: Fallback classifier if model fails
        """
        self.model_name = model_name
        self.threshold = threshold
        self.use_gpu = use_gpu
        self.fallback_classifier = fallback_classifier
        
        # Detect device with enhanced diagnostics
        if use_gpu and HAS_TRANSFORMERS:
            # Enhanced GPU detection with diagnostics
            try:
                cuda_available = torch.cuda.is_available()
                if cuda_available:
                    # Force GPU initialization
                    torch.cuda.init()
                    device_count = torch.cuda.device_count()
                    if device_count > 0:
                        self.device = torch.device("cuda:0")
                        self.gpu_name = torch.cuda.get_device_name(0)
                        self.gpu_memory = torch.cuda.get_device_properties(0).total_memory / (1024**3)  # GB
                        logger.info(f"✓ GPU detected: {self.gpu_name} ({self.gpu_memory:.1f}GB VRAM, {device_count} device(s))")
                    else:
                        raise RuntimeError("CUDA available but no devices found")
                else:
                    # Diagnose why CUDA is not available
                    logger.warning("GPU requested but CUDA not available. Diagnostics:")
                    logger.warning(f"  - PyTorch version: {torch.__version__}")
                    logger.warning(f"  - CUDA built: {torch.version.cuda if hasattr(torch.version, 'cuda') else 'N/A'}")
                    logger.warning(f"  - cuDNN version: {torch.backends.cudnn.version() if torch.backends.cudnn.is_available() else 'N/A'}")
                    raise RuntimeError("CUDA not available")
            except Exception as e:
                logger.error(f"GPU initialization failed: {e}")
                logger.warning("Falling back to CPU")
                self.device = torch.device("cpu")
                self.gpu_name = None
                self.gpu_memory = 0
        else:
            self.device = torch.device("cpu")
            self.gpu_name = None
            self.gpu_memory = 0
            if use_gpu and not HAS_TRANSFORMERS:
                logger.warning("GPU requested but transformers/PyTorch not available, using CPU")
            elif use_gpu:
                logger.warning("GPU requested but not available, using CPU")
        
        # Lazy-loaded model
        self._model = None
        self._tokenizer = None
        self._model_loaded = False
        
        # Circuit breaker
        self.circuit_breaker = SimpleCircuitBreaker(
            name="codebert",
            failure_threshold=3,
            recovery_timeout=30.0,
            on_state_change=self._on_circuit_state_change
        )
        
        logger.info(
            f"CodeBERTAdapter initialized "
            f"(model={model_name}, device={self.device}, threshold={threshold})"
        )
    
    def _on_circuit_state_change(self, name: str, state):
        """Callback when circuit breaker state changes."""
        logger.info(f"Circuit breaker {name} state changed to {state.value}")
    
    def _load_model(self) -> bool:
        """
        Lazy load CodeBERT model.
        
        Returns:
            True if model loaded successfully, False otherwise
        """
        if self._model_loaded:
            return True
        
        if not HAS_TRANSFORMERS:
            logger.warning("transformers not available, cannot load CodeBERT")
            return False
        
        try:
            logger.info(f"Loading CodeBERT model: {self.model_name} on {self.device}")
            
            # Load tokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Load model for binary classification
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                num_labels=2  # 0: benign/question, 1: execution_request
            )
            
            # Move to GPU if available
            self._model.to(self.device)
            self._model.eval()
            
            # NOTE: torch.compile() deaktiviert für selbst trainierte Modelle
            # Die Modelle funktionieren perfekt ohne Kompilierung
            # torch.compile() würde Triton benötigen und ist für unsere Modelle nicht notwendig
            # GPU-Beschleunigung funktioniert auch ohne torch.compile()
            
            self._model_loaded = True
            
            # Log GPU memory usage
            if self.device.type == "cuda":
                memory_allocated = torch.cuda.memory_allocated(0) / (1024**3)
                memory_reserved = torch.cuda.memory_reserved(0) / (1024**3)
                logger.info(
                    f"✓ CodeBERT loaded on GPU: "
                    f"{memory_allocated:.2f}GB allocated, {memory_reserved:.2f}GB reserved"
                )
            else:
                logger.info("✓ CodeBERT loaded on CPU")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load CodeBERT model: {e}", exc_info=True)
            return False
    
    def is_available(self) -> bool:
        """
        Check if classifier is available (model loaded).
        
        Returns:
            True if model is loaded and ready, False otherwise
        """
        if not self._model_loaded:
            # Try to load model
            return self._load_model()
        return self._model is not None and self._tokenizer is not None
    
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify text intent using CodeBERT.
        
        Args:
            text: Text to classify
            
        Returns:
            ClassificationResult with score, method, confidence
        """
        # Check circuit breaker
        if not self.circuit_breaker.allow_request():
            logger.warning("Circuit breaker OPEN, using fallback")
            if self.fallback_classifier:
                return self.fallback_classifier.classify(text)
            return ClassificationResult(
                score=0.5,
                method="circuit_breaker_fallback",
                confidence=0.0,
                is_execution_request=False
            )
        
        # Try to load model if not loaded
        if not self.is_available():
            logger.warning("Model not available, using fallback")
            self.circuit_breaker.on_failure()
            if self.fallback_classifier:
                return self.fallback_classifier.classify(text)
            return ClassificationResult(
                score=0.5,
                method="model_unavailable",
                confidence=0.0,
                is_execution_request=False
            )
        
        try:
            # Tokenize
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(self.device)
            
            # Infer with GPU acceleration
            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
            
            # Interpret results
            # Label 0: benign/question/documentation
            # Label 1: execution_request/malicious
            prob_execution = probs[0][1].item()
            prob_benign = probs[0][0].item()
            
            # Score is probability of execution request
            score = prob_execution
            
            # Determine if execution request
            is_execution_request = score >= self.threshold
            
            # Confidence: distance from decision boundary
            confidence = abs(score - 0.5) * 2.0  # 0.0 at 0.5, 1.0 at extremes
            
            self.circuit_breaker.on_success()
            
            return ClassificationResult(
                score=score,
                method="codebert",
                confidence=confidence,
                is_execution_request=is_execution_request,
                metadata={
                    "threshold": self.threshold,
                    "device": str(self.device),
                    "gpu_name": self.gpu_name,
                    "prob_benign": prob_benign,
                    "prob_execution": prob_execution,
                    "circuit_state": self.circuit_breaker.state.value
                }
            )
            
        except Exception as e:
            logger.error(f"CodeBERT classification failed: {e}", exc_info=True)
            self.circuit_breaker.on_failure(e)
            
            # Fallback
            if self.fallback_classifier:
                return self.fallback_classifier.classify(text)
            
            # Ultimate fallback
            return ClassificationResult(
                score=0.5,
                method="codebert_error",
                confidence=0.0,
                is_execution_request=False,
                metadata={"error": str(e)}
            )

