"""
Quantum CNN Adapter - IntentClassifierPort Implementation
==========================================================

Adapter für Quantum-Inspired CNN Model.
Nutzt bestehende quantum_model_loader Infrastruktur.

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

# Try to import ML dependencies
try:
    import torch
    HAS_TORCH = True
    # Suppress Dynamo errors if Triton is not available (fallback to eager mode)
    try:
        import torch._dynamo
        torch._dynamo.config.suppress_errors = True
        logger.debug("torch._dynamo error suppression enabled (Triton fallback)")
    except Exception:
        pass  # Dynamo might not be available in older PyTorch versions
except ImportError:
    HAS_TORCH = False
    logger.warning("PyTorch not available. QuantumCNNAdapter will use fallback.")


class QuantumCNNAdapter(IntentClassifierPort):
    """
    Adapter für Quantum-Inspired CNN Model.
    
    Features:
    - Lazy loading (model loaded on first use)
    - Circuit breaker protection
    - Fallback to rule-based classifier
    - Shadow mode support (optional)
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = 0.60,
        enable_shadow: bool = False,
        use_gpu: bool = True,
        fallback_classifier: Optional[IntentClassifierPort] = None
    ):
        """
        Initialize Quantum CNN Adapter.
        
        Args:
            model_path: Path to trained model checkpoint
            threshold: Classification threshold (0.0-1.0)
            enable_shadow: If True, run in shadow mode (log only, don't block)
            fallback_classifier: Fallback classifier if model fails
        """
        self.model_path = model_path
        self.threshold = threshold
        self.shadow_mode = enable_shadow
        self.use_gpu = use_gpu
        self.fallback_classifier = fallback_classifier
        
        # Detect device (RTX 3080Ti mit 16GB VRAM)
        if use_gpu and HAS_TORCH:
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
            if use_gpu and not HAS_TORCH:
                logger.warning("GPU requested but PyTorch not available, using CPU")
            elif use_gpu:
                logger.warning("GPU requested but not available, using CPU")
        
        # Lazy-loaded model
        self._model = None
        self._tokenizer = None
        self._model_loaded = False
        
        # Circuit breaker
        self.circuit_breaker = SimpleCircuitBreaker(
            name="quantum_cnn",
            failure_threshold=3,
            recovery_timeout=30.0,
            on_state_change=self._on_circuit_state_change
        )
        
        logger.info(
            f"QuantumCNNAdapter initialized "
            f"(model_path={model_path}, threshold={threshold}, shadow={enable_shadow})"
        )
    
    def _on_circuit_state_change(self, name: str, state):
        """Callback when circuit breaker state changes."""
        logger.info(f"Circuit breaker {name} state changed to {state.value}")
    
    def _load_model(self) -> bool:
        """
        Lazy load Quantum-Inspired model.
        
        Returns:
            True if model loaded successfully, False otherwise
        """
        if self._model_loaded:
            return True
        
        if not HAS_TORCH:
            logger.warning("PyTorch not available, cannot load Quantum model")
            return False
        
        try:
            # Import quantum model loader
            from quantum_model_loader import load_quantum_inspired_model
            
            # Determine model path
            if self.model_path and Path(self.model_path).exists():
                model_path = self.model_path
            else:
                # Try default path
                default_path = Path(__file__).parent.parent.parent.parent / "models" / "quantum_cnn_trained" / "best_model.pt"
                if default_path.exists():
                    model_path = str(default_path)
                else:
                    logger.warning(f"Model not found at {self.model_path or default_path}")
                    return False
            
            logger.info(f"Loading Quantum-Inspired model from {model_path}")
            self._model, self._tokenizer = load_quantum_inspired_model(
                vocab_size=10000,
                model_path=model_path
            )
            
            if self._model is None:
                logger.error("Failed to load Quantum model (returned None)")
                return False
            
            # Move to GPU if available
            self._model.to(self.device)
            self._model.eval()
            
            # NOTE: torch.compile() deaktiviert für selbst trainierte Modelle
            # Die Modelle funktionieren perfekt ohne Kompilierung
            # torch.compile() würde Triton benötigen und ist für unsere Modelle nicht notwendig
            
            self._model_loaded = True
            
            # Log GPU memory usage
            if self.device.type == "cuda":
                memory_allocated = torch.cuda.memory_allocated(0) / (1024**3)
                memory_reserved = torch.cuda.memory_reserved(0) / (1024**3)
                logger.info(
                    f"✓ Quantum-Inspired CNN loaded on GPU: "
                    f"{memory_allocated:.2f}GB allocated, {memory_reserved:.2f}GB reserved"
                )
            else:
                logger.info("✓ Quantum-Inspired CNN loaded on CPU")
            
            return True
            
        except ImportError as e:
            logger.error(f"Failed to import quantum_model_loader: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load Quantum-Inspired model: {e}", exc_info=True)
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
        Classify text intent using Quantum-Inspired CNN.
        
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
            # Ultimate fallback: return safe default
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
            if self._tokenizer is None:
                raise ValueError("Tokenizer not initialized")
            
            # Use tokenizer (SimpleTokenizer interface)
            tokenized = self._tokenizer(text, return_tensors="pt", max_length=512)
            input_ids = tokenized["input_ids"].to(self.device)
            
            # Infer with GPU acceleration
            with torch.no_grad():
                outputs = self._model(input_ids)
                
                # Extract score (assuming binary classification)
                if hasattr(outputs, 'logits'):
                    logits = outputs.logits
                    probs = torch.softmax(logits, dim=-1)
                    # Assuming: [prob_benign, prob_malicious]
                    score = probs[0][1].item()  # Probability of malicious/execution request
                elif hasattr(outputs, 'score'):
                    score = outputs.score.item()
                else:
                    # Fallback: use raw output
                    score = float(outputs[0][0].item()) if isinstance(outputs, torch.Tensor) else 0.5
            
            # Normalize score to 0.0-1.0
            score = max(0.0, min(1.0, score))
            
            # Determine if execution request
            is_execution_request = score >= self.threshold
            
            # Calculate confidence (distance from threshold)
            confidence = abs(score - 0.5) * 2.0  # 0.0 at 0.5, 1.0 at extremes
            
            self.circuit_breaker.on_success()
            
            return ClassificationResult(
                score=score,
                method="quantum_cnn",
                confidence=confidence,
                is_execution_request=is_execution_request,
                metadata={
                    "threshold": self.threshold,
                    "shadow_mode": self.shadow_mode,
                    "device": str(self.device),
                    "gpu_name": self.gpu_name,
                    "circuit_state": self.circuit_breaker.state.value
                }
            )
            
        except Exception as e:
            logger.error(f"Quantum CNN classification failed: {e}", exc_info=True)
            self.circuit_breaker.on_failure(e)
            
            # Fallback
            if self.fallback_classifier:
                return self.fallback_classifier.classify(text)
            
            # Ultimate fallback
            return ClassificationResult(
                score=0.5,
                method="quantum_cnn_error",
                confidence=0.0,
                is_execution_request=False,
                metadata={"error": str(e)}
            )

