"""
GPU Enforcement Module
======================

Ensures GPU is always used unless explicitly overridden by user.
Raises errors if GPU is not available and user hasn't confirmed CPU usage.

Usage:
    from llm_firewall.core.gpu_enforcement import require_gpu, get_device
    
    device = get_device()  # Returns "cuda" if available, raises error otherwise
    device = get_device(allow_cpu=True)  # Returns "cpu" if GPU not available
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# CPU is COMPLETELY DISABLED - no flags needed


def set_cpu_allowed(allowed: bool = True):
    """
    DEPRECATED: CPU usage is COMPLETELY DISABLED.
    
    This function does nothing - CPU cannot be enabled.
    
    Args:
        allowed: IGNORED - CPU is always disabled
    """
    logger.error("set_cpu_allowed() called but CPU is COMPLETELY DISABLED")
    logger.error("GPU is required - CPU fallback is not available")


def is_cpu_allowed() -> bool:
    """Check if CPU usage is allowed. Always returns False - CPU is disabled."""
    return False


def require_gpu() -> str:
    """
    Require GPU device. CPU is COMPLETELY DISABLED.
    
    Returns:
        "cuda" if GPU is available
        
    Raises:
        RuntimeError: If GPU not available (CPU is not allowed)
    """
    import torch
    
    # Check if CUDA is available
    if not torch.cuda.is_available():
        # Show detailed error message
        error_msg = (
            "\n" + "="*80 + "\n"
            "FATAL ERROR: GPU is REQUIRED but not available!\n"
            "="*80 + "\n"
            "CPU usage is COMPLETELY DISABLED for security and performance reasons.\n"
            "\n"
            "CUDA is not available on this system.\n"
            "\n"
            "To enable GPU:\n"
            "  1. Install CUDA-compatible PyTorch:\n"
            "     pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118\n"
            "  2. Ensure NVIDIA drivers are installed and up-to-date\n"
            "  3. Verify GPU availability:\n"
            "     python -c 'import torch; print(torch.cuda.is_available())'\n"
            "  4. Check GPU:\n"
            "     nvidia-smi\n"
            "\n"
            "CPU FALLBACK IS DISABLED FOR:\n"
            "  - Security: GPU provides better ML model performance\n"
            "  - Performance: CPU is too slow for production use\n"
            "  - Consistency: All benchmarks must run on GPU\n"
            "="*80 + "\n"
        )
        raise RuntimeError(error_msg)
    
    # GPU is available - return cuda
    return "cuda"


def get_device(allow_cpu: bool = False) -> str:
    """
    Get device to use. CPU is COMPLETELY DISABLED.
    
    Args:
        allow_cpu: IGNORED - CPU is always disabled
        
    Returns:
        "cuda" if available
        
    Raises:
        RuntimeError: If GPU not available (CPU is not allowed)
    """
    # CPU is completely disabled - ignore allow_cpu parameter
    return require_gpu()


def check_gpu_availability() -> tuple[bool, Optional[str]]:
    """
    Check GPU availability and return status.
    
    Returns:
        Tuple of (is_available, device_name_or_error)
    """
    import torch
    
    if torch.cuda.is_available():
        try:
            device_name = torch.cuda.get_device_name(0)
            return True, device_name
        except Exception as e:
            return False, str(e)
    else:
        return False, "CUDA not available"


def log_device_info():
    """Log current device configuration. CPU is COMPLETELY DISABLED."""
    import torch
    
    logger.info("="*60)
    logger.info("GPU CONFIGURATION (CPU DISABLED)")
    logger.info("="*60)
    logger.info(f"TORCH_DEVICE env: {os.environ.get('TORCH_DEVICE', 'not set')} (CPU ignored)")
    logger.info(f"CUDA_VISIBLE_DEVICES: {os.environ.get('CUDA_VISIBLE_DEVICES', 'not set')}")
    logger.info(f"torch.cuda.is_available(): {torch.cuda.is_available()}")
    
    if torch.cuda.is_available():
        logger.info(f"CUDA Device Count: {torch.cuda.device_count()}")
        logger.info(f"Current Device: {torch.cuda.current_device()}")
        logger.info(f"Device Name: {torch.cuda.get_device_name(0)}")
        logger.info(f"CUDA Version: {torch.version.cuda}")
        logger.info("[OK] GPU is available and will be used")
    else:
        logger.error("="*60)
        logger.error("FATAL: CUDA is NOT available")
        logger.error("CPU usage is COMPLETELY DISABLED")
        logger.error("System will raise error - GPU is required")
        logger.error("="*60)
    
    logger.info("="*60)

