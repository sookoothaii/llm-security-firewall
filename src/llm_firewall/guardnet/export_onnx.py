"""
GuardNet ONNX Export

Export trained FirewallNet model to ONNX format for production deployment.
Supports dynamic batch and sequence dimensions for flexible inference.

Optional INT8 quantization via onnxruntime for reduced model size and faster inference.

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from __future__ import annotations
import torch
from pathlib import Path
from typing import Optional

from llm_firewall.guardnet.model import FirewallNet

try:
    import onnx
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False


def export_onnx(
    model: FirewallNet,
    onnx_path: str,
    seq_len: int = 256,
    feat_dim: int = 64,
    opset_version: int = 13,
    check_model: bool = True,
    quantize_int8: bool = False,
) -> None:
    """
    Export FirewallNet model to ONNX format.
    
    Args:
        model: Trained FirewallNet model (in eval mode)
        onnx_path: Output path for ONNX model (e.g., "guardnet.onnx")
        seq_len: Sequence length for dummy input (only affects export, inference can use any length due to dynamic axes)
        feat_dim: Feature dimension (must match model's feat_dim)
        opset_version: ONNX opset version (default: 13, compatible with most runtimes)
        check_model: Whether to validate ONNX model after export
        quantize_int8: Whether to apply dynamic INT8 quantization (requires onnxruntime)
    
    Raises:
        ImportError: If onnx package not installed
        RuntimeError: If model export or validation fails
    """
    if not HAS_ONNX:
        raise ImportError(
            "onnx package required for export. "
            "Install with: pip install onnx"
        )
    
    model.eval()
    
    # Create dummy inputs
    batch_size = 1
    input_ids = torch.randint(0, 1000, (batch_size, seq_len), dtype=torch.long)
    attention_mask = torch.ones_like(input_ids)
    feat_vec = torch.zeros(batch_size, feat_dim, dtype=torch.float32)
    
    # Export to ONNX
    print(f"Exporting model to {onnx_path}...")
    
    torch.onnx.export(
        model,
        (input_ids, attention_mask, feat_vec),
        onnx_path,
        input_names=["input_ids", "attention_mask", "feat_vec"],
        output_names=["policy", "intent", "actionability", "obfuscation"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "seq_len"},
            "attention_mask": {0: "batch_size", 1: "seq_len"},
            "feat_vec": {0: "batch_size"},
            "policy": {0: "batch_size"},
            "intent": {0: "batch_size"},
            "actionability": {0: "batch_size"},
            "obfuscation": {0: "batch_size"},
        },
        opset_version=opset_version,
        do_constant_folding=True,
        export_params=True,
    )
    
    print(f"✓ Model exported to {onnx_path}")
    
    # Validate ONNX model
    if check_model:
        print("Validating ONNX model...")
        onnx_model = onnx.load(onnx_path)
        onnx.checker.check_model(onnx_model)
        print("✓ ONNX model is valid")
    
    # Optional INT8 quantization
    if quantize_int8:
        quantize_onnx_int8(onnx_path)


def quantize_onnx_int8(onnx_path: str) -> None:
    """
    Apply dynamic INT8 quantization to ONNX model.
    
    Reduces model size by ~4x and improves inference speed on CPU.
    Quality impact: minimal for most NLP tasks.
    
    Args:
        onnx_path: Path to ONNX model (will be overwritten with quantized version)
    
    Raises:
        ImportError: If onnxruntime not installed
    """
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
    except ImportError:
        raise ImportError(
            "onnxruntime required for quantization. "
            "Install with: pip install onnxruntime"
        )
    
    print(f"Applying INT8 quantization to {onnx_path}...")
    
    quantized_path = onnx_path.replace(".onnx", "_int8.onnx")
    
    quantize_dynamic(
        model_input=onnx_path,
        model_output=quantized_path,
        weight_type=QuantType.QInt8,
    )
    
    # Get file sizes for comparison
    orig_size = Path(onnx_path).stat().st_size / (1024 * 1024)  # MB
    quant_size = Path(quantized_path).stat().st_size / (1024 * 1024)  # MB
    
    print(f"✓ Quantized model saved to {quantized_path}")
    print(f"  Original size: {orig_size:.2f} MB")
    print(f"  Quantized size: {quant_size:.2f} MB")
    print(f"  Compression: {orig_size / quant_size:.2f}x")


def load_onnx_session(onnx_path: str, providers: Optional[list[str]] = None):
    """
    Load ONNX model as InferenceSession for production inference.
    
    Args:
        onnx_path: Path to ONNX model
        providers: Execution providers (default: ["CPUExecutionProvider"])
                   Options: ["CUDAExecutionProvider", "CPUExecutionProvider"]
    
    Returns:
        onnxruntime.InferenceSession
    
    Example:
        ```python
        session = load_onnx_session("guardnet.onnx")
        
        # Prepare inputs
        inputs = {
            "input_ids": input_ids_np,  # numpy array (B, T)
            "attention_mask": mask_np,  # numpy array (B, T)
            "feat_vec": feats_np,       # numpy array (B, feat_dim)
        }
        
        # Run inference
        outputs = session.run(None, inputs)
        policy_logits, intent_logits, action_logits, obf_logits = outputs
        ```
    """
    try:
        import onnxruntime as ort
    except ImportError:
        raise ImportError(
            "onnxruntime required for inference. "
            "Install with: pip install onnxruntime"
        )
    
    if providers is None:
        providers = ["CPUExecutionProvider"]
    
    session = ort.InferenceSession(onnx_path, providers=providers)
    
    print(f"✓ ONNX model loaded from {onnx_path}")
    print(f"  Providers: {providers}")
    print(f"  Input names: {[inp.name for inp in session.get_inputs()]}")
    print(f"  Output names: {[out.name for out in session.get_outputs()]}")
    
    return session

