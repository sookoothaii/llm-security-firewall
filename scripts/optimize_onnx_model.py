#!/usr/bin/env python3
"""
ONNX Model Optimization Script
==============================

Optimizes the exported ONNX model for inference:
- Removes training nodes
- Fuses operators
- Optimizes graph structure
"""

import sys
from pathlib import Path

try:
    import onnx
    from onnxruntime.transformers import optimizer
    from onnxruntime.transformers.fusion_options import FusionOptions
except ImportError:
    try:
        # Alternative: Use onnx directly
        import onnx
        from onnx import helper, optimizer as onnx_optimizer

        USE_ONNX_DIRECT = True
    except ImportError:
        print("ERROR: onnx not available")
        print("Try: pip install onnx")
        sys.exit(1)
    else:
        USE_ONNX_DIRECT = True
else:
    USE_ONNX_DIRECT = False

# Paths
project_root = Path(__file__).parent.parent
model_dir = project_root / "models" / "onnx"
input_model = model_dir / "all-MiniLM-L6-v2.onnx"
output_model = model_dir / "all-MiniLM-L6-v2_optimized.onnx"

if not input_model.exists():
    print(f"ERROR: Input model not found at {input_model}")
    sys.exit(1)

print("=" * 70)
print("ONNX MODEL OPTIMIZATION")
print("=" * 70)
print(f"\nInput model: {input_model}")
print(f"Output model: {output_model}")

# Get file sizes
input_size_mb = input_model.stat().st_size / 1024 / 1024
print(f"\nInput model size: {input_size_mb:.2f} MB")

try:
    print("\nOptimizing model...")
    print("This may take a few minutes...")

    if not USE_ONNX_DIRECT:
        # Use onnxruntime.transformers optimizer (if available)
        print("Using onnxruntime.transformers optimizer...")
        fusion_options = FusionOptions("bert")
        fusion_options.enable_attention = True
        fusion_options.enable_skip_layer_norm = True
        fusion_options.enable_embed_layer_norm = True
        fusion_options.enable_bias_skip_layer_norm = True
        fusion_options.enable_bias_gelu = True

        optimized_model = optimizer.optimize_model(
            str(input_model),
            model_type="bert",
            num_heads=12,
            hidden_size=384,
            optimization_options=fusion_options,
        )

        # Save optimized model
        optimized_model.save_model_to_file(str(output_model))
    else:
        # Use onnx optimizer directly
        print("Using ONNX optimizer...")
        model = onnx.load(str(input_model))

        # Apply optimizations
        print("Applying graph optimizations...")
        optimized_model = onnx_optimizer.optimize_model(
            model,
            passes=[
                "eliminate_nop_transpose",
                "eliminate_nop_pad",
                "fuse_matmul_add_bias_into_gemm",
                "fuse_bn_into_conv",
                "fuse_consecutive_concats",
                "fuse_consecutive_log_softmax",
                "fuse_consecutive_reduce_unsqueeze",
                "fuse_consecutive_squeezes",
                "fuse_transpose_into_gemm",
            ],
        )

        # Save optimized model
        onnx.save(optimized_model, str(output_model))

    # Get output size
    output_size_mb = output_model.stat().st_size / 1024 / 1024
    reduction = (
        ((input_size_mb - output_size_mb) / input_size_mb * 100)
        if input_size_mb > 0
        else 0
    )

    print("\n" + "=" * 70)
    print("OPTIMIZATION COMPLETE")
    print("=" * 70)
    print(f"Input size: {input_size_mb:.2f} MB")
    print(f"Output size: {output_size_mb:.2f} MB")
    print(f"Reduction: {reduction:.1f}%")
    print(f"\nOptimized model saved to: {output_model}")

except Exception as e:
    print(f"\nERROR during optimization: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
