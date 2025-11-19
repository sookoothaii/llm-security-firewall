"""Export Layer 15 Crisis Detection Model to ONNX.

ONNX opset 17, dynamic axes (batch, seq), CPUExecutionProvider
Output: models/selfharm_abuse_multilingual.onnx

Credit: GPT-5 collaboration 2025-11-04
"""

import argparse
import os

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import onnx


def main():
    """Export trained model to ONNX format."""
    ap = argparse.ArgumentParser()
    ap.add_argument('--model_dir', default='models/layer15_crisis', help='Model directory')
    ap.add_argument('--onnx_out', default='models/selfharm_abuse_multilingual.onnx', help='ONNX output path')
    ap.add_argument('--opset', type=int, default=17, help='ONNX opset version')
    args = ap.parse_args()
    
    print(f"[INFO] Loading model from {args.model_dir}...")
    tok = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    model.eval()
    
    # Dummy input
    max_len = 256
    print(f"[INFO] Creating dummy input (max_len={max_len})...")
    dummy = tok("test", return_tensors='pt', padding='max_length', truncation=True, max_length=max_len)
    
    # Export configuration
    input_names = ["input_ids", "attention_mask"]
    output_names = ["logits"]
    dynamic_axes = {
        "input_ids": {0: "batch", 1: "seq"},
        "attention_mask": {0: "batch", 1: "seq"},
        "logits": {0: "batch"}
    }
    
    print(f"[INFO] Exporting to ONNX (opset {args.opset})...")
    torch.onnx.export(
        model,
        (dummy['input_ids'], dummy['attention_mask']),
        args.onnx_out,
        input_names=input_names,
        output_names=output_names,
        dynamic_axes=dynamic_axes,
        do_constant_folding=True,
        opset_version=args.opset
    )
    
    # Validate
    print("[INFO] Validating ONNX model...")
    onnx_model = onnx.load(args.onnx_out)
    onnx.checker.check_model(onnx_model)
    
    # Get model size
    size_mb = os.path.getsize(args.onnx_out) / (1024 * 1024)
    
    print(f"\n[OK] Exported: {args.onnx_out}")
    print(f"[OK] Size: {size_mb:.1f} MB")
    print(f"[OK] Opset: {args.opset}")
    print("[OK] Dynamic axes: batch, seq")
    print("\n[INFO] Model ready for integration with crisis.py")
    print("[INFO] Place in models/ directory with thresholds.json")


if __name__ == '__main__':
    main()










