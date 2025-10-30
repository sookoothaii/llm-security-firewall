# -*- coding: utf-8 -*-
"""
Minimal ONNX builder for multinomial logistic regression with softmax.
Input:  X [N, D] float32  (name: 'features')
Params: W [K, D] float32, b [K] float32
Output: proba [N, K] float32 (softmax over classes)  (name: 'proba')

Creator: Joerg Bollwahn
License: MIT
"""
from __future__ import annotations

import pathlib
from typing import Union

import numpy as np
import onnx
from onnx import TensorProto, helper


def build_onnx(W: np.ndarray, b: np.ndarray, out_path: Union[str, pathlib.Path], input_dim: int | None = None):
    K, D = W.shape
    if input_dim is None:
        input_dim = D
    assert D == input_dim

    features = helper.make_tensor_value_info("features", TensorProto.FLOAT, [None, D])
    proba     = helper.make_tensor_value_info("proba", TensorProto.FLOAT, [None, K])

    helper.make_tensor("W", TensorProto.FLOAT, [K, D], W.flatten().tolist())
    b_init = helper.make_tensor("b", TensorProto.FLOAT, [K], b.flatten().tolist())

    # MatMul: X [N,D] @ W^T [D,K] -> [N,K]
    # ONNX MatMul is (A[NxD] x B[DxK]). We'll transpose W at runtime by precomputing Wt.
    Wt = W.T.astype(np.float32)
    Wt_init = helper.make_tensor("Wt", TensorProto.FLOAT, [D, K], Wt.flatten().tolist())

    mm = helper.make_node("MatMul", ["features", "Wt"], ["logits"], name="matmul")
    add = helper.make_node("Add", ["logits", "b"], ["logits_b"], name="add_bias")
    sm  = helper.make_node("Softmax", ["logits_b"], ["proba"], name="softmax", axis=1)

    graph = helper.make_graph(
        nodes=[mm, add, sm],
        name="logreg_softmax",
        inputs=[features],
        outputs=[proba],
        initializer=[Wt_init, b_init],
    )
    # Use IR version 9 + Opset 17 for compatibility with ONNX Runtime 1.20.1 (max IR 10, max opset 21)
    model = helper.make_model(
        graph,
        producer_name="hak_gal_firewall",
        ir_version=9,
        opset_imports=[helper.make_opsetid("", 17)]  # Opset 17 stable, widely supported
    )
    onnx.checker.check_model(model)
    onnx.save(model, str(out_path))

