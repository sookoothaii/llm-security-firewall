"""
Test GuardNet Model Shapes and Forward Pass

Validates that model outputs have correct shapes for all tasks.
Does not require trained weights - only tests architecture.

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pytest

# Optional dependency - skip tests if torch not available
try:
    import torch

    from llm_firewall.guardnet.model import FeatureMLP, FirewallNet

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

pytestmark = pytest.mark.skipif(
    not HAS_TORCH, reason="torch not installed (optional dependency)"
)


def test_feature_mlp_shape():
    """Test FeatureMLP output shape."""
    in_dim = 64
    hidden_dim = 128
    batch_size = 4

    mlp = FeatureMLP(in_dim, hidden_dim)
    x = torch.randn(batch_size, in_dim)

    out = mlp(x)

    assert out.shape == (batch_size, hidden_dim), (
        f"Expected shape ({batch_size}, {hidden_dim}), got {out.shape}"
    )


def test_firewallnet_forward_shapes():
    """Test FirewallNet forward pass output shapes."""
    encoder_name = "prajjwal1/bert-tiny"
    feat_dim = 64
    obf_k = 6

    model = FirewallNet(encoder_name=encoder_name, feat_dim=feat_dim, obf_k=obf_k)

    batch_size = 2
    seq_len = 32

    # Create dummy inputs
    input_ids = torch.randint(0, 1000, (batch_size, seq_len))
    attention_mask = torch.ones_like(input_ids)
    feat_vec = torch.randn(batch_size, feat_dim)

    # Forward pass
    model.eval()
    with torch.no_grad():
        outputs = model(input_ids, attention_mask, feat_vec)

    # Validate output shapes
    assert outputs["policy"].shape == (batch_size, 3), (
        f"Policy shape mismatch: {outputs['policy'].shape}"
    )
    assert outputs["intent"].shape == (batch_size, 5), (
        f"Intent shape mismatch: {outputs['intent'].shape}"
    )
    assert outputs["actionability"].shape == (batch_size, 3), (
        f"Actionability shape mismatch: {outputs['actionability'].shape}"
    )
    assert outputs["obfuscation"].shape == (batch_size, obf_k), (
        f"Obfuscation shape mismatch: {outputs['obfuscation'].shape}"
    )


def test_firewallnet_forward_different_seq_len():
    """Test FirewallNet with different sequence lengths (should work due to transformer)."""
    encoder_name = "prajjwal1/bert-tiny"
    feat_dim = 64

    model = FirewallNet(encoder_name=encoder_name, feat_dim=feat_dim)

    batch_size = 1

    for seq_len in [16, 32, 64, 128]:
        input_ids = torch.randint(0, 1000, (batch_size, seq_len))
        attention_mask = torch.ones_like(input_ids)
        feat_vec = torch.randn(batch_size, feat_dim)

        model.eval()
        with torch.no_grad():
            outputs = model(input_ids, attention_mask, feat_vec)

        # All outputs should have batch_size dimension regardless of seq_len
        assert outputs["policy"].shape[0] == batch_size
        assert outputs["intent"].shape[0] == batch_size
        assert outputs["actionability"].shape[0] == batch_size
        assert outputs["obfuscation"].shape[0] == batch_size


def test_firewallnet_gradient_flow():
    """Test that gradients flow through all components."""
    encoder_name = "prajjwal1/bert-tiny"
    feat_dim = 64

    model = FirewallNet(encoder_name=encoder_name, feat_dim=feat_dim)
    model.train()

    batch_size = 2
    seq_len = 32

    input_ids = torch.randint(0, 1000, (batch_size, seq_len))
    attention_mask = torch.ones_like(input_ids)
    feat_vec = torch.randn(batch_size, feat_dim)

    outputs = model(input_ids, attention_mask, feat_vec)

    # Create dummy loss (sum of all logits)
    loss = (
        outputs["policy"].sum()
        + outputs["intent"].sum()
        + outputs["actionability"].sum()
        + outputs["obfuscation"].sum()
    )

    loss.backward()

    # Check that gradients exist for key parameters
    assert model.encoder.embeddings.word_embeddings.weight.grad is not None, (
        "Encoder gradients missing"
    )
    assert model.feat_mlp.net[1].weight.grad is not None, (
        "Feature MLP gradients missing"
    )
    assert model.alpha_gate.weight.grad is not None, "Gate gradients missing"
    assert model.head_policy.weight.grad is not None, "Policy head gradients missing"


if __name__ == "__main__":
    # Run tests manually (requires transformers + torch)
    test_feature_mlp_shape()
    print("✓ test_feature_mlp_shape passed")

    test_firewallnet_forward_shapes()
    print("✓ test_firewallnet_forward_shapes passed")

    test_firewallnet_forward_different_seq_len()
    print("✓ test_firewallnet_forward_different_seq_len passed")

    test_firewallnet_gradient_flow()
    print("✓ test_firewallnet_gradient_flow passed")

    print("\nAll tests passed!")
