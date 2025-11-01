"""
GuardNet Model - Two-Tower Fusion with Multi-Head Outputs

Architecture:
- Text Tower: Small transformer encoder (MiniLM, DeBERTa-Small, or bert-tiny)
- Feature Tower: MLP over engineered features
- Fusion: Gated additive (alpha gate learned from features)
- Heads: 4 multi-task outputs (policy, intent, actionability, obfuscation)

Designed for ONNX export and production deployment.
Deterministic, reproducible, calibratable with conformal prediction.

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from __future__ import annotations

from typing import Any, Dict

import torch
import torch.nn as nn

try:
    from transformers import AutoModel

    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


class FeatureMLP(nn.Module):
    """
    MLP for engineered features.

    Input: Numeric feature vector (zwc_density, base64_frac, etc.)
    Output: Hidden representation for fusion

    Architecture: LayerNorm -> Linear -> GELU -> Linear
    """

    def __init__(self, in_dim: int, hidden_dim: int = 128):
        """
        Args:
            in_dim: Input feature dimension (e.g., 7 base + N regex categories)
            hidden_dim: Hidden layer size (default: 128)
        """
        super().__init__()
        self.net = nn.Sequential(
            nn.LayerNorm(in_dim),
            nn.Linear(in_dim, hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, hidden_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (B, in_dim) feature tensor

        Returns:
            (B, hidden_dim) hidden representation
        """
        return self.net(x)


class FirewallNet(nn.Module):
    """
    GuardNet: Proactive firewall guard model.

    Two-tower architecture:
    - Text tower: Transformer encoder (CLS token as text representation)
    - Feature tower: MLP over engineered features
    - Fusion: Gated additive (alpha gate from feature tower)
    - Heads: Multi-task classification
        * Policy: {block, allow_high_level, allow} (3 classes)
        * Intent: {jailbreak, injection, dual_use, persuasion, benign} (5 classes)
        * Actionability: {procedural, advisory, descriptive} (3 classes)
        * Obfuscation: {base64, leet, homoglyph, zwc, mixed_script, emoji_burst} (6 classes, multi-label)

    ONNX-exportable with dynamic batch and sequence dimensions.
    """

    def __init__(
        self,
        encoder_name: str = "prajjwal1/bert-tiny",
        feat_dim: int = 64,
        obf_k: int = 6,
        hidden_dim: int = 128,
    ):
        """
        Args:
            encoder_name: HuggingFace model name (e.g., "prajjwal1/bert-tiny", "sentence-transformers/all-MiniLM-L6-v2")
            feat_dim: Engineered feature dimension
            obf_k: Number of obfuscation classes (default: 6)
            hidden_dim: Feature MLP hidden dimension (default: 128)
        """
        super().__init__()

        if not HAS_TRANSFORMERS:
            raise ImportError(
                "transformers library required for FirewallNet. "
                "Install with: pip install transformers"
            )

        # Text tower: small transformer encoder
        self.encoder = AutoModel.from_pretrained(encoder_name)  # nosec B615
        h = self.encoder.config.hidden_size

        # Feature tower: MLP over engineered features
        self.feat_mlp = FeatureMLP(feat_dim, hidden_dim)

        # Gate: learns alpha for fusion
        self.alpha_gate = nn.Linear(hidden_dim, 1)

        # Fusion: gated additive (simple, stable, ONNX-friendly)
        # z = enc + alpha * enc (scaled by learned gate)
        fused_dim = h  # fusion keeps encoder dimension

        # Multi-task heads
        self.head_policy = nn.Linear(fused_dim, 3)  # {block, allow_high_level, allow}
        self.head_intent = nn.Linear(
            fused_dim, 5
        )  # {jailbreak, injection, dual_use, persuasion, benign}
        self.head_action = nn.Linear(
            fused_dim, 3
        )  # {procedural, advisory, descriptive}
        self.head_obf = nn.Linear(fused_dim, obf_k)  # multi-label obfuscation

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        feat_vec: torch.Tensor,
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass.

        Args:
            input_ids: (B, T) tokenized text
            attention_mask: (B, T) attention mask
            feat_vec: (B, feat_dim) engineered features

        Returns:
            Dict with keys:
                - policy: (B, 3) logits
                - intent: (B, 5) logits
                - actionability: (B, 3) logits
                - obfuscation: (B, obf_k) logits for BCEWithLogitsLoss
        """
        # Text tower: extract CLS token representation
        encoder_out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        text_repr = encoder_out.last_hidden_state[:, 0, :]  # (B, h) - CLS token

        # Feature tower: MLP
        feat_repr = self.feat_mlp(feat_vec)  # (B, hidden_dim)

        # Gate: compute alpha
        alpha = torch.sigmoid(self.alpha_gate(feat_repr))  # (B, 1)

        # Fusion: gated additive
        # z = text_repr + alpha * text_repr = (1 + alpha) * text_repr
        fused = text_repr + alpha * text_repr  # (B, h)

        # Multi-task heads
        return {
            "policy": self.head_policy(fused),
            "intent": self.head_intent(fused),
            "actionability": self.head_action(fused),
            "obfuscation": self.head_obf(fused),
        }


# Label mappings (for reference in training/inference)

POLICY_LABELS = ["block", "allow_high_level", "allow"]
INTENT_LABELS = ["jailbreak", "injection", "dual_use", "persuasion", "benign"]
ACTIONABILITY_LABELS = ["procedural", "advisory", "descriptive"]
OBFUSCATION_LABELS = [
    "base64",
    "leet",
    "homoglyph",
    "zwc",
    "mixed_script",
    "emoji_burst",
]


def decode_outputs(
    outputs: Dict[str, torch.Tensor],
    temperature: float = 1.0,
) -> Dict[str, Any]:
    """
    Decode model outputs to human-readable predictions.

    Args:
        outputs: Dict from forward() with logits
        temperature: Temperature for softmax (default: 1.0, use calibrated value in production)

    Returns:
        Dict with:
            - policy: str (predicted class)
            - policy_probs: list[float] (probabilities)
            - intent: str
            - intent_probs: list[float]
            - actionability: str
            - actionability_probs: list[float]
            - obfuscation: list[str] (multi-label, threshold=0.5)
            - obfuscation_probs: list[float]
    """
    import torch.nn.functional as F

    # Single-label tasks: softmax + argmax
    policy_probs = F.softmax(outputs["policy"] / temperature, dim=-1)[0].tolist()
    policy_idx = int(outputs["policy"].argmax(dim=-1).item())

    intent_probs = F.softmax(outputs["intent"] / temperature, dim=-1)[0].tolist()
    intent_idx = int(outputs["intent"].argmax(dim=-1).item())

    action_probs = F.softmax(outputs["actionability"] / temperature, dim=-1)[0].tolist()
    action_idx = int(outputs["actionability"].argmax(dim=-1).item())

    # Multi-label: sigmoid + threshold
    obf_probs = torch.sigmoid(outputs["obfuscation"])[0].tolist()
    obf_predicted = [OBFUSCATION_LABELS[i] for i, p in enumerate(obf_probs) if p > 0.5]

    return {
        "policy": POLICY_LABELS[policy_idx],
        "policy_probs": policy_probs,
        "intent": INTENT_LABELS[intent_idx],
        "intent_probs": intent_probs,
        "actionability": ACTIONABILITY_LABELS[action_idx],
        "actionability_probs": action_probs,
        "obfuscation": obf_predicted,
        "obfuscation_probs": obf_probs,
    }
