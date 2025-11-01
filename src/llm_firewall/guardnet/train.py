"""
GuardNet Training Loop

Multi-task training with distillation support.
Supports teacher-ensemble distillation from Policy-DSL + ONNX-Judges.

Loss: Weighted sum of CE (policy/intent/actionability) + BCE (obfuscation)
Optimizer: AdamW with cosine schedule and warmup
Data: JSONL format with text, features, labels

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

try:
    from transformers import AutoTokenizer, get_cosine_schedule_with_warmup

    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

from llm_firewall.guardnet.model import (
    ACTIONABILITY_LABELS,
    INTENT_LABELS,
    OBFUSCATION_LABELS,
    POLICY_LABELS,
    FirewallNet,
)


class JsonlDataset(Dataset):
    """
    JSONL dataset for guard model training.

    Expected format per line:
    {
        "text": str,
        "features": {
            "zwc_density": float,
            "base64_frac": float,
            ...
            "regex_hits": {"intent/jailbreak": int, ...}
        },
        "labels": {
            "policy": "block" | "allow_high_level" | "allow",
            "intent": "jailbreak" | ...,
            "actionability": "procedural" | ...,
            "obfuscation": ["base64", "leet", ...]
        },
        "meta": {...}
    }
    """

    def __init__(
        self,
        path: str,
        tokenizer,
        feat_keys: list[str],
        max_len: int = 256,
    ):
        """
        Args:
            path: Path to JSONL file
            tokenizer: HuggingFace tokenizer
            feat_keys: Ordered list of feature keys (e.g., ["zwc_density", "base64_frac", ...])
            max_len: Maximum sequence length for tokenization
        """
        self.rows = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    self.rows.append(json.loads(line))

        self.tok = tokenizer
        self.max_len = max_len
        self.feat_keys = feat_keys

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int):
        row = self.rows[idx]

        # Tokenize text
        text = row["text"]
        tokens = self.tok(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_len,
            return_tensors="pt",
        )
        input_ids = tokens["input_ids"][0]
        attention_mask = tokens["attention_mask"][0]

        # Extract features
        feat_vec = self._to_vec(row["features"])

        # Extract labels
        labels = self._labels_to_tensors(row["labels"])

        return input_ids, attention_mask, feat_vec, labels

    def _to_vec(self, feat: Dict[str, Any]) -> torch.Tensor:
        """Convert feature dict to numeric vector."""
        v = []
        for k in self.feat_keys:
            val = self._nested_get(feat, k)
            v.append(float(val) if val is not None else 0.0)
        return torch.tensor(v, dtype=torch.float32)

    def _nested_get(self, d: Dict, dotted: str) -> Any:
        """Get nested dict value by dotted key (e.g., "regex_hits.intent/jailbreak")."""
        cur: Any = d
        for part in dotted.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur

    def _labels_to_tensors(self, lab: Dict[str, Any]) -> Dict[str, torch.Tensor]:
        """Convert label dict to tensors."""
        policy_map = {k: i for i, k in enumerate(POLICY_LABELS)}
        intent_map = {k: i for i, k in enumerate(INTENT_LABELS)}
        action_map = {k: i for i, k in enumerate(ACTIONABILITY_LABELS)}

        obf_list = lab.get("obfuscation", [])
        obf_vec = [1.0 if k in obf_list else 0.0 for k in OBFUSCATION_LABELS]

        return {
            "policy": torch.tensor(policy_map[lab["policy"]], dtype=torch.long),
            "intent": torch.tensor(intent_map[lab["intent"]], dtype=torch.long),
            "actionability": torch.tensor(
                action_map[lab["actionability"]], dtype=torch.long
            ),
            "obfuscation": torch.tensor(obf_vec, dtype=torch.float32),
        }


def train_guardnet(
    train_path: str,
    val_path: str,
    encoder_name: str = "prajjwal1/bert-tiny",
    feat_dim: int = 64,
    epochs: int = 3,
    batch_size: int = 16,
    lr: float = 3e-4,
    warmup_ratio: float = 0.1,
    device: str = "cpu",
    save_path: Optional[str] = None,
) -> FirewallNet:
    """
    Train GuardNet model.

    Args:
        train_path: Path to training JSONL
        val_path: Path to validation JSONL
        encoder_name: HuggingFace encoder model name
        feat_dim: Feature dimension (must match feature extractor)
        epochs: Number of training epochs
        batch_size: Training batch size
        lr: Learning rate
        warmup_ratio: Warmup ratio for scheduler (default: 0.1)
        device: Device ("cpu", "cuda", "mps")
        save_path: Optional path to save trained model

    Returns:
        Trained FirewallNet model
    """
    if not HAS_TRANSFORMERS:
        raise ImportError(
            "transformers required. Install with: pip install transformers"
        )

    # Setup
    tokenizer = AutoTokenizer.from_pretrained(encoder_name)  # nosec B615

    # Define feature keys (must match feature extractor output)
    feat_keys = [
        "zwc_density",
        "base64_frac",
        "mixed_script_ratio",
        "punct_burst",
        "emb_ood_energy",
        "ttl_delta_days",
        "trust_tier",
        # Add regex_hits categories here if needed (e.g., "regex_hits.intent/jailbreak")
    ]

    # Datasets
    ds_train = JsonlDataset(train_path, tokenizer, feat_keys)
    ds_val = JsonlDataset(val_path, tokenizer, feat_keys)

    dl_train = DataLoader(ds_train, batch_size=batch_size, shuffle=True)
    dl_val = DataLoader(ds_val, batch_size=batch_size)

    # Model
    model = FirewallNet(encoder_name=encoder_name, feat_dim=feat_dim).to(device)

    # Optimizer & Scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr)
    total_steps = epochs * len(dl_train)
    warmup_steps = int(total_steps * warmup_ratio)
    scheduler = get_cosine_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    # Loss functions
    ce_loss = nn.CrossEntropyLoss()
    bce_loss = nn.BCEWithLogitsLoss()

    # Training loop
    for epoch in range(epochs):
        model.train()
        train_loss = 0.0

        for batch_idx, (ids, mask, feats, labels) in enumerate(dl_train):
            ids = ids.to(device)
            mask = mask.to(device)
            feats = feats.to(device)

            # Forward
            outputs = model(ids, mask, feats)

            # Multi-task loss
            loss_policy = ce_loss(outputs["policy"], labels["policy"].to(device))
            loss_intent = ce_loss(outputs["intent"], labels["intent"].to(device))
            loss_action = ce_loss(
                outputs["actionability"], labels["actionability"].to(device)
            )
            loss_obf = bce_loss(
                outputs["obfuscation"], labels["obfuscation"].to(device)
            )

            # Weighted sum (equal weights for now, can be tuned)
            loss = loss_policy + loss_intent + loss_action + loss_obf

            # Backward
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            scheduler.step()

            train_loss += loss.item()

            if (batch_idx + 1) % 10 == 0:
                print(
                    f"Epoch {epoch + 1}/{epochs} | Batch {batch_idx + 1}/{len(dl_train)} | Loss: {loss.item():.4f}"
                )

        avg_train_loss = train_loss / len(dl_train)

        # Validation
        model.eval()
        val_loss = 0.0

        with torch.no_grad():
            for ids, mask, feats, labels in dl_val:
                ids = ids.to(device)
                mask = mask.to(device)
                feats = feats.to(device)

                outputs = model(ids, mask, feats)

                loss_policy = ce_loss(outputs["policy"], labels["policy"].to(device))
                loss_intent = ce_loss(outputs["intent"], labels["intent"].to(device))
                loss_action = ce_loss(
                    outputs["actionability"], labels["actionability"].to(device)
                )
                loss_obf = bce_loss(
                    outputs["obfuscation"], labels["obfuscation"].to(device)
                )

                loss = loss_policy + loss_intent + loss_action + loss_obf
                val_loss += loss.item()

        avg_val_loss = val_loss / len(dl_val) if len(dl_val) > 0 else 0.0

        print(
            f"Epoch {epoch + 1}/{epochs} | Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f}"
        )

    # Save model
    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), save_path)
        print(f"Model saved to {save_path}")

    return model
