"""Train Layer 15 Crisis Detection Model.

Architecture: sentence-transformers (paraphrase-MiniLM-L6-v2) + Multi-label classifier
Output: models/selfharm_abuse_multilingual.onnx

IMPORTANT: This uses SYNTHETIC data. Real deployment requires validated datasets.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sentence_transformers import SentenceTransformer
from sklearn.metrics import precision_recall_fscore_support
import onnx
import onnxruntime as ort

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CrisisDataset(Dataset):
    """Crisis detection dataset."""
    
    def __init__(self, jsonl_path: Path, split: str = "train"):
        self.samples = []
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                sample = json.loads(line)
                if sample["split"] == split:
                    self.samples.append(sample)
        logger.info(f"Loaded {len(self.samples)} {split} samples")
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Tuple[str, torch.Tensor]:
        sample = self.samples[idx]
        text = sample["text"]
        labels = torch.tensor([
            sample["labels"]["self_harm"],
            sample["labels"]["abuse"],
            sample["labels"]["unsafe_env"]
        ], dtype=torch.float32)
        return text, labels


class CrisisClassifier(nn.Module):
    """Multi-label crisis classifier on top of sentence embeddings."""
    
    def __init__(self, input_dim: int = 384, hidden_dim: int = 128):
        super().__init__()
        self.input_dim = input_dim
        self.classifier = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 3)  # self_harm, abuse, unsafe_env
        )
    
    def forward(self, embeddings: torch.Tensor) -> torch.Tensor:
        """Forward pass.
        
        Args:
            embeddings: (batch_size, 384) sentence embeddings
        
        Returns:
            logits: (batch_size, 3) logits for each crisis category
        """
        return self.classifier(embeddings)


def collate_fn(batch: List[Tuple[str, torch.Tensor]], embedder: SentenceTransformer) -> Tuple[torch.Tensor, torch.Tensor]:
    """Collate batch with embedding computation."""
    texts, labels = zip(*batch)
    # Detach embeddings (frozen encoder, no gradients needed)
    embeddings = embedder.encode(list(texts), convert_to_tensor=True, show_progress_bar=False).detach()
    labels = torch.stack(labels)
    return embeddings, labels


def train_epoch(model: nn.Module, dataloader: DataLoader, optimizer: torch.optim.Optimizer, 
                criterion: nn.Module, device: torch.device) -> float:
    """Train one epoch."""
    model.train()
    total_loss = 0.0
    
    for embeddings, labels in dataloader:
        embeddings = embeddings.to(device)
        labels = labels.to(device)
        
        optimizer.zero_grad()
        logits = model(embeddings)
        loss = criterion(logits, labels)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
    
    return total_loss / len(dataloader)


def evaluate(model: nn.Module, dataloader: DataLoader, criterion: nn.Module, 
             device: torch.device) -> Tuple[float, Dict[str, float]]:
    """Evaluate model."""
    model.eval()
    total_loss = 0.0
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for embeddings, labels in dataloader:
            embeddings = embeddings.to(device)
            labels = labels.to(device)
            
            logits = model(embeddings)
            loss = criterion(logits, labels)
            total_loss += loss.item()
            
            # Binary predictions (threshold 0.5 on sigmoid)
            preds = torch.sigmoid(logits) > 0.5
            all_preds.append(preds.cpu().numpy())
            all_labels.append(labels.cpu().numpy())
    
    all_preds = np.vstack(all_preds)
    all_labels = np.vstack(all_labels)
    
    # Per-category metrics
    metrics = {}
    categories = ["self_harm", "abuse", "unsafe_env"]
    for i, cat in enumerate(categories):
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels[:, i], all_preds[:, i], average='binary', zero_division=0
        )
        metrics[cat] = {"precision": precision, "recall": recall, "f1": f1}
    
    return total_loss / len(dataloader), metrics


def export_to_onnx(model: nn.Module, output_path: Path, input_dim: int = 384):
    """Export model to ONNX."""
    model.eval()
    
    # Dummy input
    dummy_input = torch.randn(1, input_dim)
    
    # Export
    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        input_names=["embeddings"],
        output_names=["logits"],
        dynamic_axes={"embeddings": {0: "batch_size"}, "logits": {0: "batch_size"}},
        opset_version=13,
        do_constant_folding=True
    )
    
    logger.info(f"Exported to {output_path}")
    
    # Validate
    onnx_model = onnx.load(str(output_path))
    onnx.checker.check_model(onnx_model)
    logger.info("ONNX model validated")
    
    # Test inference
    session = ort.InferenceSession(str(output_path), providers=["CPUExecutionProvider"])
    test_input = np.random.randn(2, input_dim).astype(np.float32)
    outputs = session.run(None, {"embeddings": test_input})
    logger.info(f"ONNX inference test: input {test_input.shape} -> output {outputs[0].shape}")


def main():
    """Train crisis detection model."""
    # Config
    data_path = Path("data/crisis_detection_synthetic_v1.jsonl")
    model_dir = Path("models")
    model_dir.mkdir(exist_ok=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")
    
    # Load embedder (frozen)
    logger.info("Loading sentence-transformers model...")
    embedder = SentenceTransformer("paraphrase-MiniLM-L6-v2")
    embedder.eval()  # Frozen
    
    # Datasets
    train_dataset = CrisisDataset(data_path, split="train")
    val_dataset = CrisisDataset(data_path, split="val")
    
    train_loader = DataLoader(
        train_dataset, 
        batch_size=16, 
        shuffle=True,
        collate_fn=lambda batch: collate_fn(batch, embedder)
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=16,
        shuffle=False,
        collate_fn=lambda batch: collate_fn(batch, embedder)
    )
    
    # Model
    model = CrisisClassifier(input_dim=384, hidden_dim=128).to(device)
    logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Training setup
    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=3, factor=0.5)
    
    # Train
    best_val_loss = float('inf')
    patience = 5
    patience_counter = 0
    
    logger.info("Starting training...")
    for epoch in range(50):
        train_loss = train_epoch(model, train_loader, optimizer, criterion, device)
        val_loss, metrics = evaluate(model, val_loader, criterion, device)
        scheduler.step(val_loss)
        
        logger.info(f"Epoch {epoch+1:2d}: train_loss={train_loss:.4f}, val_loss={val_loss:.4f}")
        for cat, m in metrics.items():
            logger.info(f"  {cat}: P={m['precision']:.3f}, R={m['recall']:.3f}, F1={m['f1']:.3f}")
        
        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            # Save checkpoint
            torch.save(model.state_dict(), model_dir / "crisis_classifier_best.pth")
            logger.info("  [BEST] Saved checkpoint")
        else:
            patience_counter += 1
            if patience_counter >= patience:
                logger.info(f"Early stopping at epoch {epoch+1}")
                break
    
    # Load best model
    model.load_state_dict(torch.load(model_dir / "crisis_classifier_best.pth"))
    
    # Final evaluation
    val_loss, metrics = evaluate(model, val_loader, criterion, device)
    logger.info("\n" + "="*80)
    logger.info("FINAL VALIDATION METRICS")
    logger.info("="*80)
    for cat, m in metrics.items():
        logger.info(f"{cat:12s}: P={m['precision']:.3f}, R={m['recall']:.3f}, F1={m['f1']:.3f}")
    
    # Export to ONNX
    logger.info("\n" + "="*80)
    logger.info("EXPORTING TO ONNX")
    logger.info("="*80)
    export_to_onnx(model, model_dir / "selfharm_abuse_multilingual.onnx", input_dim=384)
    
    logger.info("\n[OK] Training complete!")
    logger.info(f"[OK] ONNX model: {model_dir / 'selfharm_abuse_multilingual.onnx'}")
    logger.info("\n[WARNING] This model trained on SYNTHETIC data!")
    logger.info("[WARNING] Real deployment requires validated datasets with IRB approval!")


if __name__ == "__main__":
    main()

