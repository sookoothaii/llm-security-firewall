"""
Feedback CLI - Continual Learning Feedback Interface
====================================================

Einfaches CLI-Tool für manuelle Korrekturen.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.ml.continual_learning_feedback import (
    ContinualLearningFeedbackLoop,
    FeedbackInterface
)
from llm_firewall.ml import ContinualLearningTrainer, QuantumInspiredCNN


def load_model(model_path: Optional[str] = None):
    """Lade Model für Feedback Loop."""
    if model_path and Path(model_path).exists():
        import torch
        model = torch.load(model_path, map_location="cpu")
    else:
        # Create new model
        model = QuantumInspiredCNN(
            vocab_size=10000,
            embedding_dim=128,
            num_classes=2
        )
    
    return model


def main():
    parser = argparse.ArgumentParser(description="Feedback CLI for Continual Learning")
    parser.add_argument(
        "--model",
        type=str,
        help="Path to model file"
    )
    parser.add_argument(
        "--feedback-file",
        type=str,
        required=True,
        help="Path to feedback JSON file"
    )
    parser.add_argument(
        "--action",
        type=str,
        choices=["add", "train", "stats", "export"],
        default="add",
        help="Action to perform"
    )
    
    args = parser.parse_args()
    
    # Load model
    model = load_model(args.model)
    
    # Create trainer
    trainer = ContinualLearningTrainer(model, method="ewc", lambda_ewc=0.4)
    
    # Create feedback loop
    feedback_loop = ContinualLearningFeedbackLoop(
        model=model,
        trainer=trainer,
        feedback_buffer_size=100,
        min_feedback_for_training=10
    )
    
    # Create interface
    interface = FeedbackInterface(feedback_loop)
    
    if args.action == "add":
        # Load feedback from file
        with open(args.feedback_file, "r", encoding="utf-8") as f:
            feedback_data = json.load(f)
        
        for entry in feedback_data:
            if entry.get("type") == "false_positive":
                interface.mark_false_positive(
                    text=entry["text"],
                    original_prediction=entry.get("original_prediction", 0.5),
                    user_id=entry.get("user_id")
                )
            elif entry.get("type") == "false_negative":
                interface.mark_false_negative(
                    text=entry["text"],
                    original_prediction=entry.get("original_prediction", 0.5),
                    user_id=entry.get("user_id")
                )
            else:
                interface.correct_prediction(
                    text=entry["text"],
                    correct_label=entry.get("correct_label", 0),
                    original_prediction=entry.get("original_prediction", 0.5),
                    user_id=entry.get("user_id")
                )
        
        print(f"Added {len(feedback_data)} feedback entries")
    
    elif args.action == "train":
        # Trigger training
        feedback_loop._trigger_training()
        print("Training triggered")
    
    elif args.action == "stats":
        # Show statistics
        stats = feedback_loop.get_statistics()
        print(json.dumps(stats, indent=2))
    
    elif args.action == "export":
        # Export feedback
        feedback_loop.export_feedback(args.feedback_file)
        print(f"Exported feedback to {args.feedback_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
