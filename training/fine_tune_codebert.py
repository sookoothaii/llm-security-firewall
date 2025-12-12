"""
Fine-Tune CodeBERT for Code Intent Detection
=============================================

Native Python training script (no Docker required).

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import argparse
import json
import os
from pathlib import Path
from typing import List, Dict, Any
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding
)
from datasets import Dataset
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_training_data(data_path: str) -> List[Dict[str, Any]]:
    """Load training data from JSONL file."""
    examples = []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                example = json.loads(line)
                examples.append(example)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping invalid JSON line: {e}")
    
    logger.info(f"Loaded {len(examples)} examples from {data_path}")
    return examples


def prepare_dataset(examples: List[Dict[str, Any]], tokenizer, max_length: int = 512):
    """Prepare dataset for training."""
    def tokenize_function(examples_batch):
        texts = examples_batch["code"] if "code" in examples_batch else examples_batch["text"]
        return tokenizer(
            texts,
            padding="max_length",
            truncation=True,
            max_length=max_length
        )
    
    dataset = Dataset.from_list(examples)
    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    
    return tokenized_dataset


def fine_tune_codebert(
    data_path: str,
    output_dir: str = "./models/code_intent_finetuned",
    model_name: str = "microsoft/codebert-base",
    epochs: int = 3,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
    max_length: int = 512
):
    """Fine-tune CodeBERT for code intent detection."""
    
    logger.info(f"Loading base model: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        num_labels=2  # malicious vs benign
    )
    
    # Load training data
    examples = load_training_data(data_path)
    
    if len(examples) == 0:
        raise ValueError(f"No training examples found in {data_path}")
    
    # Prepare dataset
    logger.info("Preparing dataset...")
    tokenized_dataset = prepare_dataset(examples, tokenizer, max_length)
    
    # Split dataset
    train_test_split = tokenized_dataset.train_test_split(test_size=0.2)
    train_dataset = train_test_split["train"]
    eval_dataset = train_test_split["test"]
    
    logger.info(f"Train examples: {len(train_dataset)}, Eval examples: {len(eval_dataset)}")
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=output_dir,
        evaluation_strategy="epoch",
        learning_rate=learning_rate,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        num_train_epochs=epochs,
        weight_decay=0.01,
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        logging_dir=f"{output_dir}/logs",
        logging_steps=100,
        save_total_limit=3,
    )
    
    # Data collator
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    
    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        tokenizer=tokenizer,
        data_collator=data_collator,
    )
    
    # Train
    logger.info("Starting training...")
    trainer.train()
    
    # Save model
    logger.info(f"Saving model to {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    # Evaluate
    logger.info("Evaluating model...")
    eval_results = trainer.evaluate()
    logger.info(f"Evaluation results: {eval_results}")
    
    # Save evaluation results
    with open(f"{output_dir}/eval_results.json", "w") as f:
        json.dump(eval_results, f, indent=2)
    
    logger.info("Fine-tuning complete!")
    return model, tokenizer, eval_results


def main():
    parser = argparse.ArgumentParser(description="Fine-tune CodeBERT for code intent detection")
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Path to training data JSONL file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./models/code_intent_finetuned",
        help="Output directory for fine-tuned model"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="microsoft/codebert-base",
        help="Base model name"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=16,
        help="Batch size"
    )
    parser.add_argument(
        "--learning_rate",
        type=float,
        default=2e-5,
        help="Learning rate"
    )
    parser.add_argument(
        "--max_length",
        type=int,
        default=512,
        help="Maximum sequence length"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Fine-tune
    fine_tune_codebert(
        data_path=args.data,
        output_dir=args.output,
        model_name=args.model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_length=args.max_length
    )


if __name__ == "__main__":
    main()
