"""
Create V2 Training Dataset with Weakness Analysis Bypasses

Adds the 17 found bypass samples to training data with variations
for targeted retraining.

Usage:
    python -m detectors.orchestrator.infrastructure.training.create_v2_training_set \
        --weakness-analysis data/adversarial_training/weakness_analysis.json \
        --base-train data/adversarial_training/code_intent_train_adversarial.jsonl \
        --base-val data/adversarial_training/code_intent_val_adversarial.jsonl \
        --output-train data/adversarial_training/code_intent_train_adversarial_v2.jsonl \
        --output-val data/adversarial_training/code_intent_val_adversarial_v2.jsonl \
        --variations-per-bypass 5
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Set
from datetime import datetime
import random

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.adversarial_training_pipeline import (
    TextAdversarialTransformations
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_weakness_analysis(json_path: Path) -> Dict[str, Any]:
    """Load weakness analysis results."""
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_existing_dataset(jsonl_path: Path) -> List[Dict[str, Any]]:
    """Load existing training/validation dataset."""
    samples = []
    if jsonl_path.exists():
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    samples.append(json.loads(line))
    return samples


def generate_bypass_variations(
    bypass_text: str,
    transformations: TextAdversarialTransformations,
    variations_per_bypass: int = 5,
    seed: int = 42
) -> List[str]:
    """Generate multiple variations of a bypass sample."""
    random.seed(hash(bypass_text) % (2**32))  # Deterministic per bypass
    
    variations = []
    
    # Always include original
    variations.append(bypass_text)
    
    # Get all transformation methods
    transformation_methods = [
        transformations.apply_zero_width_chars,
        transformations.apply_unicode_homoglyphs,
        transformations.apply_encoding_obfuscation,
        transformations.apply_case_manipulation,
        transformations.apply_whitespace_manipulation,
    ]
    
    # Generate variations
    attempts = 0
    max_attempts = variations_per_bypass * 10
    
    while len(variations) < variations_per_bypass and attempts < max_attempts:
        attempts += 1
        
        # Pick random transformation
        method = random.choice(transformation_methods)
        
        try:
            method_variations = method(bypass_text)
            for var in method_variations:
                if var and var not in variations:
                    variations.append(var)
                    if len(variations) >= variations_per_bypass:
                        break
        except Exception as e:
            logger.debug(f"Variation generation failed: {e}")
            continue
    
    return variations[:variations_per_bypass]


def create_enhanced_dataset(
    weakness_analysis: Dict[str, Any],
    base_train_samples: List[Dict[str, Any]],
    base_val_samples: List[Dict[str, Any]],
    transformations: TextAdversarialTransformations,
    variations_per_bypass: int = 5,
    bypass_train_ratio: float = 0.8
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Create enhanced training dataset with bypass samples.
    
    Args:
        weakness_analysis: Results from weakness analysis
        base_train_samples: Existing training samples
        base_val_samples: Existing validation samples
        transformations: Transformation object
        variations_per_bypass: Number of variations per bypass
        bypass_train_ratio: Ratio of bypasses for training (rest for validation)
    """
    
    # Extract all bypass samples
    all_bypasses = weakness_analysis.get('all_bypasses', [])
    
    if not all_bypasses:
        logger.warning("No bypasses found in weakness analysis!")
        return base_train_samples, base_val_samples
    
    logger.info(f"Processing {len(all_bypasses)} bypass samples...")
    
    # Get unique bypass texts (avoid duplicates)
    unique_bypass_texts = set()
    bypass_samples = []
    
    for bypass in all_bypasses:
        text = bypass.get('text', '')
        if text and text not in unique_bypass_texts:
            unique_bypass_texts.add(text)
            bypass_samples.append(text)
    
    logger.info(f"Found {len(bypass_samples)} unique bypass samples")
    
    # Split bypasses into train/val
    random.shuffle(bypass_samples)
    split_idx = int(len(bypass_samples) * bypass_train_ratio)
    train_bypasses = bypass_samples[:split_idx]
    val_bypasses = bypass_samples[split_idx:]
    
    logger.info(f"Split: {len(train_bypasses)} train, {len(val_bypasses)} val bypasses")
    
    # Generate variations for training bypasses
    logger.info("Generating variations for training bypasses...")
    train_enhanced_samples = base_train_samples.copy()
    
    for i, bypass_text in enumerate(train_bypasses):
        if (i + 1) % 5 == 0:
            logger.info(f"  Processing bypass {i+1}/{len(train_bypasses)}...")
        
        variations = generate_bypass_variations(
            bypass_text,
            transformations,
            variations_per_bypass,
            seed=42
        )
        
        for variation in variations:
            train_enhanced_samples.append({
                'text': variation,
                'label': 1,  # malicious
                'source': 'weakness_analysis_bypass',
                'original_bypass': bypass_text,
                'timestamp': datetime.now().isoformat()
            })
    
    logger.info(f"Added {len(train_bypasses) * variations_per_bypass} bypass variations to training")
    
    # Add validation bypasses (fewer variations)
    logger.info("Adding validation bypasses...")
    val_enhanced_samples = base_val_samples.copy()
    
    for bypass_text in val_bypasses:
        # Add original bypass + 1-2 variations
        val_enhanced_samples.append({
            'text': bypass_text,
            'label': 1,
            'source': 'weakness_analysis_bypass',
            'original_bypass': bypass_text,
            'timestamp': datetime.now().isoformat()
        })
        
        # Add 1 variation
        variations = generate_bypass_variations(
            bypass_text,
            transformations,
            variations_per_bypass=2,
            seed=999
        )
        if len(variations) > 1:
            val_enhanced_samples.append({
                'text': variations[1],
                'label': 1,
                'source': 'weakness_analysis_bypass',
                'original_bypass': bypass_text,
                'timestamp': datetime.now().isoformat()
            })
    
    logger.info(f"Added {len(val_bypasses)} bypass samples to validation")
    
    # Shuffle datasets
    random.shuffle(train_enhanced_samples)
    random.shuffle(val_enhanced_samples)
    
    return train_enhanced_samples, val_enhanced_samples


def save_dataset(samples: List[Dict[str, Any]], output_path: Path):
    """Save dataset to JSONL file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    logger.info(f"Saved {len(samples)} samples to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Create V2 Training Dataset with Bypass Samples")
    parser.add_argument(
        "--weakness-analysis",
        type=str,
        required=True,
        help="Path to weakness analysis JSON"
    )
    parser.add_argument(
        "--base-train",
        type=str,
        required=True,
        help="Path to base training dataset JSONL"
    )
    parser.add_argument(
        "--base-val",
        type=str,
        required=True,
        help="Path to base validation dataset JSONL"
    )
    parser.add_argument(
        "--output-train",
        type=str,
        required=True,
        help="Output path for enhanced training dataset"
    )
    parser.add_argument(
        "--output-val",
        type=str,
        required=True,
        help="Output path for enhanced validation dataset"
    )
    parser.add_argument(
        "--variations-per-bypass",
        type=int,
        default=5,
        help="Number of variations per bypass sample"
    )
    parser.add_argument(
        "--bypass-train-ratio",
        type=float,
        default=0.8,
        help="Ratio of bypasses for training (rest for validation)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("CREATING V2 TRAINING DATASET WITH BYPASS SAMPLES")
    logger.info("="*80)
    
    # Load weakness analysis
    logger.info("\nLoading weakness analysis...")
    weakness_analysis = load_weakness_analysis(Path(args.weakness_analysis))
    logger.info(f"Loaded {weakness_analysis.get('successful_bypasses', 0)} bypass samples")
    
    # Load base datasets
    logger.info("\nLoading base datasets...")
    base_train = load_existing_dataset(Path(args.base_train))
    base_val = load_existing_dataset(Path(args.base_val))
    logger.info(f"Base training samples: {len(base_train)}")
    logger.info(f"Base validation samples: {len(base_val)}")
    
    # Create enhanced datasets
    logger.info("\nCreating enhanced datasets...")
    transformations = TextAdversarialTransformations()
    
    train_enhanced, val_enhanced = create_enhanced_dataset(
        weakness_analysis,
        base_train,
        base_val,
        transformations,
        variations_per_bypass=args.variations_per_bypass,
        bypass_train_ratio=args.bypass_train_ratio
    )
    
    # Save datasets
    logger.info("\nSaving enhanced datasets...")
    save_dataset(train_enhanced, Path(args.output_train))
    save_dataset(val_enhanced, Path(args.output_val))
    
    # Print statistics
    logger.info("\n" + "="*80)
    logger.info("DATASET STATISTICS")
    logger.info("="*80)
    logger.info(f"Training Dataset:")
    logger.info(f"  Total: {len(train_enhanced)} samples")
    logger.info(f"  Added: {len(train_enhanced) - len(base_train)} new samples")
    logger.info(f"  Malicious: {sum(1 for s in train_enhanced if s.get('label') == 1)}")
    logger.info(f"  Benign: {sum(1 for s in train_enhanced if s.get('label') == 0)}")
    
    logger.info(f"\nValidation Dataset:")
    logger.info(f"  Total: {len(val_enhanced)} samples")
    logger.info(f"  Added: {len(val_enhanced) - len(base_val)} new samples")
    logger.info(f"  Malicious: {sum(1 for s in val_enhanced if s.get('label') == 1)}")
    logger.info(f"  Benign: {sum(1 for s in val_enhanced if s.get('label') == 0)}")
    
    logger.info("\n" + "="*80)
    logger.info("V2 DATASET CREATION COMPLETE")
    logger.info("="*80)
    logger.info(f"Training: {args.output_train}")
    logger.info(f"Validation: {args.output_val}")
    logger.info("\nNext step: Train model with these enhanced datasets")


if __name__ == "__main__":
    main()

