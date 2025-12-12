"""
Adversarial Training Pipeline for Phase 3

Generates adversarial training examples and fine-tunes detector models
to reduce False Negative Rate (Bypass Rate).

Usage:
    python -m detectors.orchestrator.infrastructure.training.adversarial_training_pipeline \
        --detector content_safety \
        --samples 1000 \
        --epochs 5
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
import numpy as np

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TextAdversarialTransformations:
    """Text-based adversarial transformations (character-level manipulations)."""
    
    @staticmethod
    def apply_zero_width_chars(text: str) -> List[str]:
        """Apply zero-width character insertions."""
        variations = []
        zero_width_chars = ['\u200b', '\u200c', '\u200d']
        
        for zw_char in zero_width_chars:
            # Insert after first word
            words = text.split()
            if len(words) > 0:
                words[0] = words[0] + zw_char
                variations.append(' '.join(words))
            
            # Insert before last word
            if len(words) > 1:
                words[-1] = zw_char + words[-1]
                variations.append(' '.join(words))
        
        return variations[:2]  # Limit to 2 variations
    
    @staticmethod
    def apply_unicode_homoglyphs(text: str) -> List[str]:
        """Replace ASCII characters with similar-looking Unicode."""
        variations = []
        
        # Common homoglyph replacements
        replacements = {
            'a': 'а',  # Cyrillic
            'e': 'е',  # Cyrillic
            'o': 'о',  # Cyrillic
            'p': 'р',  # Cyrillic
            'c': 'с',  # Cyrillic
        }
        
        # Replace first occurrence of each
        for char, replacement in replacements.items():
            if char in text.lower():
                idx = text.lower().find(char)
                variation = text[:idx] + replacement + text[idx+1:]
                variations.append(variation)
        
        return variations[:2]
    
    @staticmethod
    def apply_encoding_obfuscation(text: str) -> List[str]:
        """Apply encoding obfuscation patterns."""
        variations = []
        
        # URL encode special characters
        if '=' in text or '&' in text:
            encoded = text.replace('=', '%3D').replace('&', '%26')
            variations.append(encoded)
        
        # Hex encode spaces
        if ' ' in text:
            hex_encoded = text.replace(' ', '\\x20')
            variations.append(hex_encoded)
        
        return variations[:2]
    
    @staticmethod
    def apply_case_manipulation(text: str) -> List[str]:
        """Apply case alternation."""
        variations = []
        
        # Random case alternation
        chars = list(text)
        for i in range(1, min(len(chars), 5), 2):
            if chars[i].isalpha():
                chars[i] = chars[i].upper() if chars[i].islower() else chars[i].lower()
        variations.append(''.join(chars))
        
        return variations[:1]
    
    @staticmethod
    def apply_whitespace_manipulation(text: str) -> List[str]:
        """Apply whitespace manipulations."""
        variations = []
        
        # Extra whitespace
        if ' ' in text:
            doubled = text.replace(' ', '  ')
            variations.append(doubled)
        
        # Tab replacement
        if ' ' in text:
            tabbed = text.replace(' ', '\t')
            variations.append(tabbed)
        
        return variations[:1]
    
    @staticmethod
    def generate_variations(text: str, max_variations: int = 5) -> List[str]:
        """Generate multiple adversarial variations of text."""
        all_variations = []
        
        # Apply all transformations
        all_variations.extend(TextAdversarialTransformations.apply_zero_width_chars(text))
        all_variations.extend(TextAdversarialTransformations.apply_unicode_homoglyphs(text))
        all_variations.extend(TextAdversarialTransformations.apply_encoding_obfuscation(text))
        all_variations.extend(TextAdversarialTransformations.apply_case_manipulation(text))
        all_variations.extend(TextAdversarialTransformations.apply_whitespace_manipulation(text))
        
        # Remove duplicates and limit
        unique_variations = list(dict.fromkeys(all_variations))  # Preserves order
        return unique_variations[:max_variations]


class AdversarialTrainingDataset:
    """Manages adversarial training dataset generation."""
    
    def __init__(self, output_dir: str = "data/adversarial_training"):
        """Initialize dataset manager."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.transformations = TextAdversarialTransformations()
    
    def load_baseline_samples(self, results_dir: str = "test_results/adversarial") -> Tuple[List[str], List[int]]:
        """Load baseline test samples."""
        samples = []
        labels = []
        
        results_path = project_root / results_dir
        
        # Load from baseline test results
        for results_file in results_path.glob("baseline_*.json"):
            if "retest" in str(results_file):
                continue
                
            with open(results_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
                
                for test_result in results.get("test_results", []):
                    sample = test_result.get("sample", "")
                    label = test_result.get("label", 0)
                    
                    if sample:
                        samples.append(sample)
                        labels.append(label)
        
        logger.info(f"Loaded {len(samples)} baseline samples ({sum(labels)} malicious, {len(labels)-sum(labels)} benign)")
        return samples, labels
    
    def generate_adversarial_dataset(
        self,
        base_samples: List[str],
        labels: List[int],
        max_samples_per_base: int = 5,
        target_malicious_samples: int = 1000
    ) -> Tuple[List[str], List[int]]:
        """Generate adversarial training dataset."""
        adversarial_samples = []
        adversarial_labels = []
        
        # Focus on malicious samples (these need adversarial training)
        malicious_indices = [i for i, label in enumerate(labels) if label == 1]
        benign_indices = [i for i, label in enumerate(labels) if label == 0]
        
        logger.info(f"Generating adversarial examples from {len(malicious_indices)} malicious base samples...")
        
        # Generate adversarial variations for malicious samples
        variations_per_sample = max(1, target_malicious_samples // len(malicious_indices))
        variations_per_sample = min(variations_per_sample, max_samples_per_base)
        
        for idx in malicious_indices:
            base_text = base_samples[idx]
            variations = self.transformations.generate_variations(
                base_text,
                max_variations=variations_per_sample
            )
            
            # Add original (labeled as malicious)
            adversarial_samples.append(base_text)
            adversarial_labels.append(1)
            
            # Add variations (also labeled as malicious)
            for variation in variations:
                adversarial_samples.append(variation)
                adversarial_labels.append(1)
        
        # Add some benign samples (for balanced training)
        benign_to_add = min(len(adversarial_samples) // 2, len(benign_indices))
        for idx in benign_indices[:benign_to_add]:
            adversarial_samples.append(base_samples[idx])
            adversarial_labels.append(0)
        
        logger.info(f"Generated {len(adversarial_samples)} training samples "
                   f"({sum(adversarial_labels)} malicious, {len(adversarial_labels)-sum(adversarial_labels)} benign)")
        
        return adversarial_samples, adversarial_labels
    
    def save_dataset(
        self,
        samples: List[str],
        labels: List[int],
        detector_name: str,
        split: str = "train"
    ) -> Path:
        """Save dataset to JSONL file."""
        filename = self.output_dir / f"{detector_name}_{split}_adversarial.jsonl"
        
        with open(filename, 'w', encoding='utf-8') as f:
            for sample, label in zip(samples, labels):
                record = {
                    "text": sample,
                    "label": label,
                    "source": "adversarial_training",
                    "timestamp": datetime.utcnow().isoformat()
                }
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
        
        logger.info(f"Saved {len(samples)} samples to {filename}")
        return filename


class AdversarialTrainingPipeline:
    """Main pipeline for adversarial training."""
    
    def __init__(self, detector_name: str, output_dir: str = "data/adversarial_training"):
        """Initialize training pipeline."""
        self.detector_name = detector_name
        self.dataset_manager = AdversarialTrainingDataset(output_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def prepare_dataset(self, target_samples: int = 1000) -> Tuple[Path, Path]:
        """Prepare adversarial training dataset."""
        logger.info("="*80)
        logger.info(f"PREPARING ADVERSARIAL TRAINING DATASET: {self.detector_name}")
        logger.info("="*80)
        
        # Load baseline samples
        base_samples, base_labels = self.dataset_manager.load_baseline_samples()
        
        if len(base_samples) == 0:
            raise ValueError("No baseline samples found. Run baseline test first!")
        
        # Generate adversarial variations
        adv_samples, adv_labels = self.dataset_manager.generate_adversarial_dataset(
            base_samples=base_samples,
            labels=base_labels,
            target_malicious_samples=target_samples
        )
        
        # Split into train/val (80/20)
        split_idx = int(len(adv_samples) * 0.8)
        train_samples = adv_samples[:split_idx]
        train_labels = adv_labels[:split_idx]
        val_samples = adv_samples[split_idx:]
        val_labels = adv_labels[split_idx:]
        
        # Save datasets
        train_path = self.dataset_manager.save_dataset(
            train_samples, train_labels, self.detector_name, "train"
        )
        val_path = self.dataset_manager.save_dataset(
            val_samples, val_labels, self.detector_name, "val"
        )
        
        logger.info("="*80)
        logger.info("DATASET PREPARATION COMPLETE")
        logger.info("="*80)
        logger.info(f"Train samples: {len(train_samples)}")
        logger.info(f"Val samples: {len(val_samples)}")
        logger.info(f"Train path: {train_path}")
        logger.info(f"Val path: {val_path}")
        logger.info("="*80)
        
        return train_path, val_path
    
    def validate_dataset(self, dataset_path: Path) -> Dict[str, Any]:
        """Validate generated dataset."""
        samples = []
        labels = []
        
        with open(dataset_path, 'r', encoding='utf-8') as f:
            for line in f:
                record = json.loads(line)
                samples.append(record['text'])
                labels.append(record['label'])
        
        stats = {
            "total_samples": len(samples),
            "malicious_samples": sum(labels),
            "benign_samples": len(labels) - sum(labels),
            "malicious_ratio": sum(labels) / len(labels) if labels else 0,
        }
        
        logger.info(f"Dataset validation: {stats}")
        return stats


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Adversarial Training Dataset Generator")
    parser.add_argument(
        "--detector",
        type=str,
        required=True,
        choices=["content_safety", "code_intent", "persuasion"],
        help="Detector to generate training data for"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1000,
        help="Target number of adversarial training samples"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/adversarial_training",
        help="Output directory for datasets"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate existing dataset, don't generate new"
    )
    
    args = parser.parse_args()
    
    # Create pipeline
    pipeline = AdversarialTrainingPipeline(
        detector_name=args.detector,
        output_dir=args.output_dir
    )
    
    if args.validate_only:
        # Validate existing dataset
        train_path = Path(args.output_dir) / f"{args.detector}_train_adversarial.jsonl"
        if train_path.exists():
            pipeline.validate_dataset(train_path)
        else:
            logger.error(f"Dataset not found: {train_path}")
            return 1
    else:
        # Generate new dataset
        train_path, val_path = pipeline.prepare_dataset(target_samples=args.samples)
        
        # Validate
        logger.info("\nValidating generated datasets...")
        train_stats = pipeline.validate_dataset(train_path)
        val_stats = pipeline.validate_dataset(val_path)
        
        logger.info("\n" + "="*80)
        logger.info("ADVERSARIAL TRAINING DATASET GENERATION COMPLETE")
        logger.info("="*80)
        logger.info(f"Training dataset: {train_path}")
        logger.info(f"  - Total: {train_stats['total_samples']} samples")
        logger.info(f"  - Malicious: {train_stats['malicious_samples']} ({train_stats['malicious_ratio']*100:.1f}%)")
        logger.info(f"\nValidation dataset: {val_path}")
        logger.info(f"  - Total: {val_stats['total_samples']} samples")
        logger.info(f"  - Malicious: {val_stats['malicious_samples']} ({val_stats['malicious_ratio']*100:.1f}%)")
        logger.info("="*80)
        logger.info("\nNext steps:")
        logger.info("1. Review generated datasets")
        logger.info("2. Run training script (to be implemented)")
        logger.info(f"3. Evaluate trained model against baseline bypass rate")
    
    return 0


if __name__ == "__main__":
    exit(main())

