"""
Fix Data Leakage in Whitelist Module Dataset

Entfernt Duplikate und erstellt korrekte Train/Val Split ohne Überlappung.

Usage:
    python -m detectors.orchestrator.infrastructure.training.fix_whitelist_dataset_leakage \
        --input-dir data/adversarial_training/whitelist_module \
        --output-dir data/adversarial_training/whitelist_module_fixed \
        --train-ratio 0.8
"""

import sys
import json
import logging
import argparse
import random
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Any
from collections import defaultdict

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def normalize_text(text: str) -> str:
    """Normalize text for comparison."""
    return text.strip().lower()


def text_hash(text: str) -> str:
    """Create hash of normalized text."""
    return hashlib.md5(normalize_text(text).encode()).hexdigest()


def deduplicate_samples(samples: List[Dict]) -> List[Dict]:
    """Remove duplicate samples based on text hash."""
    logger.info(f"Deduplicating {len(samples)} samples...")
    
    seen_hashes: Set[str] = set()
    unique_samples: List[Dict] = []
    duplicates_removed = 0
    
    for sample in samples:
        text = sample.get('text', sample.get('input', ''))
        if not text:
            continue
        
        h = text_hash(text)
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_samples.append(sample)
        else:
            duplicates_removed += 1
    
    logger.info(f"  Removed {duplicates_removed} duplicates")
    logger.info(f"  Unique samples: {len(unique_samples)}")
    
    return unique_samples


def load_jsonl(path: Path) -> List[Dict]:
    """Load JSONL file."""
    samples = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


def create_clean_split(
    positives: List[Dict],
    negatives: List[Dict],
    train_ratio: float = 0.8,
    seed: int = 42
) -> Dict[str, Any]:
    """Create train/validation split with no overlap."""
    logger.info("Creating clean train/validation split...")
    
    random.seed(seed)
    
    # Deduplicate first
    positives = deduplicate_samples(positives)
    negatives = deduplicate_samples(negatives)
    
    # Remove any overlap between positives and negatives
    pos_texts = {text_hash(s.get('text', '')) for s in positives}
    negatives = [s for s in negatives if text_hash(s.get('text', '')) not in pos_texts]
    logger.info(f"  Removed {len(pos_texts)} negatives that overlap with positives")
    
    # Shuffle
    random.shuffle(positives)
    random.shuffle(negatives)
    
    # Split positives
    n_pos_train = int(len(positives) * train_ratio)
    train_pos = positives[:n_pos_train]
    val_pos = positives[n_pos_train:]
    
    # Split negatives
    n_neg_train = int(len(negatives) * train_ratio)
    train_neg = negatives[:n_neg_train]
    val_neg = negatives[n_neg_train:]
    
    # Verify no overlap between train and val
    train_texts = {text_hash(s.get('text', '')) for s in train_pos + train_neg}
    val_texts = {text_hash(s.get('text', '')) for s in val_pos + val_neg}
    overlap = train_texts.intersection(val_texts)
    
    if overlap:
        logger.error(f"❌ KRITISCH: {len(overlap)} Samples überlappen noch immer!")
        logger.error("   Dies sollte nicht passieren - BUG im Code!")
        # Remove overlapping samples from validation
        val_pos = [s for s in val_pos if text_hash(s.get('text', '')) not in overlap]
        val_neg = [s for s in val_neg if text_hash(s.get('text', '')) not in overlap]
        logger.warning(f"   Entfernt {len(overlap)} überlappende Samples aus Validation")
    else:
        logger.info("✅ Keine Überlappung zwischen Train und Val")
    
    # Combine
    train_samples = train_pos + train_neg
    val_samples = val_pos + val_neg
    
    # Shuffle final
    random.shuffle(train_samples)
    random.shuffle(val_samples)
    
    dataset = {
        'train': train_samples,
        'validation': val_samples,
        'statistics': {
            'train': {
                'total': len(train_samples),
                'positive': len(train_pos),
                'negative': len(train_neg),
                'positive_ratio': len(train_pos) / len(train_samples) if train_samples else 0
            },
            'validation': {
                'total': len(val_samples),
                'positive': len(val_pos),
                'negative': len(val_neg),
                'positive_ratio': len(val_pos) / len(val_samples) if val_samples else 0
            },
            'deduplication': {
                'original_positives': len(positives) + (len(positives) - len(deduplicate_samples(positives))),
                'unique_positives': len(positives),
                'original_negatives': len(negatives) + (len(negatives) - len(deduplicate_samples(negatives))),
                'unique_negatives': len(negatives)
            }
        }
    }
    
    logger.info("\nDataset Statistics:")
    logger.info(f"  Train: {len(train_samples)} samples")
    logger.info(f"    - Positive (Whitelist): {len(train_pos)} ({len(train_pos)/len(train_samples)*100:.1f}%)")
    logger.info(f"    - Negative: {len(train_neg)} ({len(train_neg)/len(train_samples)*100:.1f}%)")
    logger.info(f"  Validation: {len(val_samples)} samples")
    logger.info(f"    - Positive (Whitelist): {len(val_pos)} ({len(val_pos)/len(val_samples)*100:.1f}%)")
    logger.info(f"    - Negative: {len(val_neg)} ({len(val_neg)/len(val_samples)*100:.1f}%)")
    
    return dataset


def save_dataset(dataset: Dict[str, Any], output_dir: Path):
    """Save dataset."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # JSON
    with open(output_dir / 'dataset.json', 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    
    # JSONL
    for split in ['train', 'validation']:
        path = output_dir / f'{split}.jsonl'
        with open(path, 'w', encoding='utf-8') as f:
            for sample in dataset[split]:
                f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    # Statistics
    with open(output_dir / 'statistics.json', 'w', encoding='utf-8') as f:
        json.dump(dataset['statistics'], f, indent=2, ensure_ascii=False)
    
    logger.info(f"\nDataset saved to: {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Fix Data Leakage in Whitelist Dataset")
    parser.add_argument(
        "--input-dir",
        type=str,
        default="data/adversarial_training/whitelist_module",
        help="Input directory with existing dataset"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/adversarial_training/whitelist_module_fixed",
        help="Output directory for fixed dataset"
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Train/Validation split ratio"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("FIX DATA LEAKAGE - WHITELIST MODULE DATASET")
    logger.info("="*80)
    logger.info(f"Input: {args.input_dir}")
    logger.info(f"Output: {args.output_dir}")
    logger.info(f"Train Ratio: {args.train_ratio}")
    logger.info(f"Seed: {args.seed}")
    logger.info("="*80)
    
    # Load existing dataset
    input_dir = Path(args.input_dir)
    logger.info("\n📂 Loading existing dataset...")
    
    train_samples = load_jsonl(input_dir / 'train.jsonl')
    val_samples = load_jsonl(input_dir / 'validation.jsonl')
    
    logger.info(f"  Train: {len(train_samples)} samples")
    logger.info(f"  Validation: {len(val_samples)} samples")
    
    # Combine all samples
    all_samples = train_samples + val_samples
    
    # Separate by label
    positives = [s for s in all_samples if s.get('label') == 1]
    negatives = [s for s in all_samples if s.get('label') == 0]
    
    logger.info(f"\n📊 Original distribution:")
    logger.info(f"  Positive (Whitelist): {len(positives)}")
    logger.info(f"  Negative: {len(negatives)}")
    logger.info(f"  Total: {len(all_samples)}")
    
    # Create clean split
    logger.info("\n🔧 Creating clean split...")
    dataset = create_clean_split(
        positives=positives,
        negatives=negatives,
        train_ratio=args.train_ratio,
        seed=args.seed
    )
    
    # Verify no overlap
    logger.info("\n🔍 Verifying no overlap...")
    train_texts = {text_hash(s.get('text', '')) for s in dataset['train']}
    val_texts = {text_hash(s.get('text', '')) for s in dataset['validation']}
    overlap = train_texts.intersection(val_texts)
    
    if overlap:
        logger.error(f"❌ KRITISCH: {len(overlap)} Samples überlappen noch immer!")
        return 1
    else:
        logger.info("✅ Keine Überlappung zwischen Train und Val bestätigt!")
    
    # Save
    logger.info("\n💾 Saving fixed dataset...")
    save_dataset(dataset, Path(args.output_dir))
    
    logger.info("\n" + "="*80)
    logger.info("✅ Dataset fix complete!")
    logger.info("="*80)
    logger.info("\nNext steps:")
    logger.info("  1. Run data leakage check on fixed dataset")
    logger.info("  2. Retrain Whitelist Classifier with fixed dataset")
    logger.info("  3. Re-run validation")
    
    return 0


if __name__ == "__main__":
    exit(main())

