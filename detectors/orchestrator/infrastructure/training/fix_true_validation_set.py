"""
Fix True Validation Set - Remove Overlap with Training Data

Entfernt Samples aus True Validation Set, die auch im Train/Val Set sind.

Usage:
    python -m detectors.orchestrator.infrastructure.training.fix_true_validation_set \
        --true-validation data/adversarial_training/code_intent_true_validation.jsonl \
        --whitelist-train data/adversarial_training/whitelist_module_fixed/train.jsonl \
        --whitelist-val data/adversarial_training/whitelist_module_fixed/validation.jsonl \
        --output data/adversarial_training/code_intent_true_validation_fixed.jsonl
"""

import sys
import json
import logging
import argparse
import hashlib
from pathlib import Path
from typing import List, Dict, Set

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


def load_jsonl(path: Path) -> List[Dict]:
    """Load JSONL file."""
    samples = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


def extract_text_hashes(samples: List[Dict]) -> Set[str]:
    """Extract text hashes from samples."""
    hashes = set()
    for sample in samples:
        text = sample.get('text', sample.get('input', ''))
        if text:
            hashes.add(text_hash(text))
    return hashes


def main():
    parser = argparse.ArgumentParser(description="Fix True Validation Set")
    parser.add_argument(
        "--true-validation",
        type=str,
        required=True,
        help="Path to True Validation Set (JSONL)"
    )
    parser.add_argument(
        "--whitelist-train",
        type=str,
        required=True,
        help="Path to Whitelist Train Set (JSONL)"
    )
    parser.add_argument(
        "--whitelist-val",
        type=str,
        required=True,
        help="Path to Whitelist Val Set (JSONL)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/adversarial_training/code_intent_true_validation_fixed.jsonl",
        help="Output path for fixed True Validation Set"
    )
    parser.add_argument(
        "--v2-fps",
        type=str,
        help="Path to V2 False Positives JSON (optional, to exclude)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("FIX TRUE VALIDATION SET - REMOVE OVERLAP")
    logger.info("="*80)
    logger.info(f"True Validation: {args.true_validation}")
    logger.info(f"Whitelist Train: {args.whitelist_train}")
    logger.info(f"Whitelist Val: {args.whitelist_val}")
    logger.info(f"Output: {args.output}")
    logger.info("="*80)
    
    # Load datasets
    logger.info("\n📂 Loading datasets...")
    true_val_samples = load_jsonl(Path(args.true_validation))
    train_samples = load_jsonl(Path(args.whitelist_train))
    val_samples = load_jsonl(Path(args.whitelist_val))
    
    logger.info(f"  True Validation: {len(true_val_samples)} samples")
    logger.info(f"  Whitelist Train: {len(train_samples)} samples")
    logger.info(f"  Whitelist Val: {len(val_samples)} samples")
    
    # Load V2 FPs if provided
    v2_fps_hashes = set()
    if args.v2_fps:
        import json as json_module
        with open(args.v2_fps, 'r', encoding='utf-8') as f:
            v2_fps_data = json_module.load(f)
        v2_fps = v2_fps_data.get('v2_false_positives', [])
        v2_fps_hashes = extract_text_hashes(v2_fps)
        logger.info(f"  V2 False Positives: {len(v2_fps)} samples")
    
    # Extract hashes from train and val
    logger.info("\n🔍 Extracting text hashes...")
    train_hashes = extract_text_hashes(train_samples)
    val_hashes = extract_text_hashes(val_samples)
    train_val_hashes = train_hashes.union(val_hashes)
    
    logger.info(f"  Train hashes: {len(train_hashes)}")
    logger.info(f"  Val hashes: {len(val_hashes)}")
    logger.info(f"  Train+Val hashes: {len(train_val_hashes)}")
    logger.info(f"  V2 FP hashes: {len(v2_fps_hashes)}")
    
    # Filter True Validation Set
    logger.info("\n🔧 Filtering True Validation Set...")
    original_count = len(true_val_samples)
    filtered_samples = []
    removed_train = 0
    removed_val = 0
    removed_v2_fp = 0
    
    for sample in true_val_samples:
        text = sample.get('text', sample.get('input', ''))
        if not text:
            continue
        
        h = text_hash(text)
        
        # Check if in train or val
        if h in train_hashes:
            removed_train += 1
            continue
        if h in val_hashes:
            removed_val += 1
            continue
        if v2_fps_hashes and h in v2_fps_hashes:
            removed_v2_fp += 1
            continue
        
        # Keep sample
        filtered_samples.append(sample)
    
    removed_total = removed_train + removed_val + removed_v2_fp
    kept_count = len(filtered_samples)
    
    logger.info(f"\n📊 Filtering Results:")
    logger.info(f"  Original: {original_count} samples")
    logger.info(f"  Removed (Train overlap): {removed_train}")
    logger.info(f"  Removed (Val overlap): {removed_val}")
    logger.info(f"  Removed (V2 FP overlap): {removed_v2_fp}")
    logger.info(f"  Removed (Total): {removed_total} ({removed_total/original_count*100:.1f}%)")
    logger.info(f"  Kept: {kept_count} ({kept_count/original_count*100:.1f}%)")
    
    # Verify no overlap
    logger.info("\n🔍 Verifying no overlap...")
    filtered_hashes = extract_text_hashes(filtered_samples)
    overlap_train = filtered_hashes.intersection(train_hashes)
    overlap_val = filtered_hashes.intersection(val_hashes)
    overlap_v2 = filtered_hashes.intersection(v2_fps_hashes) if v2_fps_hashes else set()
    
    if overlap_train or overlap_val or overlap_v2:
        logger.error(f"❌ KRITISCH: Noch {len(overlap_train) + len(overlap_val) + len(overlap_v2)} Überlappungen!")
        return 1
    else:
        logger.info("✅ Keine Überlappung bestätigt!")
    
    # Save filtered True Validation Set
    logger.info("\n💾 Saving fixed True Validation Set...")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for sample in filtered_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    logger.info(f"✅ Saved to: {output_path}")
    
    # Statistics
    malicious_count = sum(1 for s in filtered_samples if s.get('label') == 1)
    benign_count = len(filtered_samples) - malicious_count
    
    logger.info("\n📊 Final Statistics:")
    logger.info(f"  Total: {kept_count} samples")
    logger.info(f"  Malicious: {malicious_count} ({malicious_count/kept_count*100:.1f}%)")
    logger.info(f"  Benign: {benign_count} ({benign_count/kept_count*100:.1f}%)")
    
    logger.info("\n" + "="*80)
    logger.info("✅ True Validation Set fix complete!")
    logger.info("="*80)
    
    return 0


if __name__ == "__main__":
    exit(main())

