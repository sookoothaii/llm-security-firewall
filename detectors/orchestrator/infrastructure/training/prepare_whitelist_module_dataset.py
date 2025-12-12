"""
Whitelist-Modul Dataset Preparation

Erstellt ein binäres Klassifikations-Dataset für das Whitelist-Modul:
- Positive: Whitelist-Cases (technical_question, best_practice, etc.)
- Negative: Malicious + normale benign (nicht Whitelist)

Usage:
    python -m detectors.orchestrator.infrastructure.training.prepare_whitelist_module_dataset \
        --v2-fps data/adversarial_training/v3_preparation/v2_false_positives_analysis_v3_training.json \
        --malicious data/adversarial_training/code_intent_train_adversarial_v2.jsonl \
        --output data/adversarial_training/whitelist_module/
"""

import sys
import json
import logging
import argparse
import random
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_v2_false_positives(fp_analysis_path: Path) -> List[Dict[str, Any]]:
    """Load V2 False Positives (Whitelist-Positive Samples)."""
    logger.info(f"Loading V2 False Positives from: {fp_analysis_path}")
    
    with open(fp_analysis_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    whitelist_positives = []
    for fp in data.get('v2_false_positives', []):
        whitelist_positives.append({
            'text': fp['text'],
            'label': 1,  # Positive (Whitelist)
            'category': fp.get('category', 'unknown'),
            'subcategory': fp.get('subcategory', 'unknown'),
            'pattern': fp.get('pattern', 'technical_question')
        })
    
    logger.info(f"Loaded {len(whitelist_positives)} whitelist positive samples")
    return whitelist_positives


def augment_whitelist_samples(
    base_samples: List[Dict],
    n_additional: int = 200
) -> List[Dict]:
    """Augment whitelist samples with variations."""
    logger.info(f"Augmenting {len(base_samples)} samples to {len(base_samples) + n_additional}...")
    
    augmented = base_samples.copy()
    
    # Templates für verschiedene Whitelist-Kategorien
    templates = {
        'technical_question': [
            "What is {term}?",
            "How does {term} work?",
            "Explain {term}",
            "What are the benefits of {term}?",
            "How do I use {term}?",
            "What is the difference between {term1} and {term2}?",
            "Can you explain {term} to me?",
            "I need help understanding {term}"
        ],
        'best_practice': [
            "What are best practices for {term}?",
            "How should I implement {term}?",
            "What is the recommended way to use {term}?",
            "Show me best practices for {term}",
            "What are the best practices when working with {term}?"
        ],
        'educational': [
            "I'm learning about {term}",
            "Can you teach me about {term}?",
            "I want to understand {term} better",
            "What should I know about {term}?",
            "Explain {term} for beginners"
        ]
    }
    
    # Technische Begriffe für Augmentation
    tech_terms = [
        'SQL', 'Docker', 'Kubernetes', 'Python', 'JavaScript', 'React',
        'API', 'REST', 'GraphQL', 'Database', 'PostgreSQL', 'MongoDB',
        'Git', 'CI/CD', 'DevOps', 'Microservices', 'Docker', 'Kubernetes',
        'AWS', 'Cloud', 'Security', 'Authentication', 'Authorization',
        'Encryption', 'HTTPS', 'SSL', 'TLS', 'OAuth', 'JWT'
    ]
    
    for i in range(n_additional):
        # Wähle zufällige Kategorie
        category = random.choice(list(templates.keys()))
        template = random.choice(templates[category])
        
        # Fülle Template
        if '{term1}' in template and '{term2}' in template:
            term1 = random.choice(tech_terms)
            term2 = random.choice([t for t in tech_terms if t != term1])
            text = template.format(term1=term1, term2=term2)
        elif '{term}' in template:
            term = random.choice(tech_terms)
            text = template.format(term=term)
        else:
            text = template
        
        augmented.append({
            'text': text,
            'label': 1,  # Positive (Whitelist)
            'category': category,
            'subcategory': 'augmented',
            'pattern': category
        })
    
    logger.info(f"Augmented to {len(augmented)} samples")
    logger.info(f"  Categories: {dict(Counter(s['category'] for s in augmented))}")
    
    return augmented


def load_malicious_samples(malicious_path: Path) -> List[Dict[str, Any]]:
    """Load malicious samples (Negative)."""
    logger.info(f"Loading malicious samples from: {malicious_path}")
    
    malicious_samples = []
    
    if malicious_path.suffix == '.jsonl':
        with open(malicious_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    malicious_samples.append({
                        'text': record.get('text', record.get('input', '')),
                        'label': 0,  # Negative (Nicht Whitelist)
                        'category': 'malicious',
                        'subcategory': record.get('category', 'malicious')
                    })
    else:
        with open(malicious_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for record in data:
                malicious_samples.append({
                    'text': record.get('text', record.get('input', '')),
                    'label': 0,
                    'category': 'malicious',
                    'subcategory': record.get('category', 'malicious')
                })
    
    logger.info(f"Loaded {len(malicious_samples)} malicious samples")
    return malicious_samples


def generate_normal_benign(
    n_samples: int = 200,
    seed: int = 42
) -> List[Dict[str, Any]]:
    """Generate normal benign samples (not whitelist)."""
    random.seed(seed)
    
    templates = {
        'small_talk': [
            "Hello, how are you?",
            "Thanks for your help!",
            "Have a great day!",
            "I appreciate it.",
            "That's interesting.",
            "Good to know!",
            "I understand now."
        ],
        'feedback': [
            "The service works well.",
            "I'm satisfied with the results.",
            "This is exactly what I needed.",
            "I would recommend this.",
            "The interface is user-friendly."
        ],
        'general_questions': [
            "What are your business hours?",
            "Where is your office?",
            "What payment methods do you accept?",
            "How long is the trial period?",
            "What is your refund policy?",
            "Do you offer discounts?",
            "Can I get a demo?"
        ]
    }
    
    normal_benign = []
    categories = list(templates.keys())
    
    for i in range(n_samples):
        category = random.choice(categories)
        template = random.choice(templates[category])
        
        # Leichte Variation
        text = template
        if random.random() < 0.3:
            text = text.lower()
        if random.random() < 0.2:
            text = text + " Thanks!"
        
        normal_benign.append({
            'text': text,
            'label': 0,  # Negative (Nicht Whitelist)
            'category': category,
            'subcategory': 'normal_benign'
        })
    
    logger.info(f"Generated {len(normal_benign)} normal benign samples")
    logger.info(f"  Categories: {dict(Counter(s['category'] for s in normal_benign))}")
    
    return normal_benign


def create_dataset(
    positives: List[Dict],
    negatives: List[Dict],
    train_ratio: float = 0.8
) -> Dict[str, Any]:
    """Create train/validation split."""
    logger.info("Creating dataset...")
    
    # Shuffle
    random.shuffle(positives)
    random.shuffle(negatives)
    
    # Split
    n_pos_train = int(len(positives) * train_ratio)
    n_neg_train = int(len(negatives) * train_ratio)
    
    train_pos = positives[:n_pos_train]
    val_pos = positives[n_pos_train:]
    
    train_neg = negatives[:n_neg_train]
    val_neg = negatives[n_neg_train:]
    
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
    parser = argparse.ArgumentParser(description="Prepare Whitelist Module Dataset")
    parser.add_argument(
        "--v2-fps",
        type=str,
        required=True,
        help="Path to V2 false positives JSON"
    )
    parser.add_argument(
        "--malicious",
        type=str,
        required=True,
        help="Path to malicious samples (JSONL or JSON)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/adversarial_training/whitelist_module",
        help="Output directory"
    )
    parser.add_argument(
        "--augment-positives",
        type=int,
        default=200,
        help="Number of additional positive samples to generate"
    )
    parser.add_argument(
        "--normal-benign",
        type=int,
        default=200,
        help="Number of normal benign (negative) samples to generate"
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
    random.seed(args.seed)
    
    logger.info("="*80)
    logger.info("WHITELIST MODULE DATASET PREPARATION")
    logger.info("="*80)
    
    # Load data
    logger.info("\nLoading data...")
    base_positives = load_v2_false_positives(Path(args.v2_fps))
    positives = augment_whitelist_samples(base_positives, n_additional=args.augment_positives)
    
    malicious = load_malicious_samples(Path(args.malicious))
    normal_benign = generate_normal_benign(n_samples=args.normal_benign, seed=args.seed)
    negatives = malicious + normal_benign
    
    # Create dataset
    logger.info("\nCreating dataset...")
    dataset = create_dataset(
        positives=positives,
        negatives=negatives,
        train_ratio=args.train_ratio
    )
    
    # Save
    logger.info("\nSaving dataset...")
    save_dataset(dataset, Path(args.output))
    
    logger.info("\n" + "="*80)
    logger.info("✅ Dataset preparation complete!")
    logger.info("="*80)
    logger.info("\nNext step: Train Whitelist Classifier")

if __name__ == "__main__":
    main()

