"""
V3 Whitelist-Learner Dataset Preparation

Erstellt ein whitelist-zentriertes Dataset für V3 Training, das V2.1's Defensivlogik internalisiert.

Konzept:
- Whitelist-Cases (V2 False Positives) = 70% der benign Samples
- Non-Whitelist benign Cases = 30% der benign Samples
- Malicious Cases = Alle verfügbaren Samples

Usage:
    python -m detectors.orchestrator.infrastructure.training.prepare_v3_whitelist_dataset \
        --v2-fps data/adversarial_training/v2_false_positives_analysis_v3_training.json \
        --malicious data/adversarial_training/code_intent_malicious.jsonl \
        --output data/adversarial_training/v3_whitelist_learner/
"""

import sys
import json
import logging
import argparse
import random
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import re

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_v2_false_positives(fp_analysis_path: Path) -> List[Dict[str, Any]]:
    """
    Lade V2 False Positives (Whitelist-Cases).
    
    Returns:
        List of whitelist cases with pattern labels
    """
    logger.info(f"Loading V2 False Positives from: {fp_analysis_path}")
    
    with open(fp_analysis_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    whitelist_cases = []
    for fp in data.get('v2_false_positives', []):
        # Kategorisiere als Whitelist-Pattern
        category = fp.get('category', 'unknown')
        subcategory = fp.get('subcategory', 'unknown')
        
        # Map zu Whitelist-Patterns
        pattern = map_category_to_pattern(category, subcategory)
        
        whitelist_cases.append({
            'text': fp['text'],
            'label': 0,  # benign
            'pattern': pattern,
            'category': category,
            'subcategory': subcategory,
            'confidence': fp.get('confidence', 0.0),
            'keywords': fp.get('keywords', [])
        })
    
    logger.info(f"Loaded {len(whitelist_cases)} whitelist cases")
    logger.info(f"  Patterns: {dict(Counter(c['pattern'] for c in whitelist_cases))}")
    
    return whitelist_cases


def map_category_to_pattern(category: str, subcategory: str) -> str:
    """
    Mappe Kategorie zu Whitelist-Pattern.
    
    Patterns:
    - technical_question: Technische Fragen
    - educational: Bildungs-/Erklärungs-Content
    - best_practice: Best Practices, Tutorials
    - explanation: Konzeptionelle Erklärungen
    """
    category_lower = category.lower()
    subcategory_lower = subcategory.lower()
    
    # Technical Questions
    if 'technical' in category_lower or 'question' in category_lower:
        return 'technical_question'
    
    # Educational
    if 'educational' in category_lower or 'education' in category_lower:
        return 'educational'
    
    # Best Practices
    if 'best' in category_lower or 'practice' in category_lower or 'tutorial' in category_lower:
        return 'best_practice'
    
    # Explanation
    if 'explanation' in category_lower or 'explain' in category_lower or 'concept' in category_lower:
        return 'explanation'
    
    # Default: technical_question (meistens)
    return 'technical_question'


def load_malicious_cases(malicious_path: Path) -> List[Dict[str, Any]]:
    """Lade malicious Cases."""
    logger.info(f"Loading malicious cases from: {malicious_path}")
    
    malicious_cases = []
    
    if malicious_path.suffix == '.jsonl':
        with open(malicious_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    malicious_cases.append({
                        'text': record.get('text', record.get('input', '')),
                        'label': 1,  # malicious
                        'pattern': None,  # Kein Whitelist-Pattern
                        'category': record.get('category', 'malicious'),
                        'metadata': record.get('metadata', {})
                    })
    else:
        with open(malicious_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for record in data:
                malicious_cases.append({
                    'text': record.get('text', record.get('input', '')),
                    'label': 1,
                    'pattern': None,
                    'category': record.get('category', 'malicious'),
                    'metadata': record.get('metadata', {})
                })
    
    logger.info(f"Loaded {len(malicious_cases)} malicious cases")
    return malicious_cases


def generate_non_whitelist_benign(
    n_samples: int,
    existing_whitelist_texts: set,
    seed: int = 42
) -> List[Dict[str, Any]]:
    """
    Generiere realistische non-whitelist benign Cases.
    
    Kategorien:
    - general_chat: Allgemeine Konversation
    - feedback: Feedback, Reviews
    - support: Support-Anfragen
    - non_technical: Nicht-technische Fragen
    """
    random.seed(seed)
    
    # Templates für realistische benign Cases
    templates = {
        'general_chat': [
            "Hello, how are you?",
            "Thanks for your help!",
            "I appreciate the assistance.",
            "Have a great day!",
            "That's interesting, tell me more.",
            "I understand now, thank you.",
            "Can you help me with something else?",
            "That makes sense.",
            "I'll try that approach.",
            "Good to know!"
        ],
        'feedback': [
            "The service works well for me.",
            "I'm satisfied with the results.",
            "This is exactly what I needed.",
            "The interface is user-friendly.",
            "I would recommend this to others.",
            "The documentation is clear.",
            "The response time is good.",
            "I'm happy with the quality.",
            "This meets my expectations.",
            "I'll continue using this service."
        ],
        'support': [
            "I need help with my account.",
            "Can you explain the pricing?",
            "How do I contact support?",
            "I have a billing question.",
            "Where can I find the documentation?",
            "I want to upgrade my plan.",
            "How do I cancel my subscription?",
            "I forgot my password.",
            "I need to update my email.",
            "Can you help me with setup?"
        ],
        'non_technical': [
            "What are your business hours?",
            "Where is your office located?",
            "What payment methods do you accept?",
            "How long is the trial period?",
            "What is your refund policy?",
            "Do you offer discounts?",
            "Can I get a demo?",
            "What languages do you support?",
            "Is there a mobile app?",
            "How do I get started?"
        ]
    }
    
    non_whitelist_cases = []
    categories = list(templates.keys())
    
    for i in range(n_samples):
        category = random.choice(categories)
        template = random.choice(templates[category])
        
        # Variiere Template leicht
        text = vary_template(template)
        
        # Stelle sicher, dass es nicht in Whitelist ist
        if text not in existing_whitelist_texts:
            non_whitelist_cases.append({
                'text': text,
                'label': 0,  # benign
                'pattern': None,  # Kein Whitelist-Pattern
                'category': category,
                'subcategory': 'non_whitelist',
                'metadata': {'generated': True, 'template_category': category}
            })
    
    logger.info(f"Generated {len(non_whitelist_cases)} non-whitelist benign cases")
    logger.info(f"  Categories: {dict(Counter(c['category'] for c in non_whitelist_cases))}")
    
    return non_whitelist_cases


def vary_template(template: str) -> str:
    """Variiere Template leicht für Diversität."""
    variations = [
        lambda t: t,  # Original
        lambda t: t.replace("?", "."),
        lambda t: t.replace("!", "."),
        lambda t: t.lower(),
        lambda t: t.capitalize(),
        lambda t: t + " Thanks!",
        lambda t: "Hi, " + t.lower(),
    ]
    
    import random
    variation = random.choice(variations)
    return variation(template)


def create_whitelist_dataset(
    whitelist_cases: List[Dict],
    malicious_cases: List[Dict],
    non_whitelist_benign: List[Dict],
    train_ratio: float = 0.8,
    whitelist_ratio: float = 0.7
) -> Dict[str, Any]:
    """
    Erstelle whitelist-zentriertes Dataset.
    
    Verteilung:
    - Train: 80%
    - Validation: 20%
    
    Benign Distribution (in Training):
    - Whitelist: 70%
    - Non-Whitelist: 30%
    """
    logger.info("Creating whitelist-zentriertes Dataset...")
    
    # Shuffle
    random.shuffle(whitelist_cases)
    random.shuffle(malicious_cases)
    random.shuffle(non_whitelist_benign)
    
    # Split Whitelist Cases
    n_whitelist_train = int(len(whitelist_cases) * train_ratio)
    whitelist_train = whitelist_cases[:n_whitelist_train]
    whitelist_val = whitelist_cases[n_whitelist_train:]
    
    # Split Malicious Cases
    n_malicious_train = int(len(malicious_cases) * train_ratio)
    malicious_train = malicious_cases[:n_malicious_train]
    malicious_val = malicious_cases[n_malicious_train:]
    
    # Berechne Non-Whitelist Benign für Training
    # Ziel: 70% Whitelist, 30% Non-Whitelist in benign Training
    n_whitelist_train_total = len(whitelist_train)
    n_non_whitelist_train = int(n_whitelist_train_total * (1 - whitelist_ratio) / whitelist_ratio)
    non_whitelist_train = non_whitelist_benign[:n_non_whitelist_train]
    
    # Non-Whitelist für Validation
    n_non_whitelist_val = int(len(whitelist_val) * (1 - whitelist_ratio) / whitelist_ratio)
    non_whitelist_val = non_whitelist_benign[n_non_whitelist_train:n_non_whitelist_train + n_non_whitelist_val]
    
    # Kombiniere Training
    train_benign = whitelist_train + non_whitelist_train
    train_malicious = malicious_train
    
    # Kombiniere Validation
    val_benign = whitelist_val + non_whitelist_val
    val_malicious = malicious_val
    
    # Shuffle final
    random.shuffle(train_benign)
    random.shuffle(train_malicious)
    random.shuffle(val_benign)
    random.shuffle(val_malicious)
    
    dataset = {
        'train': {
            'malicious': train_malicious,
            'benign': {
                'whitelist': whitelist_train,
                'non_whitelist': non_whitelist_train
            }
        },
        'validation': {
            'malicious': val_malicious,
            'benign': {
                'whitelist': whitelist_val,
                'non_whitelist': non_whitelist_val
            }
        },
        'statistics': {
            'train': {
                'malicious': len(train_malicious),
                'benign_total': len(train_benign),
                'benign_whitelist': len(whitelist_train),
                'benign_non_whitelist': len(non_whitelist_train),
                'whitelist_ratio': len(whitelist_train) / len(train_benign) if train_benign else 0
            },
            'validation': {
                'malicious': len(val_malicious),
                'benign_total': len(val_benign),
                'benign_whitelist': len(whitelist_val),
                'benign_non_whitelist': len(non_whitelist_val),
                'whitelist_ratio': len(whitelist_val) / len(val_benign) if val_benign else 0
            }
        }
    }
    
    logger.info("\nDataset Statistics:")
    logger.info(f"  Train:")
    logger.info(f"    Malicious: {len(train_malicious)}")
    logger.info(f"    Benign Total: {len(train_benign)}")
    logger.info(f"      - Whitelist: {len(whitelist_train)} ({len(whitelist_train)/len(train_benign)*100:.1f}%)")
    logger.info(f"      - Non-Whitelist: {len(non_whitelist_train)} ({len(non_whitelist_train)/len(train_benign)*100:.1f}%)")
    logger.info(f"  Validation:")
    logger.info(f"    Malicious: {len(val_malicious)}")
    logger.info(f"    Benign Total: {len(val_benign)}")
    logger.info(f"      - Whitelist: {len(whitelist_val)} ({len(whitelist_val)/len(val_benign)*100:.1f}%)")
    logger.info(f"      - Non-Whitelist: {len(non_whitelist_val)} ({len(non_whitelist_val)/len(val_benign)*100:.1f}%)")
    
    return dataset


def save_dataset(dataset: Dict[str, Any], output_dir: Path):
    """Speichere Dataset in verschiedenen Formaten."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Vollständiges Dataset (JSON)
    with open(output_dir / 'dataset.json', 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    
    # 2. Training JSONL (für Training)
    train_path = output_dir / 'train.jsonl'
    with open(train_path, 'w', encoding='utf-8') as f:
        # Malicious
        for sample in dataset['train']['malicious']:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        # Benign (Whitelist + Non-Whitelist)
        for sample in dataset['train']['benign']['whitelist']:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        for sample in dataset['train']['benign']['non_whitelist']:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    # 3. Validation JSONL
    val_path = output_dir / 'validation.jsonl'
    with open(val_path, 'w', encoding='utf-8') as f:
        # Malicious
        for sample in dataset['validation']['malicious']:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        # Benign
        for sample in dataset['validation']['benign']['whitelist']:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        for sample in dataset['validation']['benign']['non_whitelist']:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    # 4. Pattern Training Data (für Pattern Pre-Training)
    pattern_train_path = output_dir / 'train_patterns.jsonl'
    with open(pattern_train_path, 'w', encoding='utf-8') as f:
        for sample in dataset['train']['benign']['whitelist']:
            if sample.get('pattern'):
                pattern_sample = {
                    'text': sample['text'],
                    'pattern': sample['pattern'],
                    'category': sample.get('category', 'unknown'),
                    'subcategory': sample.get('subcategory', 'unknown')
                }
                f.write(json.dumps(pattern_sample, ensure_ascii=False) + '\n')
    
    # 5. Statistics
    stats_path = output_dir / 'statistics.json'
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(dataset['statistics'], f, indent=2, ensure_ascii=False)
    
    logger.info(f"\nDataset saved to: {output_dir}")
    logger.info(f"  - dataset.json (full)")
    logger.info(f"  - train.jsonl ({Path(train_path).stat().st_size / 1024:.1f} KB)")
    logger.info(f"  - validation.jsonl ({Path(val_path).stat().st_size / 1024:.1f} KB)")
    logger.info(f"  - train_patterns.jsonl (for pattern pre-training)")
    logger.info(f"  - statistics.json")


def main():
    parser = argparse.ArgumentParser(
        description="Prepare V3 Whitelist-Learner Dataset"
    )
    parser.add_argument(
        "--v2-fps",
        type=str,
        required=True,
        help="Path to V2 false positives analysis JSON (v3_training.json)"
    )
    parser.add_argument(
        "--malicious",
        type=str,
        required=True,
        help="Path to malicious cases (JSONL or JSON)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/adversarial_training/v3_whitelist_learner",
        help="Output directory for dataset"
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Train/Validation split ratio (default: 0.8)"
    )
    parser.add_argument(
        "--whitelist-ratio",
        type=float,
        default=0.7,
        help="Whitelist ratio in benign training samples (default: 0.7)"
    )
    parser.add_argument(
        "--non-whitelist-samples",
        type=int,
        default=500,
        help="Number of non-whitelist benign samples to generate (default: 500)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)"
    )
    
    args = parser.parse_args()
    
    random.seed(args.seed)
    
    logger.info("="*80)
    logger.info("V3 WHITELIST-LEARNER DATASET PREPARATION")
    logger.info("="*80)
    logger.info(f"V2 FPs: {args.v2_fps}")
    logger.info(f"Malicious: {args.malicious}")
    logger.info(f"Output: {args.output}")
    logger.info(f"Train Ratio: {args.train_ratio}")
    logger.info(f"Whitelist Ratio: {args.whitelist_ratio}")
    logger.info("="*80)
    
    # Load data
    logger.info("\nLoading data...")
    whitelist_cases = load_v2_false_positives(Path(args.v2_fps))
    malicious_cases = load_malicious_cases(Path(args.malicious))
    
    # Generate non-whitelist benign
    existing_whitelist_texts = {c['text'] for c in whitelist_cases}
    non_whitelist_benign = generate_non_whitelist_benign(
        n_samples=args.non_whitelist_samples,
        existing_whitelist_texts=existing_whitelist_texts,
        seed=args.seed
    )
    
    # Create dataset
    logger.info("\nCreating dataset...")
    dataset = create_whitelist_dataset(
        whitelist_cases=whitelist_cases,
        malicious_cases=malicious_cases,
        non_whitelist_benign=non_whitelist_benign,
        train_ratio=args.train_ratio,
        whitelist_ratio=args.whitelist_ratio
    )
    
    # Save dataset
    logger.info("\nSaving dataset...")
    save_dataset(dataset, Path(args.output))
    
    logger.info("\n" + "="*80)
    logger.info("✅ Dataset preparation complete!")
    logger.info("="*80)
    logger.info("\nNext steps:")
    logger.info("  1. Review dataset statistics in statistics.json")
    logger.info("  2. Start Pattern Pre-Training: train_pattern_embeddings.py")
    logger.info("  3. Start Main Training: train_whitelist_learner.py")


if __name__ == "__main__":
    from collections import Counter
    main()

