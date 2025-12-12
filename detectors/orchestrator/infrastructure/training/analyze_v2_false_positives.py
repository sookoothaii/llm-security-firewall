"""
V2 False Positive Analysis - Vorbereitung für V3 Training

Analysiert die False Positives von V2, um zu verstehen, was das Modell falsch versteht.
Diese Erkenntnisse werden für das V3 Training mit ausgewogenem Dataset verwendet.

Usage:
    python -m detectors.orchestrator.infrastructure.training.analyze_v2_false_positives \
        --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
        --v1-model models/code_intent_adversarial_v1/best_model.pt \
        --v2-model models/code_intent_adversarial_v2/best_model.pt \
        --output data/adversarial_training/v2_false_positives_analysis.json
"""

import sys
import json
import re
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from collections import defaultdict, Counter
import torch

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SimpleTokenizer:
    """Simple character-based tokenizer."""
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
    
    def encode(self, text: str, max_length: int = 512) -> list:
        """Encode text to token IDs."""
        tokens = [ord(c) % self.vocab_size for c in text[:max_length]]
        while len(tokens) < max_length:
            tokens.append(0)
        return tokens[:max_length]


def load_model(model_path: str, vocab_size: int = 10000, device: str = 'cpu') -> torch.nn.Module:
    """Load QuantumInspiredCNN model from checkpoint."""
    try:
        try:
            from llm_firewall.ml import QuantumInspiredCNN
        except ImportError:
            src_path = project_root / "src"
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))
            from llm_firewall.ml import QuantumInspiredCNN
    except ImportError as e:
        logger.error(f"Could not import QuantumInspiredCNN: {e}")
        raise
    
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    
    # Extract hyperparameters
    if 'hyperparameters' in checkpoint:
        hp = checkpoint['hyperparameters']
        vocab_size = hp.get('vocab_size', vocab_size)
        embedding_dim = hp.get('embedding_dim', 128)
        hidden_dims = hp.get('hidden_dims', [256, 128, 64])
        kernel_sizes = hp.get('kernel_sizes', [3, 5, 7])
        dropout = hp.get('dropout', 0.2)
    else:
        embedding_dim = 128
        hidden_dims = [256, 128, 64]
        kernel_sizes = [3, 5, 7]
        dropout = 0.2
    
    model = QuantumInspiredCNN(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        num_classes=2,
        hidden_dims=hidden_dims,
        kernel_sizes=kernel_sizes,
        dropout=dropout
    )
    
    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    else:
        model.load_state_dict(checkpoint)
    
    model = model.to(device)
    model.eval()
    
    return model


def load_validation_set(jsonl_path: Path) -> Tuple[List[Dict], List[str], List[int]]:
    """Load validation samples with metadata."""
    records = []
    samples = []
    labels = []
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                record = json.loads(line)
                records.append(record)
                samples.append(record['text'])
                labels.append(int(record['label']))
    
    return records, samples, labels


def evaluate_model_detailed(
    model: torch.nn.Module,
    samples: List[str],
    labels: List[int],
    tokenizer: SimpleTokenizer,
    device: str = 'cpu',
    max_length: int = 512
) -> List[Dict[str, Any]]:
    """Evaluate model and return detailed predictions with confidence scores."""
    model.eval()
    predictions = []
    
    with torch.no_grad():
        for text, label in zip(samples, labels):
            # Tokenize
            token_ids = tokenizer.encode(text, max_length=max_length)
            input_tensor = torch.tensor([token_ids], dtype=torch.long).to(device)
            
            # Predict
            output = model(input_tensor)
            probabilities = torch.softmax(output, dim=1)
            _, predicted = torch.max(output, 1)
            pred_label = predicted.item()
            
            # Get confidence scores for both classes
            benign_prob = probabilities[0][0].item()
            malicious_prob = probabilities[0][1].item()
            
            predictions.append({
                'text': text,
                'true_label': label,
                'predicted_label': pred_label,
                'confidence': malicious_prob if pred_label == 1 else benign_prob,
                'benign_probability': benign_prob,
                'malicious_probability': malicious_prob,
                'is_false_positive': (label == 0 and pred_label == 1),
                'is_false_negative': (label == 1 and pred_label == 0),
            })
    
    return predictions


def categorize_false_positive(text: str) -> Dict[str, Any]:
    """
    Kategorisiere einen False Positive nach Mustern.
    
    Returns:
        Dictionary mit Kategorie, Unterkategorie, Keywords und Pattern-Matches
    """
    text_lower = text.lower()
    category = "unknown"
    subcategory = "unknown"
    keywords = []
    patterns_matched = []
    confidence_reason = "unknown"
    
    # Kategorie 1: Technische Fragen (SQL, Python, etc.)
    tech_question_patterns = [
        (r'\b(what|how|explain|tell me about|describe|what is|what are)\b.*\b(sql|python|javascript|java|docker|git|rest|api|http|https|database|index|caching|dependency|environment|variable|synchronous|asynchronous)\b', 'technical_question', 'general_tech'),
        (r'\b(what|how|explain|tell me about|describe|what is|what are)\b.*\b(select|drop|update|delete|insert|union|table|database|query)\b', 'technical_question', 'sql_related'),
        (r'\b(what|how|explain|tell me about|describe|what is|what are)\b.*\b(loop|function|class|method|error|exception|branch|commit|merge)\b', 'technical_question', 'programming_concept'),
    ]
    
    for pattern, cat, subcat in tech_question_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            category = cat
            subcategory = subcat
            patterns_matched.append(pattern)
            confidence_reason = "Technical question pattern detected"
            break
    
    # Kategorie 2: Code-Beispiele in Fragen
    if category == "unknown":
        code_example_patterns = [
            (r'\b(show me|how to|example|demonstrate|write|create)\b.*\b(loop|function|code|snippet|example|for loop|while loop)\b', 'code_example_request', 'general'),
            (r'\b(show me|how to|example|demonstrate|write|create)\b.*\b(javascript|python|java|sql|bash|shell)\b', 'code_example_request', 'language_specific'),
        ]
        
        for pattern, cat, subcat in code_example_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                category = cat
                subcategory = subcat
                patterns_matched.append(pattern)
                confidence_reason = "Code example request pattern detected"
                break
    
    # Kategorie 3: Sicherheitsrelevante Begriffe ohne böswilligen Kontext
    if category == "unknown":
        security_terms = ['security', 'vulnerability', 'attack', 'exploit', 'malware', 'virus', 'firewall', 'encryption', 'authentication']
        security_in_question = any(term in text_lower for term in security_terms)
        question_markers = ['what', 'how', 'explain', 'tell me about', 'describe', 'why', 'when']
        is_question = any(marker in text_lower for marker in question_markers)
        
        if security_in_question and is_question:
            category = "security_education"
            subcategory = "general_security"
            confidence_reason = "Security-related educational question"
            keywords = [term for term in security_terms if term in text_lower]
    
    # Kategorie 4: System/API/Infrastructure Fragen
    if category == "unknown":
        system_patterns = [
            (r'\b(what|how|explain|tell me about|describe)\b.*\b(docker|kubernetes|container|orchestration|microservice|deployment|infrastructure|devops)\b', 'system_question', 'infrastructure'),
            (r'\b(what|how|explain|tell me about|describe)\b.*\b(rest|api|endpoint|http|https|request|response|authentication|authorization)\b', 'system_question', 'api'),
        ]
        
        for pattern, cat, subcat in system_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                category = cat
                subcategory = subcat
                patterns_matched.append(pattern)
                confidence_reason = "System/API question pattern detected"
                break
    
    # Kategorie 5: Best Practices / Guidelines Fragen
    if category == "unknown":
        best_practice_patterns = [
            (r'\b(best practice|guideline|recommendation|standard|convention|pattern)\b', 'best_practice_question', 'general'),
        ]
        
        for pattern, cat, subcat in best_practice_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                category = cat
                subcategory = subcat
                patterns_matched.append(pattern)
                confidence_reason = "Best practice question pattern detected"
                break
    
    # Kategorie 6: Vergleichs-/Unterschieds-Fragen
    if category == "unknown":
        comparison_patterns = [
            (r'\b(difference|compare|versus|vs|similar|different|similarity|distinction)\b', 'comparison_question', 'general'),
        ]
        
        for pattern, cat, subcat in comparison_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                category = cat
                subcategory = subcat
                patterns_matched.append(pattern)
                confidence_reason = "Comparison question pattern detected"
                break
    
    # Extrahiere Keywords
    if not keywords:
        # Technische Keywords
        tech_keywords = ['sql', 'python', 'javascript', 'java', 'docker', 'git', 'rest', 'api', 'http', 'https', 
                        'database', 'index', 'caching', 'dependency', 'environment', 'variable', 'synchronous', 
                        'asynchronous', 'select', 'drop', 'update', 'delete', 'insert', 'union', 'table', 'query',
                        'loop', 'function', 'class', 'method', 'error', 'exception', 'branch', 'commit', 'merge']
        keywords = [kw for kw in tech_keywords if kw in text_lower]
    
    return {
        'category': category,
        'subcategory': subcategory,
        'keywords': keywords,
        'patterns_matched': patterns_matched,
        'confidence_reason': confidence_reason
    }


def analyze_false_positives(
    v1_predictions: List[Dict],
    v2_predictions: List[Dict],
    validation_records: List[Dict]
) -> Dict[str, Any]:
    """
    Analysiere False Positives von V2 im Detail.
    
    Returns:
        Dictionary mit Kategorien, Statistiken und Empfehlungen
    """
    # Identifiziere False Positives
    v1_fps = [p for p in v1_predictions if p['is_false_positive']]
    v2_fps = [p for p in v2_predictions if p['is_false_positive']]
    
    # V2-spezifische FPs (nicht in V1)
    v1_fp_texts = {p['text'] for p in v1_fps}
    v2_specific_fps = [p for p in v2_fps if p['text'] not in v1_fp_texts]
    
    logger.info(f"\n{'='*80}")
    logger.info("FALSE POSITIVE ANALYSIS")
    logger.info(f"{'='*80}")
    logger.info(f"V1 False Positives: {len(v1_fps)}")
    logger.info(f"V2 False Positives: {len(v2_fps)}")
    logger.info(f"V2-spezifische FPs (neue FPs): {len(v2_specific_fps)}")
    logger.info(f"FPR V1: {len(v1_fps) / len([p for p in v1_predictions if p['true_label'] == 0]) * 100:.2f}%")
    logger.info(f"FPR V2: {len(v2_fps) / len([p for p in v2_predictions if p['true_label'] == 0]) * 100:.2f}%")
    
    # Kategorisiere alle V2 FPs
    categorized_fps = []
    for fp in v2_fps:
        categorization = categorize_false_positive(fp['text'])
        categorized_fps.append({
            **fp,
            **categorization,
            'is_v2_specific': fp['text'] not in v1_fp_texts
        })
    
    # Statistiken nach Kategorie
    category_stats = defaultdict(lambda: {'count': 0, 'v2_specific': 0, 'avg_confidence': 0.0, 'examples': [], 'subcategory': 'unknown'})
    for fp in categorized_fps:
        cat = fp['category']
        category_stats[cat]['count'] += 1
        if 'subcategory' in fp:
            category_stats[cat]['subcategory'] = fp['subcategory']
        if fp['is_v2_specific']:
            category_stats[cat]['v2_specific'] += 1
        category_stats[cat]['avg_confidence'] += fp['malicious_probability']
        if len(category_stats[cat]['examples']) < 5:
            category_stats[cat]['examples'].append({
                'text': fp['text'][:200],  # Truncate for readability
                'confidence': fp['malicious_probability'],
                'is_v2_specific': fp['is_v2_specific']
            })
    
    # Berechne Durchschnitte
    for cat in category_stats:
        if category_stats[cat]['count'] > 0:
            category_stats[cat]['avg_confidence'] /= category_stats[cat]['count']
    
    # Confidence Score Analyse
    confidence_ranges = {
        'high_confidence': [p for p in v2_fps if p['malicious_probability'] >= 0.8],
        'medium_confidence': [p for p in v2_fps if 0.5 <= p['malicious_probability'] < 0.8],
        'low_confidence': [p for p in v2_fps if p['malicious_probability'] < 0.5],
    }
    
    # Keyword-Frequenz Analyse
    all_keywords = []
    for fp in categorized_fps:
        all_keywords.extend(fp['keywords'])
    keyword_freq = Counter(all_keywords)
    
    # V3 Training Empfehlungen
    v3_recommendations = {
        'critical_categories': [],
        'training_samples_needed': {},
        'data_balance_suggestions': {}
    }
    
    # Identifiziere kritische Kategorien (viele FPs, hohe Confidence)
    for cat, stats in category_stats.items():
        if stats['count'] >= 5 and stats['avg_confidence'] >= 0.7:
            v3_recommendations['critical_categories'].append({
                'category': cat,
                'count': stats['count'],
                'avg_confidence': stats['avg_confidence'],
                'priority': 'high' if stats['count'] >= 10 else 'medium'
            })
            v3_recommendations['training_samples_needed'][cat] = {
                'min_samples': max(20, stats['count'] * 2),
                'recommended_samples': max(50, stats['count'] * 5),
                'note': f"Need {stats['count']} benign examples to counter {stats['count']} FPs"
            }
    
    # Sortiere nach Priorität
    v3_recommendations['critical_categories'].sort(key=lambda x: (x['count'], x['avg_confidence']), reverse=True)
    
    return {
        'summary': {
            'v1_fp_count': len(v1_fps),
            'v2_fp_count': len(v2_fps),
            'v2_specific_fp_count': len(v2_specific_fps),
            'v1_fpr': len(v1_fps) / len([p for p in v1_predictions if p['true_label'] == 0]) * 100,
            'v2_fpr': len(v2_fps) / len([p for p in v2_predictions if p['true_label'] == 0]) * 100,
        },
        'category_statistics': dict(category_stats),
        'confidence_analysis': {
            'high_confidence_count': len(confidence_ranges['high_confidence']),
            'medium_confidence_count': len(confidence_ranges['medium_confidence']),
            'low_confidence_count': len(confidence_ranges['low_confidence']),
            'avg_confidence': sum(p['malicious_probability'] for p in v2_fps) / len(v2_fps) if v2_fps else 0.0,
        },
        'keyword_frequency': dict(keyword_freq.most_common(20)),
        'v2_specific_false_positives': [
            {
                'text': fp['text'],
                'category': fp['category'],
                'subcategory': fp['subcategory'],
                'confidence': fp['malicious_probability'],
                'keywords': fp['keywords']
            }
            for fp in categorized_fps if fp['is_v2_specific']
        ][:50],  # Top 50 für Analyse
        'v3_training_recommendations': v3_recommendations,
        'all_categorized_fps': categorized_fps  # Für detaillierte Analyse
    }


def print_analysis_report(analysis: Dict[str, Any]):
    """Drucke einen formatierten Analyse-Report."""
    print("\n" + "="*80)
    print("V2 FALSE POSITIVE ANALYSIS REPORT")
    print("="*80)
    
    summary = analysis['summary']
    print(f"\n[SUMMARY]")
    print(f"  V1 False Positives: {summary['v1_fp_count']}")
    print(f"  V2 False Positives: {summary['v2_fp_count']}")
    print(f"  V2-spezifische FPs: {summary['v2_specific_fp_count']}")
    print(f"  V1 FPR: {summary['v1_fpr']:.2f}%")
    print(f"  V2 FPR: {summary['v2_fpr']:.2f}%")
    print(f"  FPR Degradation: {summary['v2_fpr'] - summary['v1_fpr']:.2f}%")
    
    print(f"\n[CONFIDENCE ANALYSIS]")
    conf_analysis = analysis['confidence_analysis']
    print(f"  High Confidence (>=0.8): {conf_analysis['high_confidence_count']}")
    print(f"  Medium Confidence (0.5-0.8): {conf_analysis['medium_confidence_count']}")
    print(f"  Low Confidence (<0.5): {conf_analysis['low_confidence_count']}")
    print(f"  Average Confidence: {conf_analysis['avg_confidence']:.3f}")
    
    print(f"\n[CATEGORY STATISTICS]")
    for cat, stats in sorted(analysis['category_statistics'].items(), key=lambda x: x[1]['count'], reverse=True):
        subcat = stats.get('subcategory', 'unknown')
        print(f"\n  {cat.upper()} ({subcat}):")
        print(f"    Count: {stats['count']} (V2-spezifisch: {stats['v2_specific']})")
        print(f"    Avg Confidence: {stats['avg_confidence']:.3f}")
        print(f"    Examples:")
        for ex in stats['examples'][:3]:
            print(f"      - {ex['text'][:100]}... (conf: {ex['confidence']:.3f}, V2-specific: {ex['is_v2_specific']})")
    
    print(f"\n[TOP KEYWORDS IN FALSE POSITIVES]")
    for keyword, count in list(analysis['keyword_frequency'].items())[:10]:
        print(f"  {keyword}: {count}x")
    
    print(f"\n[V3 TRAINING RECOMMENDATIONS]")
    recs = analysis['v3_training_recommendations']
    print(f"\n  Critical Categories (Priority):")
    for cat_info in recs['critical_categories']:
        print(f"    - {cat_info['category']}: {cat_info['count']} FPs, avg conf {cat_info['avg_confidence']:.3f} [{cat_info['priority']} priority]")
    
    print(f"\n  Training Samples Needed:")
    for cat, sample_info in recs['training_samples_needed'].items():
        print(f"    - {cat}: {sample_info['min_samples']}-{sample_info['recommended_samples']} samples")
        print(f"      Note: {sample_info['note']}")
    
    print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(description="Analyze V2 False Positives for V3 Training")
    parser.add_argument(
        "--validation-set",
        type=str,
        required=True,
        help="Path to true validation set JSONL"
    )
    parser.add_argument(
        "--v1-model",
        type=str,
        required=True,
        help="Path to V1 model checkpoint"
    )
    parser.add_argument(
        "--v2-model",
        type=str,
        required=True,
        help="Path to V2 model checkpoint"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/adversarial_training/v2_false_positives_analysis.json",
        help="Output JSON path for analysis results"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("V2 FALSE POSITIVE ANALYSIS")
    logger.info("="*80)
    logger.info(f"Validation Set: {args.validation_set}")
    logger.info(f"V1 Model: {args.v1_model}")
    logger.info(f"V2 Model: {args.v2_model}")
    logger.info(f"Device: {args.device}")
    logger.info("="*80)
    
    # Load validation set
    logger.info("\nLoading validation set...")
    validation_records, validation_samples, validation_labels = load_validation_set(Path(args.validation_set))
    logger.info(f"Loaded {len(validation_samples)} samples")
    logger.info(f"  - Malicious: {sum(validation_labels)}")
    logger.info(f"  - Benign: {len(validation_labels) - sum(validation_labels)}")
    
    # Load models
    logger.info("\nLoading models...")
    tokenizer = SimpleTokenizer(vocab_size=10000)
    
    logger.info("Loading V1 model...")
    v1_model = load_model(args.v1_model, device=args.device)
    
    logger.info("Loading V2 model...")
    v2_model = load_model(args.v2_model, device=args.device)
    
    # Evaluate both models
    logger.info("\nEvaluating V1 model...")
    v1_predictions = evaluate_model_detailed(
        v1_model, validation_samples, validation_labels, tokenizer, args.device
    )
    
    logger.info("Evaluating V2 model...")
    v2_predictions = evaluate_model_detailed(
        v2_model, validation_samples, validation_labels, tokenizer, args.device
    )
    
    # Analyze false positives
    logger.info("\nAnalyzing false positives...")
    analysis = analyze_false_positives(v1_predictions, v2_predictions, validation_records)
    
    # Print report
    print_analysis_report(analysis)
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Speichere auch eine vereinfachte Version für V3 Training
    v3_training_data = {
        'v2_false_positives': [
            {
                'text': fp['text'],
                'category': fp['category'],
                'subcategory': fp['subcategory'],
                'confidence': fp['malicious_probability'],
                'keywords': fp['keywords']
            }
            for fp in analysis['all_categorized_fps']
        ],
        'recommendations': analysis['v3_training_recommendations']
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    
    v3_training_path = output_path.parent / f"{output_path.stem}_v3_training.json"
    with open(v3_training_path, 'w', encoding='utf-8') as f:
        json.dump(v3_training_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n💾 Full analysis saved to: {output_path}")
    logger.info(f"💾 V3 training data saved to: {v3_training_path}")
    logger.info("="*80)
    
    logger.info("\n✅ Analysis complete! Use the recommendations to guide V3 training.")


if __name__ == "__main__":
    main()

