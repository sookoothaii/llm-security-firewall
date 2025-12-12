"""
Analyse der Modell-Schwachstellen und Generierung von Verbesserungsvorschlägen
===============================================================================

Analysiert die Ergebnisse von Test-Set-Evaluation und Adversarial-Tests,
um konkrete Verbesserungsvorschläge für das Training zu generieren.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def analyze_test_results(test_results_path: str) -> Dict:
    """Analysiere Test-Set-Evaluations-Ergebnisse."""
    with open(test_results_path, 'r', encoding='utf-8') as f:
        results = json.load(f)
    
    analysis = {
        'false_negatives': [],
        'false_positives': [],
        'patterns': defaultdict(int),
        'confidence_ranges': {
            'low_confidence_fns': [],  # < 0.4
            'medium_confidence_fns': [],  # 0.4-0.5
            'high_confidence_fns': []  # > 0.5
        }
    }
    
    # Analysiere False Negatives
    for fn in results.get('false_negatives', []):
        text = fn['text'].lower()
        confidence = fn['malicious_probability']
        
        analysis['false_negatives'].append(fn)
        
        # Pattern-Erkennung
        if 'drop table' in text or 'truncate' in text:
            analysis['patterns']['sql_destructive'] += 1
        elif 'eval' in text or 'exec' in text:
            analysis['patterns']['code_execution'] += 1
        elif 'curl' in text and ('http' in text or '&&' in text):
            analysis['patterns']['remote_execution'] += 1
        
        # Confidence-Kategorisierung
        if confidence < 0.4:
            analysis['confidence_ranges']['low_confidence_fns'].append(fn)
        elif confidence < 0.5:
            analysis['confidence_ranges']['medium_confidence_fns'].append(fn)
        else:
            analysis['confidence_ranges']['high_confidence_fns'].append(fn)
    
    return analysis


def analyze_adversarial_results(adversarial_results_path: str) -> Dict:
    """Analysiere Adversarial-Test-Ergebnisse."""
    with open(adversarial_results_path, 'r', encoding='utf-8') as f:
        results = json.load(f)
    
    analysis = {
        'test_type_failures': defaultdict(list),
        'common_patterns': defaultdict(int),
        'recommendations': []
    }
    
    # Analysiere Failures nach Test-Typ
    for failure in results.get('failures', []):
        test_type = failure['test_type']
        analysis['test_type_failures'][test_type].append(failure)
        
        # Pattern-Erkennung
        text = failure['text'].lower()
        if 'context_benign_wrapper' in test_type:
            analysis['common_patterns']['context_manipulation'] += 1
        elif 'obfuscation' in test_type:
            analysis['common_patterns']['obfuscation'] += 1
        
        # Spezifische Patterns
        if 'eval' in text:
            analysis['common_patterns']['eval_pattern'] += 1
        if 'drop table' in text or 'truncate' in text:
            analysis['common_patterns']['sql_destructive'] += 1
    
    return analysis


def generate_training_recommendations(
    test_analysis: Dict,
    adversarial_analysis: Dict
) -> List[Dict]:
    """Generiere konkrete Trainings-Empfehlungen."""
    
    recommendations = []
    
    # 1. Context-Benign-Wrapper Problem (KRITISCH!)
    context_failures = adversarial_analysis['test_type_failures'].get('context_benign_wrapper', [])
    if context_failures:
        recommendations.append({
            'priority': 'CRITICAL',
            'issue': 'Context-Benign-Wrapper: 0% Pass Rate',
            'description': f'{len(context_failures)} Tests fehlgeschlagen - Malicious Code wird nicht erkannt, wenn er in benignen Kontext eingewickelt ist.',
            'solution': {
                'data_augmentation': [
                    'Füge Trainingsdaten hinzu, bei denen malicious Code in benignen Kontext eingewickelt ist',
                    'Beispiele: "This is harmless: {malicious_code}", "Educational: {malicious_code}"',
                    'Mindestens 200-300 zusätzliche Samples'
                ],
                'training_strategy': [
                    'Erhöhe Gewichtung für False Negatives im Loss (class_weight)',
                    'Füge "context-aware" Features hinzu (z.B. Position des malicious Patterns)',
                    'Trainiere mit höherer Learning Rate für diese Samples (focal loss)'
                ]
            },
            'examples': [f['text'][:150] for f in context_failures[:3]]
        })
    
    # 2. Obfuscation-Problem
    obfuscation_failures = []
    for test_type in ['obfuscation_case', 'obfuscation_comments', 'obfuscation_whitespace']:
        obfuscation_failures.extend(adversarial_analysis['test_type_failures'].get(test_type, []))
    
    if obfuscation_failures:
        recommendations.append({
            'priority': 'HIGH',
            'issue': 'Obfuscation-Resilienz: 50-75% Pass Rate',
            'description': f'{len(obfuscation_failures)} Obfuscation-Tests fehlgeschlagen - Modell ist anfällig für Case-Variation, Comments, Whitespace.',
            'solution': {
                'data_augmentation': [
                    'Erweitere Trainingsdaten mit Obfuscation-Varianten',
                    'Case Variation: "rm -rf" → "Rm -Rf", "RM -RF"',
                    'Comment Injection: "rm -rf /tmp # harmless"',
                    'Whitespace Variation: "rm${IFS}-rf"',
                    'Mindestens 500-800 zusätzliche Samples'
                ],
                'training_strategy': [
                    'Verwende Data Augmentation während Training (on-the-fly)',
                    'Erhöhe Regularization (Dropout) für bessere Generalisierung',
                    'Trainiere mit mehr Epochs für bessere Pattern-Erkennung'
                ]
            },
            'examples': [f['text'][:150] for f in obfuscation_failures[:3]]
        })
    
    # 3. Spezifische Pattern-Probleme
    eval_failures = [f for f in adversarial_analysis.get('failures', []) if 'eval' in f['text'].lower()]
    sql_failures = [f for f in adversarial_analysis.get('failures', []) if 'drop table' in f['text'].lower() or 'truncate' in f['text'].lower()]
    
    if eval_failures:
        recommendations.append({
            'priority': 'HIGH',
            'issue': 'eval() Pattern wird nicht erkannt',
            'description': f'{len(eval_failures)} Tests mit eval() fehlgeschlagen - Kritisch für Code Execution Detection.',
            'solution': {
                'data_augmentation': [
                    'Füge mehr eval()-Varianten hinzu: eval(), eval($_GET), eval($POST), etc.',
                    'Verschiedene Sprachen: Python eval(), JavaScript eval(), PHP eval()',
                    'Mindestens 100-150 zusätzliche Samples'
                ],
                'training_strategy': [
                    'Erhöhe Gewichtung für code_execution Patterns',
                    'Füge explizite Features für eval/exec Patterns hinzu'
                ]
            },
            'examples': [f['text'][:150] for f in eval_failures[:3]]
        })
    
    if sql_failures or test_analysis['patterns'].get('sql_destructive', 0) > 0:
        recommendations.append({
            'priority': 'MEDIUM',
            'issue': 'SQL Destructive Commands (DROP TABLE, TRUNCATE)',
            'description': f'SQL-Destructive-Commands werden teilweise übersehen (Test-Set: {test_analysis["patterns"].get("sql_destructive", 0)} FNs).',
            'solution': {
                'data_augmentation': [
                    'Füge mehr SQL-Destructive-Varianten hinzu',
                    'DROP TABLE, TRUNCATE, DELETE FROM, ALTER TABLE DROP',
                    'Verschiedene SQL-Dialekte (MySQL, PostgreSQL, SQLite)',
                    'Mindestens 80-100 zusätzliche Samples'
                ],
                'training_strategy': [
                    'Erhöhe Gewichtung für SQL-Patterns',
                    'Füge SQL-spezifische Features hinzu'
                ]
            },
            'examples': [
                fn['text'][:150] for fn in test_analysis['false_negatives']
                if 'drop' in fn['text'].lower() or 'truncate' in fn['text'].lower()
            ][:3]
        })
    
    # 4. False Positive Problem (weniger kritisch, aber vorhanden)
    fp_count = len(test_analysis.get('false_positives', []))
    if fp_count > 0:
        recommendations.append({
            'priority': 'LOW',
            'issue': f'False Positives: {fp_count} fälschliche Blockierungen',
            'description': 'Benign Code wird fälschlich als malicious klassifiziert.',
            'solution': {
                'data_augmentation': [
                    'Füge mehr benign Samples hinzu, besonders solche, die ähnlich zu malicious Patterns sind',
                    'Beispiele: "echo test" (nicht malicious), "SELECT COUNT(*)" (read-only)',
                    'Mindestens 100-200 zusätzliche benign Samples'
                ],
                'training_strategy': [
                    'Erhöhe Threshold für Blockierung (z.B. 0.6 statt 0.5)',
                    'Verwende weighted loss mit höherer Gewichtung für False Positives'
                ]
            }
        })
    
    return recommendations


def generate_augmentation_script_recommendations(recommendations: List[Dict]) -> str:
    """Generiere Code-Snippets für Data Augmentation."""
    
    code_snippets = []
    
    for rec in recommendations:
        if rec['priority'] == 'CRITICAL' and 'context_benign_wrapper' in rec.get('issue', ''):
            code_snippets.append("""
# Context-Benign-Wrapper Augmentation
def add_benign_context_wrapper(text: str) -> str:
    '''Füge benignen Kontext hinzu, um malicious Code zu verschleiern.'''
    benign_prefixes = [
        "This is a harmless example: ",
        "Educational purpose only: ",
        "For testing: ",
        "Example code: ",
        "This is safe: "
    ]
    benign_suffixes = [
        " # educational purpose only",
        " # harmless",
        " # safe example",
        " // test only"
    ]
    
    import random
    prefix = random.choice(benign_prefixes)
    suffix = random.choice(benign_suffixes)
    return f"{prefix}{text}{suffix}"
""")
        
        if 'obfuscation' in rec.get('issue', '').lower():
            code_snippets.append("""
# Obfuscation Augmentation
def obfuscate_text(text: str) -> str:
    '''Erstelle Obfuscation-Varianten.'''
    import random
    
    # Case Variation
    if random.random() < 0.3:
        text = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                      for i, c in enumerate(text))
    
    # Comment Injection
    if random.random() < 0.3:
        words = text.split()
        if len(words) > 3:
            insert_pos = random.randint(1, len(words) - 1)
            words.insert(insert_pos, '# harmless comment')
            text = ' '.join(words)
    
    # Whitespace Variation
    if random.random() < 0.2:
        text = text.replace(' ', '${IFS}').replace('-', '${DASH}')
    
    return text
""")
    
    return '\n'.join(code_snippets)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze model weaknesses and generate improvement recommendations"
    )
    parser.add_argument(
        "--test_results",
        type=str,
        default="./models/quantum_cnn_trained/test_evaluation_results.json",
        help="Path to test evaluation results JSON"
    )
    parser.add_argument(
        "--adversarial_results",
        type=str,
        default="./models/quantum_cnn_trained/adversarial_test_results.json",
        help="Path to adversarial test results JSON"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./models/quantum_cnn_trained/weakness_analysis.json",
        help="Output path for analysis JSON"
    )
    
    args = parser.parse_args()
    
    logger.info("=" * 80)
    logger.info("MODEL WEAKNESS ANALYSIS")
    logger.info("=" * 80)
    logger.info("")
    
    # Analysiere Ergebnisse
    logger.info("Analyzing test results...")
    test_analysis = analyze_test_results(args.test_results)
    
    logger.info("Analyzing adversarial results...")
    adversarial_analysis = analyze_adversarial_results(args.adversarial_results)
    
    # Generiere Empfehlungen
    logger.info("Generating recommendations...")
    recommendations = generate_training_recommendations(test_analysis, adversarial_analysis)
    
    # Zusammenfassung
    report = {
        'summary': {
            'total_false_negatives': len(test_analysis['false_negatives']),
            'total_false_positives': len(test_analysis['false_positives']),
            'adversarial_pass_rate': None,  # Wird aus adversarial_results berechnet
            'critical_issues': len([r for r in recommendations if r['priority'] == 'CRITICAL']),
            'high_priority_issues': len([r for r in recommendations if r['priority'] == 'HIGH']),
        },
        'test_analysis': {
            'false_negatives': test_analysis['false_negatives'],
            'patterns': dict(test_analysis['patterns']),
            'confidence_ranges': {
                'low': len(test_analysis['confidence_ranges']['low_confidence_fns']),
                'medium': len(test_analysis['confidence_ranges']['medium_confidence_fns']),
                'high': len(test_analysis['confidence_ranges']['high_confidence_fns'])
            }
        },
        'adversarial_analysis': {
            'test_type_failures': {
                k: len(v) for k, v in adversarial_analysis['test_type_failures'].items()
            },
            'common_patterns': dict(adversarial_analysis['common_patterns'])
        },
        'recommendations': recommendations,
        'augmentation_code': generate_augmentation_script_recommendations(recommendations)
    }
    
    # Berechne Adversarial Pass Rate
    try:
        with open(args.adversarial_results, 'r') as f:
            adv_results = json.load(f)
            total = len(adv_results.get('test_cases', []))
            passed = sum(1 for tc in adv_results.get('test_cases', []) if tc.get('is_correct', False))
            report['summary']['adversarial_pass_rate'] = (passed / total * 100) if total > 0 else 0
    except:
        pass
    
    # Speichere Report
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # Ausgabe
    print("\n" + "=" * 80)
    print("📊 WEAKNESS ANALYSIS REPORT")
    print("=" * 80)
    print(f"\nTest Set False Negatives: {report['summary']['total_false_negatives']}")
    print(f"Test Set False Positives: {report['summary']['total_false_positives']}")
    print(f"Adversarial Pass Rate: {report['summary']['adversarial_pass_rate']:.2f}%")
    print(f"\nCritical Issues: {report['summary']['critical_issues']}")
    print(f"High Priority Issues: {report['summary']['high_priority_issues']}")
    
    print("\n" + "=" * 80)
    print("🎯 RECOMMENDATIONS")
    print("=" * 80)
    
    for i, rec in enumerate(recommendations, 1):
        print(f"\n{i}. [{rec['priority']}] {rec['issue']}")
        print(f"   {rec['description']}")
        print(f"\n   Solution:")
        for key, items in rec['solution'].items():
            print(f"   {key.replace('_', ' ').title()}:")
            for item in items:
                print(f"     - {item}")
    
    logger.info(f"\n✓ Full report saved to: {args.output}")
    
    return report


if __name__ == "__main__":
    main()
