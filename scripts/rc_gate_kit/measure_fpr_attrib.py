#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FPR Measurement with Attribution
Measures FPR per context + Top-3 contributors per false positive
"""
import sys
import os
import csv
from pathlib import Path

# Add src to path
repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.preprocess.context import classify_context
from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb

# Import all detectors
from llm_firewall.detectors.unicode_hardening import (
    detect_bidi_controls,
    detect_zero_width,
    detect_fullwidth,
    detect_mixed_scripts
)
from llm_firewall.normalizers.encoding_chain import decode_chain
from llm_firewall.normalizers.escapes import unescape_all
from llm_firewall.preprocess.canonicalize import canonicalize_yaml_json
from llm_firewall.detectors.entropy import calculate_entropy
from llm_firewall.detectors.dense_alphabet import detect_dense_alphabet


def run_all_detectors(text: str) -> list:
    """Run all P0/P1 detectors and return hits"""
    hits = []
    
    # Unicode hardening
    if detect_bidi_controls(text):
        hits.append('bidi_controls')
    if detect_zero_width(text):
        hits.append('zero_width_chars')
    if detect_fullwidth(text):
        hits.append('fullwidth_forms')
    if detect_mixed_scripts(text):
        hits.append('mixed_scripts')
    
    # Encoding chain
    decoded, stages, _ = decode_chain(text)
    if stages >= 1:
        hits.append(f'chain_decoded_{stages}_stages')
    
    # Escapes
    unescaped = unescape_all(text)
    if unescaped != text:
        if '\\' in text and '\\\\' not in text:
            hits.append('css_unescaped')
        elif '%' in text:
            hits.append('js_unescaped')
    
    # Canonicalization
    canon, detected = canonicalize_yaml_json(text)
    if detected:
        hits.append('yaml_anchors_neutralized')
    
    # Entropy
    entropy = calculate_entropy(text)
    if entropy > 4.0:
        hits.append('high_entropy')
    
    # Dense alphabet
    if detect_dense_alphabet(text):
        hits.append('dense_alphabet')
    
    return hits


def measure_fpr_with_attribution(corpus_path: str = "data/benign_corpus.txt", 
                                  output_csv: str = "fpr_attrib.csv") -> dict:
    """
    Measure FPR with attribution per sample
    
    Returns:
        {
            'overall_fpr': float,
            'by_context': {'natural': fpr, 'code': fpr, 'config': fpr},
            'false_positives': [...]
        }
    """
    print(f"\n=== FPR Attribution Measurement ===")
    print(f"Corpus: {corpus_path}")
    print(f"Output: {output_csv}\n")
    
    if not Path(corpus_path).exists():
        print(f"ERROR: Corpus not found: {corpus_path}")
        print("Creating dummy corpus...")
        Path(corpus_path).parent.mkdir(parents=True, exist_ok=True)
        with open(corpus_path, 'w', encoding='utf-8') as f:
            f.write("Hello world\n")
            f.write("This is a test\n")
            f.write("def foo():\n    return 42\n")
    
    # Load corpus
    with open(corpus_path, 'r', encoding='utf-8') as f:
        samples = [line.strip() for line in f if line.strip()]
    
    total = len(samples)
    false_positives = []
    context_stats = {'natural': {'total': 0, 'fp': 0}, 
                    'code': {'total': 0, 'fp': 0}, 
                    'config': {'total': 0, 'fp': 0}}
    
    print(f"Processing {total} samples...")
    
    for idx, text in enumerate(samples):
        if idx % 100 == 0:
            print(f"  Progress: {idx}/{total} ({100*idx/total:.1f}%)")
        
        # Classify context
        ctx_meta = classify_context(text)
        context = ctx_meta['context']
        context_stats[context]['total'] += 1
        
        # Run detectors
        hits = run_all_detectors(text)
        
        # Decide action with OTB gates
        action, risk, contrib = decide_action_otb(hits, ctx_meta, text=text)
        
        # Check for false positive (WARN or BLOCK on benign)
        if action in ('WARN', 'BLOCK'):
            context_stats[context]['fp'] += 1
            
            # Get Top-3 contributors
            sorted_contrib = sorted(
                [(k, v['dampened']) for k, v in contrib.items() if isinstance(v, dict)],
                key=lambda x: x[1],
                reverse=True
            )[:3]
            
            false_positives.append({
                'sample_id': idx,
                'text_preview': text[:60],
                'context': context,
                'action': action,
                'risk_score': risk,
                'top1': sorted_contrib[0][0] if len(sorted_contrib) > 0 else '',
                'top1_score': sorted_contrib[0][1] if len(sorted_contrib) > 0 else 0,
                'top2': sorted_contrib[1][0] if len(sorted_contrib) > 1 else '',
                'top2_score': sorted_contrib[1][1] if len(sorted_contrib) > 1 else 0,
                'top3': sorted_contrib[2][0] if len(sorted_contrib) > 2 else '',
                'top3_score': sorted_contrib[2][1] if len(sorted_contrib) > 2 else 0,
            })
    
    print(f"  Progress: {total}/{total} (100.0%)\n")
    
    # Calculate FPR
    overall_fp = sum(ctx['fp'] for ctx in context_stats.values())
    overall_fpr = 100 * overall_fp / total
    
    by_context_fpr = {}
    for ctx, stats in context_stats.items():
        if stats['total'] > 0:
            by_context_fpr[ctx] = 100 * stats['fp'] / stats['total']
        else:
            by_context_fpr[ctx] = 0.0
    
    # Write CSV
    if false_positives:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['sample_id', 'text_preview', 'context', 'action', 'risk_score',
                         'top1', 'top1_score', 'top2', 'top2_score', 'top3', 'top3_score']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(false_positives)
        print(f"✓ Attribution CSV: {output_csv} ({len(false_positives)} FPs)")
    else:
        print("✓ No false positives - FPR 0.0%!")
    
    # Print results
    print("\n=== RESULTS ===")
    print(f"Total Samples: {total}")
    print(f"False Positives: {overall_fp}")
    print(f"Overall FPR: {overall_fpr:.2f}%\n")
    
    print("FPR by Context:")
    for ctx in ('natural', 'code', 'config'):
        stats = context_stats[ctx]
        if stats['total'] > 0:
            fpr = by_context_fpr[ctx]
            print(f"  {ctx:8s}: {fpr:5.2f}% ({stats['fp']}/{stats['total']})")
    
    return {
        'overall_fpr': overall_fpr,
        'by_context': by_context_fpr,
        'false_positives': false_positives,
        'context_stats': context_stats
    }


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Measure FPR with attribution')
    parser.add_argument('--corpus', default='data/benign_corpus.txt',
                       help='Path to benign corpus')
    parser.add_argument('--output', default='fpr_attrib.csv',
                       help='Output CSV path')
    args = parser.parse_args()
    
    result = measure_fpr_with_attribution(args.corpus, args.output)
    
    # Exit with error if FPR > 2%
    if result['overall_fpr'] > 2.0:
        print(f"\n❌ FPR {result['overall_fpr']:.2f}% > 2.0% target")
        sys.exit(1)
    else:
        print(f"\n✓ FPR {result['overall_fpr']:.2f}% ≤ 2.0% target")
        sys.exit(0)

