#!/usr/bin/env python3
"""
Analyse-Skript für Bypass-Patterns
===================================

Analysiert Bypasses auf gemeinsame Muster und generiert Empfehlungen.
"""

import json
import re
import argparse
import glob
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any


def analyze_bypass_patterns(result_files: List[str]) -> Dict[str, Any]:
    """Analysiert Bypasses auf gemeinsame Muster"""
    
    all_bypasses = []
    
    for result_file in result_files:
        file_path = Path(result_file)
        if not file_path.exists():
            print(f"⚠️  File not found: {result_file}")
            continue
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            bypasses = data.get('bypasses', [])
            all_bypasses.extend(bypasses)
    
    if not all_bypasses:
        print("🎉 No bypasses to analyze!")
        return {}
    
    print(f"Analyzing {len(all_bypasses)} bypasses...\n")
    
    analysis = {
        "total_bypasses": len(all_bypasses),
        "score_analysis": {},
        "technique_analysis": {},
        "pattern_analysis": {},
        "recommendations": []
    }
    
    # 1. Score-Verteilung
    scores = [b['risk_score'] for b in all_bypasses]
    analysis["score_analysis"] = {
        "min": min(scores),
        "max": max(scores),
        "average": sum(scores) / len(scores),
        "median": sorted(scores)[len(scores) // 2],
        "distribution": {
            "below_0.3": sum(1 for s in scores if s < 0.3),
            "0.3_0.5": sum(1 for s in scores if 0.3 <= s < 0.5),
            "0.5_0.6": sum(1 for s in scores if 0.5 <= s < 0.6),
            "above_0.6": sum(1 for s in scores if s >= 0.6)
        }
    }
    
    print("Score Distribution:")
    print(f"  Min: {analysis['score_analysis']['min']:.3f}")
    print(f"  Max: {analysis['score_analysis']['max']:.3f}")
    print(f"  Avg: {analysis['score_analysis']['average']:.3f}")
    print(f"  Median: {analysis['score_analysis']['median']:.3f}")
    print(f"  Below 0.3: {analysis['score_analysis']['distribution']['below_0.3']}")
    print(f"  0.3-0.5: {analysis['score_analysis']['distribution']['0.3_0.5']}")
    print(f"  0.5-0.6: {analysis['score_analysis']['distribution']['0.5_0.6']}")
    print(f"  Above 0.6: {analysis['score_analysis']['distribution']['above_0.6']}")
    
    # 2. Häufigste Techniken
    techniques = Counter([b['technique'] for b in all_bypasses])
    analysis["technique_analysis"] = dict(techniques)
    
    print("\nMost Common Techniques:")
    for tech, count in techniques.most_common(10):
        print(f"  {tech}: {count} bypasses")
    
    # 3. Pattern-Analyse in Payloads
    print("\nCommon Patterns in Bypassed Payloads:")
    
    # Mathematische Symbole
    math_symbols = Counter()
    for bypass in all_bypasses:
        payload = bypass.get('full_payload', bypass.get('payload', ''))
        for symbol in '∀∃∈∉∧∨→↔∑∫∮∇∆∂≈≪≫≤≥≠±×÷':
            if symbol in payload:
                math_symbols[symbol] += 1
    
    if math_symbols:
        analysis["pattern_analysis"]["mathematical_symbols"] = dict(math_symbols)
        print("  Mathematical Symbols:")
        for symbol, count in math_symbols.most_common(10):
            print(f"    {symbol}: {count}")
    
    # Sprachen-Mixing
    language_keywords = {
        'german': ['der', 'die', 'das', 'und', 'für', 'wenn', 'dann'],
        'french': ['le', 'la', 'les', 'et', 'pour', 'dans', 'avec'],
        'spanish': ['el', 'la', 'y', 'para', 'con', 'del', 'que'],
        'italian': ['il', 'la', 'e', 'per', 'con', 'del', 'che'],
        'dutch': ['de', 'het', 'en', 'voor', 'met', 'van', 'dat'],
        'russian': ['и', 'в', 'на', 'для', 'с', 'от', 'что'],
        'japanese': ['の', 'を', 'に', 'で', 'と', 'が', 'は'],
        'chinese': ['的', '在', '和', '为', '与', '从', '这'],
        'code': ['import', 'system', 'eval', 'exec', 'SELECT', 'DROP', 'rm', 'cat']
    }
    
    lang_mix_counts = Counter()
    lang_combinations = []
    
    for bypass in all_bypasses:
        payload = bypass.get('full_payload', bypass.get('payload', '')).lower()
        langs_present = []
        for lang, keywords in language_keywords.items():
            if any(kw in payload for kw in keywords):
                langs_present.append(lang)
        if len(langs_present) >= 2:
            lang_mix_counts['mixed_languages'] += 1
            lang_combinations.append(tuple(sorted(langs_present)))
    
    if lang_mix_counts:
        analysis["pattern_analysis"]["mixed_languages"] = {
            "count": lang_mix_counts['mixed_languages'],
            "common_combinations": dict(Counter(lang_combinations).most_common(5))
        }
        print(f"  Mixed Languages: {lang_mix_counts['mixed_languages']}")
        if lang_combinations:
            print("  Common Language Combinations:")
            for combo, count in Counter(lang_combinations).most_common(5):
                print(f"    {', '.join(combo)}: {count}")
    
    # Code-Patterns
    code_patterns = Counter()
    code_keywords = ['system', 'eval', 'exec', 'rm -rf', 'DROP TABLE', 'SELECT', 'cat /etc', 'wget', 'curl', 'nc -e']
    
    for bypass in all_bypasses:
        payload = bypass.get('full_payload', bypass.get('payload', '')).lower()
        for keyword in code_keywords:
            if keyword.lower() in payload:
                code_patterns[keyword] += 1
    
    if code_patterns:
        analysis["pattern_analysis"]["code_patterns"] = dict(code_patterns)
        print("\n  Code Patterns Found:")
        for pattern, count in code_patterns.most_common(5):
            print(f"    {pattern}: {count}")
    
    # 4. Rule Score vs ML Score Analyse
    rule_scores = [b.get('rule_score', 0.0) for b in all_bypasses]
    ml_scores = [b.get('ml_score', 0.0) for b in all_bypasses if b.get('ml_score') is not None]
    
    analysis["score_analysis"]["rule_vs_ml"] = {
        "rule_score_avg": sum(rule_scores) / len(rule_scores) if rule_scores else 0.0,
        "ml_score_avg": sum(ml_scores) / len(ml_scores) if ml_scores else 0.0,
        "rule_score_zero_count": sum(1 for s in rule_scores if s == 0.0),
        "ml_score_none_count": len(all_bypasses) - len(ml_scores)
    }
    
    print("\nRule vs ML Score Analysis:")
    print(f"  Rule Score Avg: {analysis['score_analysis']['rule_vs_ml']['rule_score_avg']:.3f}")
    print(f"  ML Score Avg: {analysis['score_analysis']['rule_vs_ml']['ml_score_avg']:.3f}")
    print(f"  Rule Score = 0.0: {analysis['score_analysis']['rule_vs_ml']['rule_score_zero_count']}")
    print(f"  ML Score = None: {analysis['score_analysis']['rule_vs_ml']['ml_score_none_count']}")
    
    # 5. Empfehlungen generieren
    recommendations = []
    
    if any('Mathematical' in tech for tech in techniques):
        recommendations.append({
            "priority": "HIGH",
            "category": "mathematical",
            "issue": "Mathematical notation bypasses detected",
            "recommendations": [
                "Add more mathematical symbol combinations to rule engine",
                "Lower threshold for prompts with high symbol density (≥3 symbols)",
                "Train ML model on advanced mathematical camouflage examples",
                "Implement mathematical notation parser to extract semantic meaning",
                "Add specialized handling for mathematical-linguistic hybrids"
            ]
        })
    
    if any('Multilingual' in tech for tech in techniques):
        recommendations.append({
            "priority": "HIGH",
            "category": "multilingual",
            "issue": "Multilingual code-switching bypasses detected",
            "recommendations": [
                "Implement language switching detection (>2 languages)",
                "Add multilingual code pattern detection",
                "Boost scores for mixed-language security contexts",
                "Ensure ML model is invoked for all content types, including multilingual",
                "Add language detection to flag mixed-language content"
            ]
        })
    
    if analysis['score_analysis']['rule_vs_ml']['rule_score_zero_count'] > len(all_bypasses) * 0.5:
        recommendations.append({
            "priority": "MEDIUM",
            "category": "rule_engine",
            "issue": "High number of bypasses with rule_score = 0.0",
            "recommendations": [
                "Expand rule engine patterns for detected bypass techniques",
                "Improve pattern matching for obfuscated content",
                "Add fallback patterns for edge cases"
            ]
        })
    
    if analysis['score_analysis']['rule_vs_ml']['ml_score_none_count'] > 0:
        recommendations.append({
            "priority": "CRITICAL",
            "category": "ml_pipeline",
            "issue": "ML model not invoked for some bypasses",
            "recommendations": [
                "Audit FirewallEngineV2 pipeline to identify why ML model not invoked",
                "Ensure ML model is invoked for ALL content types",
                "Add fallback ML evaluation if primary path fails",
                "Log all cases where ml_score = None for analysis"
            ]
        })
    
    if analysis['score_analysis']['distribution']['0.5_0.6'] > 0:
        recommendations.append({
            "priority": "MEDIUM",
            "category": "threshold",
            "issue": "Bypasses in threshold range 0.5-0.6",
            "recommendations": [
                "Consider lowering threshold from 0.60 to 0.55 for better coverage",
                "Test threshold range θ ∈ [0.45, 0.65] with benign corpus",
                "Measure FN(θ) and FP(θ) curves for optimal threshold selection"
            ]
        })
    
    analysis["recommendations"] = recommendations
    
    print("\n🔧 RECOMMENDED FIXES:")
    for rec in recommendations:
        print(f"\n  [{rec['priority']}] {rec['category'].upper()}: {rec['issue']}")
        for item in rec['recommendations']:
            print(f"    • {item}")
    
    return analysis


def main():
    parser = argparse.ArgumentParser(description="Analyze bypass patterns from test results")
    parser.add_argument("--input", type=str, nargs="+", help="Input JSON result files")
    parser.add_argument("--pattern", type=str, help="Glob pattern for result files")
    parser.add_argument("--output", type=str, default=None, help="Output analysis JSON file")
    
    args = parser.parse_args()
    
    # Finde Result-Dateien
    result_files = []
    
    if args.input:
        result_files = args.input
    elif args.pattern:
        result_files = glob.glob(args.pattern)
    else:
        # Standard: Suche nach Test-Resultaten
        result_files = glob.glob("test_results/advanced_test_*.json")
    
    if not result_files:
        print("❌ No result files found!")
        print("   Run tests first:")
        print("   python scripts/run_advanced_bypass_tests.py")
        return
    
    print(f"Found {len(result_files)} result file(s)")
    
    # Analysiere
    analysis = analyze_bypass_patterns(result_files)
    
    if not analysis:
        return
    
    # Speichere Analyse
    if args.output:
        output_path = Path(args.output)
    else:
        output_dir = Path("analysis")
        output_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"bypass_patterns_analysis_{timestamp}.json"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Analysis saved to {output_path}")


if __name__ == "__main__":
    from datetime import datetime
    main()
