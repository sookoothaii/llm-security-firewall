#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze bypassed attacks from DeepSeek Red Team test results.
Identifies patterns in bypassed attacks for improvement.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

# Fix Unicode output for Windows
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def analyze_bypasses(result_file: str) -> Dict[str, Any]:
    """Analyze bypassed attacks from result file."""
    with open(result_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    bypasses = []
    all_attacks = []
    
    # Extract all attacks from results
    if "results" in data:
        all_attacks = data["results"]
    elif "summary" in data and "by_round" in data["summary"]:
        for round_data in data["summary"]["by_round"]:
            if "attacks" in round_data:
                all_attacks.extend(round_data["attacks"])
    
    # Find bypassed attacks
    for attack in all_attacks:
        if not attack.get("blocked", True):
            bypasses.append(attack)
    
    # Analyze patterns
    analysis = {
        "total_bypasses": len(bypasses),
        "by_category": defaultdict(lambda: {"count": 0, "examples": []}),
        "score_distribution": {
            "rule_score_0": 0,
            "ml_score_0_50": 0,
            "ml_score_50_60": 0,
            "ml_score_60_70": 0,
            "ml_score_70_75": 0,
            "ml_score_75_plus": 0,
        },
        "obfuscation_types": defaultdict(int),
        "examples": []
    }
    
    for bypass in bypasses:
        category = bypass.get("category", "unknown")
        analysis["by_category"][category]["count"] += 1
        
        rule_score = bypass.get("rule_score", 0.0)
        ml_score = bypass.get("ml_score", 0.0)
        payload = bypass.get("payload", "")
        technique = bypass.get("technique", "")
        
        # Score distribution
        if rule_score == 0.0:
            analysis["score_distribution"]["rule_score_0"] += 1
        
        if ml_score < 0.50:
            analysis["score_distribution"]["ml_score_0_50"] += 1
        elif ml_score < 0.60:
            analysis["score_distribution"]["ml_score_50_60"] += 1
        elif ml_score < 0.70:
            analysis["score_distribution"]["ml_score_60_70"] += 1
        elif ml_score < 0.75:
            analysis["score_distribution"]["ml_score_70_75"] += 1
        else:
            analysis["score_distribution"]["ml_score_75_plus"] += 1
        
        # Obfuscation detection
        if "fullwidth" in payload.lower() or "ｓｃｒｉｐｔ" in payload:
            analysis["obfuscation_types"]["fullwidth"] += 1
        if "\\x" in payload or "\\u" in payload:
            analysis["obfuscation_types"]["hex_escape"] += 1
        if "%" in payload and len([c for c in payload if c == '%']) > 3:
            analysis["obfuscation_types"]["url_encoding"] += 1
        if any(ord(c) > 0x1F00 and ord(c) < 0x1FFF for c in payload):
            analysis["obfuscation_types"]["unicode_variants"] += 1
        
        # Store example
        if len(analysis["by_category"][category]["examples"]) < 3:
            analysis["by_category"][category]["examples"].append({
                "technique": technique,
                "payload": payload[:200],
                "rule_score": rule_score,
                "ml_score": ml_score,
                "risk_score": bypass.get("risk_score", 0.0)
            })
    
    return analysis


def print_analysis(analysis: Dict[str, Any]):
    """Print analysis results."""
    print("=" * 80)
    print("BYPASS ANALYSIS - DeepSeek Red Team Test")
    print("=" * 80)
    print(f"\nTotal Bypasses: {analysis['total_bypasses']}")
    
    print("\n" + "-" * 80)
    print("By Category:")
    print("-" * 80)
    for category, data in sorted(analysis["by_category"].items()):
        print(f"\n{category}:")
        print(f"  Count: {data['count']}")
        print(f"  Examples:")
        for i, example in enumerate(data["examples"], 1):
            print(f"    {i}. {example['technique']}")
            print(f"       Payload: {example['payload'][:100]}...")
            print(f"       Rule: {example['rule_score']:.3f}, ML: {example['ml_score']:.3f}, Risk: {example['risk_score']:.3f}")
    
    print("\n" + "-" * 80)
    print("Score Distribution:")
    print("-" * 80)
    dist = analysis["score_distribution"]
    if analysis['total_bypasses'] > 0:
        print(f"  Rule Score = 0.0: {dist['rule_score_0']}/{analysis['total_bypasses']} ({dist['rule_score_0']/analysis['total_bypasses']*100:.1f}%)")
        print(f"  ML Score < 0.50: {dist['ml_score_0_50']}/{analysis['total_bypasses']} ({dist['ml_score_0_50']/analysis['total_bypasses']*100:.1f}%)")
        print(f"  ML Score 0.50-0.60: {dist['ml_score_50_60']}/{analysis['total_bypasses']} ({dist['ml_score_50_60']/analysis['total_bypasses']*100:.1f}%)")
        print(f"  ML Score 0.60-0.70: {dist['ml_score_60_70']}/{analysis['total_bypasses']} ({dist['ml_score_60_70']/analysis['total_bypasses']*100:.1f}%)")
        print(f"  ML Score 0.70-0.75: {dist['ml_score_70_75']}/{analysis['total_bypasses']} ({dist['ml_score_70_75']/analysis['total_bypasses']*100:.1f}%)")
        print(f"  ML Score >= 0.75: {dist['ml_score_75_plus']}/{analysis['total_bypasses']} ({dist['ml_score_75_plus']/analysis['total_bypasses']*100:.1f}%)")
    else:
        print("  No bypasses detected - all attacks were successfully blocked.")
        print(f"  Rule Score = 0.0: {dist['rule_score_0']}/0")
        print(f"  ML Score < 0.50: {dist['ml_score_0_50']}/0")
        print(f"  ML Score 0.50-0.60: {dist['ml_score_50_60']}/0")
        print(f"  ML Score 0.60-0.70: {dist['ml_score_60_70']}/0")
        print(f"  ML Score 0.70-0.75: {dist['ml_score_70_75']}/0")
        print(f"  ML Score >= 0.75: {dist['ml_score_75_plus']}/0")
    
    if analysis["obfuscation_types"]:
        print("\n" + "-" * 80)
        print("Obfuscation Types Detected:")
        print("-" * 80)
        for obf_type, count in sorted(analysis["obfuscation_types"].items(), key=lambda x: x[1], reverse=True):
            print(f"  {obf_type}: {count}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze bypassed attacks from test results")
    parser.add_argument("--input", type=str, default="deepseek_redteam_results_*.json",
                       help="Input JSON file pattern")
    parser.add_argument("--pattern", type=str, default=None,
                       help="Glob pattern for result files")
    
    args = parser.parse_args()
    
    # Find result file
    if args.pattern:
        import glob
        files = glob.glob(args.pattern)
    else:
        import glob
        files = glob.glob(args.input)
    
    if not files:
        print(f"[ERROR] No files found matching: {args.input}")
        sys.exit(1)
    
    # Use most recent file
    result_file = max(files, key=lambda f: Path(f).stat().st_mtime)
    print(f"[INFO] Analyzing: {result_file}")
    
    analysis = analyze_bypasses(result_file)
    print_analysis(analysis)
    
    # Save analysis
    output_file = f"analysis/bypass_analysis_{Path(result_file).stem}.json"
    Path("analysis").mkdir(exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Analysis saved to: {output_file}")
