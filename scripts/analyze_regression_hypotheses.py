#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression Hypotheses Analysis for Multilingual & Creative Bypasses

Tests the three hypotheses:
A) Preprocessing-Kollision: normalize_obfuscation() normalisiert legitime multilinguale Zeichen
B) Threshold-Interaktion: is_multilingual_attack() wird durch Obfuscation-Muster getäuscht
C) Creative-Erkennung: Neue Obfuscation-Regeln stufen kreative Angriffe als "benign" ein
"""

import json
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import unicodedata

# Fix Unicode output for Windows
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Import detection functions (simplified versions for analysis)
def normalize_obfuscation(text: str) -> str:
    """Simplified version of normalize_obfuscation for testing."""
    import base64
    import urllib.parse
    
    normalized = text
    
    # 1. Normalize Unicode (NFKC)
    normalized = unicodedata.normalize('NFKC', normalized)
    
    # 2. Replace Unicode homoglyphs
    homoglyph_map = {
        'ο': 'o', 'ѕ': 's', 'е': 'e', 'а': 'a', 'р': 'p', 'х': 'x', 'с': 'c',
    }
    for glyph, replacement in homoglyph_map.items():
        normalized = normalized.replace(glyph, replacement)
    
    # 3. Convert Fullwidth Unicode to ASCII
    fullwidth_to_ascii = str.maketrans(
        '！＂＃＄％＆＇（）＊＋，－．／０１２３４５６７８９：；＜＝＞？＠ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ［＼］＾＿｀ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ｛｜｝～',
        '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    )
    normalized = normalized.translate(fullwidth_to_ascii)
    
    # 4. Remove zero-width characters
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff']
    for zw in zero_width_chars:
        normalized = normalized.replace(zw, '')
    
    # 5. Decode URL encoding
    try:
        decoded = urllib.parse.unquote(normalized)
        if decoded != normalized:
            normalized = decoded
    except:
        pass
    
    # 6. Decode Base64
    text_no_ws = re.sub(r'\s+', '', normalized)
    base64_pattern = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text_no_ws)
    if base64_pattern:
        try:
            decoded_bytes = base64.b64decode(base64_pattern.group(0))
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            normalized = normalized.replace(base64_pattern.group(0), decoded_str)
        except:
            pass
    
    # 7. Remove comment injection markers
    normalized = re.sub(r'(\w+)#\w+#(\w+)', r'\1\2', normalized)
    normalized = re.sub(r'(\w+)\s*#\w+\s*(\w+)', r'\1 \2', normalized)
    
    return normalized


def is_multilingual_attack(text: str) -> bool:
    """Simplified version of is_multilingual_attack for testing."""
    security_keywords = [
        'system', 'vulnerabilit', 'attack', 'compromise', 'security', 'defense', 
        'risk', 'protection', 'exploit', 'breach', 'hack', 'inject',
        'angriff', 'schwachstelle', 'sicherheit', 'verteidigung',
        'système', 'attaque', 'vulnérabilité', 'sécurité', 'défense',
        'sistema', 'ataque', 'vulnerabilidad', 'seguridad', 'defensa',
    ]
    
    text_lower = text.lower()
    has_security_keywords = any(kw in text_lower for kw in security_keywords)
    
    code_patterns = [
        r'__import__', r'eval\s*\(', r'exec\s*\(', r'system\s*\(',
        r'shell_exec', r'passthru', r'rm\s+-rf', r'DROP\s+TABLE',
        r'SELECT\s+\*', r'UNION\s+SELECT', r'nc\s+-e', r'bash\s+-i',
        r'/dev/tcp', r'wget\s+http', r'curl\s+http', r'document\.write',
        r'window\.location', r'<script>', r'alert\s*\(', r'subprocess',
        r'malware', r'evil\.com', r'exploit'
    ]
    has_code_patterns = any(re.search(pattern, text_lower, re.IGNORECASE) for pattern in code_patterns)
    
    language_indicators = {
        'german': ['der', 'die', 'das', 'und', 'für', 'wenn', 'dann', 'zur', 'als'],
        'french': ['le', 'la', 'les', 'et', 'pour', 'dans', 'avec', 'selon'],
        'spanish': ['el', 'la', 'y', 'para', 'con', 'del', 'que', 'para la'],
        'italian': ['il', 'la', 'e', 'per', 'con', 'del', 'che', 'in un'],
        'dutch': ['de', 'het', 'en', 'voor', 'met', 'van', 'dat', 'als'],
        'russian': ['и', 'в', 'на', 'для', 'с', 'от', 'что'],
        'japanese': ['の', 'を', 'に', 'で', 'と', 'が', 'は', 'セキュリティ'],
        'chinese': ['的', '在', '和', '为', '与', '从', '这', '为了'],
    }
    
    languages_detected = []
    for lang, keywords in language_indicators.items():
        if any(kw in text_lower for kw in keywords):
            languages_detected.append(lang)
    
    is_multilingual = len(languages_detected) >= 2
    
    if is_multilingual and (has_security_keywords or has_code_patterns):
        return True
    
    return False


def detect_obfuscation(text: str) -> bool:
    """Simplified version of detect_obfuscation for testing."""
    # Check for fullwidth Unicode
    if any(0xFF00 <= ord(c) <= 0xFFEF for c in text):
        return True
    
    # Check for zero-width characters
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff']
    if any(zw in text for zw in zero_width_chars):
        return True
    
    # Check for Base64/URL encoding
    if '%' in text and len([c for c in text if c == '%']) > 3:
        return True
    
    # Check for comment injection
    if re.search(r'\w+#\w+#\w+', text):
        return True
    
    return False


def analyze_bypass_hypotheses(result_file: str) -> Dict[str, Any]:
    """Analyze bypasses to test regression hypotheses."""
    with open(result_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract bypasses
    all_attacks = []
    if "results" in data:
        all_attacks = data["results"]
    elif "summary" in data and "by_round" in data["summary"]:
        for round_data in data["summary"]["by_round"]:
            if "attacks" in round_data:
                all_attacks.extend(round_data["attacks"])
    
    bypasses = [a for a in all_attacks if not a.get("blocked", True)]
    
    # Filter by category
    multilingual_bypasses = [b for b in bypasses if b.get("category") == "multilingual"]
    creative_bypasses = [b for b in bypasses if b.get("category") == "creative"]
    
    analysis = {
        "total_bypasses": len(bypasses),
        "multilingual_bypasses": len(multilingual_bypasses),
        "creative_bypasses": len(creative_bypasses),
        "hypothesis_a": {
            "name": "Preprocessing-Kollision: normalize_obfuscation() normalisiert legitime multilinguale Zeichen",
            "tested": 0,
            "confirmed": 0,
            "examples": []
        },
        "hypothesis_b": {
            "name": "Threshold-Interaktion: is_multilingual_attack() wird durch Obfuscation-Muster getäuscht",
            "tested": 0,
            "confirmed": 0,
            "examples": []
        },
        "hypothesis_c": {
            "name": "Creative-Erkennung: Neue Obfuscation-Regeln stufen kreative Angriffe als 'benign' ein",
            "tested": 0,
            "confirmed": 0,
            "examples": []
        },
        "preprocessing_analysis": {
            "multilingual": [],
            "creative": []
        }
    }
    
    # Test Hypothesis A: Preprocessing-Kollision
    print("[HYPOTHESIS A] Testing preprocessing collision...")
    for bypass in multilingual_bypasses:
        payload = bypass.get("payload", "")
        if not payload:
            continue
        
        analysis["hypothesis_a"]["tested"] += 1
        
        original = payload
        normalized = normalize_obfuscation(original)
        
        # Check if legitimate multilingual characters were normalized
        # Look for non-ASCII characters that might be legitimate
        original_non_ascii = [c for c in original if ord(c) > 127]
        normalized_non_ascii = [c for c in normalized if ord(c) > 127]
        
        # If original had non-ASCII but normalized doesn't, might be legitimate multilingual
        if original_non_ascii and not normalized_non_ascii:
            # Check if these were legitimate language characters (not obfuscation)
            legitimate_chars = ['é', 'è', 'ê', 'à', 'ç', 'ö', 'ü', 'ä', 'ñ', 'í', 'ó', 'ú']
            if any(c in original for c in legitimate_chars):
                analysis["hypothesis_a"]["confirmed"] += 1
                analysis["hypothesis_a"]["examples"].append({
                    "original": original[:200],
                    "normalized": normalized[:200],
                    "lost_chars": [c for c in original_non_ascii if c not in normalized],
                    "rule_score": bypass.get("rule_score", 0.0),
                    "ml_score": bypass.get("ml_score", 0.0)
                })
        
        # Store preprocessing analysis
        analysis["preprocessing_analysis"]["multilingual"].append({
            "original": original[:200],
            "normalized": normalized[:200],
            "changed": original != normalized,
            "rule_score": bypass.get("rule_score", 0.0),
            "ml_score": bypass.get("ml_score", 0.0)
        })
    
    # Test Hypothesis B: Threshold-Interaktion
    print("[HYPOTHESIS B] Testing threshold interaction...")
    for bypass in multilingual_bypasses:
        payload = bypass.get("payload", "")
        if not payload:
            continue
        
        analysis["hypothesis_b"]["tested"] += 1
        
        # Test if is_multilingual_attack() works on original
        original_detected = is_multilingual_attack(payload)
        normalized_detected = is_multilingual_attack(normalize_obfuscation(payload))
        
        # Test if obfuscation detection interferes
        has_obfuscation = detect_obfuscation(payload)
        
        rule_score = bypass.get("rule_score", 0.0)
        ml_score = bypass.get("ml_score", 0.0)
        
        # If multilingual attack not detected but should be, or obfuscation interferes
        if not original_detected and ml_score > 0.55:
            # Check if obfuscation detection would trigger wrong threshold
            if has_obfuscation and rule_score == 0.0:
                # Should use 0.70 threshold for obfuscation, but might use 0.75 for benign
                analysis["hypothesis_b"]["confirmed"] += 1
                analysis["hypothesis_b"]["examples"].append({
                    "payload": payload[:200],
                    "is_multilingual_attack_original": original_detected,
                    "is_multilingual_attack_normalized": normalized_detected,
                    "has_obfuscation": has_obfuscation,
                    "rule_score": rule_score,
                    "ml_score": ml_score,
                    "expected_threshold": "0.55 (multilingual)" if original_detected else "0.70 (obfuscation)" if has_obfuscation else "0.75 (benign)"
                })
    
    # Test Hypothesis C: Creative-Erkennung
    print("[HYPOTHESIS C] Testing creative detection...")
    for bypass in creative_bypasses:
        payload = bypass.get("payload", "")
        if not payload:
            continue
        
        analysis["hypothesis_c"]["tested"] += 1
        
        # Check if creative bypass has obfuscation that was normalized away
        original = payload
        normalized = normalize_obfuscation(original)
        
        has_obfuscation = detect_obfuscation(original)
        rule_score = bypass.get("rule_score", 0.0)
        ml_score = bypass.get("ml_score", 0.0)
        
        # If rule_score is 0.0 (benign) but has obfuscation, might be misclassified
        if rule_score == 0.0 and has_obfuscation:
            analysis["hypothesis_c"]["confirmed"] += 1
            analysis["hypothesis_c"]["examples"].append({
                "payload": payload[:200],
                "has_obfuscation": has_obfuscation,
                "normalized": normalized[:200],
                "rule_score": rule_score,
                "ml_score": ml_score,
                "issue": "Obfuscation detected but rule_score=0.0 (benign classification)"
            })
        # If ML score is low but should be higher
        elif rule_score < 0.3 and ml_score < 0.60:
            analysis["hypothesis_c"]["confirmed"] += 1
            analysis["hypothesis_c"]["examples"].append({
                "payload": payload[:200],
                "has_obfuscation": has_obfuscation,
                "rule_score": rule_score,
                "ml_score": ml_score,
                "issue": "Low scores from both rule engine and ML model"
            })
        
        # Store preprocessing analysis
        analysis["preprocessing_analysis"]["creative"].append({
            "original": original[:200],
            "normalized": normalized[:200],
            "changed": original != normalized,
            "has_obfuscation": has_obfuscation,
            "rule_score": rule_score,
            "ml_score": ml_score
        })
    
    return analysis


def print_hypothesis_results(analysis: Dict[str, Any]):
    """Print hypothesis test results."""
    print("=" * 80)
    print("REGRESSION HYPOTHESES ANALYSIS")
    print("=" * 80)
    print(f"\nTotal Bypasses: {analysis['total_bypasses']}")
    print(f"Multilingual Bypasses: {analysis['multilingual_bypasses']}")
    print(f"Creative Bypasses: {analysis['creative_bypasses']}")
    
    for hyp_key in ["hypothesis_a", "hypothesis_b", "hypothesis_c"]:
        hyp = analysis[hyp_key]
        print("\n" + "=" * 80)
        print(f"HYPOTHESIS: {hyp['name']}")
        print("=" * 80)
        print(f"Tested: {hyp['tested']}")
        print(f"Confirmed: {hyp['confirmed']} ({hyp['confirmed']/max(hyp['tested'],1)*100:.1f}%)")
        
        if hyp['examples']:
            print(f"\nExamples ({min(3, len(hyp['examples']))} of {len(hyp['examples'])}):")
            for i, ex in enumerate(hyp['examples'][:3], 1):
                print(f"\n  Example {i}:")
                for key, value in ex.items():
                    if isinstance(value, str) and len(value) > 100:
                        print(f"    {key}: {value[:100]}...")
                    else:
                        print(f"    {key}: {value}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze regression hypotheses for bypasses")
    parser.add_argument("--input", type=str, default="deepseek_redteam_results_20251209_040046.json",
                       help="Input JSON file")
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"[ERROR] File not found: {args.input}")
        sys.exit(1)
    
    print(f"[INFO] Analyzing: {args.input}")
    
    analysis = analyze_bypass_hypotheses(args.input)
    print_hypothesis_results(analysis)
    
    # Save analysis
    output_file = f"analysis/regression_hypotheses_{Path(args.input).stem}.json"
    Path("analysis").mkdir(exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Analysis saved to: {output_file}")

