#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detailed analysis of Multilingual Bypasses
"""

import json
import sys
from pathlib import Path
import re

# Fix Unicode output for Windows
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

def is_multilingual_attack(text: str) -> bool:
    """Check if text is detected as multilingual attack."""
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

def detect_languages(text: str) -> list:
    """Detect which languages are present in text."""
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
    
    text_lower = text.lower()
    languages_detected = []
    for lang, keywords in language_indicators.items():
        if any(kw in text_lower for kw in keywords):
            languages_detected.append(lang)
    
    return languages_detected

if __name__ == "__main__":
    result_file = "deepseek_redteam_results_20251209_040046.json"
    
    with open(result_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract all attacks
    all_attacks = []
    if "results" in data:
        all_attacks = data["results"]
    elif "summary" in data and "by_round" in data["summary"]:
        for round_data in data["summary"]["by_round"]:
            if "attacks" in round_data:
                all_attacks.extend(round_data["attacks"])
    
    # Get multilingual bypasses
    multilingual_bypasses = [a for a in all_attacks if a.get("category") == "multilingual" and not a.get("blocked", True)]
    multilingual_blocked = [a for a in all_attacks if a.get("category") == "multilingual" and a.get("blocked", True)]
    
    print("=" * 80)
    print("MULTILINGUAL BYPASS ANALYSIS")
    print("=" * 80)
    print(f"\nTotal Multilingual Attacks: {len(multilingual_bypasses) + len(multilingual_blocked)}")
    print(f"Bypassed: {len(multilingual_bypasses)}")
    print(f"Blocked: {len(multilingual_blocked)}")
    
    print("\n" + "=" * 80)
    print("BYPASSED ATTACKS (8):")
    print("=" * 80)
    
    for i, bypass in enumerate(multilingual_bypasses, 1):
        payload = bypass.get("payload", "")
        rule_score = bypass.get("rule_score", 0.0)
        ml_score = bypass.get("ml_score", 0.0)
        
        detected = is_multilingual_attack(payload)
        languages = detect_languages(payload)
        
        print(f"\n{i}. Rule Score: {rule_score:.3f}, ML Score: {ml_score:.3f}")
        print(f"   is_multilingual_attack(): {detected}")
        print(f"   Languages detected: {languages}")
        print(f"   Payload: {payload[:400]}...")
        
        # Check why it wasn't detected
        if not detected:
            print(f"   ❌ NOT DETECTED AS MULTILINGUAL ATTACK")
            if len(languages) < 2:
                print(f"      Reason: Not multilingual (only {len(languages)} language(s) detected)")
            else:
                print(f"      Reason: Multilingual but missing security keywords/code patterns")
    
    print("\n" + "=" * 80)
    print("BLOCKED ATTACKS (Sample of 5):")
    print("=" * 80)
    
    for i, blocked in enumerate(multilingual_blocked[:5], 1):
        payload = blocked.get("payload", "")
        rule_score = blocked.get("rule_score", 0.0)
        ml_score = blocked.get("ml_score", 0.0)
        
        detected = is_multilingual_attack(payload)
        languages = detect_languages(payload)
        
        print(f"\n{i}. Rule Score: {rule_score:.3f}, ML Score: {ml_score:.3f}")
        print(f"   is_multilingual_attack(): {detected}")
        print(f"   Languages detected: {languages}")
        print(f"   Payload: {payload[:400]}...")

