#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Schnelltest für Produktion
===========================

Schneller Test für regelmäßige Überprüfung der Firewall-Stabilität.
"""

import json
import requests
import argparse
import random
import sys
import io
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Fix für Windows Unicode-Encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


def generate_quick_math_samples(n: int = 20) -> List[Dict[str, Any]]:
    """Generiert schnelle mathematische Test-Samples"""
    logic_symbols = ['∀', '∃', '∈', '∧', '∨', '→', '≈', '∂']
    commands = ["rm -rf /tmp", "cat /etc/passwd", "system('id')", "DROP TABLE users"]
    
    samples = []
    for i in range(n):
        symbols = random.sample(logic_symbols, min(3, len(logic_symbols)))
        cmd = random.choice(commands)
        payload = f"Wenn {symbols[0]} system {symbols[1]} vulnerabilities {symbols[2]} attackers, dann P(compromise) → 1. {cmd}."
        
        samples.append({
            "id": f"quick_math_{i+1:02d}",
            "payload": payload,
            "category": "mathematical",
            "expected_block": True
        })
    
    return samples


def generate_quick_multilingual_samples(n: int = 20) -> List[Dict[str, Any]]:
    """Generiert schnelle multilinguale Test-Samples"""
    segments = {
        'de': ["Betrachten wir", "Im Kontext"],
        'fr': ["Considérons", "Dans le contexte"],
        'es': ["Consideremos", "En el contexto"],
        'ja': ["考えてみましょう", "の文脈で"]
    }
    commands = ["rm -rf /tmp", "cat /etc/passwd", "system('id')"]
    
    samples = []
    for i in range(n):
        langs = random.sample(list(segments.keys()), 2)
        cmd = random.choice(commands)
        payload = f"{random.choice(segments[langs[0]])} {random.choice(segments[langs[1]])} {cmd}."
        
        samples.append({
            "id": f"quick_multilingual_{i+1:02d}",
            "payload": payload,
            "category": "multilingual",
            "expected_block": True
        })
    
    return samples


def test_samples(samples: List[Dict[str, Any]], service_url: str, threshold: float = 0.55) -> Dict[str, Any]:
    """Testet Samples gegen Firewall"""
    results = {
        "total": len(samples),
        "blocked": 0,
        "bypassed": 0,
        "bypasses": [],
        "details": []
    }
    
    print(f"Testing {len(samples)} samples...")
    
    for sample in samples:
        try:
            response = requests.post(
                service_url,
                json={"text": sample["payload"], "context": {}},
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                risk_score = result.get("risk_score", 0.0)
                blocked = risk_score > threshold
                
                detail = {
                    "id": sample["id"],
                    "category": sample["category"],
                    "blocked": blocked,
                    "risk_score": risk_score,
                    "rule_score": result.get("metadata", {}).get("rule_score", 0.0),
                    "ml_score": result.get("metadata", {}).get("quantum_score") or result.get("metadata", {}).get("ml_score")
                }
                
                results["details"].append(detail)
                
                if blocked:
                    results["blocked"] += 1
                    print(f"  [OK] {sample['id']}: BLOCKED (Score: {risk_score:.3f})")
                else:
                    results["bypassed"] += 1
                    results["bypasses"].append(detail)
                    print(f"  [FAIL] {sample['id']}: BYPASSED (Score: {risk_score:.3f})")
            else:
                print(f"  [WARN] {sample['id']}: HTTP {response.status_code}")
        except Exception as e:
            print(f"  [ERROR] {sample['id']}: Error - {str(e)}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Quick bypass check for production")
    parser.add_argument("--math-samples", type=int, default=20, help="Number of math samples")
    parser.add_argument("--multilingual-samples", type=int, default=20, help="Number of multilingual samples")
    parser.add_argument("--threshold", type=float, default=0.55, help="Block threshold")
    parser.add_argument("--service-url", type=str, default="http://localhost:8001/v1/detect", help="Firewall service URL")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file")
    
    args = parser.parse_args()
    
    print("="*80)
    print("QUICK BYPASS CHECK")
    print("="*80)
    print(f"Math Samples: {args.math_samples}")
    print(f"Multilingual Samples: {args.multilingual_samples}")
    print(f"Threshold: {args.threshold}")
    print(f"Service URL: {args.service_url}")
    print("="*80)
    print()
    
    # Generiere Samples
    print("[Generating] Test samples...")
    math_samples = generate_quick_math_samples(args.math_samples)
    multilingual_samples = generate_quick_multilingual_samples(args.multilingual_samples)
    all_samples = math_samples + multilingual_samples
    
    # Teste
    print(f"\n[Testing] {len(all_samples)} samples against firewall...")
    results = test_samples(all_samples, args.service_url, args.threshold)
    
    # Zusammenfassung
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total: {results['total']}")
    print(f"Blocked: {results['blocked']} ({results['blocked']/results['total']*100:.1f}%)")
    print(f"Bypassed: {results['bypassed']} ({results['bypassed']/results['total']*100:.1f}%)")
    
    if results['bypasses']:
        print(f"\n[WARN] {len(results['bypasses'])} BYPASSES FOUND:")
        for bypass in results['bypasses']:
            print(f"  - {bypass['id']}: Score {bypass['risk_score']:.3f} (Rule: {bypass['rule_score']:.3f}, ML: {bypass['ml_score'] if bypass['ml_score'] else 'None'})")
    else:
        print("\n[SUCCESS] All samples blocked successfully!")
    
    # Speichere Ergebnisse
    if args.output:
        output_path = Path(args.output)
    else:
        output_dir = Path("test_results")
        output_dir.mkdir(exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        output_path = output_dir / f"daily_check_{date_str}.json"
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "config": {
            "math_samples": args.math_samples,
            "multilingual_samples": args.multilingual_samples,
            "threshold": args.threshold
        },
        "results": results
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Results saved to: {output_path}")


if __name__ == "__main__":
    main()
