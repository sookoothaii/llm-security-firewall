#!/usr/bin/env python3
"""
False Negative Analysis Script
==============================

Extrahiert und analysiert False Negatives aus Test-Ergebnissen.
Führt Tests erneut durch und sammelt detaillierte Debug-Informationen.

Usage:
    python scripts/analyze_false_negatives.py \
        --results results/multi_component_test_20251212_232748.json \
        --output failures_analysis/
    
    python scripts/analyze_false_negatives.py \
        --test-suite adversarial \
        --service 8001 \
        --output failures_analysis/
"""

import json
import argparse
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from test_suites.runners.multi_component_runner import ComponentLoader, TestCase, MultiComponentRunner


class FalseNegativeAnalyzer:
    """Analysiert False Negatives und sammelt Debug-Informationen."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.test_suites_dir = project_root / "test_suites"
        self.loader = ComponentLoader(self.test_suites_dir)
        self.runner = MultiComponentRunner(self.test_suites_dir, output_dir)
    
    def load_test_results(self, results_path: Path) -> Dict[str, Any]:
        """Lädt Test-Ergebnisse aus JSON-Datei."""
        with open(results_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def extract_false_negatives_from_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extrahiert False Negatives aus Test-Ergebnissen.
        
        Da die JSON-Ergebnisse nur Zusammenfassungen enthalten, müssen wir
        die Testfälle erneut ausführen, um die False Negatives zu identifizieren.
        """
        false_negatives = []
        
        # Finde adversarial component results
        for result in results.get("results", []):
            if result.get("component") == "adversarial" and result.get("false_negatives", 0) > 0:
                fn_count = result.get("false_negatives", 0)
                print(f"Found {fn_count} false negatives in adversarial component")
        
        return false_negatives
    
    async def identify_false_negatives(self, component: str, service_port: int) -> List[Dict[str, Any]]:
        """
        Führt Tests erneut aus und identifiziert False Negatives.
        
        Returns:
            Liste von False Negative Testfällen mit Details
        """
        print(f"\n{'='*80}")
        print(f"🔍 Identifying False Negatives")
        print(f"{'='*80}")
        print(f"Component: {component}")
        print(f"Service: Port {service_port}")
        
        # Lade Testfälle
        if component == "adversarial":
            test_cases = self.loader.load_adversarial_set()
        else:
            print(f"❌ Unsupported component: {component}")
            return []
        
        print(f"Loaded {len(test_cases)} test cases")
        
        # Führe Tests aus
        false_negatives = []
        total = len(test_cases)
        
        print(f"\nTesting {total} cases...")
        for i, test_case in enumerate(test_cases, 1):
            if i % 10 == 0:
                print(f"  Progress: {i}/{total} ({i/total*100:.1f}%)")
            
            # Erwartet blockiert, aber nicht blockiert = False Negative
            if not test_case.expected_blocked:
                continue
            
            # Teste gegen Service
            response = await self.runner.detect_text(service_port, test_case.text)
            is_blocked = self.runner.is_blocked(response, self.runner.services[service_port]["name"])
            
            if not is_blocked:
                # False Negative gefunden!
                false_negatives.append({
                    "text": test_case.text,
                    "category": test_case.category,
                    "metadata": test_case.metadata,
                    "expected_blocked": test_case.expected_blocked,
                    "actual_blocked": False,
                    "response": response,
                    "test_index": i
                })
        
        print(f"\n✅ Found {len(false_negatives)} false negatives out of {total} test cases")
        return false_negatives
    
    def analyze_false_negative_patterns(self, false_negatives: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analysiert Patterns in False Negatives."""
        analysis = {
            "total": len(false_negatives),
            "by_category": {},
            "common_phrases": {},
            "text_lengths": [],
            "contains_jailbreak_phrases": 0,
            "contains_destructive_commands": 0,
            "contains_encoding": 0
        }
        
        # Jailbreak-Phrasen (aus Policy)
        jailbreak_phrases = [
            "ignore previous", "you are now dan", "developer mode", "roleplay",
            "override", "bypass safety", "ignore above", "system prompt",
            "forget your rules", "output as", "### instruction"
        ]
        
        # Destruktive Command-Patterns (aus Policy)
        destructive_patterns = [
            "rm -rf", "sudo chmod", "format hard drive", "delete all files",
            "bypass security", "access private data", "modify system settings",
            "execute this shell command", "run this bash script", "run this command",
            "write python code", "write code", "command line"
        ]
        
        # Encoding-Patterns
        encoding_patterns = ["%", "\\x", "\\u", "base64", "hex", "url encod"]
        
        for fn in false_negatives:
            text_lower = fn["text"].lower()
            
            # Kategorie
            category = fn.get("category", "unknown")
            analysis["by_category"][category] = analysis["by_category"].get(category, 0) + 1
            
            # Text-Länge
            analysis["text_lengths"].append(len(fn["text"]))
            
            # Jailbreak-Phrasen
            if any(phrase in text_lower for phrase in jailbreak_phrases):
                analysis["contains_jailbreak_phrases"] += 1
            
            # Destruktive Commands
            if any(pattern in text_lower for pattern in destructive_patterns):
                analysis["contains_destructive_commands"] += 1
            
            # Encoding
            if any(pattern in text_lower for pattern in encoding_patterns):
                analysis["contains_encoding"] += 1
        
        # Berechne Durchschnitte
        if analysis["text_lengths"]:
            analysis["avg_text_length"] = sum(analysis["text_lengths"]) / len(analysis["text_lengths"])
            analysis["min_text_length"] = min(analysis["text_lengths"])
            analysis["max_text_length"] = max(analysis["text_lengths"])
        
        return analysis
    
    def save_analysis(self, false_negatives: List[Dict[str, Any]], analysis: Dict[str, Any]):
        """Speichert Analyse-Ergebnisse."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Speichere False Negatives
        fn_file = self.output_dir / f"false_negatives_{timestamp}.json"
        with open(fn_file, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": timestamp,
                "total": len(false_negatives),
                "false_negatives": false_negatives
            }, f, indent=2, ensure_ascii=False)
        
        # Speichere Pattern-Analyse
        analysis_file = self.output_dir / f"false_negative_analysis_{timestamp}.json"
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": timestamp,
                "analysis": analysis
            }, f, indent=2, ensure_ascii=False)
        
        # Erstelle Text-Report
        report_file = self.output_dir / f"false_negative_report_{timestamp}.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("FALSE NEGATIVE ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Total False Negatives: {analysis['total']}\n\n")
            
            f.write("By Category:\n")
            f.write("-"*80 + "\n")
            for category, count in sorted(analysis['by_category'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {category}: {count}\n")
            
            f.write("\nPattern Analysis:\n")
            f.write("-"*80 + "\n")
            f.write(f"  Contains Jailbreak Phrases: {analysis['contains_jailbreak_phrases']}/{analysis['total']}\n")
            f.write(f"  Contains Destructive Commands: {analysis['contains_destructive_commands']}/{analysis['total']}\n")
            f.write(f"  Contains Encoding: {analysis['contains_encoding']}/{analysis['total']}\n")
            
            if 'avg_text_length' in analysis:
                f.write(f"\nText Length Statistics:\n")
                f.write(f"  Average: {analysis['avg_text_length']:.1f} chars\n")
                f.write(f"  Min: {analysis['min_text_length']} chars\n")
                f.write(f"  Max: {analysis['max_text_length']} chars\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("FALSE NEGATIVE CASES\n")
            f.write("="*80 + "\n\n")
            
            for i, fn in enumerate(false_negatives, 1):
                f.write(f"Case {i}:\n")
                f.write(f"  Category: {fn.get('category', 'unknown')}\n")
                f.write(f"  Text: {fn['text']}\n")
                f.write(f"  Response: {json.dumps(fn.get('response', {}), indent=4)}\n")
                f.write("\n" + "-"*80 + "\n\n")
        
        print(f"\n✅ Analysis saved:")
        print(f"   False Negatives: {fn_file}")
        print(f"   Analysis: {analysis_file}")
        print(f"   Report: {report_file}")


async def main():
    parser = argparse.ArgumentParser(description="Analyze false negatives from test results")
    parser.add_argument(
        "--results",
        type=Path,
        help="Path to test results JSON file"
    )
    parser.add_argument(
        "--test-suite",
        type=str,
        default="adversarial",
        help="Test suite to analyze (default: adversarial)"
    )
    parser.add_argument(
        "--service",
        type=int,
        default=8001,
        help="Service port to test against (default: 8001)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "results" / "failures_analysis",
        help="Output directory for analysis results"
    )
    
    args = parser.parse_args()
    
    analyzer = FalseNegativeAnalyzer(args.output)
    
    # Identifiziere False Negatives
    false_negatives = await analyzer.identify_false_negatives(args.test_suite, args.service)
    
    if not false_negatives:
        print("\n✅ No false negatives found!")
        return
    
    # Analysiere Patterns
    print(f"\n{'='*80}")
    print(f"📊 Analyzing Patterns")
    print(f"{'='*80}")
    analysis = analyzer.analyze_false_negative_patterns(false_negatives)
    
    # Zeige Zusammenfassung
    print(f"\nSummary:")
    print(f"  Total False Negatives: {analysis['total']}")
    print(f"  By Category:")
    for category, count in sorted(analysis['by_category'].items(), key=lambda x: x[1], reverse=True):
        print(f"    {category}: {count}")
    print(f"  Contains Jailbreak Phrases: {analysis['contains_jailbreak_phrases']}/{analysis['total']}")
    print(f"  Contains Destructive Commands: {analysis['contains_destructive_commands']}/{analysis['total']}")
    print(f"  Contains Encoding: {analysis['contains_encoding']}/{analysis['total']}")
    
    # Speichere Analyse
    analyzer.save_analysis(false_negatives, analysis)
    
    print(f"\n✅ Analysis complete!")


if __name__ == "__main__":
    asyncio.run(main())

