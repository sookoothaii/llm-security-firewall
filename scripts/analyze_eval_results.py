#!/usr/bin/env python3
"""
Evaluation Results Analyzer
===========================

Analysiert Result-JSONs von Evaluation Suites und generiert:
- Zusammenfassungs-Statistiken
- Kategorien-Analyse
- Latenz-Analyse
- Trend-Visualisierung (wenn matplotlib verfügbar)

Creator: HAK_GAL Security Team
Date: 2025-12-10
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


class EvalResultsAnalyzer:
    """Analysiert Evaluation Results."""
    
    def __init__(self):
        self.results: List[Dict] = []
    
    def load_result(self, result_path: Path) -> Dict:
        """Lade Result-JSON."""
        with open(result_path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    def load_results(self, results_dir: Path) -> List[Dict]:
        """Lade alle Results aus einem Verzeichnis."""
        results = []
        for result_file in results_dir.glob("*.json"):
            try:
                result = self.load_result(result_file)
                results.append(result)
            except Exception as e:
                print(f"⚠️  Fehler beim Laden von {result_file}: {e}")
        return results
    
    def analyze_single_result(self, result: Dict) -> Dict:
        """Analysiere ein einzelnes Result."""
        analysis = {
            "suite_name": result.get("suite_name", "unknown"),
            "timestamp": result.get("timestamp", ""),
            "total_attacks": result.get("total_attacks", 0),
            "detection_rate": result.get("detection_rate", 0.0),
            "false_positives": result.get("false_positives", 0),
            "false_negatives": result.get("false_negatives", 0),
            "average_latency_ms": result.get("average_latency_ms", 0.0),
        }
        
        # Kategorien-Analyse
        category_stats = defaultdict(lambda: {"total": 0, "correct": 0, "bypasses": 0})
        
        for attack_result in result.get("results", []):
            category = attack_result.get("category", "unknown")
            category_stats[category]["total"] += 1
            if attack_result.get("correct", False):
                category_stats[category]["correct"] += 1
            if attack_result.get("expected_blocked", True) and not attack_result.get("actual_blocked", False):
                category_stats[category]["bypasses"] += 1
        
        analysis["category_stats"] = dict(category_stats)
        
        return analysis
    
    def analyze_multiple_results(self, results: List[Dict]) -> Dict:
        """Analysiere mehrere Results (Trend-Analyse)."""
        if not results:
            return {}
        
        # Sortiere nach Timestamp
        results_sorted = sorted(results, key=lambda r: r.get("timestamp", ""))
        
        analysis = {
            "total_suites": len(results),
            "suites": [self.analyze_single_result(r) for r in results_sorted],
            "overall_stats": {
                "average_detection_rate": sum(r.get("detection_rate", 0) for r in results) / len(results),
                "total_bypasses": sum(r.get("false_negatives", 0) for r in results),
                "total_false_positives": sum(r.get("false_positives", 0) for r in results),
                "average_latency_ms": sum(r.get("average_latency_ms", 0) for r in results) / len(results),
            }
        }
        
        # Kategorien-Übersicht über alle Suites
        all_category_stats = defaultdict(lambda: {"total": 0, "correct": 0, "bypasses": 0})
        
        for result in results:
            for attack_result in result.get("results", []):
                category = attack_result.get("category", "unknown")
                all_category_stats[category]["total"] += 1
                if attack_result.get("correct", False):
                    all_category_stats[category]["correct"] += 1
                if attack_result.get("expected_blocked", True) and not attack_result.get("actual_blocked", False):
                    all_category_stats[category]["bypasses"] += 1
        
        analysis["overall_category_stats"] = {
            cat: {
                "total": stats["total"],
                "correct": stats["correct"],
                "detection_rate": (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0,
                "bypasses": stats["bypasses"]
            }
            for cat, stats in all_category_stats.items()
        }
        
        return analysis
    
    def print_analysis(self, analysis: Dict):
        """Print analysis results."""
        print("=" * 80)
        print("EVALUATION RESULTS ANALYSIS")
        print("=" * 80)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        if "overall_stats" in analysis:
            # Multi-result analysis
            print("OVERALL STATISTICS")
            print("-" * 80)
            stats = analysis["overall_stats"]
            print(f"Total Suites: {analysis['total_suites']}")
            print(f"Average Detection Rate: {stats['average_detection_rate']:.1f}%")
            print(f"Total Bypasses: {stats['total_bypasses']}")
            print(f"Total False Positives: {stats['total_false_positives']}")
            print(f"Average Latency: {stats['average_latency_ms']:.1f}ms")
            print()
            
            print("CATEGORY STATISTICS")
            print("-" * 80)
            for category, cat_stats in analysis.get("overall_category_stats", {}).items():
                print(f"\n{category}:")
                print(f"  Total: {cat_stats['total']}")
                print(f"  Correct: {cat_stats['correct']}/{cat_stats['total']} ({cat_stats['detection_rate']:.1f}%)")
                print(f"  Bypasses: {cat_stats['bypasses']}")
        else:
            # Single result analysis
            print(f"Suite: {analysis['suite_name']}")
            print(f"Timestamp: {analysis['timestamp']}")
            print(f"Detection Rate: {analysis['detection_rate']:.1f}%")
            print(f"False Positives: {analysis['false_positives']}")
            print(f"False Negatives (Bypasses): {analysis['false_negatives']}")
            print(f"Average Latency: {analysis['average_latency_ms']:.1f}ms")
            print()
            
            print("CATEGORY BREAKDOWN")
            print("-" * 80)
            for category, stats in analysis.get("category_stats", {}).items():
                detection_rate = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
                print(f"{category}: {stats['correct']}/{stats['total']} ({detection_rate:.1f}%) - Bypasses: {stats['bypasses']}")
        
        print("=" * 80)
    
    def plot_trends(self, analysis: Dict, output_path: Path):
        """Generate trend plots (requires matplotlib)."""
        if not HAS_MATPLOTLIB:
            print("WARNING: matplotlib not available - no plots generated")
            return
        
        if "overall_stats" not in analysis:
            print("WARNING: Trend plot requires multiple results")
            return
        
        suites = analysis["suites"]
        if len(suites) < 2:
            print("WARNING: At least 2 suites required for trend plot")
            return
        
        fig, axes = plt.subplots(2, 1, figsize=(12, 8))
        
        # Detection Rate Trend
        timestamps = [s["timestamp"][:10] for s in suites]  # Nur Datum
        detection_rates = [s["detection_rate"] for s in suites]
        
        axes[0].plot(range(len(suites)), detection_rates, marker='o', linewidth=2)
        axes[0].set_title("Detection Rate Trend")
        axes[0].set_xlabel("Suite Run")
        axes[0].set_ylabel("Detection Rate (%)")
        axes[0].set_ylim([0, 100])
        axes[0].grid(True, alpha=0.3)
        axes[0].set_xticks(range(len(suites)))
        axes[0].set_xticklabels([f"Run {i+1}" for i in range(len(suites))], rotation=45)
        
        # Latency Trend
        latencies = [s["average_latency_ms"] for s in suites]
        
        axes[1].plot(range(len(suites)), latencies, marker='o', color='orange', linewidth=2)
        axes[1].set_title("Average Latency Trend")
        axes[1].set_xlabel("Suite Run")
        axes[1].set_ylabel("Latency (ms)")
        axes[1].grid(True, alpha=0.3)
        axes[1].set_xticks(range(len(suites)))
        axes[1].set_xticklabels([f"Run {i+1}" for i in range(len(suites))], rotation=45)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        print(f"Plot saved: {output_path}")


def expand_paths(paths: List[Path]) -> List[Path]:
    """Expandiere Wildcards und Verzeichnisse zu Dateien."""
    expanded = []
    for path in paths:
        # Prüfe ob Wildcard-Pattern (enthält * oder ?)
        if '*' in str(path) or '?' in str(path):
            # Glob-Pattern
            parent = path.parent if path.parent != Path('.') else Path.cwd()
            pattern = path.name
            expanded.extend(parent.glob(pattern))
        elif path.is_file():
            expanded.append(path)
        elif path.is_dir():
            # Alle JSON-Dateien im Verzeichnis
            expanded.extend(path.glob("*.json"))
        else:
            # Versuche als Pattern zu behandeln
            parent = path.parent if path.parent != Path('.') else Path.cwd()
            if parent.exists():
                expanded.extend(parent.glob(path.name))
    
    # Entferne Duplikate und sortiere
    return sorted(set(expanded))


def main():
    parser = argparse.ArgumentParser(description="Analyze Evaluation Results")
    parser.add_argument("results", type=str, nargs="+",
                       help="Path to result JSON file(s), directory, or glob pattern (e.g., eval_results/*.json)")
    parser.add_argument("--plot", type=Path, default=None,
                       help="Generate trend plot (requires matplotlib)")
    parser.add_argument("--min-detection-rate", type=float, default=None,
                       help="Minimum detection rate threshold (0-100). Exit with error if below.")
    parser.add_argument("--max-false-positive-rate", type=float, default=None,
                       help="Maximum false positive rate threshold (0-100). Exit with error if above.")
    parser.add_argument("--max-bypasses", type=int, default=None,
                       help="Maximum number of bypasses allowed. Exit with error if exceeded.")
    
    args = parser.parse_args()
    
    analyzer = EvalResultsAnalyzer()
    
    # Konvertiere Strings zu Paths und expandiere
    result_paths = [Path(p) for p in args.results]
    expanded_paths = expand_paths(result_paths)
    
    if not expanded_paths:
        print("❌ Keine Results gefunden")
        print(f"   Gesucht in: {', '.join(str(p) for p in result_paths)}")
        return 1
    
    # Load results
    all_results = []
    for result_path in expanded_paths:
        if result_path.is_file() and result_path.suffix == ".json":
            try:
                all_results.append(analyzer.load_result(result_path))
            except Exception as e:
                print(f"WARNING: Error loading {result_path}: {e}")
    
    if not all_results:
        print("ERROR: No valid results found")
        print(f"   Files found: {len(expanded_paths)}")
        return 1
    
    # Analyze
    if len(all_results) == 1:
        analysis = analyzer.analyze_single_result(all_results[0])
    else:
        analysis = analyzer.analyze_multiple_results(all_results)
    
    # Print analysis
    analyzer.print_analysis(analysis)
    
    # Generate plot if requested
    if args.plot and len(all_results) > 1:
        analyzer.plot_trends(analysis, args.plot)
    
    # CI/CD Gates: Prüfe Schwellenwerte
    exit_code = 0
    
    if "overall_stats" in analysis:
        stats = analysis["overall_stats"]
        detection_rate = stats["average_detection_rate"]
        total_bypasses = stats["total_bypasses"]
        total_false_positives = stats["total_false_positives"]
        total_attacks = sum(r.get("total_attacks", 0) for r in all_results)
        total_benign = sum(
            sum(1 for ar in r.get("results", []) if not ar.get("expected_blocked", True))
            for r in all_results
        )
        false_positive_rate = (total_false_positives / total_benign * 100) if total_benign > 0 else 0.0
        
        print("\n" + "=" * 80)
        print("CI/CD GATES")
        print("=" * 80)
        
        # Min Detection Rate
        if args.min_detection_rate is not None:
            if detection_rate >= args.min_detection_rate:
                print(f"PASS: Detection Rate: {detection_rate:.1f}% >= {args.min_detection_rate:.1f}%")
            else:
                print(f"FAIL: Detection Rate: {detection_rate:.1f}% < {args.min_detection_rate:.1f}% (THRESHOLD NOT MET)")
                exit_code = 1
        
        # Max False Positive Rate
        if args.max_false_positive_rate is not None:
            if false_positive_rate <= args.max_false_positive_rate:
                print(f"PASS: False Positive Rate: {false_positive_rate:.1f}% <= {args.max_false_positive_rate:.1f}%")
            else:
                print(f"FAIL: False Positive Rate: {false_positive_rate:.1f}% > {args.max_false_positive_rate:.1f}% (THRESHOLD EXCEEDED)")
                exit_code = 1
        
        # Max Bypasses
        if args.max_bypasses is not None:
            if total_bypasses <= args.max_bypasses:
                print(f"PASS: Bypasses: {total_bypasses} <= {args.max_bypasses}")
            else:
                print(f"FAIL: Bypasses: {total_bypasses} > {args.max_bypasses} (THRESHOLD EXCEEDED)")
                exit_code = 1
        
        if exit_code == 0 and (args.min_detection_rate or args.max_false_positive_rate or args.max_bypasses):
            print("\nPASS: All CI/CD gates passed")
        elif exit_code != 0:
            print("\nFAIL: CI/CD gates failed - build will fail")
        
        print("=" * 80)
    
    return exit_code


if __name__ == "__main__":
    import sys
    sys.exit(main())

