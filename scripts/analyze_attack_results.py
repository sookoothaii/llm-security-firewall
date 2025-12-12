#!/usr/bin/env python3
"""
Analyse-Skript für Attack-Test-Ergebnisse.

Extrahiert Schwachstellen, generiert Statistiken und visualisiert Score-Verteilungen.

Usage:
    python scripts/analyze_attack_results.py --input attack_test_results_20251208_213245.json
    python scripts/analyze_attack_results.py --input attack_test_results_20251208_213245.json --plot
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter

try:
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_PLOTTING = True
except ImportError:
    HAS_PLOTTING = False
    print("[WARN] matplotlib not available, plotting disabled")


def load_results(json_path: Path) -> Dict[str, Any]:
    """Lädt Ergebnisse aus JSON-Datei."""
    print(f"[1] Loading results from {json_path}...")
    
    if not json_path.exists():
        print(f"[ERROR] File not found: {json_path}")
        
        # Suche nach ähnlichen Dateien im aktuellen Verzeichnis
        current_dir = Path.cwd()
        pattern = "attack_test_results*.json"
        matching_files = list(current_dir.glob(pattern))
        
        if matching_files:
            print(f"\n[INFO] Found {len(matching_files)} similar files in current directory:")
            for f in sorted(matching_files, key=lambda x: x.stat().st_mtime, reverse=True):
                print(f"  - {f.name}")
            print(f"\n[INFO] Try using one of these files, e.g.:")
            print(f"  python scripts/analyze_attack_results.py --input {matching_files[0].name} --plot")
        else:
            print(f"[INFO] No files matching '{pattern}' found in current directory")
            print(f"[INFO] Current directory: {current_dir}")
        
        sys.exit(1)
    
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    print(f"[OK] Loaded results")
    return data


def extract_bypasses(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extrahiert alle Bypasses (nicht geblockte Angriffe)."""
    return [r for r in results if not r.get("blocked", False)]


def analyze_by_category(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Analysiert Ergebnisse pro Kategorie und Subkategorie."""
    category_stats = defaultdict(lambda: {
        "total": 0,
        "blocked": 0,
        "bypassed": 0,
        "bypasses": [],
        "ml_scores": [],
        "rule_scores": [],
        "risk_scores": [],
    })
    
    subcategory_stats = defaultdict(lambda: {
        "total": 0,
        "blocked": 0,
        "bypassed": 0,
        "bypasses": [],
        "ml_scores": [],
        "rule_scores": [],
        "risk_scores": [],
    })
    
    for result in results:
        category = result.get("category", "unknown")
        subcategory = result.get("subcategory", "unknown")
        blocked = result.get("blocked", False)
        
        # Category stats
        category_stats[category]["total"] += 1
        if blocked:
            category_stats[category]["blocked"] += 1
        else:
            category_stats[category]["bypassed"] += 1
            category_stats[category]["bypasses"].append(result)
        
        # Collect scores
        ml_score = result.get("ml_score")
        rule_score = result.get("rule_score", 0.0)
        risk_score = result.get("risk_score", 0.0)
        
        if ml_score is not None:
            category_stats[category]["ml_scores"].append(ml_score)
        category_stats[category]["rule_scores"].append(rule_score)
        category_stats[category]["risk_scores"].append(risk_score)
        
        # Subcategory stats
        subcategory_stats[subcategory]["total"] += 1
        if blocked:
            subcategory_stats[subcategory]["blocked"] += 1
        else:
            subcategory_stats[subcategory]["bypassed"] += 1
            subcategory_stats[subcategory]["bypasses"].append(result)
        
        if ml_score is not None:
            subcategory_stats[subcategory]["ml_scores"].append(ml_score)
        subcategory_stats[subcategory]["rule_scores"].append(rule_score)
        subcategory_stats[subcategory]["risk_scores"].append(risk_score)
    
    # Calculate percentages
    for stats in category_stats.values():
        if stats["total"] > 0:
            stats["block_rate"] = (stats["blocked"] / stats["total"]) * 100
        else:
            stats["block_rate"] = 0.0
    
    for stats in subcategory_stats.values():
        if stats["total"] > 0:
            stats["block_rate"] = (stats["blocked"] / stats["total"]) * 100
        else:
            stats["block_rate"] = 0.0
    
    return {
        "categories": dict(category_stats),
        "subcategories": dict(subcategory_stats),
    }


def find_near_threshold_cases(results: List[Dict[str, Any]], threshold: float = 0.60, margin: float = 0.05) -> List[Dict[str, Any]]:
    """Findet Fälle nahe dem Threshold."""
    near_cases = []
    for result in results:
        ml_score = result.get("ml_score")
        if ml_score is not None:
            if threshold - margin <= ml_score <= threshold + margin:
                near_cases.append(result)
    return sorted(near_cases, key=lambda x: abs(x.get("ml_score", 0) - threshold))


def find_closest_fails(results: List[Dict[str, Any]], top_n: int = 10) -> List[Dict[str, Any]]:
    """Findet die knappsten Fails (höchste ML-Scores bei Bypasses)."""
    bypasses = extract_bypasses(results)
    
    # Sortiere nach ML-Score (höchste zuerst)
    bypasses_with_ml = [b for b in bypasses if b.get("ml_score") is not None]
    bypasses_with_ml.sort(key=lambda x: x.get("ml_score", 0), reverse=True)
    
    return bypasses_with_ml[:top_n]


def print_analysis(data: Dict[str, Any], plot: bool = False):
    """Druckt detaillierte Analyse."""
    summary = data.get("summary", {})
    results = data.get("results", [])
    
    print("\n" + "=" * 80)
    print("DETAILED ATTACK ANALYSIS")
    print("=" * 80)
    
    # Overall stats
    print(f"\nOverall Statistics:")
    print(f"  Total Attacks: {summary.get('total_attacks', len(results))}")
    print(f"  Blocked: {summary.get('total_blocked', 0)} ({summary.get('block_rate', 0):.2f}%)")
    print(f"  Bypassed: {summary.get('total_bypassed', 0)}")
    print(f"  Avg Latency: {summary.get('avg_latency_ms', 0):.1f} ms")
    
    # Category analysis
    category_analysis = analyze_by_category(results)
    
    print(f"\nCategory Statistics:")
    print("-" * 80)
    for category, stats in sorted(category_analysis["categories"].items()):
        print(f"\n{category}:")
        print(f"  Total: {stats['total']}")
        print(f"  Blocked: {stats['blocked']} ({stats['block_rate']:.2f}%)")
        print(f"  Bypassed: {stats['bypassed']}")
        
        if stats["bypassed"] > 0:
            print(f"  ⚠️  BYPASSES ({stats['bypassed']}):")
            for bypass in stats["bypasses"]:
                ml_score = bypass.get("ml_score", "N/A")
                rule_score = bypass.get("rule_score", 0.0)
                risk_score = bypass.get("risk_score", 0.0)
                print(f"    - {bypass.get('id', 'unknown')}: ML={ml_score}, Rule={rule_score:.3f}, Risk={risk_score:.3f}")
        
        # Score statistics
        if stats["ml_scores"]:
            ml_scores = stats["ml_scores"]
            print(f"  ML Score Stats: min={min(ml_scores):.3f}, max={max(ml_scores):.3f}, avg={sum(ml_scores)/len(ml_scores):.3f}")
        
        if stats["rule_scores"]:
            rule_scores = stats["rule_scores"]
            non_zero = [r for r in rule_scores if r > 0]
            if non_zero:
                print(f"  Rule Score Stats: min={min(non_zero):.3f}, max={max(rule_scores):.3f}, avg={sum(rule_scores)/len(rule_scores):.3f}, non-zero={len(non_zero)}/{len(rule_scores)}")
    
    # Subcategory analysis
    print(f"\nSubcategory Statistics:")
    print("-" * 80)
    for subcategory, stats in sorted(category_analysis["subcategories"].items()):
        if stats["bypassed"] > 0:
            print(f"\n{subcategory}:")
            print(f"  Total: {stats['total']}, Blocked: {stats['blocked']} ({stats['block_rate']:.2f}%), Bypassed: {stats['bypassed']}")
            if stats["bypasses"]:
                print(f"  Bypasses:")
                for bypass in stats["bypasses"]:
                    ml_score = bypass.get("ml_score", "N/A")
                    rule_score = bypass.get("rule_score", 0.0)
                    print(f"    - {bypass.get('id', 'unknown')}: ML={ml_score}, Rule={rule_score:.3f}")
    
    # Top 10 closest fails
    closest_fails = find_closest_fails(results, top_n=10)
    if closest_fails:
        print(f"\n🔴 Top 10 Closest Fails (Highest ML-Score Bypasses):")
        print("-" * 80)
        for i, fail in enumerate(closest_fails, 1):
            ml_score = fail.get("ml_score", "N/A")
            rule_score = fail.get("rule_score", 0.0)
            risk_score = fail.get("risk_score", 0.0)
            category = fail.get("category", "unknown")
            subcategory = fail.get("subcategory", "unknown")
            print(f"  {i}. {fail.get('id', 'unknown')} [{category}/{subcategory}]")
            print(f"     ML={ml_score}, Rule={rule_score:.3f}, Risk={risk_score:.3f}")
    
    # Near threshold cases
    near_threshold = find_near_threshold_cases(results, threshold=0.60, margin=0.05)
    print(f"\n📊 Near Threshold Cases (ML-Score 0.55-0.65): {len(near_threshold)}")
    if near_threshold:
        blocked_near = sum(1 for r in near_threshold if r.get("blocked", False))
        bypassed_near = len(near_threshold) - blocked_near
        print(f"  Blocked: {blocked_near}, Bypassed: {bypassed_near}")
    
    # Plotting
    if plot and HAS_PLOTTING:
        plot_analysis(results, category_analysis)
    elif plot and not HAS_PLOTTING:
        print("\n[WARN] Plotting requested but matplotlib not available")


def plot_analysis(results: List[Dict[str, Any]], category_analysis: Dict[str, Dict[str, Any]]):
    """Erstellt Visualisierungen."""
    print("\n[PLOTTING] Generating visualizations...")
    
    # 1. ML Score Distribution
    ml_scores_all = [r.get("ml_score") for r in results if r.get("ml_score") is not None]
    ml_scores_blocked = [r.get("ml_score") for r in results if r.get("blocked", False) and r.get("ml_score") is not None]
    ml_scores_bypassed = [r.get("ml_score") for r in results if not r.get("blocked", False) and r.get("ml_score") is not None]
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Attack Test Results Analysis", fontsize=16)
    
    # ML Score Histogram
    ax1 = axes[0, 0]
    if ml_scores_all:
        ax1.hist(ml_scores_all, bins=20, alpha=0.7, label="All", color="gray")
    if ml_scores_blocked:
        ax1.hist(ml_scores_blocked, bins=20, alpha=0.7, label="Blocked", color="red")
    if ml_scores_bypassed:
        ax1.hist(ml_scores_bypassed, bins=20, alpha=0.7, label="Bypassed", color="orange")
    ax1.axvline(x=0.60, color="black", linestyle="--", label="Threshold (0.60)")
    ax1.set_xlabel("ML Score")
    ax1.set_ylabel("Frequency")
    ax1.set_title("ML Score Distribution")
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Rule Score Distribution
    rule_scores_all = [r.get("rule_score", 0.0) for r in results]
    rule_scores_blocked = [r.get("rule_score", 0.0) for r in results if r.get("blocked", False)]
    rule_scores_bypassed = [r.get("rule_score", 0.0) for r in results if not r.get("blocked", False)]
    
    ax2 = axes[0, 1]
    if rule_scores_all:
        ax2.hist(rule_scores_all, bins=20, alpha=0.7, label="All", color="gray")
    if rule_scores_blocked:
        ax2.hist(rule_scores_blocked, bins=20, alpha=0.7, label="Blocked", color="red")
    if rule_scores_bypassed:
        ax2.hist(rule_scores_bypassed, bins=20, alpha=0.7, label="Bypassed", color="orange")
    ax2.set_xlabel("Rule Score")
    ax2.set_ylabel("Frequency")
    ax2.set_title("Rule Score Distribution")
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    # Block Rate by Category
    ax3 = axes[1, 0]
    categories = []
    block_rates = []
    for cat, stats in sorted(category_analysis["categories"].items()):
        categories.append(cat)
        block_rates.append(stats["block_rate"])
    
    if categories:
        bars = ax3.barh(categories, block_rates, color=["green" if br >= 95 else "orange" if br >= 80 else "red" for br in block_rates])
        ax3.set_xlabel("Block Rate (%)")
        ax3.set_title("Block Rate by Category")
        ax3.axvline(x=95, color="black", linestyle="--", alpha=0.5, label="95% Target")
        ax3.legend()
        ax3.grid(True, alpha=0.3, axis="x")
        
        # Add value labels
        for i, (bar, rate) in enumerate(zip(bars, block_rates)):
            ax3.text(rate + 1, i, f"{rate:.1f}%", va="center")
    
    # ML vs Rule Score Scatter
    ax4 = axes[1, 1]
    ml_rule_pairs = [(r.get("ml_score"), r.get("rule_score", 0.0)) for r in results if r.get("ml_score") is not None]
    if ml_rule_pairs:
        ml_vals, rule_vals = zip(*ml_rule_pairs)
        blocked_mask = [r.get("blocked", False) for r in results if r.get("ml_score") is not None]
        
        if any(blocked_mask):
            ax4.scatter([m for m, b in zip(ml_vals, blocked_mask) if b], 
                       [r for r, b in zip(rule_vals, blocked_mask) if b],
                       alpha=0.6, label="Blocked", color="red", s=30)
        if any(not b for b in blocked_mask):
            ax4.scatter([m for m, b in zip(ml_vals, blocked_mask) if not b],
                       [r for r, b in zip(rule_vals, blocked_mask) if not b],
                       alpha=0.6, label="Bypassed", color="orange", s=50, marker="x")
        
        ax4.axhline(y=0.8, color="gray", linestyle="--", alpha=0.5, label="Rule Threshold (0.8)")
        ax4.axvline(x=0.60, color="gray", linestyle="--", alpha=0.5, label="ML Threshold (0.60)")
        ax4.set_xlabel("ML Score")
        ax4.set_ylabel("Rule Score")
        ax4.set_title("ML Score vs Rule Score")
        ax4.legend()
        ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    output_path = Path("attack_analysis_plots.png")
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"[OK] Plots saved to: {output_path}")
    
    # Close to avoid memory issues
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Analyze attack test results")
    parser.add_argument("--input", type=str, required=True, help="Input JSON file with test results")
    parser.add_argument("--plot", action="store_true", help="Generate plots (requires matplotlib)")
    args = parser.parse_args()
    
    # Load results
    data = load_results(Path(args.input))
    
    # Print analysis
    print_analysis(data, plot=args.plot)
    
    print("\n" + "=" * 80)
    print("Analysis complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
