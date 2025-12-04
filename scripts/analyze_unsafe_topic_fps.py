#!/usr/bin/env python3
"""
UNSAFE_TOPIC False Positive Deep Analysis
==========================================

Analyzes the 17 false positive cases from UNSAFE_TOPIC category to identify
patterns and generate a manual review template.

Usage:
    python scripts/analyze_unsafe_topic_fps.py \
        --fp-analysis analysis/false_positive_analysis_kids.json \
        --dataset datasets/core_suite.jsonl \
        --results logs/kids_core_suite_full_core_suite.jsonl \
        --output review/unsafe_topic_fp_review.csv

Author: Joerg Bollwahn
Date: 2025-12-04
"""

import argparse
import json
import csv
import sys
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any


def load_jsonl(filepath: Path) -> List[Dict[str, Any]]:
    """Load JSONL file."""
    results = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return results


def load_json(filepath: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_fp_item_ids(
    fp_analysis: Dict[str, Any], category: str = "UNSAFE_TOPIC"
) -> List[str]:
    """Extract item IDs for false positives in specified category."""
    category_patterns = fp_analysis.get("category_patterns", {})
    items_by_category = category_patterns.get("items_by_category", {})
    return items_by_category.get(category, [])


def find_items_in_dataset(
    dataset: List[Dict[str, Any]], item_ids: List[str]
) -> Dict[str, Dict[str, Any]]:
    """Find items in dataset by ID."""
    items = {}
    for item in dataset:
        item_id = item.get("id", "")
        if item_id in item_ids:
            items[item_id] = item
    return items


def find_items_in_results(
    results: List[Dict[str, Any]], item_ids: List[str]
) -> Dict[str, Dict[str, Any]]:
    """Find items in results by item_id."""
    items = {}
    for result in results:
        item_id = result.get("item_id", "")
        if item_id in item_ids:
            items[item_id] = result
    return items


def extract_linguistic_patterns(prompts: List[str]) -> Dict[str, Any]:
    """
    Extract common linguistic patterns from prompts.

    Analyzes:
    - Common keywords
    - Question patterns
    - Sentence structures
    - Topic indicators
    """
    patterns = {
        "keywords": Counter(),
        "question_words": Counter(),
        "sentence_lengths": [],
        "common_phrases": Counter(),
    }

    # Common "unsafe topic" trigger words (to identify false positives)
    potential_triggers = [
        "how",
        "what",
        "explain",
        "why",
        "tell",
        "describe",
        "help",
        "improve",
        "better",
        "way",
        "method",
        "guide",
        "steps",
        "symptoms",
        "causes",
        "effects",
        "treatment",
        "prevent",
    ]

    for prompt in prompts:
        prompt_lower = prompt.lower()
        words = re.findall(r"\b\w+\b", prompt_lower)

        # Count keywords
        for word in words:
            if len(word) > 3:  # Only count meaningful words
                patterns["keywords"][word] += 1

        # Count question words
        question_words = ["how", "what", "why", "when", "where", "who", "which"]
        for qw in question_words:
            if qw in prompt_lower:
                patterns["question_words"][qw] += 1

        # Sentence length
        sentences = re.split(r"[.!?]+", prompt)
        for sent in sentences:
            word_count = len(re.findall(r"\b\w+\b", sent))
            if word_count > 0:
                patterns["sentence_lengths"].append(word_count)

        # Check for potential trigger phrases
        for trigger in potential_triggers:
            if trigger in prompt_lower:
                patterns["common_phrases"][trigger] += 1

    # Calculate statistics
    if patterns["sentence_lengths"]:
        patterns["avg_sentence_length"] = sum(patterns["sentence_lengths"]) / len(
            patterns["sentence_lengths"]
        )
        patterns["max_sentence_length"] = max(patterns["sentence_lengths"])
        patterns["min_sentence_length"] = min(patterns["sentence_lengths"])

    return patterns


def generate_review_csv(
    fp_items: Dict[str, Dict[str, Any]],
    result_items: Dict[str, Dict[str, Any]],
    dataset_items: Dict[str, Dict[str, Any]],
    output_path: Path,
):
    """Generate CSV review template."""

    rows = []

    for item_id in sorted(fp_items.keys()):
        dataset_item = dataset_items.get(item_id, {})
        result_item = result_items.get(item_id, {})

        prompt = dataset_item.get("prompt", "")
        risk_score = result_item.get("risk_score", 0.0)
        base_risk_score = (
            result_item.get("metadata", {})
            .get("answer_policy", {})
            .get("base_risk_score", 0.0)
        )

        # Extract category information
        detected_threats = result_item.get("detected_threats", [])
        category = "UNSAFE_TOPIC"

        # Try to extract more detailed category info
        metadata = result_item.get("metadata", {})
        risk_scorer_meta = metadata.get("risk_scorer", {})
        categories = risk_scorer_meta.get("by_category", {})

        # Generate suspected reason based on prompt analysis
        suspected_reason = "UNSAFE_TOPIC category triggered"
        if "how" in prompt.lower():
            suspected_reason += " - instructional/question format"
        if any(word in prompt.lower() for word in ["improve", "better", "help"]):
            suspected_reason += " - improvement language"

        row = {
            "item_id": item_id,
            "prompt": prompt,
            "category": dataset_item.get("category", "unknown"),
            "risk_score": f"{risk_score:.3f}",
            "base_risk_score": f"{base_risk_score:.3f}" if base_risk_score else "N/A",
            "detected_threats": ", ".join(str(t) for t in detected_threats)
            if detected_threats
            else "UNSAFE_TOPIC",
            "suspected_reason": suspected_reason,
            "action": "",  # To be filled during manual review
            "notes": "",  # To be filled during manual review
        }
        rows.append(row)

    # Write CSV
    if rows:
        fieldnames = [
            "item_id",
            "prompt",
            "category",
            "risk_score",
            "base_risk_score",
            "detected_threats",
            "suspected_reason",
            "action",
            "notes",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"Review template saved: {output_path}")
        print(f"Total items: {len(rows)}")
    else:
        print("Warning: No items found for review template")


def analyze_patterns(prompts: List[str]) -> Dict[str, Any]:
    """Analyze linguistic patterns across all prompts."""
    patterns = extract_linguistic_patterns(prompts)

    analysis = {
        "total_prompts": len(prompts),
        "top_keywords": dict(patterns["keywords"].most_common(10)),
        "question_words": dict(patterns["question_words"].most_common()),
        "common_phrases": dict(patterns["common_phrases"].most_common(10)),
    }

    if "avg_sentence_length" in patterns:
        analysis["sentence_statistics"] = {
            "average": patterns["avg_sentence_length"],
            "max": patterns["max_sentence_length"],
            "min": patterns["min_sentence_length"],
        }

    return analysis


def main():
    parser = argparse.ArgumentParser(
        description="Analyze UNSAFE_TOPIC false positives and generate review template"
    )
    parser.add_argument(
        "--fp-analysis",
        type=str,
        required=True,
        help="Path to false positive analysis JSON file",
    )
    parser.add_argument(
        "--dataset", type=str, required=True, help="Path to original dataset JSONL file"
    )
    parser.add_argument(
        "--results",
        type=str,
        required=True,
        help="Path to experiment results JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="review/unsafe_topic_fp_review.csv",
        help="Path to output CSV file",
    )
    parser.add_argument(
        "--pattern-analysis",
        type=str,
        default=None,
        help="Optional: Path to save pattern analysis JSON",
    )

    args = parser.parse_args()

    # Load files
    print("Loading analysis file...")
    fp_analysis = load_json(Path(args.fp_analysis))

    print("Loading dataset...")
    dataset = load_jsonl(Path(args.dataset))

    print("Loading results...")
    results = load_jsonl(Path(args.results))

    # Extract FP item IDs
    fp_item_ids = extract_fp_item_ids(fp_analysis, "UNSAFE_TOPIC")
    print(f"Found {len(fp_item_ids)} UNSAFE_TOPIC false positive items")

    if not fp_item_ids:
        print("No UNSAFE_TOPIC false positives found in analysis file.")
        sys.exit(1)

    # Find items in datasets
    dataset_items = find_items_in_dataset(dataset, fp_item_ids)
    result_items = find_items_in_results(results, fp_item_ids)

    print(f"Found {len(dataset_items)} items in dataset")
    print(f"Found {len(result_items)} items in results")

    # Extract prompts for pattern analysis
    prompts = [
        dataset_items[item_id].get("prompt", "")
        for item_id in fp_item_ids
        if item_id in dataset_items
    ]

    # Analyze patterns
    print("\nAnalyzing linguistic patterns...")
    pattern_analysis = analyze_patterns(prompts)

    print("\n" + "=" * 70)
    print("PATTERN ANALYSIS RESULTS")
    print("=" * 70)
    print(f"Total prompts analyzed: {pattern_analysis['total_prompts']}")

    if pattern_analysis.get("top_keywords"):
        print("\nTop Keywords:")
        for word, count in list(pattern_analysis["top_keywords"].items())[:10]:
            print(f"  {word}: {count}")

    if pattern_analysis.get("question_words"):
        print("\nQuestion Words:")
        for word, count in pattern_analysis["question_words"].items():
            print(f"  {word}: {count}")

    if pattern_analysis.get("sentence_statistics"):
        stats = pattern_analysis["sentence_statistics"]
        print("\nSentence Statistics:")
        print(f"  Average length: {stats['average']:.1f} words")
        print(f"  Range: {stats['min']}-{stats['max']} words")

    # Generate review CSV
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print("\nGenerating review template...")
    generate_review_csv(dataset_items, result_items, dataset_items, output_path)

    # Save pattern analysis if requested
    if args.pattern_analysis:
        pattern_output = Path(args.pattern_analysis)
        pattern_output.parent.mkdir(parents=True, exist_ok=True)
        with open(pattern_output, "w", encoding="utf-8") as f:
            json.dump(pattern_analysis, f, indent=2, ensure_ascii=False)
        print(f"Pattern analysis saved: {pattern_output}")

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print(f"Review template: {output_path}")
    print(f"Items for manual review: {len(fp_item_ids)}")
    print("\nNext steps:")
    print("1. Review CSV file and fill in 'action' and 'notes' columns")
    print("2. Identify common patterns causing false positives")
    print("3. Propose changes to UNSAFE_TOPIC detection logic")


if __name__ == "__main__":
    main()
