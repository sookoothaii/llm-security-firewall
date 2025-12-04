"""
Clean core_suite.jsonl dataset.

Removes:
1. Exact duplicates (same prompt text)
2. Corrects obviously wrong categories

Based on analysis findings:
- core_0171 and core_0173 are exact duplicates
- Many items have wrong categories (e.g., "Explain how the human heart works" → sexual_content_involving_minors)
"""

import json
import sys
from pathlib import Path
from typing import Dict, Set


def clean_dataset(input_path: str, output_path: str) -> Dict[str, int]:
    """
    Clean dataset by removing duplicates and fixing wrong categories.

    Args:
        input_path: Path to input JSONL file
        output_path: Path to output JSONL file

    Returns:
        Dict with cleaning statistics
    """
    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Load all items
    items = []
    seen_prompts: Set[str] = set()
    duplicates_removed = 0
    categories_fixed = 0

    print(f"Loading dataset from {input_path}...")
    with open(input_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                prompt = item.get("prompt", "").strip()

                # Skip exact duplicates (same prompt text)
                prompt_lower = prompt.lower()
                if prompt_lower in seen_prompts:
                    duplicates_removed += 1
                    print(f"  Removing duplicate (line {line_num}): {prompt[:60]}...")
                    continue

                seen_prompts.add(prompt_lower)

                # Fix obviously wrong categories
                original_category = item.get("category", "")
                fixed_category = fix_wrong_category(prompt, original_category)

                if fixed_category != original_category:
                    categories_fixed += 1
                    print(
                        f"  Fixing category (line {line_num}): '{original_category}' -> '{fixed_category}'"
                    )
                    print(f"    Prompt: {prompt[:60]}...")
                    item["category"] = fixed_category

                items.append(item)

            except json.JSONDecodeError as e:
                print(
                    f"  WARNING: Invalid JSON at line {line_num}: {e}", file=sys.stderr
                )
                continue

    # Write cleaned dataset
    output_file.parent.mkdir(parents=True, exist_ok=True)
    print(f"\nWriting cleaned dataset to {output_path}...")
    with open(output_file, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    stats = {
        "total_items": len(items),
        "duplicates_removed": duplicates_removed,
        "categories_fixed": categories_fixed,
    }

    return stats


def fix_wrong_category(prompt: str, current_category: str) -> str:
    """
    Fix obviously wrong categories based on prompt content.

    Args:
        prompt: The prompt text
        current_category: Current category from dataset

    Returns:
        Corrected category name
    """
    prompt_lower = prompt.lower()

    # Map of wrong category patterns to correct category
    fixes = {
        # Harmless educational content should be 'general', not threat categories
        ("explain how rain forms", "self_harm"): "general",
        (
            "explain how the human heart works",
            "sexual_content_involving_minors",
        ): "general",
        ("explain how the human heart works", "cybercrime"): "general",
        ("explain how electricity works", "cybercrime"): "general",
        ("explain how photosynthesis works", "drugs"): "general",
        ("explain how the sun produces energy", "self_harm"): "general",
    }

    # Check for exact matches
    for (prompt_pattern, wrong_cat), correct_cat in fixes.items():
        if prompt_pattern in prompt_lower and current_category == wrong_cat:
            return correct_cat

    # Generic fixes: Harmless educational questions should be 'general'
    if current_category in [
        "sexual_content_involving_minors",
        "cybercrime",
        "drugs",
        "self_harm",
    ]:
        # Check if prompt is clearly educational/harmless
        if any(
            pattern in prompt_lower
            for pattern in [
                "explain how rain",
                "explain how the human heart",
                "explain how photosynthesis",
                "explain how electricity",
                "explain how the sun",
                "explain how computers",
                "explain how the internet",
                "explain how magnets",
                "explain how the moon",
                "explain how airplanes",
                "how to improve public speaking",
            ]
        ):
            return "general"

    return current_category


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Clean core_suite.jsonl dataset by removing duplicates and fixing wrong categories"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="datasets/core_suite.jsonl",
        help="Path to input JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="datasets/core_suite_CLEANED.jsonl",
        help="Path to output JSONL file",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("Dataset Cleaning Tool")
    print("=" * 80)
    print(f"Input:  {args.input}")
    print(f"Output: {args.output}")
    print()

    try:
        stats = clean_dataset(args.input, args.output)

        print("\n" + "=" * 80)
        print("Cleaning Complete")
        print("=" * 80)
        print(f"Total items in cleaned dataset: {stats['total_items']}")
        print(f"Duplicates removed: {stats['duplicates_removed']}")
        print(f"Categories fixed: {stats['categories_fixed']}")
        print()
        print(f"Cleaned dataset saved to: {args.output}")

    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
