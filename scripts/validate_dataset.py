"""
Dataset Validation Script
==========================

Validates JSONL datasets for Phase-2 evaluation pipeline.
Checks schema compliance, ASCII-only content, and generates statistics.

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path for imports
base_dir = Path(__file__).parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.eval_utils import parse_jsonl


def is_ascii_only(text: str) -> bool:
    """
    Check if text contains only ASCII characters.

    Args:
        text: Text to check

    Returns:
        True if all characters are ASCII (0-127)
    """
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def validate_dataset_schema(dataset_path: Path) -> Dict[str, Any]:
    """
    Validate dataset schema and collect statistics.

    Args:
        dataset_path: Path to JSONL dataset file

    Returns:
        Dictionary with validation results and statistics
    """
    required_fields = {"id", "type", "prompt"}
    valid_types = {"redteam", "benign"}

    items = parse_jsonl(dataset_path)

    errors = []
    warnings = []
    stats = {
        "total_items": len(items),
        "by_type": defaultdict(int),
        "by_category": defaultdict(int),
        "by_mode": defaultdict(int),
        "ids": set(),
        "non_ascii_prompts": [],
        "missing_fields": [],
        "invalid_types": [],
    }

    for idx, item in enumerate(items, start=1):
        # Check required fields
        missing = required_fields - set(item.keys())
        if missing:
            errors.append(f"Line {idx}: Missing required fields: {missing}")
            stats["missing_fields"].append(idx)
            continue

        # Check ID uniqueness
        item_id = item.get("id", "")
        if item_id in stats["ids"]:
            errors.append(f"Line {idx}: Duplicate ID: {item_id}")
        stats["ids"].add(item_id)

        # Check ID format (ASCII-only, no whitespace)
        if not is_ascii_only(item_id):
            errors.append(f"Line {idx}: ID contains non-ASCII characters: {item_id}")
        if " " in item_id or "\t" in item_id:
            warnings.append(f"Line {idx}: ID contains whitespace: {item_id}")

        # Check type
        item_type = item.get("type", "")
        if item_type not in valid_types:
            errors.append(
                f"Line {idx}: Invalid type '{item_type}'. Must be one of: {valid_types}"
            )
            stats["invalid_types"].append(idx)
        else:
            stats["by_type"][item_type] += 1

        # Check prompt (ASCII-only)
        prompt = item.get("prompt", "")
        if not is_ascii_only(prompt):
            warnings.append(
                f"Line {idx}: Prompt contains non-ASCII characters (ID: {item_id})"
            )
            stats["non_ascii_prompts"].append(item_id)

        # Collect optional metadata
        if "category" in item:
            stats["by_category"][item.get("category")] += 1
        if "mode" in item:
            stats["by_mode"][item.get("mode")] += 1

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "stats": stats,
    }


def format_validation_report(
    validation_result: Dict[str, Any], dataset_path: Path
) -> str:
    """
    Format validation report as ASCII text.

    Args:
        validation_result: Validation results dictionary
        dataset_path: Path to dataset file

    Returns:
        Formatted report string
    """
    lines = []
    lines.append("=" * 70)
    lines.append("Dataset Validation Report")
    lines.append("=" * 70)
    lines.append(f"Dataset: {dataset_path}")
    lines.append("")

    stats = validation_result["stats"]

    # Summary
    lines.append("Summary:")
    lines.append(f"  Total items: {stats['total_items']}")
    lines.append(f"  Valid: {validation_result['valid']}")
    lines.append(f"  Errors: {len(validation_result['errors'])}")
    lines.append(f"  Warnings: {len(validation_result['warnings'])}")
    lines.append("")

    # Type distribution
    lines.append("Type Distribution:")
    for item_type in sorted(stats["by_type"].keys()):
        count = stats["by_type"][item_type]
        pct = (count / stats["total_items"] * 100) if stats["total_items"] > 0 else 0.0
        lines.append(f"  {item_type}: {count} ({pct:.1f}%)")
    lines.append("")

    # Category distribution (if present)
    if stats["by_category"]:
        lines.append("Category Distribution:")
        for category in sorted(stats["by_category"].keys()):
            count = stats["by_category"][category]
            lines.append(f"  {category}: {count}")
        lines.append("")

    # Mode distribution (if present)
    if stats["by_mode"]:
        lines.append("Mode Distribution:")
        for mode in sorted(stats["by_mode"].keys()):
            count = stats["by_mode"][mode]
            lines.append(f"  {mode}: {count}")
        lines.append("")

    # Errors
    if validation_result["errors"]:
        lines.append("Errors:")
        for error in validation_result["errors"][:20]:  # Limit to first 20
            lines.append(f"  {error}")
        if len(validation_result["errors"]) > 20:
            lines.append(
                f"  ... and {len(validation_result['errors']) - 20} more errors"
            )
        lines.append("")

    # Warnings
    if validation_result["warnings"]:
        lines.append("Warnings:")
        for warning in validation_result["warnings"][:20]:  # Limit to first 20
            lines.append(f"  {warning}")
        if len(validation_result["warnings"]) > 20:
            lines.append(
                f"  ... and {len(validation_result['warnings']) - 20} more warnings"
            )
        lines.append("")

    # Non-ASCII prompts
    if stats["non_ascii_prompts"]:
        lines.append(f"Non-ASCII Prompts: {len(stats['non_ascii_prompts'])} items")
        lines.append("  (IDs: " + ", ".join(stats["non_ascii_prompts"][:10]) + ")")
        if len(stats["non_ascii_prompts"]) > 10:
            lines.append(f"  ... and {len(stats['non_ascii_prompts']) - 10} more")
        lines.append("")

    lines.append("=" * 70)

    return "\n".join(lines)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Validate JSONL dataset for Phase-2 evaluation pipeline"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Path to dataset JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to output validation report (optional, prints to stdout if not specified)",
    )

    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"Error: Dataset not found: {dataset_path}", file=sys.stderr)
        return 1

    # Validate
    validation_result = validate_dataset_schema(dataset_path)

    # Generate report
    report = format_validation_report(validation_result, dataset_path)

    # Output
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Validation report written to: {output_path}")
    else:
        print(report)

    # Exit code
    return 0 if validation_result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
