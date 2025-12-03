"""
Evaluation Utilities
====================

Shared utility functions for Phase-2 evaluation pipeline.
Used by orchestrator and analysis scripts to avoid code duplication.

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any


def parse_jsonl(file_path: Path) -> List[Dict[str, Any]]:
    """
    Parse JSONL file into list of records.

    Args:
        file_path: Path to JSONL file

    Returns:
        List of record dictionaries
    """
    records = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                records.append(record)
            except json.JSONDecodeError as e:
                print(
                    f"Warning: Invalid JSON on line {line_num} of {file_path}: {e}",
                    file=sys.stderr,
                )
                continue
    return records


def load_dataset(dataset_path: Path) -> Dict[str, Dict[str, str]]:
    """
    Load dataset and create ID -> item mapping.

    Args:
        dataset_path: Path to dataset JSONL file

    Returns:
        Dictionary mapping item_id -> item dict
    """
    items = parse_jsonl(dataset_path)
    dataset_map = {}
    for item in items:
        item_id = item.get("id")
        if item_id:
            dataset_map[item_id] = item
    return dataset_map


def ensure_directory(path: Path) -> None:
    """
    Ensure directory exists, create if needed.

    Args:
        path: Path to directory or file (parent directory will be created)
    """
    if path.is_file() or path.suffix:
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        path.mkdir(parents=True, exist_ok=True)
