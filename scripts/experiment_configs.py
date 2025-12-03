"""
Experiment Configurations
==========================

Predefined experiment configurations for Phase-2 evaluation.
Each config specifies dataset, policies, and execution parameters.

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from pathlib import Path


@dataclass
class ExperimentConfig:
    """Structured experiment configuration."""

    experiment_id: str
    description: str
    dataset_path: Path
    policies: List[str]
    num_workers: int
    measure_latency: bool
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for compatibility with existing code."""
        return {
            "experiment_id": self.experiment_id,
            "description": self.description,
            "dataset_path": str(self.dataset_path),
            "policies": self.policies,
            "num_workers": self.num_workers,
            "measure_latency": self.measure_latency,
            "notes": self.notes,
        }


# Predefined experiment configurations
EXPERIMENT_CONFIGS: Dict[str, ExperimentConfig] = {
    "smoke_test_core": ExperimentConfig(
        experiment_id="smoke_test_core",
        description="Quick smoke test with subset of core dataset (approx. 50 items)",
        dataset_path=Path("datasets/core_suite_smoke.jsonl"),
        policies=["baseline", "kids", "default"],
        num_workers=1,
        measure_latency=True,
        notes="Fast validation run to verify pipeline end-to-end.",
    ),
    "core_suite_full": ExperimentConfig(
        experiment_id="core_suite_full",
        description="Full core AnswerPolicy evaluation across all harm categories",
        dataset_path=Path("datasets/core_suite.jsonl"),
        policies=["baseline", "default", "kids", "internal_debug"],
        num_workers=4,
        measure_latency=True,
        notes="Comprehensive evaluation of AnswerPolicy across 10 harm categories.",
    ),
    "tool_abuse_focused": ExperimentConfig(
        experiment_id="tool_abuse_focused",
        description="Focused evaluation on tool-abuse and code-generation risks",
        dataset_path=Path("datasets/tool_abuse_suite.jsonl"),
        policies=["baseline", "default", "kids"],
        num_workers=2,
        measure_latency=False,
        notes="Tests AnswerPolicy effectiveness against tool-abuse prompts.",
    ),
    "combined_suite": ExperimentConfig(
        experiment_id="combined_suite",
        description="Combined evaluation using both core and tool-abuse datasets",
        dataset_path=Path("datasets/combined_suite.jsonl"),
        policies=["baseline", "default", "kids"],
        num_workers=4,
        measure_latency=True,
        notes="Largest dataset, combines all core harm categories with tool-abuse scenarios.",
    ),
    "category_ablation": ExperimentConfig(
        experiment_id="category_ablation",
        description="Ablation study focusing on specific harm categories",
        dataset_path=Path("datasets/core_suite.jsonl"),
        policies=["baseline", "kids"],
        num_workers=2,
        measure_latency=False,
        notes=(
            "Focused comparison between baseline and kids policy. "
            "Per-category analysis is done post-hoc using the `category` field."
        ),
    ),
}


def get_smoke_test_config(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Smoke test configuration (small dataset, fast execution).

    Args:
        base_dir: Base directory for relative paths (default: current working directory)

    Returns:
        Experiment configuration dictionary
    """
    if base_dir is None:
        base_dir = Path.cwd()

    # Use predefined config if available, otherwise fallback
    if "smoke_test_core" in EXPERIMENT_CONFIGS:
        config = EXPERIMENT_CONFIGS["smoke_test_core"]
        if base_dir != Path.cwd():
            config.dataset_path = base_dir / config.dataset_path
        return config.to_dict()

    # Fallback to legacy config
    return {
        "experiment_id": "smoke_test",
        "description": "Quick smoke test with 20-40 items",
        "dataset_path": str(base_dir / "datasets" / "mixed_small.jsonl"),
        "policies": ["baseline", "default", "kids"],
        "num_workers": 1,
        "measure_latency": True,
    }


def get_medium_config(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Medium-sized configuration (100-200 items).

    Args:
        base_dir: Base directory for relative paths (default: current working directory)

    Returns:
        Experiment configuration dictionary
    """
    if base_dir is None:
        base_dir = Path.cwd()

    # Use predefined config if available, otherwise fallback
    if "core_suite_full" in EXPERIMENT_CONFIGS:
        config = EXPERIMENT_CONFIGS["core_suite_full"]
        if base_dir != Path.cwd():
            config.dataset_path = base_dir / config.dataset_path
        return config.to_dict()

    # Fallback to legacy config
    return {
        "experiment_id": "medium",
        "description": "Medium-sized evaluation with 100-200 items",
        "dataset_path": str(base_dir / "datasets" / "mixed_expanded_100.jsonl"),
        "policies": ["baseline", "default", "kids"],
        "num_workers": 4,
        "measure_latency": True,
    }


def get_experiment_config(name: str, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Get predefined experiment configuration by name.

    Args:
        name: Configuration name (e.g. "smoke_test_core", "core_suite_full")
        base_dir: Base directory for relative paths

    Returns:
        Experiment configuration dictionary

    Raises:
        ValueError: If configuration name is unknown
    """
    if name not in EXPERIMENT_CONFIGS:
        raise ValueError(
            f"Unknown experiment config: {name}. "
            f"Available configs: {', '.join(sorted(EXPERIMENT_CONFIGS.keys()))}"
        )

    config = EXPERIMENT_CONFIGS[name]
    if base_dir is not None and base_dir != Path.cwd():
        config.dataset_path = base_dir / config.dataset_path

    return config.to_dict()


def load_config_from_dict(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize experiment configuration.

    Args:
        config_dict: Configuration dictionary

    Returns:
        Validated configuration dictionary

    Raises:
        ValueError: If configuration is invalid
    """
    required_keys = ["experiment_id", "dataset_path", "policies"]
    for key in required_keys:
        if key not in config_dict:
            raise ValueError(f"Missing required key: {key}")

    # Set defaults
    normalized = {
        "experiment_id": config_dict["experiment_id"],
        "description": config_dict.get("description", ""),
        "dataset_path": str(config_dict["dataset_path"]),
        "policies": list(config_dict["policies"]),
        "num_workers": config_dict.get("num_workers", 1),
        "measure_latency": config_dict.get("measure_latency", False),
    }

    # Validate policies
    valid_policies = {"baseline", "default", "kids", "internal_debug"}
    for policy in normalized["policies"]:
        if policy not in valid_policies:
            raise ValueError(
                f"Invalid policy: {policy}. Must be one of: {sorted(valid_policies)}"
            )

    # Validate num_workers
    if normalized["num_workers"] < 1:
        raise ValueError("num_workers must be >= 1")

    return normalized


def load_config_from_json(json_path: Path) -> Dict[str, Any]:
    """
    Load experiment configuration from JSON file.

    Args:
        json_path: Path to JSON configuration file

    Returns:
        Validated configuration dictionary

    Raises:
        FileNotFoundError: If JSON file doesn't exist
        ValueError: If configuration is invalid
    """
    import json

    if not json_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        config_dict = json.load(f)

    return load_config_from_dict(config_dict)
