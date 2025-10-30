"""
Q-hat Calibration Cache
=======================

Per-category, per-judge, per-version q-hat values.

Supports:
- Granular calibration (judge × category × version)
- LODO (Leave-One-Day-Out) cross-validation
- ECE drift monitoring
- Auto-recalibration triggers

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple


@dataclass
class QHatEntry:
    """Single q-hat calibration entry."""

    judge_name: str
    category: str
    version: str
    coverage: float  # Target coverage (e.g., 0.90)
    qhat: float  # Calibrated q-hat value

    # Calibration metadata
    calibrated_at: datetime
    calibration_method: str  # "lodo" | "simple" | "bootstrap"
    sample_size: int
    ece: float  # Expected Calibration Error
    brier: float  # Brier score

    # Monitoring
    last_validated: datetime
    validation_ece: Optional[float] = None  # ECE on validation data


@dataclass
class CalibrationConfig:
    """Configuration for calibration system."""

    default_coverage: float = 0.90
    lodo_min_days: int = 7  # Minimum days for LODO
    recalibration_days: int = 7  # Re-calibrate every N days
    ece_drift_threshold: float = 0.02  # Alert if ECE changes > 0.02
    cache_path: str = "calibration/qhat_cache.json"


class QHatCache:
    """
    Q-hat calibration cache.

    Stores per-category q-hat values with versioning and drift monitoring.
    """

    def __init__(self, config: Optional[CalibrationConfig] = None):
        """
        Initialize q-hat cache.

        Args:
            config: Calibration configuration
        """
        self.config = config or CalibrationConfig()
        self.cache: Dict[Tuple[str, str, str], QHatEntry] = {}

        # Load existing cache
        self._load_cache()

    def get_qhat(
        self,
        judge_name: str,
        category: str = "default",
        version: str = "1.0",
        coverage: Optional[float] = None,
    ) -> float:
        """
        Get q-hat value for judge/category/version.

        Args:
            judge_name: Name of judge
            category: Category name (default: "default")
            version: Judge version
            coverage: Target coverage (default: from config)

        Returns:
            q-hat value
        """
        coverage = coverage or self.config.default_coverage
        key = (judge_name, category, version)

        # Check cache
        if key in self.cache:
            entry = self.cache[key]

            # Check if recalibration needed
            if self._needs_recalibration(entry):
                return self._get_default_qhat(judge_name, category, coverage)

            return entry.qhat

        # No calibration data - return conservative default
        return self._get_default_qhat(judge_name, category, coverage)

    def set_qhat(self, entry: QHatEntry):
        """
        Store q-hat calibration entry.

        Args:
            entry: Calibration entry
        """
        key = (entry.judge_name, entry.category, entry.version)
        self.cache[key] = entry

        # Persist to disk
        self._save_cache()

    def _needs_recalibration(self, entry: QHatEntry) -> bool:
        """
        Check if entry needs recalibration.

        Args:
            entry: Calibration entry

        Returns:
            True if recalibration needed
        """
        # Check age
        age_days = (datetime.now() - entry.calibrated_at).days
        if age_days > self.config.recalibration_days:
            return True

        # Check ECE drift
        if entry.validation_ece is not None:
            ece_drift = abs(entry.validation_ece - entry.ece)
            if ece_drift > self.config.ece_drift_threshold:
                return True

        return False

    def _get_default_qhat(
        self, judge_name: str, category: str, coverage: float
    ) -> float:
        """
        Get conservative default q-hat.

        Args:
            judge_name: Judge name
            category: Category name
            coverage: Target coverage

        Returns:
            Conservative q-hat estimate
        """
        # Conservative per-judge defaults
        judge_defaults = {
            "safety_validator": 0.25,
            "embedding_detector": 0.35,
            "perplexity_detector": 0.40,
            "nli_consistency": 0.30,
            "policy_judge": 0.40,
            "persuasion_fusion": 0.35,
        }

        # Per-category modifiers
        category_modifiers = {
            "self-harm": 1.2,  # More conservative
            "violence": 1.2,
            "csam": 1.5,  # Most conservative
            "default": 1.0,
        }

        base = judge_defaults.get(judge_name, 0.5)
        modifier = category_modifiers.get(category, 1.0)

        # Scale by coverage
        qhat = base * modifier * (1.0 / (1.0 - coverage))

        return qhat

    def _load_cache(self):
        """Load cache from disk."""
        cache_path = Path(self.config.cache_path)

        if not cache_path.exists():
            return

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for key_str, entry_dict in data.items():
                # Parse key
                judge, cat, ver = key_str.split("||")
                key = (judge, cat, ver)

                # Parse entry
                entry = QHatEntry(
                    judge_name=entry_dict["judge_name"],
                    category=entry_dict["category"],
                    version=entry_dict["version"],
                    coverage=entry_dict["coverage"],
                    qhat=entry_dict["qhat"],
                    calibrated_at=datetime.fromisoformat(entry_dict["calibrated_at"]),
                    calibration_method=entry_dict["calibration_method"],
                    sample_size=entry_dict["sample_size"],
                    ece=entry_dict["ece"],
                    brier=entry_dict["brier"],
                    last_validated=datetime.fromisoformat(entry_dict["last_validated"]),
                    validation_ece=entry_dict.get("validation_ece"),
                )

                self.cache[key] = entry
        except Exception:
            # Cache corrupted or incompatible - start fresh
            self.cache = {}

    def _save_cache(self):
        """Save cache to disk."""
        cache_path = Path(self.config.cache_path)
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to JSON-serializable format
        data = {}
        for (judge, cat, ver), entry in self.cache.items():
            key_str = f"{judge}||{cat}||{ver}"
            data[key_str] = {
                "judge_name": entry.judge_name,
                "category": entry.category,
                "version": entry.version,
                "coverage": entry.coverage,
                "qhat": entry.qhat,
                "calibrated_at": entry.calibrated_at.isoformat(),
                "calibration_method": entry.calibration_method,
                "sample_size": entry.sample_size,
                "ece": entry.ece,
                "brier": entry.brier,
                "last_validated": entry.last_validated.isoformat(),
                "validation_ece": entry.validation_ece,
            }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def get_calibration_status(self) -> Dict[str, int]:
        """
        Get calibration status summary.

        Returns:
            Dictionary with counts
        """
        total = len(self.cache)
        needs_recal = sum(
            1 for e in self.cache.values() if self._needs_recalibration(e)
        )

        return {
            "total_entries": total,
            "needs_recalibration": needs_recal,
            "up_to_date": total - needs_recal,
        }

