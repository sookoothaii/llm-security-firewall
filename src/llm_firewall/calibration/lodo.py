"""
LODO Cross-Validation
=====================

Leave-One-Day-Out cross-validation for calibration stability.

Detects drift and validates q-hat calibration.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from dataclasses import dataclass
from datetime import date
from typing import Dict, List

import numpy as np


@dataclass
class LODOResult:
    """Result of LODO cross-validation."""

    judge_name: str
    category: str
    mean_auc: float
    std_auc: float
    mean_ece: float
    std_ece: float
    mean_brier: float
    std_brier: float
    n_folds: int
    dates: List[date]


@dataclass
class DailyData:
    """Data for a single day."""

    date: date
    predictions: List[float]  # Risk scores
    labels: List[int]  # Ground truth (0=benign, 1=attack)
    categories: List[str]  # Category per sample


def lodo_cross_validate(
    data_by_day: Dict[date, DailyData], judge_name: str, category: str = "default"
) -> LODOResult:
    """
    Perform Leave-One-Day-Out cross-validation.

    For each day:
    - Train on all other days
    - Validate on held-out day
    - Compute AUC, ECE, Brier

    Args:
        data_by_day: Dictionary mapping date -> daily data
        judge_name: Name of judge being calibrated
        category: Category to filter (or "default" for all)

    Returns:
        LODOResult with cross-validation metrics
    """
    dates = sorted(data_by_day.keys())

    if len(dates) < 3:
        raise ValueError(f"LODO requires >= 3 days, got {len(dates)}")

    auc_scores = []
    ece_scores = []
    brier_scores = []

    for held_out_date in dates:
        # Split data
        train_days = [d for d in dates if d != held_out_date]

        # Aggregate training data
        train_preds = []
        train_labels = []

        for d in train_days:
            day_data = data_by_day[d]

            # Filter by category if specified
            if category != "default":
                indices = [
                    i for i, c in enumerate(day_data.categories) if c == category
                ]
                train_preds.extend([day_data.predictions[i] for i in indices])
                train_labels.extend([day_data.labels[i] for i in indices])
            else:
                train_preds.extend(day_data.predictions)
                train_labels.extend(day_data.labels)

        # Validation data
        val_data = data_by_day[held_out_date]
        if category != "default":
            indices = [i for i, c in enumerate(val_data.categories) if c == category]
            val_preds = [val_data.predictions[i] for i in indices]
            val_labels = [val_data.labels[i] for i in indices]
        else:
            val_preds = val_data.predictions
            val_labels = val_data.labels

        if not val_preds or not val_labels:
            continue

        # Compute metrics on validation fold
        from sklearn.metrics import roc_auc_score

        from llm_firewall.metrics.hooks import brier_score, expected_calibration_error

        try:
            auc = roc_auc_score(val_labels, val_preds)
            ece = expected_calibration_error(val_preds, val_labels)
            brier = brier_score(val_preds, val_labels)

            auc_scores.append(auc)
            ece_scores.append(ece)
            brier_scores.append(brier)
        except Exception:
            # Fold failed (e.g., all same class) - skip
            continue

    # Aggregate results
    return LODOResult(
        judge_name=judge_name,
        category=category,
        mean_auc=float(np.mean(auc_scores)) if auc_scores else 0.0,
        std_auc=float(np.std(auc_scores)) if auc_scores else 0.0,
        mean_ece=float(np.mean(ece_scores)) if ece_scores else 1.0,
        std_ece=float(np.std(ece_scores)) if ece_scores else 0.0,
        mean_brier=float(np.mean(brier_scores)) if brier_scores else 1.0,
        std_brier=float(np.std(brier_scores)) if brier_scores else 0.0,
        n_folds=len(auc_scores),
        dates=dates,
    )


def compute_qhat_from_data(
    predictions: List[float], labels: List[int], coverage: float = 0.90
) -> float:
    """
    Compute q-hat from calibration data.

    q-hat = (1-alpha) quantile of nonconformity scores on calibration set.

    Args:
        predictions: Predicted risk scores [0, 1]
        labels: True labels (0=benign, 1=attack)
        coverage: Target coverage (e.g., 0.90)

    Returns:
        q-hat value
    """
    if not predictions or not labels:
        return 0.5  # Conservative default

    # Nonconformity score = |prediction - label|
    nonconformity = [abs(pred - label) for pred, label in zip(predictions, labels)]

    # (1-alpha) quantile
    quantile = 1.0 - (1.0 - coverage)
    qhat = float(np.quantile(nonconformity, quantile))

    return qhat


def check_drift(current_ece: float, cached_ece: float, threshold: float = 0.02) -> bool:
    """
    Check if ECE has drifted significantly.

    Args:
        current_ece: Current ECE on validation data
        cached_ece: Cached ECE from calibration
        threshold: Drift threshold (default: 0.02)

    Returns:
        True if drift detected
    """
    delta = abs(current_ece - cached_ece)
    return delta > threshold
