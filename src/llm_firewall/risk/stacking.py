"""
Risk Aggregation via Stacking (Production-Grade)
=================================================

Logistic stacker (pattern, semantic, toxicity, optional features) -> calibrated p_risk.
Uses LogisticRegression + Platt (sigmoid) via CalibratedClassifierCV.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Tuple, Optional
import numpy as np

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.calibration import CalibratedClassifierCV
except Exception as _e:  # pragma: no cover
    LogisticRegression = None  # type: ignore
    CalibratedClassifierCV = None  # type: ignore

@dataclass
class RiskAggregator:
    """
    Logistic stacker (pattern, semantic, toxicity, optional features) -> calibrated p_risk.
    Uses LogisticRegression + Platt (sigmoid) via CalibratedClassifierCV.
    """
    clf: object
    classes_: np.ndarray
    tau_block: float = 0.85
    epsilon: float = 0.05
    alpha: float = 0.10  # conformal alpha
    q_alpha_: Optional[float] = None  # conformal quantile

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.clf.predict_proba(X)

    def p_hat(self, X: np.ndarray) -> np.ndarray:
        # probability for class 1 == "unsafe"
        proba = self.predict_proba(X)
        idx = int(np.where(self.classes_ == 1)[0][0])
        p = proba[:, idx]
        if self.q_alpha_ is not None:
            # simple inductive conformal adjustment: clip to [q_alpha, 1]
            p = np.maximum(p, self.q_alpha_)
        return p

    def decide(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        p = self.p_hat(X)
        block = (p >= self.tau_block).astype(int)
        return block, p

def fit_aggregator(
    X_dev: np.ndarray,
    y_dev: np.ndarray,
    tau_block: float = 0.85,
    epsilon: float = 0.05,
    alpha: float = 0.10,
) -> RiskAggregator:
    """
    Fit logistic stacker on dev split (y: 1=unsafe/should block, 0=safe).
    Calibrate with Platt (sigmoid). Compute conformal quantile q_alpha.
    """
    if LogisticRegression is None or CalibratedClassifierCV is None:
        raise RuntimeError("scikit-learn required for RiskAggregator.")

    base = LogisticRegression(solver="liblinear", max_iter=200)
    base.fit(X_dev, y_dev)
    calib = CalibratedClassifierCV(base, method="sigmoid", cv="prefit")
    calib.fit(X_dev, y_dev)

    # Conformal: nonconformity as (1 - p) for positives (unsafe=1)
    # q_alpha is (1 - alpha)-quantile on nonconformities of the positive class
    proba = calib.predict_proba(X_dev)
    idx1 = int(np.where(calib.classes_ == 1)[0][0])
    nonconf = 1.0 - proba[y_dev == 1, idx1]
    if nonconf.size == 0:
        q_alpha = 0.0
    else:
        q_alpha = np.quantile(nonconf, 1.0 - alpha)  # coverage ~ 1 - alpha
    # Convert nonconformity quantile back to a floor for p (p >= 1 - q_alpha)
    q_floor = 1.0 - float(q_alpha)

    agg = RiskAggregator(
        clf=calib, 
        classes_=calib.classes_, 
        tau_block=tau_block, 
        epsilon=epsilon, 
        alpha=alpha, 
        q_alpha_=q_floor
    )
    return agg

