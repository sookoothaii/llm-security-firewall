# English-only code
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, List, Tuple

import numpy as np


@dataclass(frozen=True)
class Metrics:
    threshold: float
    asr: float  # attack success rate among attacks
    fpr: float  # false positive rate among benign
    support_attacks: int
    support_benign: int


def evaluate_threshold(scores: np.ndarray, labels: np.ndarray, thr: float) -> Metrics:
    """labels: 1=attack/malicious, 0=benign. Decision: 'bypass' if score<thr."""
    is_bypass = scores < thr
    att = labels == 1
    ben = labels == 0
    asr = (is_bypass & att).sum() / max(1, att.sum())
    fpr = (is_bypass & ben).sum() / max(1, ben.sum())
    return Metrics(float(thr), float(asr), float(fpr), int(att.sum()), int(ben.sum()))


def optimize_threshold_offline(
    scores: Iterable[float], labels: Iterable[int], fpr_max: float = 0.005
) -> Metrics:
    """Grid-search on unique score quantiles to minimize ASR under FPR constraint."""
    s = np.asarray(list(scores), dtype=np.float64)
    y = np.asarray(list(labels), dtype=np.int32)
    # candidate thresholds at percentiles
    qs = np.unique(np.quantile(s, np.linspace(0.0, 1.0, num=101)))
    best: Tuple[float, float] | None = None  # (asr, thr)
    best_metrics: Metrics | None = None
    for thr in qs:
        m = evaluate_threshold(s, y, thr)
        if m.fpr <= fpr_max:
            if (
                best is None
                or m.asr < best[0]
                or (math.isclose(m.asr, best[0]) and thr < best[1])
            ):
                best = (m.asr, thr)
                best_metrics = m
    if best_metrics is None:
        # fallback: pick min fpr (most conservative)
        m = evaluate_threshold(s, y, thr=float(np.min(s)))
        return m
    return best_metrics


def safe_ucb_simulation(
    scores_stream: Iterable[float],
    label_stream: Iterable[int],
    grid: List[float],
    fpr_max: float = 0.005,
    horizon: int = 1000,
    seed: int = 1337,
) -> Metrics:
    """
    Very small 'safe-UCB' style simulation:
      - maintain counts of (benign, bypass) per arm to estimate FPR with LCB;
      - only consider arms whose FPR_LCB <= fpr_max;
      - among safe arms, choose smallest estimated ASR.
    """
    rng = np.random.default_rng(seed)
    n = len(grid)
    # stats per arm
    ben_seen = np.zeros(n)
    ben_bypass = np.zeros(n)
    att_seen = np.zeros(n)
    att_bypass = np.zeros(n)

    scores = list(scores_stream)
    labels = list(label_stream)
    idxs = rng.integers(0, len(scores), size=horizon)

    def lcb(p_hat, t, n):
        if n == 0:
            return 0.0
        # Clopper-Pearson conservative LCB
        from math import sqrt

        z = 2.576  # ~99% one-sided
        return max(0.0, p_hat - z * sqrt(max(1e-9, p_hat * (1 - p_hat)) / n))

    for t, i in enumerate(idxs, start=1):
        s_i = scores[i]
        y_i = labels[i]
        # evaluate FPR_LCB per arm
        safe_arms = []
        for k, thr in enumerate(grid):
            bypass = 1 if s_i < thr else 0
            # temporary stats to compute LCB if benign
            p_hat = (ben_bypass[k] / ben_seen[k]) if ben_seen[k] > 0 else 0.0
            fpr_lcb = lcb(p_hat, t, ben_seen[k]) if ben_seen[k] > 0 else 0.0
            if fpr_lcb <= fpr_max:
                safe_arms.append(k)
        if not safe_arms:
            safe_arms = [int(np.argmin(grid))]  # most conservative

        # pick arm with minimal estimated ASR among safe arms
        est_asr = []
        for k in safe_arms:
            phat = att_bypass[k] / max(1, att_seen[k])
            est_asr.append((phat, k))
        k_sel = min(est_asr, key=lambda x: (x[0], grid[x[1]]))[1]

        # update counts
        thr = grid[k_sel]
        bypass = 1 if s_i < thr else 0
        if y_i == 0:
            ben_seen[k_sel] += 1
            ben_bypass[k_sel] += bypass
        else:
            att_seen[k_sel] += 1
            att_bypass[k_sel] += bypass

    # pick best arm at the end
    asr_hat = att_bypass / np.maximum(1, att_seen)
    fpr_hat = ben_bypass / np.maximum(1, ben_seen)
    safe = np.where(fpr_hat <= fpr_max)[0]
    k_best = int(np.argmin(asr_hat[safe])) if len(safe) else int(np.argmin(grid))
    return Metrics(
        grid[k_best],
        float(asr_hat[k_best]),
        float(fpr_hat[k_best]),
        int(att_seen[k_best]),
        int(ben_seen[k_best]),
    )
