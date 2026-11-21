"""Tie-aware ranking metrics and deterministic display ordering."""
from __future__ import annotations

from collections.abc import Iterable

import numpy as np
import pandas as pd


def expected_recall_precision_at_k(
    y: np.ndarray, score: np.ndarray, ks: Iterable[int]
) -> dict[int, tuple[float, float, int]]:
    """Return expected (recall, precision, picks) under uniform tie breaking.

    NaN scores are excluded. If the top-k boundary splits a tied-score group,
    expected hits are the number of available slots times the positive share
    within that group. This is the exact expectation over random tie orders.
    """
    labels = np.asarray(y)
    scores = np.asarray(score, dtype=float)
    if labels.ndim != 1 or scores.ndim != 1 or len(labels) != len(scores):
        raise ValueError("y and score must be one-dimensional arrays of equal length")
    valid = np.isfinite(scores)
    labels = labels[valid].astype(float, copy=False)
    scores = scores[valid]
    ks = tuple(dict.fromkeys(int(k) for k in ks))
    if any(k <= 0 for k in ks):
        raise ValueError("Each K must be a positive integer")
    if not len(scores):
        return {k: (float("nan"), float("nan"), 0) for k in ks}

    order = np.argsort(-scores, kind="stable")
    sorted_scores = scores[order]
    sorted_labels = labels[order]
    cumulative = np.cumsum(sorted_labels)
    total_positive = float(sorted_labels.sum())
    out = {}
    for k in ks:
        take = min(k, len(scores))
        threshold = sorted_scores[take - 1]
        n_above = int(np.searchsorted(-sorted_scores, -threshold, side="left"))
        # Scores are descending; locate the first row strictly below threshold.
        group_end = int(np.searchsorted(-sorted_scores, -threshold, side="right"))
        group_size = group_end - n_above
        positives_above = float(cumulative[n_above - 1]) if n_above else 0.0
        positives_group = float(cumulative[group_end - 1] - positives_above)
        expected_hits = positives_above + (take - n_above) * positives_group / group_size
        recall = expected_hits / total_positive if total_positive else float("nan")
        precision = expected_hits / take if take else float("nan")
        out[k] = (recall, precision, take)
    return out


def rank_priority_rows(
    frame: pd.DataFrame, score_col: str, k: int, *, id_col: str = "cve_id",
    secondary_col: str = "epss_at_decision",
) -> pd.DataFrame:
    """Sort by score, EPSS, then ID; mark whether K cuts a primary-score tie."""
    eligible = frame.loc[np.isfinite(pd.to_numeric(frame[score_col], errors="coerce"))].copy()
    eligible[score_col] = pd.to_numeric(eligible[score_col], errors="coerce")
    if secondary_col in eligible:
        eligible[secondary_col] = pd.to_numeric(eligible[secondary_col], errors="coerce")
        ranked = eligible.sort_values(
            [score_col, secondary_col, id_col], ascending=[False, False, True],
            na_position="last", kind="stable",
        )
    else:
        ranked = eligible.sort_values([score_col, id_col], ascending=[False, True], kind="stable")
    take = min(max(int(k), 0), len(ranked))
    selected = ranked.head(take).copy()
    tied_at_cutoff = False
    if 0 < take < len(ranked):
        cutoff_score = ranked.iloc[take - 1][score_col]
        tied_count = int(ranked[score_col].eq(cutoff_score).sum())
        above_count = int(ranked[score_col].gt(cutoff_score).sum())
        tied_at_cutoff = above_count < take < above_count + tied_count
    selected["rank"] = np.arange(1, take + 1)
    selected["tied_at_cutoff"] = tied_at_cutoff
    return selected


def expected_metrics_from_codes(
    y: np.ndarray, score_codes: np.ndarray, ks: Iterable[int], n_groups: int
) -> dict[int, tuple[float, float, int]]:
    """Compute exact expected top-k metrics from ascending score-group codes."""
    labels = np.asarray(y, dtype=float)
    codes = np.asarray(score_codes, dtype=np.int64)
    if labels.ndim != 1 or codes.ndim != 1 or len(labels) != len(codes):
        raise ValueError("y and score_codes must be one-dimensional arrays of equal length")
    if not len(codes):
        return {int(k): (float("nan"), float("nan"), 0) for k in ks}
    counts = np.bincount(codes, minlength=n_groups)
    positive_counts = np.bincount(codes, weights=labels, minlength=n_groups)
    reverse_counts = np.cumsum(counts[::-1])
    reverse_positives = np.cumsum(positive_counts[::-1])
    total_positives = float(labels.sum())
    result = {}
    for raw_k in ks:
        k = int(raw_k)
        if k <= 0:
            raise ValueError("Each K must be a positive integer")
        take = min(k, len(codes))
        group_from_top = int(np.searchsorted(reverse_counts, take, side="left"))
        above = int(reverse_counts[group_from_top - 1]) if group_from_top else 0
        hits_above = float(reverse_positives[group_from_top - 1]) if group_from_top else 0.0
        score_group = n_groups - 1 - group_from_top
        group_size = int(counts[score_group])
        group_positives = float(positive_counts[score_group])
        expected_hits = hits_above + (take - above) * group_positives / group_size
        recall = expected_hits / total_positives if total_positives else float("nan")
        result[k] = (recall, expected_hits / take, take)
    return result
