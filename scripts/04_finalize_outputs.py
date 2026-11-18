"""Create the latest-date example rankings and remaining report figures.

Run after scripts/03_analyze.py. This step does not refit models or alter labels.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
TABLES = ROOT / "outputs" / "tables"
FIGURES = ROOT / "outputs" / "figures"
spec = importlib.util.spec_from_file_location("analysis", ROOT / "scripts" / "03_analyze.py")
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def main() -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    panel = analysis.read_panel()
    ranking = pd.read_csv(TABLES / "ranking_results.csv")
    models = pd.read_csv(TABLES / "model_results.csv")
    analysis.make_figures(panel, ranking)
    analysis.make_model_figure(models)

    latest_date = panel["decision_date"].max()
    latest = panel.loc[panel["decision_date"].eq(latest_date)].copy()
    methods = (("CVSS-only", "cvss_v3"), ("EPSS-only", "epss_at_decision"), ("Combined", "combined_score"))
    ranked_rows = []
    for method, score_col in methods:
        ranked = latest.loc[latest[score_col].notna()].sort_values([score_col, "cve_id"], ascending=[False, True]).head(1000).copy()
        ranked.insert(0, "rank", np.arange(1, len(ranked) + 1))
        ranked.insert(0, "method", method)
        ranked["decision_date"] = latest_date.strftime("%Y-%m-%d")
        ranked["ranking_score"] = ranked[score_col]
        ranked_rows.append(ranked[["decision_date", "method", "rank", "cve_id", "ranking_score",
                                  "cvss_score_asof", "cvss_version_asof", "cvss_severity_asof", "epss_at_decision",
                                  "epss_percentile_at_decision", "epss_model_version", "cve_age_days", "cwe"]])
    pd.concat(ranked_rows, ignore_index=True).to_csv(TABLES / "latest_patch_priorities.csv", index=False)
    print(f"Saved {sum(map(len, ranked_rows)):,} strategy-ranked rows for {latest_date:%Y-%m-%d}.")


if __name__ == "__main__":
    main()
