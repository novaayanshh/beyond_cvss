"""EDA, ranking comparison, hypothesis tests, and time-ordered models.

Run after scripts/02b_reconstruct_historical_cvss.py:
    python scripts/03_analyze.py

The analysis is deliberately explicit about cohort sizes and the repeated-CVE
unit in the pooled panel. It does not use current EPSS as a feature.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.stats import mannwhitneyu
from statsmodels.stats.multitest import multipletests

try:
    from scripts.ranking_utils import expected_recall_precision_at_k, expected_metrics_from_codes, rank_priority_rows
except ModuleNotFoundError:
    from ranking_utils import expected_recall_precision_at_k, expected_metrics_from_codes, rank_priority_rows

ROOT = Path(__file__).resolve().parents[1]
PANEL_PATH = ROOT / "data" / "processed" / "ssot_historical.csv"
TABLES = ROOT / "outputs" / "tables"
FIGURES = ROOT / "outputs" / "figures"
SEED = 20261118
N_BOOT = 1000
KS = (50, 100, 500, 1000)
MAIN_CVSS = {"3.0", "3.1"}


def read_panel() -> pd.DataFrame:
    if not PANEL_PATH.exists():
        raise FileNotFoundError("Run scripts/02b_reconstruct_historical_cvss.py after downloading NVD histories")
    df = pd.read_csv(PANEL_PATH, parse_dates=["published_date", "last_modified_date", "decision_date", "kev_date_added"],
                     dtype={"cve_tag_values": "string"}, low_memory=False)
    df["decision_date"] = pd.to_datetime(df["decision_date"])
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["epss_at_decision"] = pd.to_numeric(df["epss_at_decision"], errors="coerce")
    df["epss_percentile_at_decision"] = pd.to_numeric(df["epss_percentile_at_decision"], errors="coerce")
    df["kev_30d_label"] = pd.to_numeric(df["kev_30d_label"], errors="coerce").fillna(0).astype("int8")
    df["cve_age_days"] = pd.to_numeric(df["cve_age_days"], errors="coerce")
    df["cvss_score_asof"] = pd.to_numeric(df["cvss_score_asof"], errors="coerce")
    df["cvss_v3"] = df["cvss_score_asof"].where(df["cvss_version_asof"].astype(str).isin(MAIN_CVSS))
    # CVSS base scores are already on a documented 0-10 scale; EPSS is 0-1.
    # Equal weighting of these unit-normalized values is a transparent baseline.
    df["cvss_normalized"] = df["cvss_v3"] / 10.0
    df["combined_score"] = 0.5 * df["cvss_normalized"] + 0.5 * df["epss_at_decision"]
    df["top_cwe"] = df["cwe"].fillna("").str.split(";").str[0]
    cwe_counts = df["top_cwe"].value_counts()
    top = set(cwe_counts.head(20).index)
    df["top_cwe"] = df["top_cwe"].where(df["top_cwe"].isin(top), "Other/Unknown")
    return df


def metric_at_k(y: np.ndarray, score: np.ndarray, k: int) -> tuple[float, float, int]:
    return expected_recall_precision_at_k(y, score, [k])[k]


def boot_metrics(groups: list[pd.DataFrame], score_col: str, seed: int) -> dict[int, tuple[float, float, float, float]]:
    rng = np.random.default_rng(seed)
    values = {k: ([], []) for k in KS}
    base = pd.concat(groups, ignore_index=True)
    base_scores = base[score_col].to_numpy(dtype=float)
    base_score_codes = np.unique(base_scores, return_inverse=True)[1].astype(np.uint32)
    y_base = base["kev_30d_label"].to_numpy(dtype=np.int8)
    offsets, start = [], 0
    for group in groups:
        offsets.append((start, start + len(group)))
        start += len(group)
    # Resample CVE decision rows within each date, preserving each date's pool size.
    for _ in range(N_BOOT):
        sampled = np.concatenate([rng.integers(a, b, size=b - a) for a, b in offsets if b > a])
        sampled_score_codes = base_score_codes[sampled]
        y = y_base[sampled]
        replicate_metrics = expected_metrics_from_codes(y, sampled_score_codes, KS, int(base_score_codes.max()) + 1)
        positives = int(y.sum())
        for k in KS:
            recall, precision, _ = replicate_metrics[k]
            values[k][0].append(recall)
            values[k][1].append(precision)
    out = {}
    for k, (recalls, precisions) in values.items():
        out[k] = (*np.nanpercentile(recalls, [2.5, 97.5]), *np.nanpercentile(precisions, [2.5, 97.5]))
    return out


def ranking_outputs(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    records = []
    all_dates = sorted(df["decision_date"].dropna().unique())
    methods = {"CVSS-only": "cvss_v3", "EPSS-only": "epss_at_decision", "Combined": "combined_score"}
    # Available-cohort comparisons answer each ranking's operational question.
    # Common-v3 cohort is the fair paired comparison used for H2/H3 tests.
    cohorts = {
        "available": lambda x: x,
        "common_v3_epss": lambda x: x.loc[x["cvss_v3"].notna() & x["epss_at_decision"].notna()],
    }
    for date in all_dates:
        date_df = df.loc[df["decision_date"].eq(date)].copy()
        for cohort_name, selector in cohorts.items():
            cohort = selector(date_df)
            for method, score_col in methods.items():
                g = cohort.loc[cohort[score_col].notna()].copy()
                if cohort_name == "available":
                    g = date_df.loc[date_df[score_col].notna()].copy()
                y, s = g["kev_30d_label"].to_numpy(dtype=np.int8), g[score_col].to_numpy(dtype=float)
                boot = boot_metrics([g], score_col, SEED + int(pd.Timestamp(date).strftime("%Y%m%d")) + len(method))
                for k in KS:
                    recall, precision, n_picks = metric_at_k(y, s, k)
                    rlo, rhi, plo, phi = boot[k]
                    records.append({
                        "decision_date": pd.Timestamp(date).date().isoformat(), "cohort": cohort_name,
                        "method": method, "k": k, "pool_size": int(len(g)),
                        "positives_in_pool": int(y.sum()), "recall_at_k": recall,
                        "recall_ci_low": rlo, "recall_ci_high": rhi,
                        "precision_at_k": precision, "precision_ci_low": plo,
                        "precision_ci_high": phi, "actual_picks": n_picks,
                    })
    # Pooled estimand is one CVE-decision opportunity; repeated CVEs on later
    # dates are intentionally retained and documented as such.
    for cohort_name, selector in cohorts.items():
        cohort = selector(df)
        for method, score_col in methods.items():
            g = cohort.loc[cohort[score_col].notna()].copy()
            if cohort_name == "available":
                g = df.loc[df[score_col].notna()].copy()
            y, s = g["kev_30d_label"].to_numpy(dtype=np.int8), g[score_col].to_numpy(dtype=float)
            groups = [x for _, x in g.groupby("decision_date", sort=True)]
            boot = boot_metrics(groups, score_col, SEED + len(method) + (0 if cohort_name == "available" else 99))
            for k in KS:
                recall, precision, n_picks = metric_at_k(y, s, k)
                rlo, rhi, plo, phi = boot[k]
                records.append({
                    "decision_date": "POOLED", "cohort": cohort_name, "method": method, "k": k,
                    "pool_size": int(len(g)), "positives_in_pool": int(y.sum()),
                    "recall_at_k": recall, "recall_ci_low": rlo, "recall_ci_high": rhi,
                    "precision_at_k": precision, "precision_ci_low": plo,
                    "precision_ci_high": phi, "actual_picks": n_picks,
                })
    result = pd.DataFrame(records)
    result.to_csv(TABLES / "ranking_results.csv", index=False)
    per_date_summary = (
        result.loc[result["decision_date"].ne("POOLED")]
        .groupby(["cohort", "method", "k"], as_index=False)
        .agg(
            dates=("decision_date", "nunique"),
            mean_recall_at_k=("recall_at_k", "mean"),
            mean_precision_at_k=("precision_at_k", "mean"),
            min_recall_at_k=("recall_at_k", "min"),
            max_recall_at_k=("recall_at_k", "max"),
            min_precision_at_k=("precision_at_k", "min"),
            max_precision_at_k=("precision_at_k", "max"),
        )
    )
    per_date_summary.to_csv(TABLES / "ranking_per_date_summary.csv", index=False)

    # Paired bootstrap tests H2/H3 on the common complete-case, CVSS 3.x pool.
    test_rows = []
    methods_for_test = {"CVSS-only": "cvss_v3", "EPSS-only": "epss_at_decision", "Combined": "combined_score"}
    for label, first, second in (("H2 EPSS vs CVSS", "EPSS-only", "CVSS-only"),
                                 ("H3 Combined vs CVSS", "Combined", "CVSS-only")):
        pairs = []
        for date in all_dates:
            common = cohorts["common_v3_epss"](df.loc[df["decision_date"].eq(date)])
            pairs.append((str(pd.Timestamp(date).date()), common))
        pairs.append(("POOLED", cohorts["common_v3_epss"](df)))
        for date_label, g in pairs:
            if date_label == "POOLED":
                g = g.sort_values("decision_date", kind="stable").reset_index(drop=True)
            y = g["kev_30d_label"].to_numpy(dtype=np.int8)
            s1 = g[methods_for_test[first]].to_numpy(dtype=float)
            s2 = g[methods_for_test[second]].to_numpy(dtype=float)
            score_codes1 = np.unique(s1, return_inverse=True)[1].astype(np.uint32)
            score_codes2 = np.unique(s2, return_inverse=True)[1].astype(np.uint32)
            rng = np.random.default_rng(SEED + len(label) + (0 if date_label == "POOLED" else int(date_label.replace("-", ""))))
            date_offsets = []
            start = 0
            if date_label == "POOLED":
                for _, group in g.groupby("decision_date", sort=True):
                    date_offsets.append((start, start + len(group)))
                    start += len(group)
            else:
                date_offsets = [(0, len(g))]
            boot_diffs = {k: [] for k in KS}
            for _ in range(N_BOOT):
                idx = np.concatenate([rng.integers(a, b, size=b-a) for a,b in date_offsets if b>a])
                b_y = y[idx]
                sampled_s1, sampled_s2 = score_codes1[idx], score_codes2[idx]
                metrics1 = expected_metrics_from_codes(b_y, sampled_s1, KS, int(score_codes1.max()) + 1)
                metrics2 = expected_metrics_from_codes(b_y, sampled_s2, KS, int(score_codes2.max()) + 1)
                for k in KS:
                    recall1 = metrics1[k][0]
                    recall2 = metrics2[k][0]
                    boot_diffs[k].append(recall1 - recall2)
            for k in KS:
                diff = metric_at_k(y, s1, k)[0] - metric_at_k(y, s2, k)[0]
                arr = np.asarray(boot_diffs[k])
                lo, hi = np.nanpercentile(arr, [2.5, 97.5])
                null = arr - np.nanmean(arr)
                p = (1 + np.sum(np.abs(null) >= abs(diff))) / (len(arr) + 1)
                test_rows.append({"hypothesis": label, "decision_date": date_label, "k": k,
                                  "cohort": "common_v3_epss", "first_method": first,
                                  "second_method": second, "recall_difference": diff,
                                  "bootstrap_ci_low": lo, "bootstrap_ci_high": hi,
                                  "bootstrap_two_sided_p": p, "positives": int(y.sum()), "pool_size": int(len(g))})
    return result, pd.DataFrame(test_rows)


def hypothesis_tests(df: pd.DataFrame, paired: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for date, group in list(df.groupby("decision_date", sort=True)) + [("POOLED", df)]:
        pos = group.loc[group["kev_30d_label"].eq(1), "epss_at_decision"].dropna()
        neg = group.loc[group["kev_30d_label"].eq(0), "epss_at_decision"].dropna()
        if len(pos) and len(neg):
            stat, p = mannwhitneyu(pos, neg, alternative="greater", method="asymptotic")
            rows.append({"hypothesis": "H1 Higher EPSS associates with future KEV", "decision_date": str(pd.Timestamp(date).date()) if date != "POOLED" else "POOLED",
                         "test": "one-sided Mann-Whitney U", "statistic": stat, "p_value": p,
                         "effect": float(pos.median() - neg.median()), "effect_measure": "median EPSS difference (positive minus negative)",
                         "positives": len(pos), "negative_rows": len(neg),
                         "interpretation": "Association test; repeated CVE-date rows are retained in pooled result."})
    if len(paired):
        for _, row in paired.iterrows():
            rows.append({"hypothesis": row["hypothesis"], "decision_date": row["decision_date"],
                         "test": f"paired bootstrap recall difference at K={row['k']}",
                         "statistic": row["recall_difference"], "p_value": row["bootstrap_two_sided_p"],
                         "effect": row["recall_difference"], "effect_measure": "recall difference",
                         "ci_low": row["bootstrap_ci_low"], "ci_high": row["bootstrap_ci_high"],
                         "positives": row["positives"], "negative_rows": row["pool_size"] - row["positives"],
                         "interpretation": "Paired comparison within the CVSS 3.x and EPSS complete-case cohort; bootstrap inference is exploratory with few positives."})
    out = pd.DataFrame(rows)
    out["p_holm_within_hypothesis"] = np.nan
    for hypothesis, idx in out.groupby("hypothesis").groups.items():
        valid_idx = [i for i in idx if pd.notna(out.loc[i, "p_value"])]
        if valid_idx:
            out.loc[valid_idx, "p_holm_within_hypothesis"] = multipletests(
                out.loc[valid_idx, "p_value"].astype(float), method="holm"
            )[1]
    out.to_csv(TABLES / "test_results.csv", index=False)
    return out


def make_figures(df: pd.DataFrame, ranking: pd.DataFrame) -> None:
    sns.set_theme(style="whitegrid", context="talk")
    plot = df.loc[df["cvss_v3"].notna() & df["epss_at_decision"].notna()].copy()
    if len(plot) > 50000:
        plot = plot.sample(50000, random_state=SEED)
    fig, ax = plt.subplots(figsize=(9, 6))
    sns.scatterplot(data=plot, x="cvss_v3", y="epss_at_decision", hue="kev_30d_label", alpha=.35, s=18, ax=ax, palette={0: "#5278a3", 1: "#d84a3a"})
    ax.set(title="Decision-date CVSS and EPSS", xlabel="Historical CVSS v3.x score", ylabel="EPSS at decision date")
    fig.tight_layout(); fig.savefig(FIGURES / "cvss_epss_scatter.png", dpi=180); plt.close(fig)

    summary = df.groupby("decision_date", as_index=False).agg(rows=("cve_id", "size"), positives=("kev_30d_label", "sum"))
    summary["decision_date"] = summary["decision_date"].dt.strftime("%Y-%m-%d")
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.barplot(data=summary, x="decision_date", y="positives", color="#d84a3a", ax=ax)
    ax.set(title="Future KEV additions by decision date", xlabel="Decision date", ylabel="Positive CVE decision rows")
    ax.tick_params(axis="x", rotation=30); fig.tight_layout(); fig.savefig(FIGURES / "kev_positives_by_date.png", dpi=180); plt.close(fig)

    per_date = ranking.query("decision_date != 'POOLED' and cohort == 'common_v3_epss'")
    pooled = ranking.query("decision_date == 'POOLED' and cohort == 'common_v3_epss'")
    fig, (ax, pooled_ax) = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={"width_ratios": [1.5, 1]})
    for method, g in per_date.groupby("method"):
        g = g.groupby("k", as_index=False).agg(mean=("recall_at_k", "mean"), low=("recall_at_k", "min"), high=("recall_at_k", "max")).sort_values("k")
        ax.plot(g["k"], g["mean"], marker="o", label=method)
        ax.fill_between(g["k"], g["low"], g["high"], alpha=.12)
    ax.set(title="Headline: mean per-date Recall@K", xlabel="Top-K patch picks", ylabel="Mean recall across dates", ylim=(0, 1))
    for method, g in pooled.groupby("method"):
        g = g.sort_values("k")
        pooled_ax.plot(g["k"], g["recall_at_k"], marker="o", label=method)
    pooled_ax.set(title="Pooled recall (secondary)", xlabel="Top-K patch picks", ylabel="Pooled recall", ylim=(0, 1))
    pooled_ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(FIGURES / "recall_at_k.png", dpi=180); plt.close(fig)

    band_df = df.loc[df["epss_at_decision"].notna()].copy()
    band_df["epss_band"] = pd.qcut(band_df["epss_at_decision"].rank(method="first"), 10, labels=False) + 1
    bands = band_df.groupby("epss_band", as_index=False).agg(kev_rate=("kev_30d_label", "mean"), count=("cve_id", "size"))
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.lineplot(data=bands, x="epss_band", y="kev_rate", marker="o", ax=ax, color="#466b8d")
    ax.set(title="Observed 30-day KEV rate by within-panel EPSS decile", xlabel="EPSS decile (1=lowest)", ylabel="Observed KEV rate")
    fig.tight_layout(); fig.savefig(FIGURES / "kev_rate_by_epss_decile.png", dpi=180); plt.close(fig)

    fig, ax = plt.subplots(figsize=(8, 5))
    sns.histplot(df["cvss_v3"].dropna(), bins=25, color="#5278a3", ax=ax)
    ax.set(title="CVSS v3.x score distribution", xlabel="CVSS base score", ylabel="CVE-date rows")
    fig.tight_layout(); fig.savefig(FIGURES / "cvss_distribution.png", dpi=180); plt.close(fig)

    epss_positive = df.loc[df["epss_at_decision"].gt(0), "epss_at_decision"]
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.histplot(np.log10(epss_positive), bins=35, color="#6b9279", ax=ax)
    ax.set(title="Decision-date EPSS distribution", xlabel="log10(EPSS probability)", ylabel="CVE-date rows")
    fig.tight_layout(); fig.savefig(FIGURES / "epss_distribution.png", dpi=180); plt.close(fig)

    positives = df.loc[df["kev_30d_label"].eq(1) & df["kev_date_added"].notna()].copy()
    positives["age_at_kev_days"] = (positives["kev_date_added"] - positives["published_date"]).dt.days
    positives["decision_date_label"] = positives["decision_date"].dt.strftime("%Y-%m-%d")
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.boxplot(data=positives, x="decision_date_label", y="age_at_kev_days", color="#87a9c5", ax=ax)
    ax.set(title="Age of CVEs when added to KEV", xlabel="Decision date", ylabel="Days since NVD publication")
    ax.tick_params(axis="x", rotation=35); fig.tight_layout(); fig.savefig(FIGURES / "age_at_kev_listing.png", dpi=180); plt.close(fig)

    miss = df.isna().mean().sort_values(ascending=False).rename_axis("column").head(15).reset_index(name="missing_fraction")
    fig, ax = plt.subplots(figsize=(9, 6))
    sns.barplot(data=miss, x="missing_fraction", y="column", color="#c69a52", ax=ax)
    ax.set(title="Columns with the most missing values", xlabel="Missing fraction", ylabel="")
    fig.tight_layout(); fig.savefig(FIGURES / "missingness.png", dpi=180); plt.close(fig)


def make_model_figure(models: pd.DataFrame) -> None:
    test = models.loc[models.get("split", pd.Series(index=models.index, dtype="object")).eq("test")].copy()
    if test.empty or "average_precision" not in test:
        return
    fig, ax = plt.subplots(figsize=(9, 5))
    pivot = test.pivot(index="model", columns="feature_set", values="average_precision")
    pivot.plot(kind="bar", ax=ax, color=["#5278a3", "#d78b43"])
    ax.set(title="Average Precision on the August 2026 test period", xlabel="Model", ylabel="Average Precision")
    ax.legend(title="Features", frameon=False)
    ax.tick_params(axis="x", rotation=0); fig.tight_layout(); fig.savefig(FIGURES / "model_comparison.png", dpi=180); plt.close(fig)


def model_outputs(df: pd.DataFrame) -> pd.DataFrame:
    """Evaluate course-level baselines using date-forward train/validation/test."""
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
    from sklearn.metrics import average_precision_score
    from xgboost import XGBClassifier

    date_values = sorted(df["decision_date"].unique())
    if len(date_values) < 3:
        return pd.DataFrame([{"status": "insufficient dates for time-ordered train/validation/test"}])
    train_dates, validation_date, test_date = date_values[:-2], date_values[-2], date_values[-1]
    model_df = df.copy()
    categorical = ["cvss_version_asof", "cvss_severity_asof", "attack_vector_asof", "attack_complexity_asof", "privileges_required_asof", "user_interaction_asof", "scope_asof", "confidentiality_impact_asof", "integrity_impact_asof", "availability_impact_asof"]
    for col in categorical:
        if col in model_df:
            model_df[col] = model_df[col].map(lambda value: str(value) if pd.notna(value) else "Unknown")
    split_sets = {
        "train": model_df.loc[model_df["decision_date"].isin(train_dates)],
        "validation": model_df.loc[model_df["decision_date"].eq(validation_date)],
        "test": model_df.loc[model_df["decision_date"].eq(test_date)],
    }
    numeric_base = ["cvss_v3", "cve_age_days"]
    results = []
    for include_epss in (False, True):
        numeric = numeric_base + (["epss_at_decision", "epss_percentile_at_decision"] if include_epss else [])
        numeric = [c for c in numeric if c in df.columns]
        transformer = ColumnTransformer([
            ("num", Pipeline([("impute", SimpleImputer(strategy="median", add_indicator=True)), ("scale", StandardScaler())]), numeric),
            ("cat", Pipeline([("impute", SimpleImputer(strategy="constant", fill_value="Unknown")), ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=100))]), [c for c in categorical if c in df.columns]),
        ])
        train = split_sets["train"].dropna(subset=["kev_30d_label"])
        validation = split_sets["validation"]
        test = split_sets["test"]
        y_train = train["kev_30d_label"].to_numpy(dtype=int)
        if len(np.unique(y_train)) < 2:
            continue
        ratio = (len(y_train) - y_train.sum()) / max(y_train.sum(), 1)
        models = {
            "Logistic Regression": LogisticRegression(class_weight="balanced", max_iter=500, solver="liblinear", random_state=SEED),
            "Random Forest": RandomForestClassifier(n_estimators=250, max_depth=12, min_samples_leaf=20, class_weight="balanced_subsample", n_jobs=1, random_state=SEED),
            "XGBoost": XGBClassifier(n_estimators=250, max_depth=4, learning_rate=.04, subsample=.8, colsample_bytree=.8,
                                     reg_lambda=2, scale_pos_weight=ratio, objective="binary:logistic", eval_metric="aucpr",
                                     n_jobs=4, random_state=SEED),
        }
        for name, estimator in models.items():
            pipe = Pipeline([("prep", transformer), ("model", estimator)])
            pipe.fit(train[numeric + categorical], y_train)
            for split_name, subset in (("validation", validation), ("test", test)):
                y = subset["kev_30d_label"].to_numpy(dtype=int)
                score = pipe.predict_proba(subset[numeric + categorical])[:, 1]
                ap = average_precision_score(y, score) if y.sum() else np.nan
                result = {"model": name, "feature_set": "With EPSS" if include_epss else "Without EPSS",
                          "split": split_name, "decision_date": str(pd.Timestamp(validation_date if split_name == "validation" else test_date).date()),
                          "training_dates": ",".join(str(pd.Timestamp(d).date()) for d in train_dates),
                          "rows": len(subset), "positives": int(y.sum()), "average_precision": ap,
                          "note": "Date-forward holdout; CVSS reconstructed from timestamped NVD history. Other NVD enrichment fields are not model inputs."}
                for k in KS:
                    result[f"recall_at_{k}"] = metric_at_k(y, score, k)[0]
                    result[f"precision_at_{k}"] = metric_at_k(y, score, k)[1]
                results.append(result)
    out = pd.DataFrame(results)
    out.to_csv(TABLES / "model_results.csv", index=False)
    return out


def main() -> None:
    TABLES.mkdir(parents=True, exist_ok=True); FIGURES.mkdir(parents=True, exist_ok=True)
    if not PANEL_PATH.exists():
        raise FileNotFoundError("Run scripts/02_build_decision_panel.py, 02a_download_nvd_history.py, and 02b_reconstruct_historical_cvss.py first")
    df = read_panel()
    print("Building rankings and bootstrap intervals...", flush=True)
    ranking, paired = ranking_outputs(df)
    print("Running hypothesis tests and creating figures...", flush=True)
    tests = hypothesis_tests(df, paired)
    make_figures(df, ranking)

    # Date-aware data-quality summary and machine-readable coverage limitations.
    quality = df.groupby("decision_date", as_index=False).agg(
        rows=("cve_id", "size"), unique_cves=("cve_id", "nunique"), positives=("kev_30d_label", "sum"),
        missing_cvss=("cvss_score_asof", lambda x: x.isna().mean()), missing_epss=("epss_at_decision", lambda x: x.isna().mean()),
        cvss_min=("cvss_score_asof", "min"), cvss_max=("cvss_score_asof", "max"), epss_min=("epss_at_decision", "min"), epss_max=("epss_at_decision", "max"))
    quality["decision_date"] = quality["decision_date"].dt.strftime("%Y-%m-%d")
    quality.to_csv(TABLES / "data_quality_by_date.csv", index=False)
    version_mix = df.groupby(["decision_date", "cvss_any_version_asof"], dropna=False).size().rename("rows").reset_index()
    version_mix.to_csv(TABLES / "cvss_version_mix.csv", index=False)
    version_metrics = []
    for version in sorted(df["cvss_any_version_asof"].dropna().astype(str).unique()):
        vdf = df.loc[df["cvss_any_version_asof"].astype(str).eq(version) & df["cvss_any_score_asof"].notna()]
        for date_label, subset in [(str(pd.Timestamp(d).date()), g) for d, g in vdf.groupby("decision_date", sort=True)] + [("POOLED", vdf)]:
            y, score = subset["kev_30d_label"].to_numpy(dtype=np.int8), subset["cvss_any_score_asof"].to_numpy(dtype=float)
            for k in KS:
                recall, precision, picks = metric_at_k(y, score, k)
                version_metrics.append({"cvss_version": version, "decision_date": date_label, "pool_size": len(subset),
                                        "positives": int(y.sum()), "k": k, "recall_at_k": recall,
                                        "precision_at_k": precision, "actual_picks": picks})
    pd.DataFrame(version_metrics).to_csv(TABLES / "cvss_version_performance.csv", index=False)
    all_columns = []
    descriptions = {
        "cve_id": ("NVD", "string", "Normalized CVE identifier", "No"),
        "published_date": ("NVD", "date", "NVD publication date", "No"),
        "cvss_score_asof": ("NVD change history", "numeric", "CVSS base score reconstructed from the latest vector recorded by the decision date", "Yes"),
        "cvss_score": ("NVD current record", "numeric", "Current NVD score retained for audit only; never used in rankings or models", "No"),
        "epss_at_decision": ("FIRST EPSS", "numeric", "Dated exploitation probability (0-1)", "Yes in EPSS feature set"),
        "epss_percentile_at_decision": ("FIRST EPSS", "numeric", "Dated EPSS percentile (0-1)", "Yes in EPSS feature set"),
        "kev_date_added": ("CISA KEV", "date", "Catalogue addition date", "No; label construction only"),
        "kev_30d_label": ("Derived from KEV", "binary", "1 if added within 30 days after decision date", "Target only"),
        "decision_date": ("Derived", "date", "Fixed decision snapshot date", "No"),
        "cve_age_days": ("Derived from NVD", "integer", "Decision date minus publication date in days", "Yes"),
        "cvss_version_asof": ("NVD change history", "categorical", "CVSS version available by the decision date", "Yes"),
        "epss_model_version": ("FIRST EPSS", "categorical", "Model version embedded in dated file", "No"),
        "has_cvss_score": ("Derived from NVD", "binary", "CVSS availability flag", "No (not in model feature set)"),
        "has_epss_at_decision": ("Derived from EPSS", "binary", "Decision-date EPSS availability flag", "No"),
        "vendor": ("NVD CPE", "categorical", "Semicolon-delimited affected CPE vendors", "No (high cardinality)"),
        "product": ("NVD CPE", "categorical", "Semicolon-delimited affected CPE products", "No (high cardinality)"),
        "cwe": ("NVD current record", "categorical", "Current weakness identifiers", "No; current enrichment is excluded from models"),
        "description": ("NVD", "text", "English vulnerability description", "No"),
        "cwe_count": ("NVD", "integer", "Count of distinct CWE values on the NVD record", "No"),
        "has_cwe": ("Derived from NVD", "binary", "Whether an NVD CWE is present", "No"),
        "cpe_match_count": ("NVD CPE", "integer", "Count of distinct CPE criteria in configuration data", "No"),
        "affected_vendor_count": ("Derived from NVD CPE", "integer", "Count of distinct affected vendors", "No"),
        "affected_product_count": ("Derived from NVD CPE", "integer", "Count of distinct affected products", "No"),
        "reference_count": ("NVD", "integer", "Count of linked references", "No"),
        "reference_tag_count": ("NVD", "integer", "Count of reference tags", "No"),
        "exploit_reference_count": ("Derived from NVD", "integer", "References tagged Exploit", "No"),
        "patch_reference_count": ("Derived from NVD", "integer", "References tagged Patch", "No"),
        "advisory_reference_count": ("Derived from NVD", "integer", "References tagged Advisory", "No"),
        "cve_tag_count": ("NVD", "integer", "Count of CVE tags", "No"),
        "cve_tag_values": ("NVD", "categorical", "Semicolon-delimited CVE tag labels", "No"),
        "description_length_chars": ("Derived from NVD", "integer", "Character count of English CVE description", "No"),
        "description_word_count": ("Derived from NVD", "integer", "Word count of English CVE description", "No"),
        "cvss_v2_partial_impact_flag": ("Derived from NVD", "binary", "CVSS v2 flag for a PARTIAL impact component", "No"),
        "cvss_v2_complete_impact_flag": ("Derived from NVD", "binary", "CVSS v2 flag for a COMPLETE impact component", "No"),
    }
    derived_columns = {"cvss_v3", "cvss_normalized", "combined_score", "top_cwe"}
    for col in df.columns:
        if col in descriptions:
            source, typ, description, model_input = descriptions[col]
        elif col in derived_columns:
            source, typ, description, model_input = ("Derived", "numeric" if col != "top_cwe" else "categorical", {
                "cvss_v3": "Decision-date CVSS v3.0/v3.1 base score reconstructed from NVD history",
                "cvss_normalized": "CVSS v3.x score divided by 10",
                "combined_score": "Equal-weight average of normalized CVSS v3.x and dated EPSS",
                "top_cwe": "First CWE mapped to top 20 across panel; exploratory only; not used in models",
            }[col], "Yes" if col == "cvss_v3" else "Ranking only")
        else:
            source = "NVD" if col not in {"epss_model_version", "epss_percentile_at_decision", "has_epss_at_decision", "kev_date_added", "kev_30d_label", "decision_date", "cve_age_days"} else "Derived/EPSS/CISA"
            typ = "numeric" if pd.api.types.is_numeric_dtype(df[col]) else ("date" if "date" in col else "categorical")
            description, model_input = col.replace("_", " ").capitalize(), "Yes" if col.endswith("_asof") and col.startswith(("attack_", "privileges_", "user_", "scope_", "confidentiality_", "integrity_", "availability_", "cvss_severity_", "cvss_version_")) else "No"
        all_columns.append({"column": col, "source": source, "type": typ, "description": description, "model_input": model_input})
    pd.DataFrame(all_columns).to_csv(TABLES / "schema.csv", index=False)
    paired.to_csv(TABLES / "ranking_paired_tests.csv", index=False)
    expected_dates = {pd.Timestamp(y, m, 19).strftime("%Y-%m-%d") for y in range(2022, 2027) for m in (2, 8)}
    available_dates = set(df["decision_date"].dt.strftime("%Y-%m-%d").unique())
    missing_dates = sorted(expected_dates - available_dates)
    nvd_years = sorted(int(p.name.split("-")[-1].split(".")[0]) for p in (ROOT / "data" / "raw").glob("nvdcve-2.0-*.json.gz"))
    coverage_note = "All planned decision-date files are present." if not missing_dates else "Some planned EPSS decision-date files are missing."
    pd.DataFrame([{
        "decision_dates_in_panel": int(df["decision_date"].nunique()),
        "available_decision_dates": ";".join(sorted(df["decision_date"].dt.strftime("%Y-%m-%d").unique())),
        "missing_expected_decision_dates": ";".join(missing_dates),
        "nvd_latest_year_feed": max(nvd_years) if nvd_years else None,
        "nvd_2026_feed_missing": 2026 not in nvd_years,
        "overall_positive_rows": int(df["kev_30d_label"].sum()),
        "panel_rows": len(df),
        "unique_cves_across_dates": df["cve_id"].nunique(),
        "interpretation": coverage_note,
    }]).to_csv(TABLES / "coverage_limitations.csv", index=False)

    by_date = ranking.loc[ranking["decision_date"].ne("POOLED")].merge(
        df[["decision_date", "epss_model_version"]].drop_duplicates().assign(
            decision_date=lambda x: x["decision_date"].dt.strftime("%Y-%m-%d")),
        on="decision_date", how="left", validate="many_to_one")
    version_summary = by_date.groupby(["epss_model_version", "cohort", "method", "k"], as_index=False).agg(
        dates=("decision_date", "nunique"), mean_recall=("recall_at_k", "mean"),
        min_recall=("recall_at_k", "min"), max_recall=("recall_at_k", "max"),
        mean_positives_per_date=("positives_in_pool", "mean"), mean_precision=("precision_at_k", "mean"))
    version_summary.to_csv(TABLES / "robustness_results.csv", index=False)
    feature_set = {"cvss_v3", "cve_age_days", "cvss_version_asof", "cvss_severity_asof", "attack_vector_asof", "attack_complexity_asof", "privileges_required_asof", "user_interaction_asof", "scope_asof", "confidentiality_impact_asof", "integrity_impact_asof", "availability_impact_asof"}
    forbidden = {"kev_30d_label", "kev_date_added", "epss_current"}
    current_metadata_excluded = {"cvss_score", "cvss_version", "cvss_severity", "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope", "confidentiality_impact", "integrity_impact", "availability_impact", "cvss_impact_score", "cvss_exploitability_score", "top_cwe"}
    feature_audit_rows = []
    for feature in sorted(feature_set | {"epss_at_decision", "epss_percentile_at_decision", *forbidden, "decision_date", "epss_model_version"} | current_metadata_excluded):
        included = feature in feature_set or feature in {"epss_at_decision", "epss_percentile_at_decision"}
        reason = ("Included as a pre-decision feature" if feature in feature_set else
                  "Included only in EPSS model feature set" if feature in {"epss_at_decision", "epss_percentile_at_decision"} else
                  "Current NVD value; excluded to prevent temporal leakage" if feature in current_metadata_excluded else
                  "Target or outcome source; excluded from model inputs" if feature in forbidden else
                  "Split metadata; excluded from model inputs")
        feature_audit_rows.append({"feature": feature, "included": included, "reason": reason})
    pd.DataFrame(feature_audit_rows).to_csv(TABLES / "model_feature_audit.csv", index=False)

    print("Fitting time-ordered models...", flush=True)
    models = model_outputs(df)
    make_model_figure(models)
    print(f"Analysis complete: {len(df):,} panel rows; {int(df['kev_30d_label'].sum())} positives")
    print(f"Wrote rankings ({len(ranking):,} rows), tests ({len(tests):,} rows), and model results ({len(models):,} rows)")
    print("See outputs/tables/coverage_limitations.csv for missing source coverage.")


if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=FutureWarning)
    main()

