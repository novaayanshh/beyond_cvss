# Beyond CVSS
## Evaluating EPSS for vulnerability patch prioritization

**Team:** Sumit Sharma and Ayansh Pandey | **Course:** Advanced Data Science, BML Munjal University | **Analysis date:** 19 November 2026

## Executive summary

This project asks whether a security team can capture more soon-to-be-listed vulnerabilities under a fixed patching budget by ranking with EPSS or with a CVSS and EPSS combination instead of CVSS alone. We joined NVD, ten dated FIRST EPSS snapshots, and the CISA KEV catalogue. The panel contains 934,180 CVE-date rows and 109 future KEV additions across decision dates from February 2022 through August 2026.

The main ranking result gives each of the ten dates equal weight. Mean expected Recall@1,000 is 7.94% for historical CVSS-only, 26.43% for EPSS-only, and 27.64% for the equal-weight combination. The pooled common cohort has 859,971 rows and 99 positives; exact expected captures at K=1,000 are 1.86 for CVSS, 5 for EPSS, and 5 for Combined. H2 and H3 remain inconclusive overall after Holm correction, although one date-specific H2 comparison survives correction. The best ranking changes by period. On the August 2026 holdout, all three model families had higher Average Precision after adding EPSS, but the test contains only 19 positives.

These findings support a controlled shadow-mode pilot of EPSS-enhanced triage. They do not show that EPSS causes better outcomes or justify replacing analyst judgment or asset context.

## 1. Decision problem

Vulnerability teams often have more open CVEs than they can patch immediately. CVSS describes severity; EPSS estimates the probability that a vulnerability will be exploited in the next 30 days. The decision in this project is which CVEs would be selected first when the patching budget is K items.

The primary metric is Recall@K, the share of future KEV additions captured in the top K. Precision@K is reported alongside it. The model comparisons use Average Precision (AP), which is suitable for the rare positive class. Accuracy is not used.

## 2. Data and preparation

### Sources

| Source | Use |
|---|---|
| [NVD CVE 2.0 feeds](https://nvd.nist.gov/vuln/data-feeds) and [CVE Change History API](https://nvd.nist.gov/developers/vulnerabilities), 2021–2026 | CVE IDs, publication dates, current descriptive/enrichment attributes, and timestamped CVSS vector changes |
| FIRST EPSS dated score files | EPSS probability, percentile, and the model version embedded in each decision-date file |
| CISA KEV catalogue | CVE IDs and catalogue-added dates for the future outcome label |

The six NVD annual feeds yielded 260,255 records before the current-status filter. The pipeline removed 6,726 records currently marked Rejected and produced a clean base table of 253,529 distinct CVEs. The integrated panel contains 46 columns, including score-availability flags, CPE/reference summaries, decision-date EPSS fields, CVE age, and the outcome label. Raw files are untouched and excluded from Git.

### Decision dates and label

The date rule is 19 February and 19 August in each year from 2022 to 2026. For date `d`, the panel includes CVEs published strictly before `d`, removes CVEs already listed in KEV on or before `d`, and sets the label to one when `d < dateAdded <= d + 30 days`. Each panel uses only the EPSS file dated `d`. The ten files use four model versions: 2022.01.01, 2023.03.01, 2025.03.14, and 2026.06.15.

| Decision date | Eligible rows | Positive labels |
|---|---:|---:|
| 2022-02-19 | 19,484 | 10 |
| 2022-08-19 | 31,132 | 10 |
| 2023-02-19 | 43,662 | 8 |
| 2023-08-19 | 57,322 | 6 |
| 2024-02-19 | 71,940 | 4 |
| 2024-08-19 | 92,895 | 10 |
| 2025-02-19 | 113,382 | 16 |
| 2025-08-19 | 136,374 | 6 |
| 2026-02-19 | 161,402 | 20 |
| 2026-08-19 | 206,587 | 19 |
| **Total** | **934,180** | **109** |

There are 206,865 unique CVE IDs across the panel because the same CVE may be observed at multiple decision dates. Pooled results therefore count CVE-decision opportunities rather than unique vulnerabilities.

### Data checks

The pipeline normalizes CVE IDs, checks for duplicate records, validates CVSS in `[0,10]` and EPSS/percentile in `[0,1]`, checks date leakage, removes prior KEVs, and fails if an EPSS snapshot contains duplicate CVE IDs. Missing scores remain missing; they are not filled with zero. CVSS 3.0/3.1 is the main score group; CVSS 4.0 and other versions have separate comparison tables. `ADJACENT_NETWORK` is normalized to `ADJACENT`, and flags retain legacy CVSS v2 PARTIAL/COMPLETE impact values.

For each decision date, CVSS 3.1/3.0 is reconstructed from the most recent vector change recorded strictly before 00:00 UTC on that date; this conservative cutoff avoids unknown within-day ordering between the EPSS snapshot and NVD updates. The CVSS base score is calculated from that vector. The current score is retained only for audit and is never substituted. Historical CVSS 3.x coverage ranges from 89.8% to 93.7% by date (92.1% pooled); when no 3.x vector is present in the history before that cutoff, the historical score remains missing. Other NVD attributes, including CWE, CPE and rejection status, are current values, so they are not used as model predictors.

## 3. Methods

### Ranking comparison

At each date, CVEs are ranked by:

1. CVSS 3.0/3.1 base score reconstructed as of the decision date from timestamped NVD CVE history.
2. EPSS at that decision date.
3. An equal-weight score: `0.5 * (CVSS / 10) + 0.5 * EPSS`.

The main paired comparison uses rows with both CVSS 3.x and EPSS available. We report Recall@K and Precision@K at K = 50, 100, 500, and 1,000 per date and pooled. Tied scores use exact expected metrics under uniform random tie-breaking. Confidence intervals and paired tests use 1,000 bootstrap resamples within each date, including date-stratified pooled resampling. Latest example priority lists use score descending, EPSS descending as the secondary sort, then CVE ID; a tied_at_cutoff flag identifies a primary-score tie crossing K.

### Hypothesis tests

H1 compares EPSS distributions for future KEV positives and negatives with a one-sided Mann-Whitney U test. H2 and H3 compare paired Recall@K differences using a bootstrap on the common cohort. Holm adjustment is applied within each hypothesis family across dates and K values.

### Predictive models

Logistic Regression, Random Forest, and XGBoost are trained on dates through August 2025, validated on February 2026, and evaluated on August 2026. Each model is fit with and without EPSS. Both feature sets include the as-of CVSS 3.x score, its vector fields from the same historical record, and CVE age; the EPSS set adds the dated EPSS probability and percentile. Current CWE/CPE and other enrichment fields are excluded. Class weights address the positive class imbalance. KEV outcome fields, current EPSS, current CVSS, decision date, and EPSS model version are not predictors.

## 4. Results

### Per-date results (headline)

Expected Recall@1,000 on the common complete-case cohort. The final row gives the unweighted mean across decision dates.

| Decision date | CVSS-only | EPSS-only | Combined |
|---|---:|---:|---:|
| 2022-02-19 | 25.0% | 0.0% | 10.0% |
| 2022-08-19 | 12.1% | 50.0% | 50.0% |
| 2023-02-19 | 2.3% | 71.4% | 57.1% |
| 2023-08-19 | 4.6% | 60.0% | 60.0% |
| 2024-02-19 | 2.1% | 25.0% | 25.0% |
| 2024-08-19 | 2.1% | 22.2% | 22.2% |
| 2025-02-19 | 8.9% | 14.3% | 14.3% |
| 2025-08-19 | 0.0% | 0.0% | 0.0% |
| 2026-02-19 | 5.5% | 15.8% | 21.1% |
| 2026-08-19 | 16.7% | 5.6% | 16.7% |
| **Mean across 10 dates** | **7.9%** | **26.4%** | **27.6%** |

Each date has equal weight in the mean. Sparse positive counts make date-level recall move in large steps. In February 2024, each of the four common-cohort positives changes recall by 25 percentage points. Ties are averaged rather than resolved by input row order.

### Pooled results (secondary)

The pooled metric combines CVE-date opportunities across dates. Repeated CVEs remain in the panel; this is not one live patch queue. At K=1,000:

| Method | Expected captures of 99 | Recall@1,000 | Precision@1,000 | 95% bootstrap interval for recall |
|---|---:|---:|---:|---:|
| CVSS-only | 1.86 / 99 | 1.88% | 0.186% | 0.45%–4.05% |
| EPSS-only | 5.00 / 99 | 5.05% | 0.500% | 1.02%–9.38% |
| Combined | 5.00 / 99 | 5.05% | 0.500% | 1.15%–9.62% |

The exact expected CVSS capture is fractional because the 1,000-item boundary falls inside a tied-score group.

### Statistical tests

In the pooled H1 test, the median EPSS score for positive rows exceeded that for negative rows by 0.00718 (raw p = 2.72e-11; Holm-adjusted p = 2.99e-10). The result is statistically strong under the row-level test, but the date-level evidence is mixed and repeated CVEs make pooled rows dependent.

For H2, the pooled EPSS minus CVSS Recall@1,000 difference is 3.17 percentage points (95% stratified bootstrap interval −1.83 to 7.83 points; raw p = 0.1868; Holm-adjusted p = 1.000). For H3, the pooled Combined minus CVSS difference is also 3.17 points (95% interval −1.29 to 8.84 points; raw p = 0.1998; Holm-adjusted p = 1.000). One date-specific H2 result on 2023-08-19 at K=500 and K=1,000 survives Holm correction (adjusted p = 0.044); other periods differ, so H2 remains inconclusive overall. H3 remains inconclusive.

### Model results

The August 2026 test panel has 206,587 rows and 19 positives. Average Precision was:

| Model | Without EPSS | With EPSS |
|---|---:|---:|
| Logistic Regression | 0.00209 | 0.00735 |
| Random Forest | 0.00025 | 0.00048 |
| XGBoost | 0.00027 | 0.00099 |

All three model families had higher AP with EPSS in this holdout. The estimate is provisional because it is based on 19 positives and one final period. NVD enrichment fields are excluded from model predictors; CVSS features come from the reconstructed historical vector.

## 5. Hypothesis status

| Hypothesis | Status | Summary |
|---|---|---|
| H1 | Supported, with a period caveat | Strong pooled association; date-level tests vary and repeated rows limit pooled inference. |
| H2 | Inconclusive overall | One 2023-08-19 result at K=500 and K=1,000 survives Holm correction, but the pooled difference is inconclusive and effects vary by date. |
| H3 | Inconclusive | Combined and EPSS-only tied for pooled top-1,000 recall, but adjusted tests and per-period variation do not establish a consistent advantage. |
| H4 | Supported provisionally | EPSS improved AP for all three models on the held-out period, which contains 19 positives. |
| H5 | Inconclusive | The leading ranking changes across dates; the 2026.06.15 EPSS version has only one decision date. |

## 6. Recommendation

Use EPSS as an additional signal in a shadow-mode prioritization pilot, while keeping CVSS, asset criticality, exposure, compensating controls, and patch feasibility visible to analysts. The equal-weight combined score is a candidate for that pilot, not a proven optimal score. Do not automate patching from this result.

The roadmap in `docs/recommendations.md` covers data/asset matching, a shadow evaluation, a controlled analyst-approved pilot, and a decision review. Track Recall@K, Precision@K, AP, time-to-patch, analyst overrides, infeasible recommendations, and data freshness.

## 7. Limitations

- Ties in CVSS scores are broken at random and averaged (expected recall).

1. NVD history may not contain a CVSS 3.x vector for every CVE/date; such scores remain missing and are not replaced with current scores. CWE, CPE, references, and rejection status still reflect current NVD records rather than historical snapshots.
2. KEV dates measure catalogue addition, not actual exploitation time.
3. There are only 109 positive CVE-date rows; results for periods with four to six positives are highly noisy.
4. EPSS model versions change, and the newest version is represented by one date.
5. Pooled panels repeat some CVEs. Bootstrap resampling within date does not fully remove within-CVE dependence.
6. No asset inventory, internet exposure, business impact, compensating controls, or patch cost is available.
7. These results establish association and predictive performance in this panel, not a causal effect of EPSS on security outcomes.

## 8. Reproducibility and sources

Run `scripts/01_download.py`, `scripts/02_build_decision_panel.py`, `scripts/02a_download_nvd_history.py`, `scripts/02b_reconstruct_historical_cvss.py`, `scripts/03_analyze.py`, and `scripts/04_finalize_outputs.py` in order. The generated processed data and raw downloads are excluded from Git; source code and data access instructions are included.

Sources: [NVD CVE data feeds](https://nvd.nist.gov/vuln/data-feeds), [FIRST EPSS](https://www.first.org/epss/), and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

AI assistance was used for code and document drafting. The team should review this work, be able to explain it, and report AI use as required by the course and university policy.
