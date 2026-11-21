# Hypothesis assessment

Results use ten fixed decision dates and 109 positive CVE-date rows. Statuses describe this dataset and these methods; they are not causal conclusions. Ranking metrics use exact expected values under uniform random tie-breaking. Bootstrap comparisons use 1,000 replicates and preserve date composition in pooled resampling.

| Hypothesis | Status | Evidence |
|---|---|---|
| **H1** Higher EPSS is associated with a greater chance of future KEV listing. | **Supported, with a period caveat** | The pooled one-sided Mann–Whitney test found higher EPSS among positive rows (median difference 0.00718; raw p = 2.72e-11; Holm-adjusted p = 2.99e-10). Direction and significance vary by date; four individual dates remain significant after adjustment. CVEs recur across dates, so pooled inference is exploratory. |
| **H2** EPSS captures more future KEVs than CVSS at the same budget. | **Inconclusive overall** | Mean per-date Recall@1,000 is higher for EPSS than CVSS (26.43% vs 7.94%). In the pooled common cohort, the difference is 0.0317 (95% stratified bootstrap interval −0.0183 to 0.0783; raw p = 0.1868; Holm-adjusted p = 1.000). One date-specific result on 2023-08-19 at K=500 and K=1,000 survives Holm adjustment (adjusted p = 0.044), but other dates move in different directions. This supports a period-specific observation, not a stable overall advantage. |
| **H3** A combined CVSS and EPSS ranking beats CVSS alone. | **Inconclusive** | Mean per-date Recall@1,000 is 27.64% for Combined and 7.94% for CVSS. The pooled difference is 0.0317 (95% stratified bootstrap interval −0.0129 to 0.0884; raw p = 0.1998; Holm-adjusted p = 1.000). The evidence does not establish a consistent advantage across periods. |
| **H4** EPSS adds predictive value beyond CVSS and other features. | **Supported in the held-out period, provisionally** | On 2026-08-19 (19 positives), Average Precision increased with EPSS for Logistic Regression (0.002086 to 0.007346), Random Forest (0.000253 to 0.000483), and XGBoost (0.000269 to 0.000991). One small test period cannot establish stable generalization. AP is unchanged by the top-K tie correction. |
| **H5** Relative performance stays consistent across periods. | **Inconclusive** | Date-level results vary. On 2026-08-19, expected Recall@1,000 is 16.7% for CVSS, 5.6% for EPSS, and 16.7% for Combined. The latest EPSS version is represented by one date, so version stability cannot be established. |

## Statistical notes

- H1 uses a one-sided Mann–Whitney U test by date and pooled. P-values receive Holm adjustment within H1. The pooled test treats recurring CVE-date rows as independent, so its p-value may understate uncertainty.
- H2 and H3 compare paired Recall@K differences in the common CVSS 3.x/EPSS cohort. Each bootstrap replicate resamples rows within every date, preserving that date's panel size. Within each replicate, metrics are computed as exact expectations over tied score groups. P-values receive Holm adjustment within each hypothesis across dates and K values.
- Percentile confidence intervals use 1,000 resamples. Sparse positive labels and repeated CVE IDs still limit precision.
- Average Precision on the final holdout has no confidence interval in this run; it uses 19 positives.
