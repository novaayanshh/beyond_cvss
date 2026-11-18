# Hypothesis assessment

Results use ten fixed decision dates and 109 positive CVE-date rows. Statuses describe this dataset and these methods; they are not causal conclusions.

| Hypothesis | Status | Evidence |
|---|---|---|
| **H1** Higher EPSS is associated with a greater chance of future KEV listing. | **Supported, with a period caveat** | The pooled one-sided Mann-Whitney test found higher EPSS values among positive rows (median difference 0.00718; raw p = 2.72e-11; Holm-adjusted p = 2.99e-10). The direction and significance varied by date; only four individual dates remained significant after adjustment. CVE rows repeat across dates, so the pooled p-value may understate uncertainty from within-CVE dependence. |
| **H2** EPSS captures more future KEVs than CVSS at the same budget. | **Inconclusive** | In the pooled common cohort (859,971 rows, 99 positives), top 1,000 captured 5 positives with EPSS and 0 with historical CVSS 3.x. The recall difference was 0.0505 (95% bootstrap interval 0.0098–0.0930; raw p = 0.0166), but Holm-adjusted p = 0.648 across dates and budgets. Performance varied by date. |
| **H3** A combined CVSS and EPSS ranking beats CVSS alone. | **Inconclusive** | The pooled combined ranking captured 5/99 positives in the top 1,000, the same as EPSS-only and versus 0/99 for CVSS 3.x. The recall difference was 0.0505 (95% bootstrap interval 0.0114–0.0943; raw p = 0.0166), but Holm-adjusted p = 0.664 across dates and K values. |
| **H4** EPSS adds predictive value beyond CVSS and other features. | **Supported in the held-out period, provisionally** | On the 2026-08-19 test date (19 positives), Average Precision increased when EPSS features were added for Logistic Regression (0.00209 to 0.00735), Random Forest (0.00025 to 0.00048), and XGBoost (0.00027 to 0.00099). One small test period is not enough to establish stable generalization. |
| **H5** Relative performance stays consistent across periods. | **Inconclusive** | Date-level results change direction. EPSS and the combined score captured more positives than CVSS in several earlier periods; on 2026-08-19, historical CVSS and Combined tied at K=1,000, ahead of EPSS-only. The latest EPSS model version is represented by only one date, so version stability cannot be established. |

## Statistical notes

- H1 uses a one-sided Mann-Whitney U test separately by date and on pooled decision rows. P-values are Holm-adjusted within the H1 family. The pooled test treats CVE-date rows as independent, so its p-value is exploratory because the same CVE can recur across dates.
- H2 and H3 use paired bootstrap differences in Recall@K on the common cohort of CVSS 3.0/3.1 and decision-date EPSS rows. The bootstrap resamples CVE-date rows within each date. P-values are Holm-adjusted within each hypothesis across dates and K values.
- The confidence intervals are percentile intervals from 300 bootstrap resamples. Positive labels are scarce, and resampling does not remove all repeated-CVE dependence.
- Average Precision on the final holdout has no confidence interval in this run; compare it cautiously because it is based on 19 positives.
