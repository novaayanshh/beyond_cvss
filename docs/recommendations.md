# Recommendation and implementation roadmap

## Recommendation

Use EPSS as an additional signal in a **shadow-mode prioritization pilot**, while keeping CVSS and asset context visible to analysts. The project results do not justify automatically replacing an existing CVSS workflow or sending patches solely from an EPSS ranking.

The headline is the equal-weight mean across dates: expected Recall@1,000 is 7.94% for CVSS-only, 26.43% for EPSS-only, and 27.64% for Combined. In the pooled common cohort (859,971 rows, 99 positives), expected top-1,000 captures are 1.86 for CVSS, 5 for EPSS, and 5 for Combined. H2/H3 remain inconclusive overall after Holm adjustment, although one date-specific H2 comparison survives correction; results vary across periods. On 2026-08-19, expected Recall@1,000 is 16.7% for CVSS-only, 5.6% for EPSS-only, and 16.7% for Combined. A pilot should test whether these signals help a specific organization after asset criticality, exposure, compensating controls, and patch feasibility are considered.

Ties in CVSS scores are broken at random and averaged (expected recall). For research use, treat the equal-weight combined score as an initial candidate, not a proven optimal weight: `0.5 * (CVSS v3.x / 10) + 0.5 * EPSS at decision date`. Keep the three separate ranked lists available for comparison. The example top-1,000 rankings for the latest snapshot are in `outputs/tables/latest_patch_priorities.csv`; they contain scores and CVE metadata only, not the future outcome label.

## Roadmap

| Phase | Timing | Owner | Actions | Measurable indicators |
|---|---|---|---|---|
| Data and policy review | Weeks 1–2 after approval | Vulnerability management lead and data owner | Confirm CVE inventory completeness, asset joins, EPSS refresh time, data retention, and the handling of missing scores. Keep all scores dated. | At least 95% of in-scope CVEs join to an asset record; 100% of EPSS scores carry a source date/version; missingness is reported before ranking. |
| Shadow evaluation | Weeks 3–6 | Security operations analyst and data science owner | Run CVSS, EPSS, and combined lists side by side without changing patch decisions. Record analyst overrides and patch constraints. Evaluate Recall@K, Precision@K, Average Precision, and time-to-patch on a predeclared horizon. | Weekly coverage report; override reason recorded for at least 90% of changed priorities; no future/current values enter historical backtests. |
| Controlled pilot | Weeks 7–12, only after review | Vulnerability management lead | Apply the selected ranking as an advisory input for one service group. Keep a rollback to the existing workflow and require analyst approval for each action. | Compare KEV coverage at fixed K, median time-to-patch, overdue critical vulnerabilities, analyst workload, and rate of infeasible recommendations against a baseline. |
| Decision and monitoring | End of week 12, then monthly | Security leadership and data owner | Continue, revise weights, or stop based on predeclared service-level goals and evidence across multiple periods. Review model-version changes and data drift. | Publish monthly Recall@K/Precision@K and AP, report confidence intervals, review score-version changes, and document any workflow change. |

## Guardrails and limitations

- Do not describe the observed association as proof that EPSS causes better security outcomes.
- Keep CVSS version and missingness visible. Compare CVSS 4.0 separately from the main CVSS 3.x analysis. Ties in CVSS scores are broken at random and averaged (expected recall).
- Do not compare raw EPSS probabilities across model versions without accounting for the version change.
- Keep asset criticality, internet exposure, exploit mitigations, and patch feasibility in analyst review; they are not represented in this dataset.
- Re-run the backtest after new decision dates accumulate. The current positive count and period-to-period variation do not establish a stable policy.
