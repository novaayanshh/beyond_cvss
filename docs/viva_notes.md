# Viva notes

## Project in one minute

We ask whether EPSS, which estimates exploitation probability over the next 30 days, helps rank CVEs for patching beyond CVSS severity. We combine NVD, dated FIRST EPSS snapshots, and CISA KEV. For each fixed decision date, we include CVEs published before that date, exclude CVEs already in KEV, and label later KEV additions within 30 days. We reconstruct CVSS from timestamped NVD change history strictly before the decision date, then compare three rankings at fixed K and test whether adding EPSS improves a time-ordered model. The analysis covers ten dates, 934,180 CVE-date rows, and 109 positive labels; historical CVSS 3.x coverage is 89.8%–93.7% by date.

## What each script does

- `scripts/01_download.py` downloads missing annual NVD feeds, dated EPSS snapshots, and the CISA KEV catalogue. It skips files that already exist and logs newly downloaded files.
- `scripts/02_build_decision_panel.py` parses and normalizes NVD records, drops current NVD `Rejected` records, extracts CWE/CPE/reference fields, validates score ranges, joins dated EPSS, applies the pre-existing KEV exclusion, and creates the 30-day label. It also runs duplicate and leakage checks.
- `scripts/02a_download_nvd_history.py` retrieves resumable batches from the NVD CVE Change History API; `scripts/02b_reconstruct_historical_cvss.py` replays timestamped vector changes and creates decision-date CVSS values. Current CVSS is retained for audit only and is never used as a fallback.
- `scripts/03_analyze.py` creates the data-quality tables, schema, EDA charts, CVSS-version robustness table, ranking metrics, bootstrap intervals, H1–H3 tests with Holm adjustment, and time-forward Logistic Regression, Random Forest, and XGBoost evaluations with and without EPSS.
- `scripts/04_finalize_outputs.py` creates the latest-date example top-1,000 lists for CVSS, EPSS, and the combined score and renders the final EDA/model figures from the existing outputs.

## Key choices to explain

- Decision dates follow a fixed February/August calendar, 2022–2026. The same CVE can appear at different dates, so a pooled row is a CVE-decision opportunity.
- The label window is `decision_date < dateAdded <= decision_date + 30 days`. This identifies catalogue additions, not first exploitation.
- The main CVSS score comparison uses v3.0/v3.1 reconstructed from timestamped NVD history, strictly before 00:00 UTC on each decision date. When history is missing, the historical score stays missing. CVSS 4.0 is summarized separately.
- The combined ranking is an equal-weight average of CVSS v3.x divided by 10 and EPSS at the decision date. This is a transparent baseline, not a tuned optimum.
- Models use dates through 2025-08 for training, 2026-02 for validation, and 2026-08 for final testing. Class weighting addresses the rare positive label. EPSS fields are excluded from the no-EPSS feature set; KEV fields are target-only.
- The headline is the mean across ten dates: expected Recall@1,000 is 7.94% for CVSS-only, 26.43% for EPSS-only, and 27.64% for Combined. Pooled expected captures at K=1,000 are 1.86, 5, and 5 of 99 positive rows. H2/H3 remain inconclusive overall after Holm adjustment, although one date-specific H2 comparison survives correction. EPSS features improve AP for all three model families on the final holdout, which has only 19 positives. Ties in CVSS scores are broken at random and averaged (expected recall).

## Limitations to state aloud

NVD CWE/CPE enrichments and rejection status are current, not historical; CVSS history is incomplete; EPSS model versions change; KEV dates are catalogue dates; the number of positives is small; and repeated CVEs create dependence across pooled rows. The results support a cautious shadow pilot, not an automatic patch policy. AI assistance was used; each team member should be able to explain and verify the code and follow course and university disclosure requirements.
