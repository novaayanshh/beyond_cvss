# Data README

## Overview

The integrated panel uses NVD vulnerability records as the base table, dated FIRST EPSS score files joined by normalized CVE ID, and the CISA Known Exploited Vulnerabilities (KEV) catalogue to construct the outcome. Raw files are read only. Rebuild the base table and decision panel with `scripts/02_build_decision_panel.py`.

## Sources and collection

| Source | Owner | Access | Fields used | Coverage and limitations |
|---|---|---|---|---|
| [NVD CVE 2.0 feeds](https://nvd.nist.gov/vuln/data-feeds) and [CVE Change History API](https://nvd.nist.gov/developers/vulnerabilities) | NIST | Annual JSON 2.0 gzip feeds, then timestamped change history in batches of 100 via `scripts/02a_download_nvd_history.py` | CVE ID, dates, current descriptive/enrichment fields, and timestamped CVSS vector changes | Annual feeds 2021–2026. CVSS 3.0/3.1 vectors are reconstructed as of each decision date; other NVD descriptive/enrichment fields are current values. |
| [EPSS](https://www.first.org/epss/) | FIRST | Dated gzip CSV files from `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz` | CVE, EPSS score, percentile, embedded model version | Ten decision dates, 2022–2026. A model version may change between dates; scores are compared within date. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CISA | Current JSON catalogue feed, `scripts/01_download.py` | CVE ID and date added | Catalogue addition is not the attack date. A current catalogue is used to label historical windows. |

The current EPSS file, if present, is for exploratory use only. It is never used as a historical decision-date value or a model feature. Current NVD CVSS scores are retained only for audit; rankings and models use the timestamped CVSS history reconstruction and do not fall back to current scores.

## Raw file inventory

Raw files are excluded from Git. Byte sizes below are the local files used for the current build. The downloader log records newly downloaded files; dates for pre-existing files were not recorded and are shown as unknown rather than inferred from filesystem timestamps.

| Local file | Bytes | Download date recorded |
|---|---:|---|
| `data/raw/nvdcve-2.0-2021.json.gz` | 16,864,823 | Unknown (pre-existing) |
| `data/raw/nvdcve-2.0-2022.json.gz` | 18,388,247 | Unknown (pre-existing) |
| `data/raw/nvdcve-2.0-2023.json.gz` | 20,226,366 | Unknown (pre-existing) |
| `data/raw/nvdcve-2.0-2024.json.gz` | 25,050,976 | Unknown (pre-existing) |
| `data/raw/nvdcve-2.0-2025.json.gz` | 24,977,798 | Unknown (pre-existing) |
| `data/raw/nvdcve-2.0-2026.json.gz` | 47,108,155 | 2026-11-18 |
| `data/raw/nvd_cvss_history/batch_*.json.gz` | 112,631,446 (2,069 batches) | Retrieved 2026-11-19 from NVD CVE Change History API for 206,865 decision-panel CVEs |
| `data/raw/known_exploited_vulnerabilities.json` | 1,831,265 | Unknown (pre-existing) |
| `data/raw/epss_scores-current.csv.gz` | 2,766,315 | Unknown (pre-existing; EDA only) |
| `data/raw/epss_decision_dates/epss_scores-2022-02-19.csv.gz` | 719,757 | Unknown (pre-existing) |
| `data/raw/epss_decision_dates/epss_scores-2022-08-19.csv.gz` | 735,071 | 2026-11-18 |
| `data/raw/epss_decision_dates/epss_scores-2023-02-19.csv.gz` | 785,004 | Unknown (pre-existing) |
| `data/raw/epss_decision_dates/epss_scores-2023-08-19.csv.gz` | 1,335,497 | 2026-11-18 |
| `data/raw/epss_decision_dates/epss_scores-2024-02-19.csv.gz` | 1,490,852 | Unknown (pre-existing) |
| `data/raw/epss_decision_dates/epss_scores-2024-08-19.csv.gz` | 1,556,287 | 2026-11-18 |
| `data/raw/epss_decision_dates/epss_scores-2025-02-19.csv.gz` | 1,670,888 | Unknown (pre-existing) |
| `data/raw/epss_decision_dates/epss_scores-2025-08-19.csv.gz` | 1,939,987 | 2026-11-18 |
| `data/raw/epss_decision_dates/epss_scores-2026-02-19.csv.gz` | 2,110,333 | Unknown (pre-existing) |
| `data/raw/epss_decision_dates/epss_scores-2026-08-19.csv.gz` | 2,557,427 | 2026-11-18 |
| `data/raw/download_log.csv` | 789 | Generated 2026-11-18 |

## EPSS model versions

The model version and score date are parsed from each gzip file's first comment line. Observed versions are 2022.01.01, 2023.03.01, 2025.03.14, and 2026.06.15. The current-score file is not used in the panel.

## Integration and SSOT rules

- Normalize CVE IDs by trimming whitespace and converting to uppercase; use NVD as the base.
- Drop NVD records whose current `vulnStatus` is `Rejected`. The current build dropped 6,726 records from the six annual feeds. Earlier notes had a different count because the 2026 feed was not yet included.
- Omit the fully missing `authentication` field and highly incomplete `attack_requirements` field. Preserve the CVSS version and keep the score missing when NVD has no score.
- Prefer CVSS 3.1, then 3.0, then 4.0, then 2.0 when selecting one current score for the clean base SSOT. Main historical rankings use the latest CVSS 3.1 vector recorded by each decision date, falling back to CVSS 3.0; current scores are not substituted.
- Normalize `ADJACENT_NETWORK` to `ADJACENT`. Retain old CVSS v2 impact values and add flags for `PARTIAL` and `COMPLETE` components.
- Keep missing CVSS and EPSS values missing, with `has_cvss_score` and `has_epss_at_decision` flags. Do not replace missing scores by zero.
- Serialize date fields as ISO `YYYY-MM-DD`. EPSS scores and percentile are checked within `[0,1]`; CVSS base scores within `[0,10]`.
- Resolve duplicate NVD CVE IDs by most recent `lastModified` date and fail on duplicate CVE IDs inside any EPSS snapshot. The current six NVD feeds contain no duplicate IDs after parsing.
- Keep long descriptions in `ssot_clean.csv` and omit them from the final panel; derived description-length features are retained.

## Decision dates and label

The fixed date rule is 19 February and 19 August of each year, 2022–2026. See [`docs/decision_dates.md`](docs/decision_dates.md) for per-date pool sizes, model versions, and positive counts.

For each decision date `d`, include CVEs published strictly before `d`, exclude CVEs already listed in KEV on or before `d`, and set `kev_30d_label = 1` when `d < dateAdded <= d + 30 days`. Join only the EPSS snapshot dated `d`. Leakage checks fail if future CVEs, already-listed KEVs, duplicate CVEs, or out-of-range EPSS scores appear in a date panel. To avoid unknown within-day ordering between the EPSS snapshot and NVD updates, CVSS reconstruction applies only history events timestamped strictly before 00:00 UTC on `d`; CVEs with no recorded 3.x vector before then retain a missing score.

## Data quality and generated tables

The panel build writes `outputs/tables/panel_summary.csv` and `missingness.csv`. Historical reconstruction writes `historical_cvss_coverage.csv`; the analysis writes `data_quality_by_date.csv`, `cvss_version_mix.csv`, `cvss_version_performance.csv`, and `schema.csv`. `scripts/04_finalize_outputs.py` produces the example latest-date ranked lists and final figures. The current panel has 934,180 CVE-date rows, 206,865 distinct CVE IDs across dates, and 109 positive labels; 860,287 rows have historical CVSS 3.x (92.1%). Because CVEs recur at multiple decision dates, the pooled unit is a CVE-decision opportunity.

## Limitations

- CVSS 3.x vectors and base scores are reconstructed from dated NVD history; their coverage is 89.8%–93.7% by decision date. CWE, configurations, references, and rejection status still reflect the current NVD feeds, not what was known on each historical decision date.
- KEV `dateAdded` is catalogue inclusion date, not the time of the first real-world attack.
- Only 109 positive CVE-date rows are available across the ten periods, and the 2024 February period has four. Recall@K and model metrics are consequently unstable.
- EPSS model versions change over time. Interpret date-specific rankings rather than comparing raw scores directly across versions.
- Pooled analyses retain repeated CVEs across dates. Confidence intervals resample decision rows within each date; they do not remove all dependence from repeated IDs.
- The findings concern association and predictive ranking, not a causal effect of EPSS on patch outcomes.

## Reproducibility

From the repository root, with the Python environment described in `requirements.txt`:

1. `python scripts/01_download.py` downloads missing public source files and leaves existing raw files untouched.
2. `python scripts/02_build_decision_panel.py` rebuilds the clean base table, dated decision panel, panel summary, and missingness table.
3. `python scripts/02a_download_nvd_history.py` retrieves timestamped CVE histories in resumable batches. It observes NVD's public request limit; setting `NVD_API_KEY` uses the authenticated rate limit.
4. `python scripts/02b_reconstruct_historical_cvss.py` reconstructs CVSS 3.0/3.1 scores and vector fields as of each date, without substituting current scores.
5. `python scripts/03_analyze.py` rebuilds EDA, ranking metrics and bootstrap intervals, hypothesis tests, figures, model evaluations, schema, robustness tables, and leakage audit using historical CVSS.
6. `python scripts/04_finalize_outputs.py` creates the latest-date example ranked lists and remaining figures from the generated panel/results.
7. `python scripts/05_build_report.py` rebuilds the formatted DOCX report from `docs/final_report.md`.
8. `python scripts/06_build_report_pdf.py` rebuilds the formatted report PDF from `docs/final_report.md`.

The PowerPoint source is `scripts/07_build_slides.mjs`. Rebuilding it requires the Codex Artifact Tool runtime and the presentation validation utilities noted in that script; the delivered deck is `docs/slides.pptx`.

The current generated panel and analysis CSVs are excluded from Git. The scripts and this documentation are tracked so the team can regenerate them from raw files.

