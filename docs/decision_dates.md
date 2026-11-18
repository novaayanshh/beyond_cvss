# Decision dates and 30-day outcome

## Frozen date rule

The analysis uses the 19 February and 19 August snapshot on each year from 2022 through 2026. This calendar rule was selected before the final ranking/model run, as prescribed in `docs/srs.md`. The second snapshot was added to increase the number of labelled outcomes and reduce reliance on the February-only sample.

For decision date `d`, the panel includes CVEs whose NVD publication date is strictly before `d`, removes CVEs already in CISA KEV on or before `d`, and labels a remaining CVE positive when `d < dateAdded <= d + 30 days`. EPSS values come only from the file dated `d`; a current EPSS score is never substituted.

## Available panel counts

| Decision date | EPSS model version | Eligible CVEs | KEV additions in next 30 days |
|---|---:|---:|---:|
| 2022-02-19 | 2022.01.01 | 19,484 | 10 |
| 2022-08-19 | 2022.01.01 | 31,132 | 10 |
| 2023-02-19 | 2022.01.01 | 43,662 | 8 |
| 2023-08-19 | 2023.03.01 | 57,322 | 6 |
| 2024-02-19 | 2023.03.01 | 71,940 | 4 |
| 2024-08-19 | 2023.03.01 | 92,895 | 10 |
| 2025-02-19 | 2023.03.01 | 113,382 | 16 |
| 2025-08-19 | 2025.03.14 | 136,374 | 6 |
| 2026-02-19 | 2025.03.14 | 161,402 | 20 |
| 2026-08-19 | 2026.06.15 | 206,587 | 19 |
| **Total decision rows** |  | **934,180** | **109** |

The same CVE can appear at more than one decision date; the pooled analysis therefore counts CVE-decision opportunities, not unique vulnerabilities. There are 206,865 unique CVE IDs across the panel. The 2024 February date has only four positives and is interpreted as especially noisy.

The model-version values above are read from the metadata line embedded in each EPSS file. Model versions change over time, so raw EPSS scores are compared within their decision date/version context.
