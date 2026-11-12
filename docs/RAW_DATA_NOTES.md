# Raw Data Notes

Project: EPSS vs CVSS for patch prioritisation
Rule: raw files go in `data/raw/`, never edited. Raw files are tracked in Git (each under 100 MB).

## Sources
- NVD (NIST): CVE details, CVSS, CWE, vendor. Yearly JSON files or API 2.0.
- EPSS (FIRST.org): exploit probability (0 to 1) and percentile. Daily CSV.gz files.
- KEV (CISA): list of exploited CVEs. Its date-added field builds the 30-day label.

## Raw files
- `nvdcve-2.0-2021` to `2025.json.gz` (2026 file still missing, re-download it)
- `known_exploited_vulnerabilities.json`
- `epss_scores-current.csv.gz`: today's scores, EDA only, never for ranking or models
- 5 EPSS decision-date files: 19 Feb 2022, 2023, 2024, 2025, 2026
- Download dates: DD-MM-2026 (fill from file modified dates)

## EPSS decision files
- 2022-02-19: 170,438 rows, model 2022.01.01
- 2023-02-19: 195,958 rows, model 2022.01.01
- 2024-02-19: 236,156 rows, model 2023.03.01
- 2025-02-19: 278,497 rows, model 2023.03.01
- 2026-02-19: 316,261 rows, model 2025.03.14
- Columns: cve, epss, percentile. Read with `skiprows=1` (first line is a comment).
- 3 model versions, so compare raw scores within a date only.

## How to download
- NVD: yearly JSON or API 2.0 in chunks of 120 days max. Free API key gives 50 requests per 30 seconds (5 without).
- EPSS: `https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz`
- KEV: full JSON or CSV from the CISA catalogue page (mirror: `cisagov/kev-data`).

## Initial merged dataset
- 167,135 rows, 39 columns, no duplicate CVE IDs.
- Holds today's CVSS and EPSS values, so it is a snapshot, not decision-date data.
- 5,348 rejected CVEs to drop.
- Only 867 CVEs (about 0.5%) are in KEV.

## Known gaps
- CVSS is the current NVD value, not the value on the decision date.
- CVSS versions are mixed (2.0, 3.0, 3.1, 4.0). Version 4.0 has no exploitability or impact scores.
- `authentication` is 100% missing, `attack_requirements` is 89.5% missing.
- 107 KEVs were added on 2021-11-03 (launch day), not real new exploitation.
- KEV shows listing date, not attack date. KEV columns are for labels only, never model inputs.
- 2021 is excluded as a decision year because KEV started in Nov 2021.
