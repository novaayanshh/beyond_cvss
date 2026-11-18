# Beyond CVSS

**Question:** Does EPSS improve vulnerability patch prioritization beyond CVSS severity alone?

**Team:** Sumit Sharma and Ayansh Pandey  
**Course:** Advanced Data Science, BML Munjal University  
**Data window:** Decision snapshots on 19 February and 19 August, 2022–2026

## Project summary

This project compares CVSS-only, EPSS-only, and combined rankings for a limited patching budget. NVD provides CVE records and CVSS metrics, FIRST EPSS provides a historical exploitation probability for each fixed decision date, and CISA KEV supplies the outcome. A CVE is labelled positive when CISA adds it to KEV within 30 days after a decision date. Results are about catalogue additions and predictive association; they are not causal evidence or a live patch recommendation.

## Findings from historical CVSS analysis

CVSS 3.x is reconstructed from timestamped NVD history using only vectors recorded strictly before 00:00 UTC on each decision date. Current CVSS values are kept for audit and never substituted for missing history. Coverage ranges from 89.8% to 93.7% per date.

The ten decision panels contain 934,180 CVE-date rows and 109 positive labels. On the pooled common cohort (859,971 rows, 99 positives), the top 1,000 captured 0 positives with historical CVSS-only, 5 with EPSS-only, and 5 with the equal-weight combined ranking. These are exploratory pooled results across decision dates; uncertainty is wide because there are few positives and some CVEs recur across dates. Per-date results and multiplicity-adjusted tests are in `outputs/tables/` and the final report.

## Hypotheses

- **H1:** Higher EPSS is associated with a higher chance of future KEV listing.
- **H2:** EPSS captures more future KEVs than CVSS at the same patching budget.
- **H3:** Combining CVSS and EPSS beats CVSS alone.
- **H4:** EPSS adds predictive value beyond CVSS and other features.
- **H5:** Relative performance stays consistent across periods.

The final status and supporting evidence for each hypothesis are in `docs/hypothesis_assessment.md`.

## Repository layout

```text
data/raw/          Local source downloads; excluded from Git
data/processed/    Generated base table and decision panel; excluded from Git
scripts/           Numbered download, panel-building, and analysis scripts
notebooks/         Complete analysis notebook and presentation narrative
outputs/figures/   Generated charts
outputs/tables/    Generated quality, ranking, hypothesis, and model tables
docs/              SRS, provenance, decisions, recommendations, report, and viva notes
```

## Setup and run

Python 3.14 is used for the current run. Create an environment and install the pinned dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

From the repository root, run:

```powershell
python scripts/01_download.py
python scripts/02_build_decision_panel.py
python scripts/02a_download_nvd_history.py
python scripts/02b_reconstruct_historical_cvss.py
python scripts/03_analyze.py
python scripts/04_finalize_outputs.py
python scripts/05_build_report.py
python scripts/06_build_report_pdf.py
```

The reports are `docs/final_report.docx` and `docs/final_report.pdf`; the editable source is `docs/final_report.md`. The 11-slide presentation is `docs/slides.pptx`; `scripts/07_build_slides.mjs` rebuilds it with the Codex Artifact Tool runtime and its presentation validation utilities.

Launch the interactive dashboard from the repository root after installing requirements:

```powershell
streamlit run streamlit_app.py
```

The source downloader skips existing raw files. NVD history retrieval is resumable and observes the public API rate limit; the first full retrieval can take several hours. Raw files are never edited. Data dates, fields, model versions, file sizes, and limitations are documented in `DATA_README.md`.

## Outputs

- `data/processed/ssot_clean.csv`: cleaned NVD base table.
- `data/processed/ssot_final.csv`: dated panel without long description text.
- `data/processed/ssot_historical.csv`: dated panel augmented with CVSS 3.0/3.1 values reconstructed from NVD change history.
- `outputs/tables/panel_summary.csv`: panel size, positives, EPSS missingness, and model version per date.
- `outputs/tables/ranking_results.csv`: Recall@K, Precision@K, and bootstrap intervals by method, date, and pooled cohort.
- `outputs/tables/test_results.csv`: H1–H3 tests with Holm-adjusted p-values.
- `outputs/tables/model_results.csv`: time-ordered Logistic Regression, Random Forest, and XGBoost comparisons with/without EPSS.
- `outputs/tables/latest_patch_priorities.csv`: latest-date top-1,000 lists for each ranking method.
- `outputs/figures/`: EDA, ranking, and model figures.
- `notebooks/Beyond_CVSS_Presentation.ipynb`: complete executable EDA, feature engineering, ranking metrics, hypothesis tests, date-forward ML evaluation, results, and presentation narrative. Run it from the activated project environment.
- `streamlit_app.py`: interactive presentation dashboard for ranking performance, historical CVSS coverage, model holdout results, and hypothesis tests. It reads saved outputs and does not retrain models.
- `docs/final_report.pdf`: formatted six-page project report.
- `docs/slides.pptx`: three-stage project presentation.

## Limitations and integrity

- CVSS 3.x scores/vectors are reconstructed from timestamped NVD history; other NVD enrichment fields remain current and are excluded from model features.
- KEV records catalogue inclusion date, not actual attack time.
- Only 109 positive CVE-date rows occur in the ten periods; small-date estimates are noisy.
- The pooled unit is a CVE-decision opportunity, not a unique CVE. Bootstrap intervals resample within each date.
- Recommendations are for a controlled evaluation/pilot, not automatic patching.
- Team members should review and understand the code and follow the instructor's and university's requirements for reporting AI assistance before submission.

## Credits and licence

Data sources: [NVD](https://nvd.nist.gov/vuln/data-feeds), [FIRST EPSS](https://www.first.org/epss/), and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). No software licence has been selected for this project yet.

