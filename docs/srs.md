# Software Requirements Specification (v2)
**Project:** Prioritizing Cybersecurity Vulnerabilities for Effective Patch Management
**Team:** Sumit Sharma (250238), Ayansh Pandey (240418)
**Course:** Advanced Data Science (ADS), end-term project (40% of the grade)
**Deadline:** Semester ends 24 Nov 2026. Confirm your exact submission date, because the 15 Nov target has passed.

## 1. Purpose and Scope
- Test whether EPSS (probability of exploitation in the next 30 days) improves patch prioritization beyond CVSS (severity).
- Output: a ranked patch list and a recommended strategy (CVSS-only, EPSS-only or combined) for a limited patching budget.
- Out of scope: causal claims, live deployment, and any method outside the course handout.

## 2. Stakeholder and Decision
- **Stakeholder:** Vulnerability management and security operations teams.
- **Needs:** Thousands of open vulnerabilities, a fixed patching budget, and no clear way to choose which to fix first.
- **Decision:** Given a fixed budget, which vulnerabilities should be patched first?
- **Primary KPI:** Recall@K, the share of future KEV vulnerabilities captured in the top K patch picks.
- **Good outcome:** A ranking that catches more soon-to-be-exploited CVEs at the same budget.

## 3. Data Requirements
| ID | Requirement |
|---|---|
| D1 | Three independent, credible sources, and no Kaggle: NVD (CVSS and CVE details), FIRST EPSS (daily scores), CISA KEV (outcome labels). |
| D2 | Join key is CVE ID (upper case, trimmed), and NVD is the base table. |
| D3 | The final integrated dataset has at least 100,000 rows and at least 20 variables (aim for 40+). Current state: 253,529 current non-rejected CVEs in the clean base table; the ten-date panel contains 934,180 CVE-date rows and 46 saved columns (long descriptions are omitted from the panel). |
| D4 | Variables must be real, observed or recorded values. Derived variables (`cve_age_days`, `kev_30d_label`, flags) must be transparently calculated. |
| D5 | Provenance is documented for every source: link, how collected, download date, time coverage, fields used, known gaps and, for EPSS, the model version of each file. |
| D6 | Decision dates are fixed before modelling: 19 February and 19 August, 2022–2026. 2021 is excluded because KEV began in November 2021. |
| D7 | Completed: the ten fixed dates contain 109 positive CVE-date rows. February 2024 has four positives and must be interpreted as highly uncertain. |
| D8 | EPSS scores come from the file for each decision date, never from the current snapshot. |

## 4. SSOT and Data Preparation Requirements
| ID | Requirement |
|---|---|
| S1 | Document the join logic, units, schema (name, source, type), duplicate handling, missing-value treatment and data-quality checks. |
| S2 | Drop the 5,348 CVEs with status "Rejected" (not real vulnerabilities). |
| S3 | Drop `authentication` (100% missing) and `attack_requirements` (89% missing). |
| S4 | Merge `ADJACENT` and `ADJACENT_NETWORK`, and flag or convert old CVSS v2 impact values such as PARTIAL. |
| S5 | Convert all date columns to proper dates in one format. |
| S6 | Do not fill missing CVSS or EPSS with zero. Keep the `has_cvss_score` and `has_epss_at_decision` flags. |
| S7 | Keep `cvss_version` as a column. CVSS 3.x is the main score, and 4.0 rows are a separate group or a robustness check. |
| S8 | Quality checks: rows vs unique CVE IDs, missing % per column, value ranges (CVSS 0 to 10, EPSS 0 to 1), date ranges and outlier handling. |
| S9 | Keep raw files untouched in `data/raw/`, and write all cleaning as re-runnable, numbered scripts or notebook cells. |

## 5. Functional Requirements
| ID | Requirement |
|---|---|
| F1 | For each decision date, keep only CVEs published before it. |
| F2 | Remove CVEs already in KEV on or before the decision date. |
| F3 | Label a CVE 1 if added to KEV within 30 days after the decision date, else 0. |
| F4 | Add `epss_at_decision`, `epss_percentile_at_decision`, `epss_model_version`, `decision_date` and `cve_age_days`. |
| F5 | Rank CVEs three ways at each date: CVSS-only, EPSS-only and a weighted combination. |
| F6 | Compute Recall@K and Precision@K at K = 50, 100, 500 and 1000, per date and pooled. |
| F7 | Train Logistic Regression (baseline), Random Forest and XGBoost, each with and without EPSS. |
| F8 | Use time-ordered train, validation and test splits, and report Average Precision. |
| F9 | Use class weights because KEV is about 0.5% of CVEs. |
| F10 | Run statistical tests (for example, tests on EPSS vs KEV outcome and on differences between rankings) for H1 to H3. |
| F11 | Report uncertainty, for example a bootstrap confidence interval resampling CVEs within each date. |
| F12 | Repeat all comparisons across the decision dates and across EPSS model versions (H5). |
| F13 | Mark each hypothesis as supported, not supported or inconclusive, with evidence. Unsupported or inconclusive is a valid outcome. |
| F14 | Optional if time allows: EPSS calibration check, then SHAP. Cut SHAP first, then calibration. |

## 6. Hypotheses
- **H1:** Higher EPSS means a higher chance of future KEV listing.
- **H2:** EPSS captures more future KEVs than CVSS at the same budget.
- **H3:** Combining CVSS and EPSS beats CVSS alone.
- **H4:** EPSS adds predictive value beyond CVSS and other features.
- **H5:** The relative performance stays consistent across periods.

## 7. Non-Functional Requirements
| ID | Requirement |
|---|---|
| N1 | **No leakage:** use only information available on the decision date. `epss_current`, current CVSS values and all `kev_*` columns are never model inputs. The `kev_*` columns are used only for the label and for EDA. |
| N2 | **Reproducible:** code runs from raw data to results, and the final dataset or the procedure to rebuild it is included. |
| N3 | **Public GitHub repository** with a README (mandatory per the handout). Large data files stay out of Git. |
| N4 | **Original work:** AI-generated code or plagiarism is reported under the Unfair Means policy. |
| N5 | **Viva:** each member can explain every part of the code. |
| N6 | **Association, not causation:** results are not presented as proof that EPSS causes better outcomes. |
| N7 | **Imbalance-aware metrics:** use Recall@K, Precision@K and AP, never accuracy. |
| N8 | **Scope:** use only methods in the course handout. Hierarchical clustering is not used unless the instructor approves. Deviations need instructor approval. |

## 8. BADIR Mapping
| Stage | What it covers in this project |
|---|---|
| **B** Business question | Which vulnerability should we patch first? |
| **A** Analysis plan | Hypotheses H1 to H5, the three rankings, the models and the metrics. |
| **D** Data collection | NVD, EPSS and KEV collection, cleaning, SSOT and the decision panel. |
| **I** Insights | Recall@K, Precision@K and AP results, tests, EDA and robustness. |
| **R** Recommendations | A patch prioritization strategy with limitations and an implementation roadmap. |

## 9. Deliverables
**Final submission (per the guidelines)**
1. Problem statement, research questions and hypotheses.
2. Data sources, provenance and integration methodology (`DATA_README.md`).
3. Final integrated dataset, or a reproducible procedure to access it.
4. Data-quality checks and EDA.
5. Course methods and hypothesis assessments.
6. Supporting evidence, final findings and limitations.
7. Business recommendations and an implementation roadmap (actions, timelines, owners, measurable indicators).
8. Reproducible code and supporting documentation on public GitHub.

**Three-stage presentation**
| Stage | Slides | Content |
|---|---|---|
| 1. Define the problem | 3 to 5 | Stakeholder and problem, research questions and hypotheses, data audit, SSOT plan, project plan. |
| 2. Validate the evidence | 3 to 5 | Data preparation, EDA, hypothesis testing, unsupported or inconclusive hypotheses, revised plan. |
| 3. Inform the decision | 3 to 4 | Final findings, business implications, impact and limitations, implementation roadmap. |

**Assessment weights:** Pre-submission 10%, final report 10%, final presentation 20% (total 40%).

## 10. Constraints and Assumptions
- CVSS 3.0/3.1 values are reconstructed from timestamped NVD CVE history strictly before 00:00 UTC on each decision date; current CVSS is retained for audit only. Other NVD enrichment attributes are current values and are excluded from model features.
- EPSS used four model versions across the dates (2022.01.01, 2023.03.01, 2025.03.14, 2026.06.15), so raw scores are compared within a date, not across dates.
- KEV shows catalogue inclusion, not the date of the actual attack.
- Positives are very few, which makes Recall@K noisy. Budgets are not equally tight across dates because the pool size grows each year.
- Time: two-person team, with a short window before submission.

## 11. Acceptance Criteria
- Dataset requirements (D3) and SSOT documentation (S1 to S9) are met.
- No leakage: checks confirm that no future CVEs, no already-listed KEVs and no duplicates are in any decision-date table.
- Recall@K, Precision@K and AP are reported for CVSS, EPSS and combined, with uncertainty, for all decision dates.
- All five hypotheses have a status with evidence.
- The report and slides link stakeholder needs, hypotheses, data, methods, findings and recommendations, and state the limitations.
- The GitHub repo is public and the code reproduces the results.

## 12. Current Status
| Item | Status |
|---|---|
| Data collection | Done locally: NVD 2021–2026, CISA KEV, and ten dated EPSS snapshots. Raw data remains ignored by Git. |
| SSOT cleaning | Done: 253,529 non-rejected CVEs, 6,726 current NVD rejected records dropped, normalized IDs, CVSS/EPSS range checks, and 46 base panel columns. |
| Decision dates and panel | Done: all ten February/August dates; 934,180 CVE-date rows, 206,865 unique CVEs across dates, and 109 positive labels. Leakage checks run in the panel script. |
| Historical CVSS reconstruction | Done locally: timestamped histories retrieved for 206,865 CVEs; scores use the last vector recorded strictly before 00:00 UTC on each decision date, with no current-score fallback. 3.x coverage is 89.8%–93.7% by date. |
| EDA, rankings, tests, models | Rerun complete on the historical CVSS panel: 934,180 rows, 109 positive labels; the ranking common cohort contains 859,971 rows and 99 positives. |
| Data provenance and reproducibility docs | Done locally in `DATA_README.md`, `docs/decision_dates.md`, and numbered scripts. |
| Hypothesis assessment and recommendations | Done locally in `docs/hypothesis_assessment.md` and `docs/recommendations.md`; evidence is qualified by the small positive count. |
| Final report and slides | Historical CVSS findings updated; six-page PDF inspected, 11-slide deck regenerated and validated. DOCX/PDF and deck are ready for team review. |
| Public GitHub repository | Not published from this workspace. |

The project files are ready for team review. Publishing the repository publicly is still pending a separate user request.

# Plan of Action

**Implementation note:** The completed reproducible workflow uses numbered Python scripts in `scripts/` rather than the originally proposed Jupyter notebooks. Raw files are never edited; each script reads the preceding outputs and writes generated files under `data/processed/` or `outputs/`.
- Suggested folders: `data/raw/`, `data/processed/`, `notebooks/`, `outputs/figures/`, `outputs/tables/`, `docs/`.

## Task 1: Repository and documentation setup
Create the public GitHub repo and the documentation skeleton, so that provenance and SSOT rules are written as you go.

Files to create:
* `README.md`: Project summary, folder structure, how to run the notebooks in order, and how to get the raw data.
* `DATA_README.md`: Source provenance (links, download dates, coverage, EPSS model versions), SSOT rules, cleaning log and schema. Filled in progressively by Tasks 2 and 3.
* `.gitignore`: Excludes large data files, keeps notebooks and small samples.
* `requirements.txt`: Python libraries and versions.

**Changes and additions to the folder structure**

1. **Add `DATA_README.md`** in the root. It does not exist yet.
2. **Add `outputs/figures/` and `outputs/tables/`** with a `.gitkeep` in each. Your POA saves charts and tables there.
3. **Merge or remove `reports/`.** It duplicates `outputs/`. Either delete it, or keep it only for the final report and slides and put everything else in `outputs/`.
4. **Add `data/interim/`** (optional) for intermediate files, or just use `data/processed/`.
5. **Move `scripts/01_download.py`.** Your plan uses notebooks, so either keep it as the single download script (reproducibility is good) or convert it to `notebooks/00_download_data.ipynb`. Keeping the script is fine.
6. **Rename `docs/RAW_DATA_NOTES.md`** or fold it into `DATA_README.md` so there is one source of truth for provenance.
7. **Add `docs/decision_dates.md`** later, in Task 4. It is not needed today.
8. **Missing raw file:** there is no `nvdcve-2.0-2026.json.gz`. Your data has 2026 CVEs, so the 2026 file was probably downloaded under a different name or merged. Check and note it in `DATA_README.md`.
9. **Put the data in `.gitignore`:** `data/raw/` and `data/processed/` stay out of Git, and the `.gitkeep` files keep the empty folders.

**README.md should contain**
1. Project title, team and course.
2. One-paragraph summary: the question (does EPSS beat CVSS for patch prioritization), the three data sources and the 30-day KEV label.
3. Research questions and hypotheses H1 to H5 (short).
4. Folder structure (a short tree with one line per folder).
5. Setup: Python version, how to create the environment and install `requirements.txt`.
6. How to get the data: point to `scripts/01_download.py` and `DATA_README.md`.
7. Notebook run order (01 to 10, then 13, optional 11 and 12) with one line for each.
8. Key results (placeholder for now, filled at the end).
9. Limitations and the association-not-causation note.
10. Licence and data-source credits (NVD, FIRST, CISA).

**DATA_README.md should contain**
1. Overview: the three sources and how they join (CVE ID, NVD as the base).
2. Source table: owner, link, access method, download date, time coverage, fields used, known gaps.
3. Raw file inventory: every file in `data/raw/` with its size and date (including the EPSS decision-date files and their model versions).
4. SSOT rules: join logic, duplicate handling, missing-value treatment, units (CVSS 0 to 10, EPSS 0 to 1) and date format.
5. Cleaning log (filled in Task 2): each step, rows before and after, and the reason.
6. Decision dates and labelling rule: the final dates, the 30-day label, and the leakage rules (only CVEs published before the date, remove CVEs already in KEV, EPSS from that date's file).
7. Data-quality checks and results (filled in Tasks 2 and 5).
8. Schema table: column, source, type, description and whether it is a model input (filled in Task 6).
9. Known limitations: incomplete historical CVSS coverage where NVD history has no vector, EPSS model version changes, KEV is not the attack date, few positives, and current non-CVSS NVD enrichments.
10. Reproducibility: the order of the scripts and notebooks that rebuild everything.

**requirements.txt (libraries only)**
- pandas
- numpy
- scipy
- scikit-learn
- xgboost
- matplotlib
- seaborn
- statsmodels (for the hypothesis tests)
- jupyter (or notebook and ipykernel)
- summarytools (you already use it for `dfSummary`)
- requests (used by the download script)
- tqdm (optional, for download progress)
- shap (optional, only if you do Task 11)

Pin the versions that run on your machine with `pip freeze` for these packages only.

**.gitignore (files and folders)**
- `data/raw/`
- `data/processed/`
- `*.csv`, `*.csv.gz`, `*.json.gz` and large `*.json` files (but keep a small sample file if you want one)
- `.venv/` and `venv/`
- `__pycache__/` and `*.pyc`
- `.ipynb_checkpoints/`
- `.env` (the NVD API key must never be committed)
- `.DS_Store` and `Thumbs.db`
- `*.html` summary exports (for example `df_summary.html`) because they are large
- Keep the `.gitkeep` files, so the empty folders stay in the repo.

**Two things to check before your first commit**
- Search `scripts/01_download.py` for a hard-coded NVD API key and move it to `.env`.
- Run `git status` and confirm that no large data file is staged.

## Task 2: Clean the base dataset
Turn the initial CSV into a clean SSOT base table.

Files to create:
* `01_clean_base_data.ipynb`: Drops rejected CVEs, drops `authentication` and `attack_requirements`, merges `ADJACENT` and `ADJACENT_NETWORK`, converts dates, normalises `cve_id`, runs quality checks (rows vs unique IDs, missing %, value ranges), and logs the row count after each step.
* `data/processed/ssot_clean.csv`: Output of the notebook.

## Task 3: Collect and prepare EPSS snapshots
Prepare one EPSS file per decision date, including the second snapshot per year to fix the low positives problem.

Files to create:
* `02_prepare_epss_snapshots.ipynb`: Loads each EPSS file, skips the comment line, reads the model version, renames the columns (`cve_id`, `epss_at_decision`, `epss_percentile_at_decision`), adds `decision_date` and `epss_model_version`, and checks for duplicates.
* `data/processed/epss_snapshots.csv`: All snapshots stacked in one file, plus a small table of file name, date, model version, row count and download date for `DATA_README.md`.

## Task 4: Check positives and finalise decision dates
Confirm that the dates give enough positives before building anything else.

Files to create:
* `03_decision_date_check.ipynb`: Counts KEVs added in the 30 days after each candidate date (February and August of 2022 to 2026) and shows the pool size and positive rate. Used to freeze the final date list.
* `docs/decision_dates.md`: The final dates, the reason for choosing them (fixed rule, chosen before modelling), and the positive count for each.

## Task 5: Build the decision panel
Build one table where each row is a CVE on a decision date, with a 30-day KEV label.

Files to create:
* `04_build_decision_panel.ipynb`: For each date, keeps CVEs published before it, removes CVEs already in KEV, joins the EPSS snapshot, and adds `has_epss_at_decision`, `cve_age_days` and `kev_30d_label`. Runs the leakage checks (no future CVEs, no already-listed KEVs, labels inside the window, no duplicates).
* `data/processed/ssot_decision_panel.csv`: The final panel (without the long description text).
* `outputs/tables/panel_summary.csv`: Rows, positives, positive rate and missing EPSS per date.

## Task 6: Add features and finish the schema
Reach 40+ columns and document every variable.

Files to create:
* `05_feature_engineering.ipynb`: Adds `vendor` and `product` from the raw NVD CPE data, a grouped `top_cwe` (common CWEs plus "other"), a CVSS v3.x flag, and a combined score for the CVSS and EPSS ranking. Marks which columns are model inputs and which are not (KEV columns and `epss_current` are excluded).
* `data/processed/ssot_final.csv`: The panel with the new features.
* `outputs/tables/schema.csv`: Column name, source, type, description and whether it is a model input. Pasted into `DATA_README.md`.

## Task 7: Exploratory data analysis
Describe the data and show the problem the stakeholder faces.

Files to create:
* `06_eda.ipynb`: CVSS and EPSS distributions, KEV rate per date, missing-data patterns, CVSS version mix, EPSS vs KEV outcome (box plot or rate by EPSS band), and the age of CVEs at KEV listing.
* `outputs/figures/`: Saved charts for the report and slides.

## Task 7b: Statistical tests
Give each of H1 to H3 evidence beyond model scores.

Files to create:
* `07_hypothesis_tests.ipynb`: Tests for H1 (EPSS vs future KEV, for example a rank-based test), a comparison of captured KEVs between CVSS and EPSS rankings at the same K for H2, and a comparison between the combined ranking and CVSS alone for H3.
* `outputs/tables/test_results.csv`: Test, statistic, p-value and interpretation.

## Task 8: Ranking comparison
Answer the main research question with the main KPI.

Files to create:
* `08_ranking_comparison.ipynb`: Ranks CVEs by CVSS, EPSS and the combined score for each date. Computes Recall@K and Precision@K at K = 50, 100, 500 and 1000, per date and pooled. Adds bootstrap confidence intervals.
* `outputs/tables/ranking_results.csv`: Metrics by method, K and date.
* `outputs/figures/recall_at_k.png`: Recall@K curves by method.

## Task 9: Predictive models
Test whether EPSS adds value beyond CVSS and other features (H4).

Files to create:
* `09_models.ipynb`: Time-ordered train, validation and test splits. Trains Logistic Regression, Random Forest and XGBoost with and without EPSS, with class weights. Reports Average Precision, Recall@K and Precision@K on the test period.
* `outputs/tables/model_results.csv`: Model, feature set, AP and Recall@K.
* `outputs/figures/model_comparison.png`: With vs without EPSS.

## Task 10: Robustness across periods
Test whether the results hold across dates and EPSS model versions (H5).

Files to create:
* `10_robustness.ipynb`: Repeats the ranking comparison per date and per EPSS model version (v2, v3, v4), with uncertainty. Flags dates with very few positives as unreliable.
* `outputs/tables/robustness_results.csv`: Results by date and model version.
* `outputs/figures/robustness.png`: Metric by date with confidence intervals.

## Task 11: Optional extras (only if time allows; cut SHAP first)
Files to create:
* `11_calibration.ipynb`: Compares EPSS probability bands with the actual KEV rate (a reliability plot).
* `12_shap.ipynb`: SHAP values for the best model, to show the contribution of EPSS vs CVSS and other features.

## Task 12: Hypothesis table and recommendations
Turn the results into decisions.

Files to create:
* `13_findings_summary.ipynb`: Collects results from tasks 7 to 10 and builds the hypothesis status table (supported, not supported, inconclusive, with evidence).
* `docs/recommendations.md`: The recommended patching strategy, an implementation roadmap (actions, timelines, owners, measurable indicators), impact, and limitations including the association-not-causation statement.

## Task 13: Report, slides and final repo
Files to create:
* `docs/final_report.docx` or `.pdf`: Problem, data and provenance, SSOT, EDA, methods, findings, recommendations, roadmap and limitations.
* `docs/slides.pptx`: Three-stage deck (define the problem, validate the evidence, inform the decision).
* Updated `README.md` and `DATA_README.md`: Final versions, with the run order of the notebooks.
* `docs/viva_notes.md`: A one-page note on what each notebook does, so both members can explain it.

**Run order:** `scripts/01_download.py` through `scripts/04_finalize_outputs.py`; report generation uses `scripts/06_build_report_pdf.py`. `scripts/07_build_slides.mjs` rebuilds the PowerPoint with the Codex Artifact Tool runtime. Calibration and SHAP remain out of scope.
