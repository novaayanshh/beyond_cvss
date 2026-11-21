# Post-submission corrections

This note records the post-submission tie-handling and bootstrap corrections. Ties in CVSS scores are broken at random and averaged (expected recall). The original tables and figures remain unchanged in outputs_submitted_v1/, and Git tag submitted-v1 marks the original submitted commit. New results use exact expected Recall@K/Precision@K under uniform tie-breaking, 1,000 bootstrap replicates, and date-stratified resampling for pooled paired tests.

## Recall comparison before and after

All values use the common historical CVSS 3.x and dated EPSS cohort. Mean per-date recall gives each decision date equal weight. Pooled recall stacks CVE-date rows. Values are shown as proportions.

| Method | K | Per-date mean before | Per-date mean after | Pooled before | Pooled after |
|---|---:|---:|---:|---:|---:|
| CVSS-only | 50 | 0.0000 | 0.0020 | 0.0000 | 0.0009 |
| CVSS-only | 100 | 0.0000 | 0.0052 | 0.0000 | 0.0019 |
| CVSS-only | 500 | 0.0235 | 0.0469 | 0.0000 | 0.0094 |
| CVSS-only | 1,000 | 0.0343 | 0.0794 | 0.0000 | 0.0188 |
| EPSS-only | 50 | 0.1036 | 0.1036 | 0.0101 | 0.0101 |
| EPSS-only | 100 | 0.1379 | 0.1379 | 0.0101 | 0.0101 |
| EPSS-only | 500 | 0.2379 | 0.2410 | 0.0404 | 0.0404 |
| EPSS-only | 1,000 | 0.2643 | 0.2643 | 0.0505 | 0.0505 |
| Combined | 50 | 0.1236 | 0.1236 | 0.0101 | 0.0101 |
| Combined | 100 | 0.1391 | 0.1391 | 0.0202 | 0.0202 |
| Combined | 500 | 0.2265 | 0.2265 | 0.0404 | 0.0404 |
| Combined | 1,000 | 0.2764 | 0.2764 | 0.0505 | 0.0505 |

## Hypothesis status comparison

| Hypothesis | Before | After | Changed? | Updated evidence |
|---|---|---|---|---|
| H1 EPSS association | Supported, period caveat | Supported, period caveat | No | Pooled median EPSS difference remains 0.00718; raw p = 2.72e-11 and Holm-adjusted p = 2.99e-10. Repeated CVEs still limit the pooled independence assumption. |
| H2 EPSS vs CVSS | Inconclusive | Inconclusive overall | No | Pooled Recall@1,000 difference is 0.0317 with a 95% stratified bootstrap interval that includes zero and raw p = 0.1868. One date-specific result (2023-08-19 at K=500 and K=1,000) remains positive after Holm adjustment, but results vary by period and the pooled result is inconclusive. |
| H3 Combined vs CVSS | Inconclusive | Inconclusive | No | Pooled Recall@1,000 difference is 0.0317; the stratified interval includes zero and raw p = 0.1998. No consistent adjusted advantage is established. |
| H4 EPSS added model value | Supported in held-out period, provisionally | Supported in held-out period, provisionally | No | Test Average Precision is unchanged because AP does not depend on top-K tie order: Logistic Regression 0.002086 to 0.007346, Random Forest 0.000253 to 0.000483, XGBoost 0.000269 to 0.000991. The test has 19 positives. |
| H5 Stability across periods | Inconclusive | Inconclusive | No | Expected per-date recall continues to vary across dates. EPSS model versions also change across the study window. |

## What changed

- Tied scores no longer use panel row order to determine which records land at K. The metric helper computes exact expected hits over uniform tie-breaking.
- Bootstrap replicates calculate expected metrics within each resample. Pooled paired resampling preserves each decision date’s panel size.
- Bootstrap repetitions increased from 300 to 1,000. Recall intervals and H2/H3 p-values were recalculated; Holm adjustment remains within each hypothesis family.
- Latest priority lists use score descending, EPSS descending as a secondary key, and CVE ID ascending as the final key. tied_at_cutoff flags a primary-score tie crossing the cut.
- The largest change is in CVSS-only because many CVSS scores tie. At pooled K=1,000, the expected number of CVSS-only captures is 1.86 of 99, rather than a deterministic zero. EPSS-only and Combined each have 5 expected captures at that K.
- H2 remains inconclusive overall even though one date-specific H2 comparison survives adjustment. The evidence does not support a general advantage across dates.

The label definition, panel build, and raw source files were not changed.
