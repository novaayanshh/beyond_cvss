import unittest

import numpy as np
import pandas as pd

from scripts.ranking_utils import expected_recall_precision_at_k, rank_priority_rows


class ExpectedRankingMetricTests(unittest.TestCase):
    def test_no_ties_matches_stable_top_k(self):
        y = np.array([0, 1, 0, 1])
        score = np.array([0.9, 0.8, 0.7, 0.1])
        got = expected_recall_precision_at_k(y, score, [1, 2, 4])
        expected = {1: (0.0, 0.0, 1), 2: (0.5, 0.5, 2), 4: (1.0, 0.5, 4)}
        for k, want in expected.items():
            np.testing.assert_allclose(got[k][:2], want[:2])
            self.assertEqual(got[k][2], want[2])

    def test_all_tied_expected_recall(self):
        y = np.array([1] + [0] * 9)
        result = expected_recall_precision_at_k(y, np.ones(10), [4])[4]
        self.assertAlmostEqual(result[0], 4 / 10)
        self.assertAlmostEqual(result[1], 1 / 10)
        self.assertEqual(result[2], 4)

    def test_cutoff_inside_tie_group(self):
        y = np.array([0, 1, 0, 1])
        score = np.array([3.0, 2.0, 2.0, 1.0])
        recall, precision, picks = expected_recall_precision_at_k(y, score, [2])[2]
        self.assertAlmostEqual(recall, 0.25)
        self.assertAlmostEqual(precision, 0.25)
        self.assertEqual(picks, 2)

    def test_all_nan_scores(self):
        result = expected_recall_precision_at_k(np.array([1, 0]), np.array([np.nan, np.nan]), [1, 2])
        self.assertTrue(np.isnan(result[1][0]))
        self.assertTrue(np.isnan(result[1][1]))
        self.assertEqual(result[1][2], 0)

    def test_priority_secondary_sort_and_cutoff_flag(self):
        rows = pd.DataFrame({
            "cve_id": ["CVE-3", "CVE-2", "CVE-1"],
            "score": [9.0, 9.0, 8.0],
            "epss_at_decision": [0.1, 0.8, 0.2],
        })
        ranked = rank_priority_rows(rows, "score", 1)
        self.assertEqual(ranked.cve_id.iloc[0], "CVE-2")
        self.assertTrue(ranked.tied_at_cutoff.iloc[0])


if __name__ == "__main__":
    unittest.main()
