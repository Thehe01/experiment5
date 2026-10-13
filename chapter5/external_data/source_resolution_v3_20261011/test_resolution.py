import importlib.util
import pathlib
import unittest

P = pathlib.Path(__file__).with_name("resolution.py")
S = importlib.util.spec_from_file_location("resolution_v3", P)
R = importlib.util.module_from_spec(S)
S.loader.exec_module(R)

def e(source, value, kind="Secondary"):
    return {"source": source, "type": kind, "value": value}

class ResolutionTests(unittest.TestCase):
    def test_assigning_source_preserves_specificity_without_union(self):
        result = R.choose_cwe("vendor", [e("vendor", "CWE-121"), e("nvd@nist.gov", "CWE-787", "Primary")])
        self.assertEqual(result["ids"], ["CWE-121"])
        self.assertEqual(result["source"], "vendor")

    def test_nvd_secondary_is_still_nvd_when_cna_missing(self):
        result = R.choose_cwe("vendor", [e("vendor", "NVD-CWE-noinfo"), e("nvd@nist.gov", "CWE-532")])
        self.assertEqual(result["ids"], ["CWE-532"])
        self.assertEqual(result["source"], "nvd@nist.gov")

    def test_multiple_cwes_within_one_provider_are_preserved(self):
        result = R.choose_cwe("vendor", [e("vendor", "CWE-214"), e("vendor", "CWE-532"), e("nvd@nist.gov", "CWE-532")])
        self.assertEqual(result["ids"], ["CWE-214", "CWE-532"])

    def test_non_numeric_and_substring_values_are_not_nodes(self):
        result = R.choose_cwe("vendor", [e("vendor", "CWE-noinfo"), e("vendor", "prefix-CWE-79"), e("vendor", "CWE-79 note"), e("vendor", "CWE-79")])
        self.assertEqual(result["ids"], ["CWE-79"])

    def test_unknown_third_provider_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "provider"):
            R.choose_cwe("vendor", [e("unknown-adp", "CWE-287")])

    def test_adp_values_require_exact_official_record_agreement(self):
        good = R.choose_cwe("vendor", [e("cisa-id", "CWE-287")], {"cisa-id": ["CWE-287"]})
        self.assertEqual(good["policy"], "verified_adp_fallback")
        with self.assertRaisesRegex(ValueError, "provider"):
            R.choose_cwe("vendor", [e("cisa-id", "CWE-287")], {"cisa-id": ["CWE-862"]})

    def test_whole_cve_is_quarantined_and_all_data_preserved(self):
        records = [{"id": "a", "techniques": ["T1203"], "unknown_labels": ["T1190"], "role": "original_development_pool"}, {"id": "b", "techniques": ["T1190"], "unknown_labels": [], "role": "external_train_only"}]
        clean, quarantine = R.partition(records)
        self.assertEqual([x["id"] for x in clean], ["b"])
        self.assertEqual(quarantine, records[:1])
        self.assertEqual(records[0]["techniques"], ["T1203"])

    def test_duplicate_and_missing_review_pairs_are_rejected(self):
        unknown = [{"id": "a", "technique": "T1203"}]
        opinion = {"id": "a", "technique": "T1203", "finding": "context_required", "canonical_action": "KEEP_UNKNOWN_QUARANTINE_CVE", "human_semantic_adjudication": False}
        self.assertTrue(R.validate_review(unknown, [opinion]))
        with self.assertRaisesRegex(ValueError, "pair"):
            R.validate_review(unknown, [])
        with self.assertRaisesRegex(ValueError, "pair"):
            R.validate_review(unknown, [opinion, opinion])

    def test_ai_opinion_cannot_be_promoted_to_gold(self):
        unknown = [{"id": "a", "technique": "T1203"}]
        with self.assertRaisesRegex(ValueError, "Gold"):
            R.validate_review(unknown, [{"id": "a", "technique": "T1203", "finding": "supports_potential_association", "canonical_action": "ADD_GOLD", "human_semantic_adjudication": False}])

if __name__ == "__main__":
    unittest.main()
