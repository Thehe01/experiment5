import csv
import io
import json
from pathlib import Path
import re
import unittest
import zipfile
from alignment import resolve_record

HERE=Path(__file__).resolve().parent
SCOPE={"T1005","T1040","T1055","T1059","T1068","T1078","T1083","T1110","T1133","T1134","T1136","T1185","T1189","T1190","T1203","T1204","T1210","T1211","T1212","T1485","T1499","T1505","T1548","T1552","T1557","T1560","T1565","T1566","T1574","T1606","T1608"}
def actual_evidence(cve):
    result=[]
    with zipfile.ZipFile(HERE/"ctid-source-inputs.zip") as z:
        for row in csv.DictReader(io.StringIO(z.read("ctid-attack-to-cve.csv").decode("utf-8-sig"))):
            if row["CVE ID"]!=cve:continue
            for column,stage in [("Exploitation Technique","exploitation_technique"),("Primary Impact","primary_impact"),("Secondary Impact","secondary_impact"),("Uncategorized","uncategorized")]:
                for t in re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?",row[column]):
                    result.append({"technique":t,"source":"ctid_cve","stage":stage})
        for row in json.loads(z.read("ctid-kev.json"))["mapping_objects"]:
            if row["capability_id"]==cve:
                result.append({"technique":row["attack_object_id"],"source":"ctid_kev","stage":row["mapping_type"]})
    return result

class AlignmentTests(unittest.TestCase):
    def test_kev_supplement_recovers_documented_user_execution(self):
        r=resolve_record("CVE-2008-2992",["T1203","T1204"],[["T1203"]],actual_evidence("CVE-2008-2992"),SCOPE)
        self.assertEqual(r["canonical_labels"],["T1203","T1204"])
        self.assertEqual(r["author_added_ctid_labels"],["T1204"])
        self.assertEqual(r["unknown_labels"],[])
    def test_disjoint_author_labels_do_not_replace_ctid(self):
        r=resolve_record("CVE-2021-21166",["T1059","T1203"],[["T1110","T1189"]],actual_evidence("CVE-2021-21166"),SCOPE)
        self.assertEqual(r["canonical_labels"],["T1059","T1203"])
        self.assertEqual(r["unknown_labels"],["T1110","T1189"])
        self.assertFalse(r["independent_human_iaa"])
    def test_duplicate_variants_are_not_unioned_into_positives(self):
        r=resolve_record("CVE-2011-4106",["T1190","T1505"],[["T1059","T1190","T1203","T1505"],["T1190","T1505"]],actual_evidence("CVE-2011-4106"),SCOPE)
        self.assertEqual(r["canonical_labels"],["T1190","T1505"])
        self.assertEqual(r["unknown_labels"],["T1059","T1203"])
        self.assertEqual(r["author_variants"],[["T1059","T1190","T1203","T1505"],["T1190","T1505"]])
    def test_unexpected_authority_conflict_blocks_generation(self):
        with self.assertRaisesRegex(ValueError,"CTID.*original"):
            resolve_record("CVE-2008-2992",["T1203"],[["T1203"]],actual_evidence("CVE-2008-2992"),SCOPE)
    def test_protected_id_rejected_before_inspecting_labels(self):
        with self.assertRaisesRegex(ValueError,"protected"):
            resolve_record("CVE-2008-0655",object(),object(),object(),object(),["CVE-2008-0655"])
    def test_mobile_only_mapping_is_quarantined(self):
        for cve,labels in [("CVE-2017-0493",["T1005"]),("CVE-2019-7287",["T1068"])]:
            r=resolve_record(cve,None,[labels],actual_evidence(cve),SCOPE)
            self.assertEqual(r["status"],"quarantined_cross_domain")
            self.assertEqual(r["canonical_labels"],[])
            self.assertEqual(r["held_author_labels"],labels)
    def test_new_unmapped_source_labels_remain_partial(self):
        r=resolve_record("CVE-2021-99999",None,[["T1005"]],[],SCOPE)
        self.assertEqual(r["canonical_labels"],["T1005"])
        self.assertEqual(r["status"],"external_curated_not_ctid_revalidated")
        self.assertFalse(r["missing_labels_are_confirmed_negatives"])
    def test_new_ambiguous_source_does_not_silently_choose_variant(self):
        r=resolve_record("CVE-2021-99999",None,[["T1005"],["T1068"]],[],SCOPE)
        self.assertEqual(r["status"],"quarantined_ambiguous_author")
        self.assertEqual(r["canonical_labels"],[])
    def test_enterprise_out_of_scope_is_not_misclassified_as_mobile(self):
        with self.assertRaisesRegex(ValueError,"out.of.scope"):
            resolve_record("CVE-2021-99999",None,[["T1005"]],
                           [{"technique":"T1105","source":"ctid_cve","stage":"primary_impact"}],SCOPE)

if __name__=="__main__":unittest.main()

