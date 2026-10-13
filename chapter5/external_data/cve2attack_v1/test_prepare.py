import copy
import csv
import tempfile
import unittest
from pathlib import Path
from prepare import read_rows, prepare


REGISTRY = {'mapping': [
    {'source_name': 'Command and Scripting Interpreter', 'technique_id': 'T1059'},
    {'source_name': 'Exploitation for Defense Evasion', 'technique_id': 'T1211'}]}
ACTIVE = {'T1059', 'T1059.001', 'T1211'}
PUBLIC = [
    {'id': 'CVE-2020-1001', 'description': 'first known vulnerability', 'techniques': ['T1059', 'T1059.001']},
    {'id': 'CVE-2020-1002', 'description': 'development vulnerability', 'techniques': ['T1211']},
    {'id': 'CVE-2020-1003', 'description': 'reserved vulnerability', 'techniques': ['T1059']}]
FOLDS = {'reserved_ids': ['CVE-2020-1003'], 'folds': [
    {'fold': 0, 'train': ['CVE-2020-1001'], 'dev': ['CVE-2020-1002']} ]}


def row(cve='CVE-2020-9999', text='new independent description', labels=('T1059',), source_row=1):
    return {'id': cve, 'description': text, 'techniques': list(labels),
            'source_split': 'train', 'source_row': source_row}


def run(rows, public=None, folds=None, active=None):
    return prepare(rows, public or PUBLIC, PUBLIC, {'CVE-2020-1004'},
                   folds or FOLDS, REGISTRY, active or ACTIVE)


class PreparationTests(unittest.TestCase):
    def test_new_sample_preserves_parent_and_has_no_invented_background(self):
        out = run([row()])
        candidate = out['new_candidates'][0]
        self.assertEqual(candidate['techniques'], ['T1059'])
        self.assertEqual(candidate['cpes'], [])
        self.assertEqual(candidate['cwes'], [])
        self.assertFalse(candidate['graph_ready'])
        self.assertEqual(candidate['role'], 'unassigned_external_development_candidate')

    def test_reserved_public_and_exposure_never_enter_candidates(self):
        out = run([row(cve=f'CVE-2020-100{i}') for i in range(1, 5)] + [row()])
        self.assertEqual([r['id'] for r in out['new_candidates']], ['CVE-2020-9999'])
        excluded = {r['id']: r['status'] for r in out['excluded']}
        self.assertEqual(excluded['CVE-2020-1003'], 'reserved_id_excluded')
        self.assertEqual(excluded['CVE-2020-1004'], 'recorded_exposure_excluded')
        self.assertNotIn('CVE-2020-1003', {r['id'] for r in out['overlap_reviews']})

    def test_exact_duplicates_collapse_with_all_provenance(self):
        out = run([row(), row(source_row=2)])
        self.assertEqual(len(out['new_candidates']), 1)
        self.assertEqual(len(out['new_candidates'][0]['provenance']), 2)

    def test_conflicting_labels_are_quarantined_without_union(self):
        out = run([row(), row(labels=('T1211',), source_row=2)])
        self.assertEqual(out['new_candidates'], [])
        self.assertEqual(out['quarantine'][0]['status'], 'duplicate_variant_quarantined')
        self.assertTrue(out['duplicate_reviews'][0]['label_conflict'])

    def test_conflicting_descriptions_are_quarantined(self):
        out = run([row(), row(text='a materially different description', source_row=2)])
        self.assertEqual(out['new_candidates'], [])
        self.assertTrue(out['duplicate_reviews'][0]['description_conflict'])

    def test_normalized_description_collision_with_public_is_quarantined(self):
        out = run([row(text='  FIRST known\n vulnerability  ')])
        self.assertEqual(out['new_candidates'], [])
        self.assertEqual(out['quarantine'][0]['status'], 'public_description_collision_quarantined')

    def test_distinct_new_cves_with_same_description_share_group(self):
        out = run([row(), row(cve='CVE-2020-9998', text='NEW independent description')])
        self.assertEqual(len(out['new_candidates']), 2)
        self.assertEqual(out['new_candidates'][0]['description_group'], out['new_candidates'][1]['description_group'])

    def test_parent_support_counts_each_train_cve_once(self):
        out = run([row()])
        support = out['support_preview'][0]
        self.assertEqual(support['current_train_parent_support']['T1059'], 1)
        self.assertEqual(support['hypothetical_augmented_parent_support']['T1059'], 2)
        self.assertNotIn('T1211', support['current_train_parent_support'])

    def test_public_outside_current_pool_is_also_excluded(self):
        public = PUBLIC + [{'id': 'CVE-2020-9998', 'description': 'another public source', 'techniques': ['T1059']}]
        out = run([row(cve='CVE-2020-9998')], public=public)
        self.assertEqual(out['new_candidates'], [])
        self.assertEqual(out['excluded'][0]['status'], 'public_source_overlap_excluded')

    def test_inactive_mapping_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'active'):
            run([row()], active={'T1059', 'T1059.001'})

    def test_invalid_cve_is_quarantined(self):
        out = run([row(cve='not-a-cve')])
        self.assertEqual(out['new_candidates'], [])
        self.assertEqual(out['quarantine'][0]['status'], 'invalid_record_quarantined')

    def test_fold_overlap_is_rejected(self):
        folds = copy.deepcopy(FOLDS)
        folds['folds'][0]['dev'].append('CVE-2020-1001')
        with self.assertRaisesRegex(ValueError, 'overlap'):
            run([row()], folds=folds)

    def test_overlapping_labels_compared_in_shared_parent_scope(self):
        out = run([row(cve='CVE-2020-1001')])
        review = out['overlap_reviews'][0]
        self.assertEqual(review['public_shared_parent_labels'], ['T1059'])
        self.assertEqual(review['external_only_labels'], [])
        self.assertEqual(review['public_only_labels'], [])


class CsvTests(unittest.TestCase):
    def write(self, p, name, header, rows):
        with (p/name).open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f); w.writerow(header); w.writerows(rows)

    def source(self, xrows=None, yrows=None, header=None):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); p = Path(temp.name)
        columns = [m['source_name'] for m in REGISTRY['mapping']]
        for split in ['train', 'test']:
            self.write(p, f'X_{split}.csv', ['Name', 'Text'], xrows or [['CVE-2020-9999', 'a description']])
            self.write(p, f'y_{split}.csv', header or columns, yrows if yrows is not None else [['1', '0']])
        return p

    def test_paired_rows_preserve_source_coordinates(self):
        rows = read_rows(self.source(), REGISTRY)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['techniques'], ['T1059'])
        self.assertEqual(rows[0]['source_split'], 'train')
        self.assertEqual(rows[1]['source_split'], 'test')

    def test_mismatched_lengths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'row count'):
            read_rows(self.source(yrows=[]), REGISTRY)

    def test_nonbinary_label_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'binary'):
            read_rows(self.source(yrows=[['0.5', '0']]), REGISTRY)

    def test_unknown_label_column_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'label columns'):
            read_rows(self.source(header=['Unknown technique', 'Exploitation for Defense Evasion']), REGISTRY)

    def test_duplicate_label_columns_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'label columns'):
            read_rows(self.source(header=['Command and Scripting Interpreter']*2), REGISTRY)

    def test_row_width_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'row width'):
            read_rows(self.source(yrows=[['1', '0', '1']]), REGISTRY)


if __name__ == '__main__':
    unittest.main()
