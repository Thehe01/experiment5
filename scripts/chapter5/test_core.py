import unittest
from chapter5 import core


def attack_fixture():
    return {'objects': [
        {'type': 'attack-pattern', 'id': 'ap1', 'name': 'Exploitation for Client Execution',
         'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1203'}],
         'kill_chain_phases': [{'phase_name': 'execution'}]},
        {'type': 'attack-pattern', 'id': 'ap2', 'name': 'Command and Scripting Interpreter',
         'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1059'}]},
        {'type': 'x-mitre-tactic', 'id': 'ta1', 'x_mitre_shortname': 'execution',
         'external_references': [{'source_name': 'mitre-attack', 'external_id': 'TA0002'}]},
        {'type': 'relationship', 'id': 'r1', 'relationship_type': 'uses', 'target_ref': 'ap1',
         'description': 'The actor exploited CVE-2024-1111 and CVE-2024-2222 for client execution.'},
        {'type': 'relationship', 'id': 'r2', 'relationship_type': 'uses', 'target_ref': 'ap2',
         'description': 'After exploiting CVE-2024-3333 the actor ran shell commands.'},
        {'type': 'relationship', 'id': 'r3', 'relationship_type': 'uses', 'target_ref': 'ap1',
         'description': 'The actor did not exploit CVE-2024-4444.'},
        {'type': 'relationship', 'id': 'r4', 'relationship_type': 'uses', 'target_ref': 'ap1',
         'description': 'A report mentions CVE-2024-5555 without a described exploit.'},
    ]}


class DataTests(unittest.TestCase):
    def test_mixed_clause_and_citation_only_cves_are_not_promoted(self):
        fixture=attack_fixture()
        fixture['objects']=[o for o in fixture['objects'] if o['type']!='relationship']
        fixture['objects'].append({'type':'relationship','id':'mixed','relationship_type':'uses','target_ref':'ap1',
                                  'description':'The actor exploited CVE-2024-1111; the report only mentions CVE-2024-2222 (Citation: CVE-2024-3333).'})
        result=core.extract_attack(fixture)
        self.assertEqual({e['head'] for e in result['targets']},{'CVE-2024-1111'})

    def test_repeated_deduplication_preserves_flat_provenance(self):
        edges=[{'head':'c','relation':'affects','tail':'p','layer':'official_nvd','evidence':'one'},
               {'head':'c','relation':'affects','tail':'p','layer':'c4_frozen_gold','evidence':'two'}]
        once=core.deduplicate(edges)
        self.assertEqual(core.deduplicate(once),once)

    def test_admission_requires_direct_semantics(self):
        result = core.extract_attack(attack_fixture())
        accepted = {(e['head'], e['tail']) for e in result['targets']}
        self.assertEqual(accepted, {('CVE-2024-1111', 'T1203'), ('CVE-2024-2222', 'T1203')})
        self.assertEqual(len(result['pending']), 3)
        self.assertTrue(all(e['evidence'] and e['source_record'] for e in result['targets']))

    def test_mapping_does_not_depend_on_cve_labels(self):
        a = core.extract_attack(attack_fixture())['context']
        fixture = attack_fixture()
        fixture['objects'] = [o for o in fixture['objects'] if o['type'] != 'relationship']
        self.assertEqual(a, core.extract_attack(fixture)['context'])

    def test_nvd_preserves_vulnerable_and_environment_distinction(self):
        record = {'id': 'CVE-2024-1111', 'weaknesses': [{'description': [{'value': 'CWE-79'}, {'value': 'NVD-CWE-noinfo'}]}],
                  'configurations': [{'nodes': [{'operator': 'AND', 'cpeMatch': [
                      {'vulnerable': True, 'criteria': 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', 'versionEndExcluding': '2.0'},
                      {'vulnerable': False, 'criteria': 'cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*'}]}]}]}
        out = core.nvd_context(record)
        self.assertEqual({(e['relation'], e['tail']) for e in out}, {
            ('instantiates', 'CWE-79'), ('affects', 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*')})
        affected = next(e for e in out if e['relation'] == 'affects')
        self.assertEqual(affected['configuration']['nodes'][0]['operator'], 'AND')

    def test_split_is_grouped_and_exposure_safe(self):
        targets = [{'head': f'CVE-2024-{1000+i}', 'relation': 'exploited_by', 'tail': t}
                   for i in range(60) for t in (['T1203', 'T1190'] if i % 7 == 0 else ['T1203' if i % 2 else 'T1190'])]
        exposed = {f'CVE-2024-{1000+i}' for i in range(12)}
        s = core.grouped_split(targets, exposed)
        self.assertEqual(s, core.grouped_split(list(reversed(targets)), exposed))
        self.assertFalse(set(s['test']) & exposed)
        self.assertEqual(len(s['test']), 9)
        self.assertEqual(len(s['dev']), 9)
        self.assertEqual(len(set(s['train']) | set(s['dev']) | set(s['test'])), 60)
        self.assertFalse(set(s['train']) & set(s['dev']))

    def test_no_silent_reuse_when_no_new_test_candidates(self):
        targets = [{'head': f'CVE-2024-{1000+i}', 'relation': 'exploited_by', 'tail': 'T1203'} for i in range(20)]
        with self.assertRaisesRegex(ValueError, 'unexposed'):
            core.grouped_split(targets, {t['head'] for t in targets})

    def test_held_edges_and_inverse_are_removed_everywhere(self):
        edges = [{'head': 'c1', 'relation': 'exploited_by', 'tail': 't1'},
                 {'head': 't1', 'relation': 'exploited_by_inverse', 'tail': 'c1'},
                 {'head': 'c2', 'relation': 'exploited_by', 'tail': 't1'},
                 {'head': 'c1', 'relation': 'affects', 'tail': 'p1'}]
        split = {'train': ['c2'], 'dev': ['c1'], 'test': []}
        out = core.training_edges(edges, split)
        self.assertEqual({(e['head'], e['relation'], e['tail']) for e in out}, {('c2','exploited_by','t1'),('c1','affects','p1')})
        core.check_no_leakage(out, split)
        with self.assertRaisesRegex(ValueError, 'leak'):
            core.check_no_leakage(edges, split)

    def test_target_derived_context_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'derived'):
            core.check_no_leakage([{'head': 't1', 'relation': 'implies', 'tail': 'a1', 'derived_from_target': True}],
                                 {'train': [], 'dev': [], 'test': []})

    def test_ablations_remove_context_from_training(self):
        edges = [{'head':'c1','relation':r,'tail':'x'} for r in ('affects','instantiates','exploited_by')]
        self.assertEqual({e['relation'] for e in core.training_edges(edges, {'train':['c1'],'dev':[],'test':[]}, ('affects',))},
                         {'instantiates','exploited_by'})


class MetricTests(unittest.TestCase):
    def test_filtering_truth_and_average_ties(self):
        self.assertEqual(core.filtered_rank({'a':10.,'b':9.,'c':9.,'d':1.}, {'a','b'}, 'b'), 1.5)

    def test_macro_cve_mrr_not_edge_weighted(self):
        out=core.summarize_ranks([{'head':'c1','tail':'a','rank':1.}, {'head':'c1','tail':'b','rank':1.}, {'head':'c2','tail':'a','rank':4.}])
        self.assertEqual(out['mrr'], .625)
        self.assertEqual(out['hits@1'], .5)
        self.assertEqual(out['by_technique']['a']['queries'],2)

    def test_invalid_scores_fail_closed(self):
        with self.assertRaises(ValueError):
            core.filtered_rank({'a':float('nan')}, {'a'}, 'a')


if __name__ == '__main__':
    unittest.main()
