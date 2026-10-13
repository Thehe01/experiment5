import copy
import unittest
from chapter5.public_data.adapter import adapt, split_groups, training_view

def pattern(t, revoked=False):
    return {'type':'attack-pattern','id':'attack-pattern--'+t,'revoked':revoked,
            'external_references':[{'source_name':'mitre-attack','external_id':t}],
            'x_mitre_domains':['enterprise-attack'],'kill_chain_phases':[]}

def row(c='CVE-2020-1000', labels=None, **kw):
    out={'id':c,'title':'Example','description':'An example vulnerability.',
         'techniques':labels or ['T1190'],'exploitation_techniques':[],
         'primary_impact':[],'secondary_impact':[], 'cwes':['Elevation of Privilege','CWE-787 Out-of-bounds Write'],
         'cpes':['cpe:2.3:a:acme:server:1.2:*:*:*:*:*:*:*'],'affected_products':['acme server'],
         'cvss_vector':'','cvss_version':'','attack_version':'19.1','label_sources':['ctid_cve'],
         'public_split':'train','techniques_derived':['T1005'],'cwes_predicted':['CWE-79']}
    return dict(out,**kw)

def old_graph():
    return {'nodes':[],'edges':[],'exposed_cves':[],'techniques':['T1190','T1203'],
            'attack_version':'19.2'}

class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.bundle={'objects':[pattern('T1190'),pattern('T1203')]}

    def test_unclassified_gold_and_weak_fields(self):
        result=adapt([row()],self.bundle,old_graph())
        r=result['records'][0]
        self.assertEqual(r['unclassified_techniques'],['T1190'])
        self.assertEqual(r['techniques'],['T1190'])
        self.assertEqual(r['cwe_ids'],['CWE-787'])
        self.assertEqual(r['cpe_families'],['cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*'])
        self.assertNotIn('techniques_derived',r)
        self.assertNotIn('cwes_predicted',r)
        self.assertNotIn('exploited_by',{e['relation'] for e in result['graph']['edges']})
        self.assertTrue(any(e['relation']=='has_reported_cpe' for e in result['graph']['edges']))

    def test_overlap_union_is_not_summed(self):
        g=old_graph();g['nodes']=[{'id':'CVE-2020-1000','type':'Vulnerability'}]
        g['edges']=[{'head':'CVE-2020-1000','relation':'exploited_by','tail':'T1190'}]
        g['exposed_cves']=['CVE-2020-1000']
        result=adapt([row(),row('CVE-2020-1001')],self.bundle,g)
        self.assertEqual([r['id'] for r in result['records']],['CVE-2020-1001'])
        self.assertEqual(result['audit']['overlap']['excluded_union'],1)

    def test_stage_labels_outside_union_are_quarantined(self):
        result=adapt([row(primary_impact=['T1203']),row('CVE-2020-1001')],self.bundle,old_graph())
        self.assertEqual(len(result['quarantine']),1)
        self.assertEqual(result['quarantine'][0]['reason'],'stage_not_in_curated_union')

    def test_duplicate_cve_and_candidate_mismatch_fail(self):
        with self.assertRaisesRegex(ValueError,'duplicate CVE'):
            adapt([row(),row()],self.bundle,old_graph())
        g=old_graph();g['techniques']=['T1190']
        with self.assertRaisesRegex(ValueError,'candidate'):
            adapt([row()],self.bundle,g)

    def test_unknown_technique_is_quarantined(self):
        result=adapt([row(labels=['T9999']),row('CVE-2020-1001')],self.bundle,old_graph())
        self.assertEqual(result['quarantine'][0]['reason'],'inactive_or_unknown_technique')

    def test_invalid_metadata_does_not_become_background(self):
        result=adapt([row(cwes=['CWE-noinfo','Elevation of Privilege'],cpes=['invalid'])],self.bundle,old_graph())
        self.assertEqual(result['records'],[])
        self.assertEqual(len(result['no_context']),1)
        self.assertEqual(result['no_context'][0]['cwe_ids'],[])

    def test_unique_revocation_chain_keeps_provenance(self):
        b=copy.deepcopy(self.bundle)
        b['objects'] += [pattern('T1000',True),{'id':'relationship--a','type':'relationship','relationship_type':'revoked-by',
                           'source_ref':'attack-pattern--T1000','target_ref':'attack-pattern--T1190'}]
        r=adapt([row(labels=['T1000'],exploitation_techniques=['T1000'])],b,old_graph())['records'][0]
        self.assertEqual(r['techniques'],['T1190'])
        self.assertEqual(r['label_changes'],[{'from':'T1000','to':'T1190'}])

    def test_ambiguous_revocation_is_rejected(self):
        b=copy.deepcopy(self.bundle);b['objects'].append(pattern('T1000',True))
        b['objects'] += [{'id':'relationship--'+t,'type':'relationship','relationship_type':'revoked-by',
                         'source_ref':'attack-pattern--T1000','target_ref':'attack-pattern--'+t} for t in ['T1190','T1203']]
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            adapt([row(labels=['T1000'])],b,old_graph())

    def test_split_determinism_coverage_and_singleton(self):
        records=[{'id':f'CVE-2020-{1000+i}','techniques':['T1190']+(['T1203'] if i==0 else [])} for i in range(20)]
        s=split_groups(records)
        self.assertEqual(s,split_groups(list(reversed(records))))
        groups=[set(s[k]) for k in ['train','dev','reserved_holdout']]
        self.assertEqual(set.union(*groups),{r['id'] for r in records})
        self.assertFalse(groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2])
        self.assertIn('CVE-2020-1000',s['train'])
        self.assertEqual([len(g) for g in groups],[14,3,3])

    def test_held_forward_inverse_and_stage_edges_are_masked(self):
        s={'train':['CVE-2020-1000'],'dev':['CVE-2020-1001'],'reserved_holdout':['CVE-2020-1002']}
        graph={'edges':[{'head':'CVE-2020-1001','relation':'potentially_associated_with','tail':'T1190'},
                        {'head':'T1190','relation':'potentially_associated_with_inverse','tail':'CVE-2020-1002'},
                        {'head':'CVE-2020-1001','relation':'primary_impact','tail':'T1203'},
                        {'head':'CVE-2020-1001','relation':'has_reported_cwe','tail':'CWE-787'},
                        {'head':'CVE-2020-1000','relation':'potentially_associated_with','tail':'T1190'}]}
        edges=training_view(graph,s)
        self.assertEqual(len(edges),2)
        self.assertTrue(any(e['head']=='CVE-2020-1001' and e['relation']=='has_reported_cwe' for e in edges))

    def test_target_derived_background_fails(self):
        graph={'edges':[{'head':'CVE-2020-1000','relation':'has_reported_cwe','tail':'CWE-787','derived_from_target':True}]}
        with self.assertRaisesRegex(ValueError,'target-derived'):
            training_view(graph,{'train':['CVE-2020-1000'],'dev':[],'reserved_holdout':[]})

    def test_cyclic_revocation_is_rejected(self):
        b=copy.deepcopy(self.bundle)
        b['objects'] += [pattern('T1000',True),pattern('T1001',True)]
        b['objects'] += [{'id':'relationship--'+a,'type':'relationship','relationship_type':'revoked-by',
                         'source_ref':'attack-pattern--'+a,'target_ref':'attack-pattern--'+z}
                        for a,z in [('T1000','T1001'),('T1001','T1000')]]
        with self.assertRaisesRegex(ValueError,'cyclic'):
            adapt([row(labels=['T1000'])],b,old_graph())

    def test_invalid_identity_empty_label_and_empty_description(self):
        for changed in [{'id':['CVE-2020-1000']},{'techniques':[]},{'description':' '}]:
            result=adapt([row(**changed)],self.bundle,old_graph())
            self.assertEqual(len(result['quarantine']),1)
            self.assertEqual(result['records'],[])

    def test_overlap_split_and_observed_edge_fail(self):
        with self.assertRaisesRegex(ValueError,'group overlap'):
            training_view({'edges':[]},{'train':['CVE-2020-1000'],'dev':['CVE-2020-1000'],'reserved_holdout':[]})
        with self.assertRaisesRegex(ValueError,'observed exploited_by'):
            training_view({'edges':[{'head':'CVE-2020-1000','relation':'exploited_by','tail':'T1190'}]},
                          {'train':['CVE-2020-1000'],'dev':[],'reserved_holdout':[]})

if __name__=='__main__':
    unittest.main()
