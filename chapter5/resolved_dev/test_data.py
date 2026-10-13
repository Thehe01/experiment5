import copy
import unittest
from chapter5.resolved_dev.data import admitted_views, make_fold

def fixture():
    nodes=[{'id':c,'type':'Vulnerability'} for c in ['c1','c2','c3']]
    nodes += [{'id':'T1203','type':'AttackTechnique'},{'id':'CWE-1','type':'Weakness'},{'id':'p1','type':'Configuration'}]
    edges=[{'head':c,'relation':'has_reported_cwe','tail':'CWE-1'} for c in ['c1','c2','c3']]
    edges += [{'head':c,'relation':'potentially_associated_with','tail':'T1203'} for c in ['c1','c2']]
    base={'nodes':nodes,'edges':edges,'techniques':['T1203']}
    def row(c,role,ts,cwe=['CWE-1']):
        return {'id':c,'role':role,'techniques':ts,'cwe_ids':cwe,'cpe_families':[],
                'candidate_domain':['T1203'],'unknown_labels':[],
                'admission_status':'USABLE_KNOWN_DISPUTES_EXCLUDED','independent_human_iaa':False}
    rows=[row('c1','original_development_pool',['T1203']),row('c3','original_development_pool',[]),
          row('c4','external_train_only',['T1203'],['CWE-2'])]
    groups={'reserved_ids':['r1'],'folds':[{'fold':0,'seed':42,'train':['c1','c3'],'dev':['c2']}]}
    preview={'folds':[{'fold':0,'source_split_seed':42,'train':['c1','c3','c4'],'dev':[],
                       'supervised_train':['c1','c4'],'scored_dev':[]}]}
    return base,rows,groups,preview

class AdmissionTests(unittest.TestCase):
    def test_whole_cve_quarantine_nodes_and_all_edges(self):
        b,e,g=admitted_views(*fixture())
        self.assertNotIn('c2',{n['id'] for n in b['nodes']})
        self.assertFalse(any(x['head']=='c2' or x['tail']=='c2' for x in b['edges']))
        self.assertEqual(g['folds'][0]['dev'],[])
        self.assertEqual(g['folds'][0]['train'],['c1','c3'])
    def test_external_selected_cwe_preserved_and_train_only(self):
        b,e,g=admitted_views(*fixture())
        self.assertEqual([x['id'] for x in e],['c4'])
        self.assertEqual(e[0]['cwe_ids'],['CWE-2'])
        self.assertTrue(e[0]['graph_ready'])
        self.assertNotIn('c4',{n['id'] for n in b['nodes']})
    def test_unknown_cannot_be_admitted(self):
        f=fixture();f[1][0]['unknown_labels']=['T1005']
        with self.assertRaisesRegex(ValueError,'UNKNOWN'):admitted_views(*f)
    def test_duplicate_id_rejected(self):
        f=fixture();f[1].append(copy.deepcopy(f[1][0]))
        with self.assertRaisesRegex(ValueError,'duplicate'):admitted_views(*f)
    def test_reserved_id_rejected(self):
        f=fixture();f[1][2]['id']='r1'
        with self.assertRaisesRegex(ValueError,'reserved'):admitted_views(*f)
    def test_original_label_or_context_mutation_rejected(self):
        for key,value in [('techniques',[]),('cwe_ids',['CWE-2'])]:
            f=fixture();f[1][0][key]=value
            with self.assertRaisesRegex(ValueError,'original.*changed'):admitted_views(*f)
    def test_external_must_not_become_dev(self):
        f=fixture();f[3]['folds'][0]['dev']=['c4']
        with self.assertRaisesRegex(ValueError,'preview'):admitted_views(*f)
    def test_label_outside_scope_rejected(self):
        f=fixture();f[1][2]['techniques']=['T1005']
        with self.assertRaisesRegex(ValueError,'scope'):admitted_views(*f)
    def test_admission_status_and_role_rejected(self):
        for key,value in [('role','human_gold'),('admission_status','QUARANTINED_UNKNOWN_CVE')]:
            f=fixture();f[1][0][key]=value
            with self.assertRaises(ValueError):admitted_views(*f)

if __name__=='__main__':unittest.main()
