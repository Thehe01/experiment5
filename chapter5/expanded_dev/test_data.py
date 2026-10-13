import copy
import unittest
from chapter5.expanded_dev.data import project_base, make_fold, fixed_major, paired_summary
from chapter5.public_dev.core import baseline_scores, labels, evaluate_scores
from chapter5.public_dev.model import PublicGraph

TARGET='potentially_associated_with'
def toy():
    nodes=[{'id':c,'type':'Vulnerability'} for c in ['c0','c1','c2','c3','x']]
    nodes += [{'id':t,'type':'AttackTechnique'} for t in ['T1190','T1190.001','T1203','T9999']]
    nodes += [{'id':'w','type':'Weakness'},{'id':'p','type':'Configuration'},{'id':'a','type':'AttackTactic'},{'id':'k','type':'KillChainPhase'}]
    edges=[{'head':c,'relation':TARGET,'tail':t} for c,t in [('c0','T1190'),('c0','T1190.001'),('c1','T1203'),('c2','T1190'),('c3','T9999'),('x','T1190')]]
    edges += [{'head':c,'relation':'has_reported_cwe','tail':'w'} for c in ['c0','c1','c2','c3','x']]
    edges += [{'head':'T1190.001','relation':'implies','tail':'a'},{'head':'T1190','relation':'implies','tail':'a'},{'head':'a','relation':'belongs_to_phase','tail':'k'}]
    return {'nodes':nodes,'edges':edges,'techniques':['T1190','T1190.001','T1203','T9999']}

EXT=[{'id':'n','techniques':['T1203'],'cwe_ids':['w'],'cpe_families':['p'],'graph_ready':True}]
FOLD={'fold':0,'seed':1,'train':['c0','c1','c3'],'dev':['c2']}

class DataTests(unittest.TestCase):
    def test_parent_projection_deduplicates_and_removes_reserved(self):
        g=project_base(toy(),['x'],['T1190','T1203'])
        self.assertEqual(labels(g)['c0'],{'T1190'})
        self.assertEqual(sum(e['head']=='c0' and e['relation']==TARGET for e in g['edges']),1)
        self.assertNotIn('x',{n['id'] for n in g['nodes']})
        self.assertNotIn('T1190.001',{n['id'] for n in g['nodes']})
        self.assertNotIn('T9999',g['techniques'])
        self.assertEqual(sum(e['relation']=='implies' for e in g['edges']),1)

    def test_no_target_derived_context_allowed(self):
        g=toy();g['edges'][0]['derived_from_target']=True
        with self.assertRaises(ValueError):project_base(g,['x'],['T1190','T1203'])

    def test_paired_dev_and_targets_equal(self):
        base=project_base(toy(),['x'],['T1190','T1203'])
        a=make_fold(base,EXT,FOLD,'base',['x'],1);b=make_fold(base,EXT,FOLD,'augmented',['x'],1)
        self.assertEqual(a['split']['dev'],b['split']['dev'])
        self.assertEqual(labels(a)['c2'],labels(b)['c2'])
        self.assertEqual(a['techniques'],b['techniques'])
        self.assertEqual(a['fixed_major'],b['fixed_major'])
        self.assertEqual(a['split']['train'],['c0','c1']);self.assertEqual(b['split']['train'],['c0','c1','n'])
        self.assertEqual(a['coverage']['train_background_only'],['c3'])

    def test_partial_scope_not_fanned_out(self):
        base=project_base(toy(),['x'],['T1190','T1203']);e=copy.deepcopy(EXT);e[0]['techniques']=['T1203.001']
        with self.assertRaises(ValueError):make_fold(base,e,FOLD,'augmented',['x'])

    def test_rejected_and_duplicate_or_reserved_external_refused(self):
        base=project_base(toy(),['x'],['T1190','T1203'])
        for change in [{'graph_ready':False},{'id':'c0'},{'id':'x'}]:
            e=copy.deepcopy(EXT);e[0].update(change)
            with self.assertRaises(ValueError):make_fold(base,e,FOLD,'augmented',['x'])

    def test_message_graph_masks_dev_and_inverse(self):
        g=make_fold(project_base(toy(),['x'],['T1190','T1203']),EXT,FOLD,'augmented',['x'])
        pg=PublicGraph(g,'mixed');held=pg.ids['c2']
        self.assertFalse(any(r==2 and s==held or r==7 and d==held for s,d,r in pg.message_edges))
        self.assertNotIn('x',pg.ids)

    def test_fixed_macro_keeps_same_denominator(self):
        metric={'by_technique':{'T1190':{'mrr':.2},'T1203':{'mrr':.8}},'major_macro_mrr':.5,'major_eligible':['T1190','T1203']}
        result=fixed_major(metric,['T1190']);self.assertEqual(result['major_macro_mrr'],.2)
        self.assertEqual(result['major_eligible'],['T1190']);self.assertEqual(metric['major_macro_mrr'],.5)

    def test_added_train_changes_frequency_not_dev_labels(self):
        base=project_base(toy(),['x'],['T1190','T1203'])
        a=make_fold(base,EXT,FOLD,'base',['x']);b=make_fold(base,EXT,FOLD,'augmented',['x'])
        self.assertEqual(baseline_scores(a,'frequency')['c2']['T1203'],1)
        self.assertEqual(baseline_scores(b,'frequency')['c2']['T1203'],2)
        b['edges']=[dict(e,tail='T1203') if e['relation']==TARGET and e['head']=='c2' else e for e in b['edges']]
        self.assertEqual(baseline_scores(b,'frequency')['c2']['T1203'],2)

    def test_complete_pair_inventory_and_metric_delta(self):
        units=[{'id':f'{c}-{s}','condition':c,'arm':'rgcn_mixed','fold':0,'seed':s} for s in [1,2] for c in ['base','augmented']]
        results=[u|{'unit':u['id'],'status':'trained','dev':{'mrr':.2 if u['condition']=='base' else .3,'major_macro_mrr':.4}} for u in units]
        p=paired_summary(results,units);self.assertAlmostEqual(p['rgcn_mixed']['mean_delta_mrr'],.1);self.assertEqual(p['rgcn_mixed']['wins'],2)
        with self.assertRaises(ValueError):paired_summary(results[:-1],units)
        with self.assertRaises(ValueError):paired_summary(results+[results[0]],units)

    def test_unknown_condition_and_role_overlap(self):
        base=project_base(toy(),['x'],['T1190','T1203'])
        with self.assertRaises(ValueError):make_fold(base,EXT,FOLD,'wrong',['x'])
        f=copy.deepcopy(FOLD);f['train'].append('c2')
        with self.assertRaises(ValueError):make_fold(base,EXT,f,'base',['x'])

if __name__=='__main__':unittest.main()
