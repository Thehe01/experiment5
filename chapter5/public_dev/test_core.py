import copy
import unittest
from chapter5.public_dev import core
from chapter5.test_model import toy_graph as old_toy


def toy_graph():
    g=old_toy();rename={'affects':'has_reported_cpe','instantiates':'has_reported_cwe','exploited_by':'potentially_associated_with'}
    g['edges']=[dict(e,relation=rename.get(e['relation'],e['relation'])) for e in g['edges']]
    g['nodes'].append({'id':'T9999','type':'AttackTechnique'});g['techniques'].append('T9999')
    g['split']['reserved_holdout']=g['split'].pop('test')
    return g


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.g=toy_graph();self.reserved=self.g['split']['reserved_holdout']
        self.fg=core.fold_graph(self.g,self.g['split'],self.reserved)

    def test_fold_mask_and_reserved_scoring_fail(self):
        self.assertFalse(any(e['relation']=='potentially_associated_with' and e['head'] in self.reserved for e in self.fg['edges']))
        scores=core.baseline_scores(self.fg,'frequency')
        with self.assertRaisesRegex(ValueError,'Dev only'):
            core.evaluate_scores(self.fg,scores,'reserved_holdout')
        self.assertNotIn(self.reserved[0],scores)

    def test_frequency_cwe_smoothing_and_multilabel_denominator(self):
        g=copy.deepcopy(self.fg)
        g['edges'].append({'head':'c0','relation':'potentially_associated_with','tail':'T1203'})
        freq=core.baseline_scores(g,'frequency')
        self.assertEqual(freq['c30']['T1190'],15)
        self.assertEqual(freq['c30']['T1203'],16)
        plain=core.baseline_scores(g,'cwe_frequency')
        self.assertEqual(plain['c30']['T1203'],1)
        smooth=core.baseline_scores(g,'smoothed_cwe',alpha=1)
        self.assertAlmostEqual(smooth['c30']['T1190'],(15+15/30)/16)
        self.assertAlmostEqual(smooth['c30']['T1203'],(1+16/30)/16)

    def test_neighbor_vote_and_no_context_fallback(self):
        scores=core.baseline_scores(self.fg,'neighbor_vote')
        self.assertEqual(scores['c30']['T1190'],1)
        self.assertEqual(scores['c30']['T1203'],0)
        g=copy.deepcopy(self.fg)
        g['edges']=[e for e in g['edges'] if not(e['head']=='c30' and e['relation'] in ['has_reported_cpe','has_reported_cwe'])]
        for kind in ['smoothed_cwe','neighbor_vote']:
            s=core.baseline_scores(g,kind)
            self.assertEqual(s['c30']['T1190'],.5)

    def test_dev_labels_do_not_change_training_scores(self):
        g=copy.deepcopy(self.fg)
        for e in g['edges']:
            if e['relation']=='potentially_associated_with' and e['head'] in g['split']['dev']:
                e['tail']='T9999'
        for kind in ['frequency','cwe_frequency','smoothed_cwe','neighbor_vote']:
            self.assertEqual(core.baseline_scores(g,kind),core.baseline_scores(self.fg,kind))

    def test_metrics_ties_and_cve_macro(self):
        scores={c:{t:1. for t in self.g['techniques']} for c in self.g['split']['dev']}
        metrics,rows=core.evaluate_scores(self.fg,scores,major_support=1)
        self.assertEqual(metrics['mrr'],.5)
        self.assertTrue(all(r['rank']==2. for r in rows))
        self.assertEqual(metrics['queries'],5)

    def test_three_repeated_group_folds_cover_and_keep_train_support(self):
        fs=core.folds(self.g,self.g['split'],[11,12,13])
        self.assertEqual(fs,core.folds(self.g,self.g['split'],[11,12,13]))
        for s in fs:
            self.assertEqual(len(s['train']),30);self.assertEqual(len(s['dev']),5)
            self.assertFalse(set(s['dev'])&set(self.reserved))
            self.assertFalse(set(s['train'])&set(s['dev']))

    def test_target_derived_context_is_rejected(self):
        g=copy.deepcopy(self.g);g['edges'][0]['derived_from_target']=True
        with self.assertRaisesRegex(ValueError,'target-derived'):
            core.fold_graph(g,g['split'],self.reserved)

    def test_inverse_mask_and_candidate_domain(self):
        g=copy.deepcopy(self.g)
        g['edges'].append({'head':'T1190','relation':core.TARGET+'_inverse','tail':'c30'})
        fg=core.fold_graph(g,g['split'],self.reserved)
        self.assertFalse(any(e['relation'].endswith('_inverse') for e in fg['edges']))
        scores=core.baseline_scores(fg,'frequency');scores['c30'].pop('T9999')
        with self.assertRaisesRegex(ValueError,'candidate domain'):
            core.evaluate_scores(fg,scores)

if __name__=='__main__':
    unittest.main()
