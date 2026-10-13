import copy
import unittest
from . import core


class CoreTests(unittest.TestCase):
    def test_contexts_and_unknown(self):
        graph = {'nodes': [{'id': c, 'type': t} for c, t in [('a','Vulnerability'),('b','Vulnerability'),('w','Weakness'),('p','Configuration')]], 'edges': [{'head':'a','relation':'has_reported_cwe','tail':'w'}, {'head':'a','relation':'has_reported_cpe','tail':'p'}]}
        ctx = core.context_index(graph)
        self.assertEqual(ctx['a'], {'cwe':['w'], 'cpe':['p']})
        self.assertEqual(ctx['b'], {'cwe':[], 'cpe':[]})
        bad = copy.deepcopy(graph); bad['edges'][0]['tail'] = 'unseen'
        with self.assertRaises(ValueError): core.context_index(bad)

    def test_budget_and_checkpoint_resume(self):
        ledger = {'budget':1, 'units': {'a': {'status':'planned'}, 'b': {'status':'planned'}}}
        self.assertTrue(core.claim(ledger,'a'))
        with self.assertRaises(ValueError): core.claim(ledger,'a')
        with self.assertRaises(ValueError): core.claim(ledger,'b')
        ledger['units']['a']['status']='checkpointed'
        self.assertFalse(core.claim(ledger,'a'))
        ledger['units']['a']['status']='UNKNOWN'
        with self.assertRaises(ValueError): core.claim(ledger,'a')
        ledger['units']['a']['status']='done'
        self.assertFalse(core.claim(ledger,'a'))

    def test_gate_exact_boundaries(self):
        gate={'mean_delta_mrr':0.02,'wins_of_nine':6,'major_macro_delta_min':-0.01}
        self.assertTrue(core.gate({'pair_count':9,'mean_delta_mrr':0.02,'wins':6,'mean_delta_major_macro':-0.01},gate))
        for key,value in [('mean_delta_mrr',0.019),('wins',5),('mean_delta_major_macro',-0.011)]:
            p={'pair_count':9,'mean_delta_mrr':0.02,'wins':6,'mean_delta_major_macro':-0.01};p[key]=value
            self.assertFalse(core.gate(p,gate))
        with self.assertRaises(ValueError): core.gate({'pair_count':8},gate)

    def test_abstention_complete_denominator(self):
        metrics=core.penalize_abstentions({'queries':1,'mrr':0.5,'hits@1':0.,'hits@3':1.,'hits@10':1.},2)
        self.assertEqual(metrics['queries'],2)
        self.assertEqual(metrics['mrr'],0.25)
        self.assertEqual(metrics['hits@3'],0.5)
        self.assertEqual(metrics['coverage'],0.5)


if __name__=='__main__':unittest.main()
