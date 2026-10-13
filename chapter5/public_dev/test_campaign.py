import copy
import json
import unittest
from pathlib import Path
from chapter5.public_dev.campaign import promotion_gate, claim_unit

class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.cfg=json.loads((Path(__file__).parent/'config.json').read_text())
        self.baselines={str(f):{'mrr':.5,'major_macro_mrr':.5} for f in range(3)}
        self.results=[{'fold':f,'arm':'rgcn_mixed','seed':s,'dev':{'mrr':.52,'major_macro_mrr':.49}} for f in range(3) for s in range(3)]
    def test_gate_boundaries_and_negative_result(self):
        self.assertTrue(promotion_gate(self.results,self.baselines,self.cfg)['passed'])
        r=copy.deepcopy(self.results)
        for x in r:x['dev']['major_macro_mrr']=.489
        self.assertFalse(promotion_gate(r,self.baselines,self.cfg)['passed'])
        for x in r:x['dev'].update(mrr=.519,major_macro_mrr=.5)
        self.assertFalse(promotion_gate(r,self.baselines,self.cfg)['passed'])
        r=copy.deepcopy(self.results)
        for x in r[:4]:x['dev']['mrr']=.5
        for x in r[4:]:x['dev']['mrr']=.6
        self.assertFalse(promotion_gate(r,self.baselines,self.cfg)['passed'])
        with self.assertRaisesRegex(ValueError,'nine'):
            promotion_gate(r[:8],self.baselines,self.cfg)
    def test_unique_claim_budget_and_unknown_unit(self):
        ledger={'allowed':['a','b'],'units':{}}
        self.assertTrue(claim_unit(ledger,'a',2))
        self.assertFalse(claim_unit(ledger,'a',2))
        with self.assertRaisesRegex(ValueError,'unregistered'):
            claim_unit(ledger,'c',2)
        with self.assertRaisesRegex(ValueError,'budget'):
            claim_unit(ledger,'b',1)
        self.assertEqual(len(ledger['units']),1)

if __name__=='__main__':unittest.main()
