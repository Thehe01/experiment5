import unittest
import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from chapter5.expanded_dev.campaign import claim_unit, expected_units, data_gate

class CampaignTests(unittest.TestCase):
    def test_inventory_pairs36_and_no_other_arms(self):
        cfg={'arms':['distmult_mixed','rgcn_mixed'],'development_seeds':[1,2,3],'conditions':['base','augmented'],'training_unit_budget':36}
        units=expected_units(cfg)
        self.assertEqual(len(units),36);self.assertEqual(len({u['id'] for u in units}),36)
        self.assertEqual(sum(u['condition']=='augmented' for u in units),18)

    def test_unknown_unit_budget_and_reuse(self):
        ledger={'allowed':['a','b'],'units':{}}
        self.assertTrue(claim_unit(ledger,'a',1));self.assertFalse(claim_unit(ledger,'a',1))
        with self.assertRaises(ValueError):claim_unit(ledger,'b',1)
        with self.assertRaises(ValueError):claim_unit(ledger,'z',1)

    def test_data_effect_gate_boundary(self):
        cfg={'gate':{'mean_delta_mrr':.02,'wins_of_nine':6,'major_macro_delta_min':-.01}}
        p={'rgcn_mixed':{'pair_count':9,'mean_delta_mrr':.02,'wins':6,'mean_delta_major_macro':-.01}}
        self.assertTrue(data_gate(p,cfg)['passed'])
        p['rgcn_mixed']['wins']=5;self.assertFalse(data_gate(p,cfg)['passed'])
        p['rgcn_mixed']['pair_count']=8
        with self.assertRaises(ValueError):data_gate(p,cfg)

    def test_synthetic_campaign_checkpoint_resume_and_all_paired_outputs(self):
        from chapter5.expanded_dev import campaign
        from chapter5.expanded_dev.data import project_base,make_fold
        from chapter5.public_dev.test_core import toy_graph
        from chapter5.public_dev.model import train as numerical_train
        g=toy_graph();reserved=g['split']['reserved_holdout']
        base=project_base(g,reserved,g['techniques'])
        ext=[{'id':'c100','techniques':['T1203'],'cwe_ids':['w0'],'cpe_families':['p0'],'graph_ready':True}]
        graphs={}
        for f in range(3):
            fold={'fold':f,'train':g['split']['train'],'dev':g['split']['dev']}
            for condition in ['base','augmented']:graphs[(condition,f)]=make_fold(base,ext,fold,condition,reserved)
        cfg=json.loads((Path(__file__).parent/'config.json').read_text())
        cfg.update(max_epochs=2,patience=30,development_seeds=[1,2,3])
        cfg['params']=dict(dimension=8,learning_rate=.003,dropout=.3)
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);root=tmp/'config';root.mkdir();state=tmp/'state'
            (root/'config.json').write_text(json.dumps(cfg))
            (root/'registration.json').write_text(json.dumps({'units':expected_units(cfg)}))
            with patch.object(campaign,'ROOT',root), \
                 patch.object(campaign,'verify_registration',return_value={'registration_sha256':'synthetic_test_only'}), \
                 patch.object(campaign,'load_inputs',return_value=(graphs,{'dev_overlap':{}},{})):
                def pause(*args,**kwargs):return numerical_train(*args,**kwargs,stop_after_epochs=1)
                with patch.object(campaign,'train',side_effect=pause):first=campaign.run(tmp,state,14400)
                self.assertEqual(first['phase'],'continuation_needed');self.assertEqual(first['reserved_units'],1)
                final=campaign.run(tmp,state,14400)
                self.assertEqual(final['phase'],'development_complete');self.assertEqual(final['completed_units'],36)
                result=json.loads((state/'comparison.json').read_text())
                self.assertEqual(result['paired_data_effect']['rgcn_mixed']['pair_count'],9)
                self.assertEqual(result['paired_data_effect']['distmult_mixed']['pair_count'],9)
                self.assertFalse(final['reserved_holdout_evaluated'])
                again=campaign.run(tmp,state,14400);self.assertEqual(again,final)

if __name__=='__main__':unittest.main()
