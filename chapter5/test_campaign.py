import copy
import tempfile
import unittest
from pathlib import Path
from chapter5 import campaign
from chapter5.test_model import toy_graph, CFG
from chapter5.io import read_json


class CampaignTests(unittest.TestCase):
    def test_frequency_counts_only_train_targets_and_cwe_uses_context(self):
        graph=toy_graph()
        # Deliberately unbalanced training labels; held labels must not change either baseline.
        for e in graph['edges']:
            if e['relation']=='exploited_by' and e['head'] in ('c1','c3'):
                e['tail']='T1190'
        global_scores=campaign.baseline_scores(graph,'frequency')
        cwe=campaign.baseline_scores(graph,'cwe_frequency')
        self.assertEqual(global_scores['c30']['T1190'],17)
        self.assertEqual(global_scores['c30']['T1203'],13)
        self.assertGreater(cwe['c30']['T1190'],cwe['c30']['T1203'])
        self.assertGreater(cwe['c31']['T1203'],cwe['c31']['T1190'])
        changed=copy.deepcopy(graph)
        for e in changed['edges']:
            if e['relation']=='exploited_by' and e['head'] in graph['split']['test']:
                e['tail']='T1190'
        self.assertEqual(cwe,campaign.baseline_scores(changed,'cwe_frequency'))

    def test_selection_is_frozen_before_test_and_completed_campaign_is_reused(self):
        cfg=dict(CFG,protocol='test',grid={'dimension':[8],'learning_rate':[.02],'dropout':[.2]},
                 tuning_seed=42,final_seeds=[43,44],learning_arms=['distmult','rgcn','rgcn_without_product','rgcn_without_cwe','rgcn_without_tactic_phase'])
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)
            out=campaign.run(toy_graph(),cfg,path)
            self.assertEqual(out['phase'],'evaluation_complete')
            self.assertEqual(len(out['test']),7)
            self.assertEqual(len(out['test']['rgcn']['seeds']),2)
            self.assertLess(read_json(path/'selection.json')['sequence'],out['sequence'])
            self.assertEqual(out,campaign.run(toy_graph(),cfg,path))


if __name__=='__main__':
    unittest.main()
