import unittest
from chapter5.core import training_edges
from chapter5.supplement import prediction_overlay
from chapter5.test_model import toy_graph


class SupplementTests(unittest.TestCase):
    def test_real_prediction_layer_is_separate_and_held_prediction_is_removed(self):
        graph=toy_graph()
        for e in graph['edges']:
            e['provenance']=[{'layer':'c4_frozen_gold'}] if e['relation']=='affects' else [{'layer':'official_mapping'}]
        # Fixture IDs use real canonical forms only for the separately admitted prediction.
        head='CVE-2025-12345';graph['nodes'].append({'id':head,'type':'Vulnerability'})
        graph['split']['test'].append(head)
        graph['edges'].append({'head':head,'relation':'exploited_by','tail':'T1190','provenance':[{'layer':'official_procedure'}]})
        predictions={'doc':{'entities':[{'id':'e1','type':'Vulnerability','normalized_id':head},
                                        {'id':'e2','type':'AttackTechnique','normalized_id':'T1203'}],
                            'relations':[{'head':'e1','tail':'e2','type':'exploited_by','evidence':'predicted'}]}}
        result,report=prediction_overlay(graph,predictions,'source')
        self.assertFalse(any(e['relation']=='affects' for e in result['edges']))
        self.assertTrue(any(e['tail']=='T1203' and e['head']==head for e in result['edges']))
        self.assertFalse(any(e['relation']=='exploited_by' and e['head']==head for e in training_edges(result['edges'],result['split'])))
        self.assertEqual({e['tail'] for e in result['evaluation_targets'] if e['head']==head},{'T1190'})
        self.assertEqual(report['covered_target_cves']['test'],1)
        self.assertEqual(len(graph['edges']),125)


if __name__=='__main__':
    unittest.main()
