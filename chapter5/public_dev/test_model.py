import copy
import json
import tempfile
import unittest
from pathlib import Path
import torch
from chapter5.public_dev.core import fold_graph, TARGET
from chapter5.public_dev.test_core import toy_graph
from chapter5.public_dev.model import PublicGraph, train

class ModelTests(unittest.TestCase):
    def setUp(self):
        g=toy_graph();self.g=fold_graph(g,g['split'],g['split']['reserved_holdout'])
        self.cfg=json.loads((Path(__file__).parent/'config.json').read_text())
        self.cfg.update(max_epochs=3,patience=30)
        self.cfg['params']=dict(dimension=8,learning_rate=.003,dropout=.3)

    def test_mixed_allocation_legal_heads_and_message_mask(self):
        g=PublicGraph(self.g,'mixed');torch.manual_seed(71)
        neg=g.negative_samples(10)
        self.assertFalse(any(tuple(v) in g.known for v in neg.tolist()))
        self.assertEqual(g.last_sampling_stats['target_full'],150)
        self.assertEqual(g.last_sampling_stats['target_seen'],150)
        self.assertEqual(g.last_sampling_stats['target_seen_fallback'],0)
        target=neg[neg[:,1]==2]
        self.assertTrue(set(target[:,0].tolist())<=set(g.ids[c] for c in self.g['split']['train']))
        held={g.ids[c] for c in self.g['split']['dev']+self.g['reserved_ids']}
        self.assertFalse(any(r==2 and s in held or r==7 and d in held for s,d,r in g.message_edges))
        for h,r,t in target.tolist():
            self.assertNotIn(t,g.truth_ids[h])

    def test_hard_empty_fallback_and_full_empty_failure(self):
        g=copy.deepcopy(self.g)
        g['edges']=[dict(e,tail='T1190') if e['relation']==TARGET else e for e in g['edges']]
        pg=PublicGraph(g,'mixed');pg.negative_samples(10)
        self.assertEqual(pg.last_sampling_stats['target_seen_fallback'],150)
        pg.pools[3]=torch.tensor([pg.ids['T1190']])
        with self.assertRaisesRegex(ValueError,'no legal target'):
            pg.negative_samples(10)

    def test_four_arms_train_and_completed_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            for arm in self.cfg['arms']:
                d=Path(tmp)/arm
                r=train(self.g,arm,self.cfg,72,d)
                self.assertEqual(r['status'],'trained');self.assertEqual(r['epoch'],3)
                self.assertTrue(0<r['dev']['mrr']<=1)
                rows=json.loads((d/'ranks.json').read_text())
                self.assertEqual(len(rows),5)
                self.assertEqual(train(self.g,arm,self.cfg,72,d),r)
                (d/'ranks.json').write_text('[]')
                with self.assertRaisesRegex(ValueError,'completed'):
                    train(self.g,arm,self.cfg,72,d)

    def test_exact_resume_and_missing_binding_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,b=Path(tmp)/'a',Path(tmp)/'b'
            full=train(self.g,'rgcn_mixed',self.cfg,73,a)
            first=train(self.g,'rgcn_mixed',self.cfg,73,b,stop_after_epochs=1)
            self.assertEqual(first['status'],'checkpointed')
            resumed=train(self.g,'rgcn_mixed',self.cfg,73,b)
            self.assertEqual(full,resumed)
            sa=torch.load(a/'checkpoint.pt',weights_only=False)
            sb=torch.load(b/'checkpoint.pt',weights_only=False)
            for k in sa['model']:
                self.assertTrue(torch.equal(sa['model'][k],sb['model'][k]),k)
            c=Path(tmp)/'c';train(self.g,'distmult_uniform',self.cfg,74,c,stop_after_epochs=1)
            (c/'checkpoint.pt').unlink()
            with self.assertRaisesRegex(ValueError,'missing checkpoint'):
                train(self.g,'distmult_uniform',self.cfg,74,c)
            changed=copy.deepcopy(self.cfg);changed['params']['dropout']=.2
            with self.assertRaisesRegex(ValueError,'binding mismatch'):
                train(self.g,'rgcn_mixed',changed,73,b)

    def test_early_stop_and_corrupt_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=copy.deepcopy(self.cfg);cfg.update(patience=1,min_improvement=2.)
            r=train(self.g,'distmult_uniform',cfg,75,tmp)
            self.assertEqual(r['epoch'],2);self.assertEqual(r['stopping_reason'],'patience')
            p=Path(tmp)/'checkpoint.pt';p.write_bytes(p.read_bytes()+b'bad')
            with self.assertRaisesRegex(ValueError,'checkpoint'):
                train(self.g,'distmult_uniform',cfg,75,tmp)

    def test_auxiliary_full_domain_is_not_silently_skipped(self):
        g=copy.deepcopy(self.g)
        g['edges']=[e for e in g['edges'] if e['relation']!='belongs_to_phase']
        g['edges'] += [{'head':a,'relation':'belongs_to_phase','tail':k} for a in ['a0','a1'] for k in ['k0','k1']]
        pg=PublicGraph(g,'uniform')
        with self.assertRaisesRegex(ValueError,'no legal typed auxiliary'):
            pg.negative_samples(10)

if __name__=='__main__':unittest.main()
