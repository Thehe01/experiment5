"""Synthetic-only numerical tests; never score registered CVEs."""
import os
import unittest
import torch
from chapter5.public_dev.model import PublicGraph, PublicPredictor
if os.environ.get('CONTEXT_POOL_RED')=='1':
    from .model_red import ContextPoolPredictor
else:
    from .model import ContextPoolPredictor


def fixture():
    nodes=[{'id':c,'type':t} for c,t in [('a','Vulnerability'),('b','Vulnerability'),('c','Vulnerability'),('d','Vulnerability'),('w1','Weakness'),('w2','Weakness'),('p1','Configuration'),('p2','Configuration'),('t1','AttackTechnique'),('t2','AttackTechnique'),('ta','AttackTactic'),('ta2','AttackTactic'),('phase','KillChainPhase'),('phase2','KillChainPhase')]]
    triples=[('a','has_reported_cwe','w1'),('a','has_reported_cwe','w2'),('a','has_reported_cpe','p1'),('a','has_reported_cpe','p2'),('b','has_reported_cwe','w1'),('c','has_reported_cpe','p1'),('a','potentially_associated_with','t1'),('b','potentially_associated_with','t2'),('c','potentially_associated_with','t1'),('t1','implies','ta'),('t2','implies','ta'),('ta','belongs_to_phase','phase')]
    graph={'nodes':nodes,'edges':[{'head':h,'relation':r,'tail':t} for h,r,t in triples],'split':{'train':['a','b'],'dev':['c']},'techniques':['t1','t2'],'reserved_ids':[]}
    pg=PublicGraph(graph,'mixed');cfg={'bases':4,'layers':2,'negatives_per_positive':10,'auxiliary_weight':1.}
    net=ContextPoolPredictor(pg,'distmult',{'dimension':2,'dropout':0.},cfg)
    x=torch.zeros(len(pg.names),2)
    for n,v in {'w1':[2.,0.],'w2':[4.,2.],'p1':[0.,2.],'p2':[2.,4.],'t1':[3.,1.],'t2':[-1.,2.]}.items():x[pg.ids[n]]=torch.tensor(v)
    with torch.no_grad():net.relation.weight.fill_(1.)
    return pg,net,x,cfg


class ModelTests(unittest.TestCase):
    def test_pool_channels_and_abstention(self):
        pg,net,x,_=fixture();q=net.queries(x)
        torch.testing.assert_close(q[pg.ids['a']],torch.tensor([2.,2.]))
        torch.testing.assert_close(q[pg.ids['b']],torch.tensor([2.,0.]))
        torch.testing.assert_close(q[pg.ids['c']],torch.tensor([0.,2.]))
        self.assertFalse(bool(net.context_valid[pg.ids['d']]))
        with self.assertRaises(ValueError):net.score(x,torch.tensor([[pg.ids['d'],2,pg.ids['t1']]]))

    def test_target_independence_and_aux_unchanged(self):
        pg,net,x,cfg=fixture();target=torch.tensor([[pg.ids['a'],2,pg.ids['t1']]])
        self.assertEqual(float(net.score(x,target)),8.)
        changed=x.clone();changed[pg.ids['a']]=torch.tensor([999.,-999.])
        torch.testing.assert_close(net.score(x,target),net.score(changed,target))
        aux=torch.tensor([[pg.ids['a'],1,pg.ids['w1']]])
        reference=PublicPredictor(pg,'distmult',{'dimension':2,'dropout':0.},cfg);reference.relation.weight.data.copy_(net.relation.weight.data)
        torch.testing.assert_close(net.score(changed,aux),reference.score(changed,aux))

    def test_target_gradients_use_context(self):
        pg,net,x,_=fixture();x.requires_grad_();net.score(x,torch.tensor([[pg.ids['a'],2,pg.ids['t1']]])).sum().backward()
        torch.testing.assert_close(x.grad[pg.ids['a']],torch.zeros(2))
        self.assertGreater(float(x.grad[pg.ids['w1']].abs().sum()),0.)
        self.assertGreater(float(x.grad[pg.ids['p1']].abs().sum()),0.)
        self.assertGreater(float(net.relation.weight.grad[2].abs().sum()),0.)

    def test_prediction_kernel_matches_training_score(self):
        pg,net,x,_=fixture();heads=['a','b','c'];q=net.queries(x);tails=x[pg.candidates];matrix=(q[torch.tensor([pg.ids[h] for h in heads])]*net.relation.weight[2])@tails.T
        for i,h in enumerate(heads):
            triples=torch.tensor([[pg.ids[h],2,int(t)] for t in pg.candidates])
            torch.testing.assert_close(matrix[i],net.score(x,triples))
        negatives=pg.negative_samples(10)
        self.assertTrue(set(negatives[negatives[:,1]==2,0].tolist())<={pg.ids['a'],pg.ids['b']})


if __name__=='__main__':unittest.main()
