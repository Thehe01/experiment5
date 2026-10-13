import tempfile
import unittest
from pathlib import Path
import torch
from chapter5 import model
from chapter5.core import RELATIONS


def toy_graph():
    nodes=[{'id':f'c{i}','type':'Vulnerability'} for i in range(40)]
    nodes += [{'id':n,'type':tp} for n,tp in [('p0','Configuration'),('p1','Configuration'),('w0','Weakness'),('w1','Weakness'),
               ('T1190','AttackTechnique'),('T1203','AttackTechnique'),('a0','AttackTactic'),('a1','AttackTactic'),('k0','KillChainPhase'),('k1','KillChainPhase')]]
    edges=[]
    for i in range(40):
        edges.extend([{'head':f'c{i}','relation':'affects','tail':f'p{i%2}'},
                      {'head':f'c{i}','relation':'instantiates','tail':f'w{i%2}'},
                      {'head':f'c{i}','relation':'exploited_by','tail':'T1190' if i%2==0 else 'T1203'}])
    edges += [{'head':'T1190','relation':'implies','tail':'a0'},{'head':'T1203','relation':'implies','tail':'a1'},
              {'head':'a0','relation':'belongs_to_phase','tail':'k0'},{'head':'a1','relation':'belongs_to_phase','tail':'k1'}]
    return {'nodes':nodes,'edges':edges,'techniques':['T1190','T1203'],
            'split':{'train':[f'c{i}' for i in range(30)],'dev':[f'c{i}' for i in range(30,35)],'test':[f'c{i}' for i in range(35,40)]}}


CFG={'layers':2,'bases':2,'threads':1,'negatives_per_positive':2,'auxiliary_weight':1.,'weight_decay':.00001,
     'max_epochs':6,'patience':30,'min_improvement':1e-8,'evaluation_interval_epochs':1}
PARAMS={'dimension':8,'learning_rate':.02,'dropout':.2}


class ModelTests(unittest.TestCase):
    def test_incoming_relation_mean_and_gradient(self):
        g=model.Graph(toy_graph());layer=model.RGCNLayer(2,1)
        with torch.no_grad():
            layer.bases.copy_(torch.eye(2).unsqueeze(0));layer.coefficients.zero_();layer.coefficients[0,0]=1.;layer.self_weight.zero_()
        x=torch.arange(len(g.names)*2,dtype=torch.float32).reshape(len(g.names),2).requires_grad_()
        out=layer(x,g.adjacency)
        source=[g.ids['c'+str(i)] for i in range(0,40,2)]
        self.assertTrue(torch.allclose(out[g.ids['p0']],x[source].mean(0)))
        self.assertTrue(torch.equal(out[g.ids['c0']],torch.zeros(2)))
        out[g.ids['p0']].sum().backward()
        self.assertTrue(torch.allclose(x.grad[source],torch.full((20,2),1/20)))
        self.assertGreater(float(layer.coefficients.grad[0,0]),0)

    def test_unassigned_prediction_cve_cannot_expand_target_training(self):
        graph=toy_graph()
        graph['nodes'].append({'id':'additional','type':'Vulnerability'})
        graph['edges'].append({'head':'additional','relation':'exploited_by','tail':'T1190'})
        g=model.Graph(graph)
        for head,relation,tail in g.positive.tolist():
            if relation==2:
                self.assertIn(g.names[head],graph['split']['train'])

    def test_negative_types_truth_and_held_head_boundary(self):
        g=model.Graph(toy_graph())
        neg=g.negative_samples(3)
        for h,r,t in neg.tolist():
            self.assertNotIn((h,r,t),g.known)
            if RELATIONS[r]=='exploited_by':
                self.assertIn(g.names[h],g.graph['split']['train'])
                self.assertEqual(g.node_types[t],3)

    def test_inverse_messages_cannot_recover_held_labels(self):
        g=model.Graph(toy_graph())
        for src,dst,relation in g.message_edges:
            if relation in (2,7):
                cve=g.names[src] if relation==2 else g.names[dst]
                self.assertNotIn(cve,g.graph['split']['dev']+g.graph['split']['test'])

    def test_every_learning_arm_trains_and_produces_finite_dev_metrics(self):
        with tempfile.TemporaryDirectory() as d:
            for arm in ('distmult','rgcn','rgcn_without_product','rgcn_without_cwe','rgcn_without_tactic_phase'):
                result=model.train(toy_graph(),arm,PARAMS,CFG,42,Path(d)/arm)
                self.assertTrue(0 < result['dev']['mrr'] <= 1)
                self.assertEqual(result['epoch'],6)
                self.assertTrue((Path(d)/arm/'checkpoint.pt').exists())

    def test_resume_is_identical_to_uninterrupted_training(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            a=model.train(toy_graph(),'rgcn',PARAMS,CFG,42,root/'full')
            partial=model.train(toy_graph(),'rgcn',PARAMS,CFG,42,root/'resumed',stop_after_epochs=3)
            self.assertEqual(partial['status'],'checkpointed')
            b=model.train(toy_graph(),'rgcn',PARAMS,CFG,42,root/'resumed')
            self.assertEqual(a['dev'],b['dev'])
            ca=torch.load(root/'full/checkpoint.pt',weights_only=False)
            cb=torch.load(root/'resumed/checkpoint.pt',weights_only=False)
            self.assertTrue(all(torch.equal(ca['model'][k],cb['model'][k]) for k in ca['model']))

    def test_changed_inputs_and_corrupt_checkpoint_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            model.train(toy_graph(),'rgcn',PARAMS,CFG,42,root,stop_after_epochs=2)
            changed=toy_graph();changed['split']['dev'],changed['split']['test']=changed['split']['test'],changed['split']['dev']
            with self.assertRaisesRegex(ValueError,'binding'):
                model.train(changed,'rgcn',PARAMS,CFG,42,root)
            (root/'checkpoint.pt').write_bytes(b'broken')
            with self.assertRaises(Exception):
                model.train(toy_graph(),'rgcn',PARAMS,CFG,42,root)


if __name__=='__main__':
    unittest.main()
