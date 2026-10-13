"""Public graph reader and fail-closed CPU training, independent of v1 labels."""
import collections
import copy
import random
import time
from pathlib import Path
import torch
from torch.nn import functional as F
from chapter5.core import TYPES, digest, filtered_rank, summarize_ranks
from chapter5.io import atomic_json, append_event, read_json, sha_file
from chapter5.model import Predictor, binding as numerical_binding, save_checkpoint, load_state, scores_by_head
from chapter5.public_dev.core import RELATIONS, TARGET, labels, evaluate_scores


def code_binding():
    root = Path(__file__).parent
    return {p.name:sha_file(p) for p in sorted(root.glob('*.py')) if not p.name.startswith('test_')}


class PublicGraph:
    def __init__(self, graph, strategy='uniform'):
        if strategy not in ('uniform','mixed'):
            raise ValueError('unregistered sampling strategy')
        self.graph, self.strategy = graph, strategy
        ordered = sorted(graph['nodes'],key=lambda n:n['id'])
        self.names = [n['id'] for n in ordered]; self.ids = {n:i for i,n in enumerate(self.names)}
        if len(self.ids)!=len(self.names):raise ValueError('duplicate node')
        self.node_types = [TYPES.index(n['type']) for n in ordered]
        self.pools = {tp:torch.tensor([i for i,v in enumerate(self.node_types) if v==tp],dtype=torch.long) for tp in range(6)}
        endpoints = [(0,1),(0,2),(0,3),(3,4),(4,5)]
        self.known = set(); self.truth = labels(graph)
        self.truth_ids = {self.ids[h]:{self.ids[t] for t in ts} for h,ts in self.truth.items()}
        triples = set(); train = set(graph['split']['train'])
        if (train|set(graph['split']['dev'])) & set(graph.get('reserved_ids', [])):
            raise ValueError('reserved role in development graph')
        for e in graph['edges']:
            if e.get('derived_from_target') or any(p.get('derived_from_target') for p in e.get('provenance',[])):
                raise ValueError('target-derived context')
            r = RELATIONS.index(e['relation']);h,t=self.ids[e['head']],self.ids[e['tail']]
            if (self.node_types[h],self.node_types[t])!=endpoints[r]:raise ValueError('endpoint types')
            if r==2 and e['head'] in graph.get('reserved_ids',[]):raise ValueError('reserved target present')
            self.known.add((h,r,t))
            if r!=2 or e['head'] in train:triples.add((h,r,t))
        self.positive=torch.tensor(sorted(triples),dtype=torch.long)
        if not any(r==2 for h,r,t in triples):raise ValueError('no training target')
        self.by_relation={r:self.positive[self.positive[:,1]==r] for r in range(5)}
        self.message_edges=[(h,t,r) for h,r,t in sorted(triples)]+[(t,h,r+5) for h,r,t in sorted(triples)]
        self.adjacency=[]
        for r in range(10):
            pairs=[(s,d) for s,d,k in self.message_edges if k==r]
            src=torch.tensor([s for s,d in pairs],dtype=torch.long);dst=torch.tensor([d for s,d in pairs],dtype=torch.long)
            degree=torch.bincount(dst,minlength=len(self.names)).clamp_min(1)
            self.adjacency.append((src,dst,(1./degree[dst].float()).unsqueeze(1)))
        self.candidate_names=sorted(graph['techniques'])
        self.candidates=torch.tensor([self.ids[t] for t in self.candidate_names],dtype=torch.long)
        if len(set(self.candidate_names))!=len(self.candidate_names) or set(self.candidates.tolist())!=set(self.pools[3].tolist()):
            raise ValueError('candidate node domain mismatch')
        self.seen=torch.tensor(sorted({t for h,r,t in triples if r==2}),dtype=torch.long)
        self.target_positives=self.by_relation[2].tolist()
        self.known_keys=torch.tensor(sorted({h*len(self.names)*5+r*len(self.names)+t for h,r,t in self.known}),dtype=torch.long)
        self.last_sampling_stats={}
        self._target_pool_binding=None;self._target_legal={}

    def _known(self, triples):
        keys=triples[:,0]*len(self.names)*5+triples[:,1]*len(self.names)+triples[:,2]
        ix=torch.searchsorted(self.known_keys,keys)
        return (ix<len(self.known_keys)) & (self.known_keys[ix.clamp(max=len(self.known_keys)-1)]==keys)

    def negative_samples(self, count):
        if count<=0 or self.strategy=='mixed' and count%2:raise ValueError('invalid negative allocation')
        out=[];stats={'target_full':0,'target_seen':0,'target_seen_fallback':0,'auxiliary_fallback':0}
        pool_binding=tuple(self.pools[3].tolist())
        if pool_binding!=self._target_pool_binding:
            self._target_legal={};self._target_pool_binding=pool_binding
        legal_cache=self._target_legal
        for h,r,t in self.target_positives:
            if h not in legal_cache:
                full=torch.tensor([int(x) for x in self.pools[3] if int(x) not in self.truth_ids[h]],dtype=torch.long)
                seen=torch.tensor([int(x) for x in self.seen if int(x) not in self.truth_ids[h]],dtype=torch.long)
                if not len(full):raise ValueError('no legal target negative')
                legal_cache[h]=(full,seen)
            full,seen=legal_cache[h]
            nfull=count if self.strategy=='uniform' else count//2
            chosen=[full[torch.randint(len(full),(nfull,))]];stats['target_full']+=nfull
            if self.strategy=='mixed':
                stats['target_seen']+=count//2
                if not len(seen):seen=full;stats['target_seen_fallback']+=count//2
                chosen.append(seen[torch.randint(len(seen),(count//2,))])
            tails=torch.cat(chosen);out.append(torch.stack((torch.full_like(tails,h),torch.full_like(tails,2),tails),1))
        # Batched rejection has the same endpoint-coin/type-uniform distribution as v1.
        # Each slot gets at most 100 independent attempts, then the same legal-union fallback.
        for r,(a,b) in enumerate(((0,1),(0,2),(0,3),(3,4),(4,5))):
            if r==2 or not len(self.by_relation[r]):continue
            base=self.by_relation[r].repeat_interleave(count,0);neg=base.clone();pending=torch.arange(len(base))
            for _ in range(100):
                if not len(pending):break
                draw=base[pending].clone();coin=torch.randint(2,(len(pending),)).bool()
                draw[coin,0]=self.pools[a][torch.randint(len(self.pools[a]),(int(coin.sum()),))]
                draw[~coin,2]=self.pools[b][torch.randint(len(self.pools[b]),(int((~coin).sum()),))]
                valid=~self._known(draw);neg[pending[valid]]=draw[valid];pending=pending[~valid]
            for ix in pending.tolist():
                h,_,t=base[ix].tolist()
                legal=[(h,r,int(x)) for x in self.pools[b] if (h,r,int(x)) not in self.known]
                legal += [(int(x),r,t) for x in self.pools[a] if (int(x),r,t) not in self.known]
                if not legal:raise ValueError('no legal typed auxiliary negative')
                neg[ix]=torch.tensor(legal[torch.randint(len(legal),()).item()]);stats['auxiliary_fallback']+=1
            out.append(neg)
        self.last_sampling_stats=stats
        return torch.cat(out)


class PublicPredictor(Predictor):
    def objective(self, graph, cfg):
        x=self.encode(graph);neg=graph.negative_samples(cfg['negatives_per_positive']);loss=x.sum()*0;parts={}
        for r,name in enumerate(RELATIONS):
            pos=graph.by_relation[r]
            if not len(pos):continue
            n=neg[neg[:,1]==r]
            value=.5*(F.softplus(-self.score(x,pos)).mean()+F.softplus(self.score(x,n)).mean())
            parts[name]=float(value.detach());loss=loss+value*(1. if r==2 else cfg['auxiliary_weight']/4.)
        return loss,parts


def dev_scores(net, graph):
    heads=graph.graph['split']['dev']
    if set(heads)&set(graph.graph.get('reserved_ids',[])):raise ValueError('Dev only')
    return scores_by_head(net,graph,heads)


def binding(graph,arm,cfg,seed):
    return digest({'numerical':numerical_binding(graph,arm,cfg['params'],cfg,seed),'public_code':code_binding()})


def train(graph, arm, cfg, seed, directory, stop_after_epochs=None, deadline=None):
    if arm not in cfg['arms']:raise ValueError('unregistered arm')
    encoder,strategy=arm.split('_');directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    signature=binding(graph,arm,cfg,seed)
    checkpoint=directory/'checkpoint.pt';reservation=directory/'reservation.json'
    final=directory/'result.json';receipt=directory/'completed.json'
    torch.set_num_threads(cfg['threads']);torch.use_deterministic_algorithms(True)
    random.seed(seed);torch.manual_seed(seed)
    g=PublicGraph(graph,strategy);net=PublicPredictor(g,encoder,cfg['params'],cfg)
    optimizer=torch.optim.Adam(net.parameters(),lr=cfg['params']['learning_rate'],weight_decay=cfg['weight_decay'])
    if reservation.exists():
        if read_json(reservation)['binding']!=signature:raise ValueError('reservation binding mismatch')
        if not checkpoint.exists():raise ValueError('reserved unit missing checkpoint; refuse reset')
        state=load_state(checkpoint,signature);net.load_state_dict(state['model']);optimizer.load_state_dict(state['optimizer'])
        random.setstate(state['python_rng']);torch.set_rng_state(state['torch_rng'])
    else:
        if any(directory.iterdir()):raise ValueError('unreserved existing state')
        atomic_json(reservation,{'binding':signature,'arm':arm,'seed':seed,'status':'reserved'})
        state={'binding':signature,'epoch':0,'patience_count':0,'best_score':-1.,'best_model':None,'best_dev':None}
        state.update(model=net.state_dict(),optimizer=optimizer.state_dict(),python_rng=random.getstate(),torch_rng=torch.get_rng_state())
        save_checkpoint(checkpoint,state)
    if final.exists() or receipt.exists():
        if not receipt.exists():raise ValueError('completed result missing receipt')
        info=read_json(receipt)
        if info['binding']!=signature or any(not (directory/n).exists() or sha_file(directory/n)!=h for n,h in info['files'].items()):
            raise ValueError('completed outputs hash/binding mismatch')
        result=read_json(final)
        if result['binding']!=signature or result['epoch']!=state['epoch']:raise ValueError('completed epoch mismatch')
        return result
    while state['epoch']<cfg['max_epochs'] and state['patience_count']<cfg['patience']:
        if deadline is not None and time.monotonic()>=deadline:
            return {'status':'checkpointed','epoch':state['epoch'],'binding':signature}
        net.train();optimizer.zero_grad(set_to_none=True);loss,parts=net.objective(g,cfg)
        if not torch.isfinite(loss):raise ValueError('nonfinite loss')
        loss.backward()
        if any(p.grad is not None and not torch.isfinite(p.grad).all() for p in net.parameters()):raise ValueError('nonfinite gradient')
        optimizer.step();state['epoch']+=1
        scores=dev_scores(net,g)
        ranks=[{'head':h,'tail':t,'rank':filtered_rank(scores[h],g.truth[h],t)} for h in sorted(scores) for t in sorted(g.truth[h])]
        metrics=summarize_ranks(ranks)
        if state['best_model'] is None or metrics['mrr']>state['best_score']+cfg['min_improvement']:
            state.update(best_score=metrics['mrr'],best_dev=metrics,best_model=copy.deepcopy(net.state_dict()),patience_count=0,best_epoch=state['epoch'])
        else:state['patience_count']+=1
        state.update(model=net.state_dict(),optimizer=optimizer.state_dict(),python_rng=random.getstate(),torch_rng=torch.get_rng_state())
        save_checkpoint(checkpoint,state)
        append_event(directory/'epochs.jsonl',{'epoch':state['epoch'],'loss':float(loss.detach()),'components':parts,'dev_mrr':metrics['mrr'],'best_dev_mrr':state['best_score'],'patience':state['patience_count'],'sampling':g.last_sampling_stats})
        if state['epoch']==1 or state['epoch']%10==0:
            print(f"{directory.name} epoch={state['epoch']} dev_mrr={metrics['mrr']:.6f} best={state['best_score']:.6f} patience={state['patience_count']}",flush=True)
        if stop_after_epochs is not None and state['epoch']>=stop_after_epochs:
            return {'status':'checkpointed','epoch':state['epoch'],'binding':signature}
    net.load_state_dict(state['best_model']);metrics,rows=evaluate_scores(graph,dev_scores(net,g),major_support=cfg['major_technique_train_support'])
    result={'status':'trained','arm':arm,'seed':seed,'params':cfg['params'],'binding':signature,'epoch':state['epoch'],'best_epoch':state['best_epoch'],'dev':metrics,'stopping_reason':'patience' if state['patience_count']>=cfg['patience'] else 'max_epochs','reserved_holdout_evaluated':False}
    atomic_json(directory/'ranks.json',rows);atomic_json(final,result)
    atomic_json(receipt,{'binding':signature,'files':{n:sha_file(directory/n) for n in ('result.json','ranks.json')}})
    return result
