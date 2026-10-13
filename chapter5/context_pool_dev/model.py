"""Target query pooling; frozen auxiliary loss/sampler remain unchanged."""
import copy
import random
from pathlib import Path
import time
import torch
from chapter5.core import digest, filtered_rank, summarize_ranks
from chapter5.io import atomic_json, read_json, sha_file, append_event
from chapter5.model import save_checkpoint, load_state
from chapter5.public_dev.model import PublicGraph, PublicPredictor, binding as original_binding
from chapter5.public_dev.core import evaluate_scores
from chapter5.resolved_dev.data import fixed_major
from .core import context_index


class ContextPoolPredictor(PublicPredictor):
    def __init__(self,graph,encoder,params,cfg):
        if encoder!='distmult':raise ValueError('only the registered DistMult context-pool candidate')
        super().__init__(graph,encoder,params,cfg)
        ctx=context_index(graph.graph);n=len(graph.names)
        for channel in ('cwe','cpe'):
            pairs=[(graph.ids[c],graph.ids[t]) for c,row in sorted(ctx.items()) for t in row[channel]]
            heads=torch.tensor([h for h,t in pairs],dtype=torch.long)
            tails=torch.tensor([t for h,t in pairs],dtype=torch.long)
            counts=torch.bincount(heads,minlength=n).to(torch.float32)
            self.register_buffer(channel+'_heads',heads);self.register_buffer(channel+'_tails',tails);self.register_buffer(channel+'_counts',counts)
        self.register_buffer('context_valid',(self.cwe_counts+self.cpe_counts)>0)

    def queries(self,x):
        pools=[]
        for channel in ('cwe','cpe'):
            heads=getattr(self,channel+'_heads');tails=getattr(self,channel+'_tails');counts=getattr(self,channel+'_counts')
            pooled=torch.zeros_like(x).index_add(0,heads,x[tails])/counts.clamp_min(1).unsqueeze(1)
            pools.append(pooled)
        divisor=((self.cwe_counts>0).float()+(self.cpe_counts>0).float()).clamp_min(1).unsqueeze(1)
        return (pools[0]+pools[1])/divisor

    def score(self,x,triples):
        target=triples[:,1]==2
        if not bool(target.any()):return super().score(x,triples)
        selected=triples[target]
        if not bool(self.context_valid[selected[:,0]].all()):raise ValueError('target query has no usable background; abstain')
        q=self.queries(x)
        value=(q[selected[:,0]]*self.relation(selected[:,1])*x[selected[:,2]]).sum(1)
        if bool(target.all()):return value
        out=super().score(x,triples);out[target]=value;return out


def candidate_scores(net,graph,heads):
    net.eval()
    covered=[h for h in heads if h in graph.ids and bool(net.context_valid[graph.ids[h]])]
    abstained=sorted(set(heads)-set(covered))
    with torch.no_grad():
        x=net.encode(graph);q=net.queries(x)
        values=(q[torch.tensor([graph.ids[h] for h in covered],dtype=torch.long)]*net.relation.weight[2])@x[graph.candidates].T
    if not torch.isfinite(values).all():raise ValueError('nonfinite context-pool score')
    return {h:dict(zip(graph.candidate_names,row.tolist())) for h,row in zip(covered,values)},abstained


def binding(graph,cfg,original_cfg,seed):
    root=Path(__file__).parent
    files={p.name:sha_file(p) for p in sorted(root.glob('*.py')) if not p.name.startswith('test_') and p.name!='model_red.py'}
    return digest({'original_engine':original_binding(graph,'distmult_mixed',original_cfg,seed),'candidate_config':cfg,'candidate_code':files,'seed':seed})


def train(graph,cfg,original_cfg,seed,directory,persist,deadline=None):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    signature=binding(graph,cfg,original_cfg,seed)
    checkpoint=directory/'checkpoint.pt';reservation=directory/'reservation.json';final=directory/'result.json';receipt=directory/'completed.json'
    torch.set_num_threads(2);torch.use_deterministic_algorithms(True);random.seed(seed);torch.manual_seed(seed)
    pg=PublicGraph(graph,'mixed');net=ContextPoolPredictor(pg,'distmult',cfg['params'],cfg)
    if any(not bool(net.context_valid[pg.ids[c]]) for r in ('train','dev') for c in graph['split'][r]):raise ValueError('registered actual-data coverage is no longer100%')
    optimizer=torch.optim.Adam(net.parameters(),lr=cfg['params']['learning_rate'],weight_decay=cfg['weight_decay'])
    if reservation.exists():
        if read_json(reservation)['binding']!=signature or not checkpoint.exists():raise ValueError('reserved checkpoint missing or changed; refuse reset')
        state=load_state(checkpoint,signature);net.load_state_dict(state['model']);optimizer.load_state_dict(state['optimizer'])
        random.setstate(state['python_rng']);torch.set_rng_state(state['torch_rng'])
    else:
        if any(directory.iterdir()):raise ValueError('unregistered existing unit state')
        atomic_json(reservation,{'binding':signature,'seed':seed,'status':'reserved'})
        state={'binding':signature,'epoch':0,'patience_count':0,'best_score':-1.,'best_model':None,'best_dev':None,'optimization_forwards':0,'dev_scoring_forwards':0}
        state.update(model=net.state_dict(),optimizer=optimizer.state_dict(),python_rng=random.getstate(),torch_rng=torch.get_rng_state())
        save_checkpoint(checkpoint,state);persist('running',state)
    if final.exists() or receipt.exists():
        if not receipt.exists():raise ValueError('completed result lacks receipt')
        info=read_json(receipt)
        if info['binding']!=signature or any(sha_file(directory/n)!=h for n,h in info['files'].items()):raise ValueError('completed outputs mismatch')
        return read_json(final)
    while state['epoch']<cfg['max_epochs'] and state['patience_count']<cfg['patience']:
        if deadline is not None and time.monotonic()>=deadline:
            persist('checkpointed',state);return {'status':'checkpointed','epoch':state['epoch'],'binding':signature}
        net.train();optimizer.zero_grad(set_to_none=True)
        loss,parts=net.objective(pg,cfg);state['optimization_forwards']+=1
        if not torch.isfinite(loss):raise ValueError('nonfinite loss')
        loss.backward()
        if any(p.grad is not None and not torch.isfinite(p.grad).all() for p in net.parameters()):raise ValueError('nonfinite gradient')
        optimizer.step();state['epoch']+=1
        scores,abstained=candidate_scores(net,pg,graph['split']['dev']);state['dev_scoring_forwards']+=1
        if abstained:raise ValueError('registered actual-data abstention')
        rows=[{'head':h,'tail':t,'rank':filtered_rank(scores[h],pg.truth[h],t)} for h in sorted(scores) for t in sorted(pg.truth[h])]
        metrics=summarize_ranks(rows)
        if state['best_model'] is None or metrics['mrr']>state['best_score']+cfg['min_improvement']:
            state.update(best_score=metrics['mrr'],best_dev=metrics,best_model=copy.deepcopy(net.state_dict()),patience_count=0,best_epoch=state['epoch'])
        else:state['patience_count']+=1
        state.update(model=net.state_dict(),optimizer=optimizer.state_dict(),python_rng=random.getstate(),torch_rng=torch.get_rng_state())
        save_checkpoint(checkpoint,state)
        append_event(directory/'epochs.jsonl',{'epoch':state['epoch'],'loss':float(loss.detach()),'components':parts,'dev_mrr':metrics['mrr'],'best_dev_mrr':state['best_score'],'patience':state['patience_count'],'sampling':pg.last_sampling_stats})
        if state['epoch']%10==0:print(f'{directory.name} epoch={state["epoch"]} mrr={metrics["mrr"]:.6f} best={state["best_score"]:.6f}',flush=True)
        if state['epoch']%cfg['checkpoint_interval_epochs']==0:persist('running',state)
    state['model']=copy.deepcopy(state['model'])
    net.load_state_dict(state['best_model'])
    scores,abstained=candidate_scores(net,pg,graph['split']['dev']);state['dev_scoring_forwards']+=1
    if abstained:raise ValueError('final coverage changed')
    metrics,rows=evaluate_scores(graph,scores,major_support=cfg['major_technique_train_support']);metrics=fixed_major(metrics,graph['fixed_major'])
    result={'status':'trained','arm':'context_pool_mixed','seed':seed,'params':cfg['params'],'binding':signature,'epoch':state['epoch'],'best_epoch':state['best_epoch'],'dev':metrics,'coverage':1.,'abstained':[],'optimization_forwards':state['optimization_forwards'],'dev_scoring_forwards':state['dev_scoring_forwards'],'stopping_reason':'patience' if state['patience_count']>=cfg['patience'] else 'max_epochs','reserved_holdout_evaluated':False}
    # Preserve the actual last optimization model/RNG for recovery; best weights are separate.
    save_checkpoint(checkpoint,state)
    atomic_json(directory/'scores.json',scores);atomic_json(directory/'ranks.json',rows);atomic_json(final,result)
    atomic_json(receipt,{'binding':signature,'files':{n:sha_file(directory/n) for n in ('result.json','ranks.json','scores.json')}})
    persist('done',state);return result
