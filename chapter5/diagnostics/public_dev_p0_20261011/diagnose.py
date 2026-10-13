"""Read-only P0 development diagnosis. Never calls training or scores reserved heads."""
import argparse
import collections
import copy
import hashlib
import json
import math
import platform
import random
import statistics
import time
from pathlib import Path

import torch
from torch.nn import functional as F
from chapter5.core import digest
from chapter5.io import sha_file
from chapter5.model import load_state
from chapter5.public_dev.campaign import load_inputs, verify_registration
from chapter5.public_dev.core import RELATIONS, TARGET, baseline_scores, evaluate_scores, fold_graph, labels
from chapter5.public_dev.model import PublicGraph, PublicPredictor, binding


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)+'\n')


def independent_ranks(scores, truth):
    """Separate implementation: remove other positives; use average rank for ties."""
    rows=[]
    for h in sorted(scores):
        s=scores[h]
        assert all(math.isfinite(v) for v in s.values())
        negative=[v for t,v in s.items() if t not in truth[h]]
        for t in sorted(truth[h]):
            v=s[t]
            rows.append({'head':h, 'tail':t, 'rank':1+sum(x>v for x in negative)+0.5*sum(x==v for x in negative)})
    return rows


def independent_metrics(rows):
    by_head=collections.defaultdict(list)
    for r in rows:
        by_head[r['head']].append(r['rank'])
    out={'queries':len(by_head), 'edges':len(rows)}
    out['mrr']=statistics.mean(statistics.mean(1/r for r in rs) for rs in by_head.values())
    for k in (1,3,10):
        out['hits@'+str(k)]=statistics.mean(statistics.mean(r<=k for r in rs) for rs in by_head.values())
    return out


def self_checks():
    scores={'a':{'p':4.,'q':5.,'n':4.,'m':6.},'b':{'p':1.,'q':2.,'n':3.,'m':4.}}
    rows=independent_ranks(scores,{'a':{'p','q'},'b':{'p'}})
    assert [r['rank'] for r in rows]==[2.5,2.,4.]
    assert abs(independent_metrics(rows)['mrr']-0.35)<1e-15
    assert independent_ranks({'a':{'p':0.,'q':0.,'n':0.}}, {'a':{'p','q'}})[0]['rank']==1.5


def max_numeric_error(a,b):
    if isinstance(a,dict):
        assert set(a)==set(b), (set(a)^set(b))
        return max([max_numeric_error(a[k],b[k]) for k in a] or [0.])
    if isinstance(a,list):
        assert len(a)==len(b)
        return max([max_numeric_error(x,y) for x,y in zip(a,b)] or [0.])
    if isinstance(a,(int,float)) and not isinstance(a,bool):
        return abs(a-b)
    assert a==b, (a,b)
    return 0.


def check_roles(g):
    assert len(g['split']['dev'])==155
    assert not set(g['split']['dev'])&set(g['reserved_ids'])
    assert not any(e['relation']==TARGET and e['head'] in g['reserved_ids'] for e in g['edges'])


def matrix_scores(net, pg):
    check_roles(pg.graph)
    heads=sorted(pg.graph['split']['dev'])
    assert len(pg.candidate_names)==697
    net.eval()
    with torch.no_grad():
        x=net.encode(pg)
        m=(x[torch.tensor([pg.ids[h] for h in heads])]*net.relation.weight[2])@x[pg.candidates].T
    assert torch.isfinite(m).all()
    scores={h:dict(zip(pg.candidate_names,row.tolist())) for h,row in zip(heads,m)}
    return heads,m,scores


def top3(scores):
    return {h:sorted(s,key=lambda t:(-s[t],t))[:3] for h,s in scores.items()}


def rank_vector(v):
    items=sorted(enumerate(v),key=lambda x:x[1]); out=[0.]*len(items); i=0
    while i<len(items):
        j=i+1
        while j<len(items) and items[j][1]==items[i][1]:j+=1
        for k in range(i,j):out[items[k][0]]=(i+j-1)/2.
        i=j
    return torch.tensor(out,dtype=torch.float64)


def spearman(a,b):
    x,y=rank_vector(a),rank_vector(b);x-=x.mean();y-=y.mean()
    denom=x.norm()*y.norm()
    return float(x.dot(y)/denom) if denom>0 else None


def effective_rank(x):
    sv=torch.linalg.svdvals(x.double()); p=sv/sv.sum() if float(sv.sum()) else sv
    p=p[p>0]
    return float(torch.exp(-(p*p.log()).sum())) if len(p) else 0.


def representation_stats(x):
    x=x.double(); centered=x-x.mean(0,keepdim=True)
    normalized=F.normalize(x,dim=1)
    n=len(x); cosine=normalized@normalized.T
    return {'mean_pairwise_cosine':float((cosine.sum()-cosine.diagonal().sum())/(n*(n-1))),
            'centered_energy_fraction':float(centered.square().sum()/x.square().sum()),
            'effective_rank':effective_rank(x), 'centered_effective_rank':effective_rank(centered),
            'mean_norm':float(x.norm(dim=1).mean()), 'zero_fraction':float((x==0).double().mean())}


def two_way_variance(x):
    x=x.double(); center=x.mean();row=x.mean(1,keepdim=True)-center;col=x.mean(0,keepdim=True)-center
    residual=x-center-row-col; denom=(x-center).square().sum()
    return {'row_component_fraction':float(row.square().sum()*x.shape[1]/denom),
            'technique_component_fraction':float(col.square().sum()*x.shape[0]/denom),
            'interaction_component_fraction':float(residual.square().sum()/denom)}


def detailed_stats(net,pg,heads,m,scores):
    support=collections.Counter(t for h in pg.graph['split']['train'] for t in pg.truth[h])
    counts=[support[t] for t in pg.candidate_names]; means=m.double().mean(0).tolist()
    seen=[i for i,t in enumerate(pg.candidate_names) if support[t]>0]
    z=(m.double()-m.double().mean(1,keepdim=True))/m.double().std(1,keepdim=True,unbiased=False).clamp_min(1e-15)
    reps={}
    with torch.no_grad():
        x=net.entity.weight+net.types(net.type_ids)
        ids=torch.tensor([pg.ids[h] for h in heads]); reps['layer0']=representation_stats(x[ids])
        for i,layer in enumerate(net.layers,1):
            x=F.relu(layer(x,pg.adjacency));reps['layer'+str(i)]=representation_stats(x[ids])
        reps['decoder_query']=representation_stats(x[ids]*net.relation.weight[2])
        tails=x[pg.candidates]; cosine_tail=F.normalize(tails,dim=1)
        relation=net.relation.weight[2]
        tailnorm_scores=(x[ids]*relation)@cosine_tail.T
    rawtop=top3(scores)
    common=set(('T1059','T1190','T1203'))
    residual=m-m.mean(0,keepdim=True)
    residual_scores={h:dict(zip(pg.candidate_names,row.tolist())) for h,row in zip(heads,residual)}
    tail_scores={h:dict(zip(pg.candidate_names,row.tolist())) for h,row in zip(heads,tailnorm_scores)}
    def probe(s):
        ts=top3(s)
        return {'mrr':independent_metrics(independent_ranks(s,pg.truth))['mrr'],
                'raw_top3_unique':len(set(t for v in ts.values() for t in v)),
                'top3_set_changed_fraction':statistics.mean(set(ts[h])!=set(rawtop[h]) for h in heads)}
    query_corr=[spearman(row,means) for row in m.tolist()]
    return {'representations':reps, 'raw_score_variance':two_way_variance(m), 'standardized_score_variance':two_way_variance(z),
            'score_mean_vs_train_support_spearman_697':spearman(means,counts),
            'score_mean_vs_train_support_spearman_seen174':spearman([means[i] for i in seen],[counts[i] for i in seen]),
            'mean_query_vs_mean_score_spearman':statistics.mean(query_corr),
            'raw_top3_unique':len(set(t for v in rawtop.values() for t in v)),
            'popular_triple_fraction':statistics.mean(set(v)==common for v in rawtop.values()),
            'top3_counts':dict(collections.Counter(t for v in rawtop.values() for t in v)),
            'seen_technique_tail_norm_vs_support_spearman':spearman(tails[seen].norm(dim=1).tolist(),[counts[i] for i in seen]),
            'explanatory_probes':{'subtract_dev_column_mean':probe(residual_scores),'normalize_tail_vectors':probe(tail_scores)}}


def perturb(graph,kind,seed):
    out=copy.deepcopy(graph);heads=sorted(graph['split']['dev']); donor=heads.copy();rng=random.Random(seed)
    while True:
        rng.shuffle(donor)
        if all(a!=b for a,b in zip(heads,donor)):break
    mapping=dict(zip(donor,heads)); hs=set(heads)
    rels=RELATIONS[:2] if kind in ('joint','remove') else (RELATIONS[0],) if kind=='cpe' else (RELATIONS[1],)
    edges=[]
    for e in out['edges']:
        if e['head'] in hs and e['relation'] in rels:
            if kind=='remove':continue
            e['head']=mapping[e['head']]
        edges.append(e)
    out['edges']=edges
    assert labels(out)==labels(graph)
    assert out['nodes']==graph['nodes'] and out['techniques']==graph['techniques']
    assert out['split']==graph['split'] and out['reserved_ids']==graph['reserved_ids']
    if kind!='remove':
        assert collections.Counter((e['relation'],e['tail']) for e in out['edges'])==collections.Counter((e['relation'],e['tail']) for e in graph['edges'])
    check_roles(out)
    return out,mapping


def control_stats(original,changed,m0,m1,truth):
    heads=sorted(original);a,b=top3(original),top3(changed)
    old,new=independent_metrics(independent_ranks(original,truth)),independent_metrics(independent_ranks(changed,truth))
    return {'original':old,'changed':new,'delta_mrr':new['mrr']-old['mrr'],
            'top3_set_changed_fraction':statistics.mean(set(a[h])!=set(b[h]) for h in heads),
            'top3_order_changed_fraction':statistics.mean(a[h]!=b[h] for h in heads),
            'relative_score_l2_change':float((m1-m0).double().norm()/m0.double().norm()),
            'mean_query_score_spearman':statistics.mean(spearman(original[h].values(),changed[h].values()) for h in heads)}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--state',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();root=args.repo.resolve();state=args.state.resolve();out=args.output.resolve()
    assert out!=state and state not in out.parents
    assert not out.exists(), 'new output directory required'
    started=time.time();self_checks();proto=read(Path(__file__).with_name('protocol.json'))
    audit=verify_registration(root); assert audit['registration_sha256']==proto['registration_sha256']
    cfg=read(root/'chapter5/public_dev/config.json');groups=read(root/'chapter5/public_dev/folds.json');reg=read(root/'chapter5/public_dev/registration.json')
    # The frozen runner writes config through atomic_json (sorted/reformatted).
    # Config contents must match; folds and registration retain exact bytes.
    assert read(state/'config.json')==cfg
    for name in ('folds.json','registration.json'):
        assert sha_file(state/name)==sha_file(root/'chapter5/public_dev'/name), name
    torch.set_num_threads(cfg['threads']);torch.use_deterministic_algorithms(True)
    base,split,_=load_inputs(root,cfg);graphs=[fold_graph(base,f,groups['reserved_ids']) for f in groups['folds']]
    out.mkdir(parents=True);replay=[];detail=[];controls=[];query_rows=[]
    baseline_receipt=read(state/'baselines/receipt.json')
    assert baseline_receipt['binding']==digest({'graphs':graphs,'config':cfg,'registration':sha_file(root/'chapter5/public_dev/registration.json')})
    for n,h in baseline_receipt['files'].items():assert sha_file(state/'baselines'/n)==h
    baseline_summary=read(state/'baselines/summary.json')
    for fold,g in enumerate(graphs):
        for key,fold_metrics in baseline_summary['metrics'].items():
            name=key.split('-')[0];alpha=int(key.split('-')[1]) if '-' in key else 1
            s=baseline_scores(g,name,alpha);rows=independent_ranks(s,labels(g)); saved=read(state/'baselines'/f'{key}-f{fold}-ranks.json')
            assert rows==saved, f'baseline rank mismatch {key} {fold}'
            m,original_rows=evaluate_scores(g,s);err=max_numeric_error(m,fold_metrics[str(fold)])
            assert rows==original_rows and err<1e-12
            independent=independent_metrics(rows)
            assert max(abs(independent[k]-m[k]) for k in independent)<1e-12
            replay.append({'unit':f'{key}-f{fold}','kind':'baseline','rank_rows':len(rows),'rank_mismatches':0,'metric_max_error':err,'mrr':independent['mrr']})
        print(f'baseline fold {fold} replay passed',flush=True)
    comparison=read(state/'comparison.json');comparison_index={(r['fold'],r['arm'],r['seed']):r for r in comparison['results']}
    for u in reg['units']:
        uid=u['id'];d=state/'units'/uid;g=graphs[u['fold']];pg=PublicGraph(g,u['arm'].split('_')[1]);signature=binding(g,u['arm'],cfg,u['seed'])
        receipt=read(d/'completed.json');assert receipt['binding']==signature
        for n,h in receipt['files'].items():assert sha_file(d/n)==h
        checkpoint=load_state(d/'checkpoint.pt',signature);net=PublicPredictor(pg,u['arm'].split('_')[0],cfg['params'],cfg);net.load_state_dict(checkpoint['best_model'])
        assert not any(h in set(g['split']['dev']) for h,r,t in [(pg.names[h],r,pg.names[t]) for h,r,t in pg.positive.tolist()] if r==2)
        heads,m,s=matrix_scores(net,pg);rows=independent_ranks(s,pg.truth);saved=read(d/'ranks.json');result=read(d/'result.json');assert rows==saved,uid
        metrics,original_rows=evaluate_scores(g,s);err=max_numeric_error(metrics,result['dev']);assert rows==original_rows and err<1e-12
        assert max_numeric_error(result['dev'],comparison_index[(u['fold'],u['arm'],u['seed'])]['dev'])==0
        independent=independent_metrics(rows);assert max(abs(independent[k]-metrics[k]) for k in independent)<1e-12
        assert abs(checkpoint['best_score']-independent['mrr'])<1e-12 and checkpoint['best_epoch']==result['best_epoch']
        replay.append({'unit':uid,'kind':'model','arm':u['arm'],'fold':u['fold'],'seed':u['seed'],'rank_rows':len(rows),'rank_mismatches':0,'metric_max_error':err,'mrr':independent['mrr'],'checkpoint_sha256':sha_file(d/'checkpoint.pt'),'best_epoch':checkpoint['best_epoch']})
        if u['arm'].endswith('_mixed'):
            item={'unit':uid,'fold':u['fold'],'arm':u['arm'],'seed':u['seed'],'mrr':independent['mrr'],**detailed_stats(net,pg,heads,m,s)};detail.append(item)
            conditions=[('joint',seed) for seed in proto['permutation_seeds']]+[('cpe',proto['permutation_seeds'][0]),('cwe',proto['permutation_seeds'][0]),('remove',proto['permutation_seeds'][0])] if u['arm']=='rgcn_mixed' else [('joint',proto['permutation_seeds'][0])]
            raw=top3(s);perhead=collections.defaultdict(list)
            for row in rows:perhead[row['head']].append(row['rank'])
            for h in heads:query_rows.append({'unit':uid,'condition':'original','head':h,'top3':raw[h],'mrr':statistics.mean(1/r for r in perhead[h])})
            for kind,seed in conditions:
                changed,donors=perturb(g,kind,seed);newpg=PublicGraph(changed,pg.strategy);assert pg.names==newpg.names and pg.candidate_names==newpg.candidate_names
                _,m1,s1=matrix_scores(net,newpg)
                if u['arm']=='distmult_mixed':assert torch.equal(m,m1), 'negative control failed'
                ctrl={'unit':uid,'fold':u['fold'],'arm':u['arm'],'condition':kind,'permutation_seed':seed,**control_stats(s,s1,m,m1,pg.truth)};controls.append(ctrl)
                rr=independent_ranks(s1,pg.truth);qh=collections.defaultdict(list)
                for row in rr:qh[row['head']].append(row['rank'])
                ts=top3(s1)
                for h in heads:query_rows.append({'unit':uid,'condition':kind,'permutation_seed':seed,'head':h,'top3':ts[h],'mrr':statistics.mean(1/r for r in qh[h])})
        print(uid+' best checkpoint replay passed'+(' + diagnosis' if u['arm'].endswith('_mixed') else ''),flush=True)
    for fold,g in enumerate(graphs):
        s=baseline_scores(g,'neighbor_vote');heads=sorted(s);m=torch.tensor([list(s[h].values()) for h in heads],dtype=torch.float64)
        for seed in proto['permutation_seeds']:
            changed,donors=perturb(g,'joint',seed);s1=baseline_scores(changed,'neighbor_vote');m1=torch.tensor([list(s1[h].values()) for h in heads],dtype=torch.float64)
            controls.append({'unit':f'neighbor_vote-f{fold}','fold':fold,'arm':'neighbor_vote','condition':'joint','permutation_seed':seed,**control_stats(s,s1,m,m1,labels(g))})
        print(f'neighbor context controls fold {fold} passed',flush=True)
    write(out/'replay.json',replay);write(out/'analysis.json',{'units':detail,'controls':controls})
    (out/'query_diagnostics.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True,allow_nan=False)+'\n' for r in query_rows))
    arm_mrr={arm:statistics.mean(r['mrr'] for r in replay if r.get('arm')==arm) for arm in cfg['arms']}
    control_summary={}
    for arm,kind in sorted({(c['arm'],c['condition']) for c in controls}):
        cs=[c for c in controls if c['arm']==arm and c['condition']==kind]
        control_summary[arm+'/'+kind]={k:statistics.mean(c[k] for c in cs) for k in ('delta_mrr','top3_set_changed_fraction','relative_score_l2_change','mean_query_score_spearman')}
        control_summary[arm+'/'+kind]['changed_mrr']=statistics.mean(c['changed']['mrr'] for c in cs)
        control_summary[arm+'/'+kind]['observations']=len(cs)
    totals={'model_units':36,'baseline_fold_outputs':18,'model_rank_rows':sum(r['rank_rows'] for r in replay if r['kind']=='model'),'baseline_rank_rows':sum(r['rank_rows'] for r in replay if r['kind']=='baseline'),'rank_mismatches':sum(r['rank_mismatches'] for r in replay),'metric_max_error':max(r['metric_max_error'] for r in replay),'arm_mrr':arm_mrr,'controls':control_summary}
    write(out/'summary.json',totals)
    receipt={'protocol_sha256':sha_file(Path(__file__).with_name('protocol.json')),'script_sha256':sha_file(__file__),'registration_sha256':audit['registration_sha256'],'runtime':{'python':platform.python_version(),'torch':torch.__version__,'cpu_capability':torch.backends.cpu.get_cpu_capability(),'threads':torch.get_num_threads()},'artifact_sha256':proto['artifact_sha256'],'config_materialization':{'source_sha256':sha_file(root/'chapter5/public_dev/config.json'),'artifact_sha256':sha_file(state/'config.json'),'logical_contents_equal':True,'runner_reformats_config':True},'new_training_units':0,'external_model_api_calls':0,'reserved_holdout_evaluated':False,'reserved_heads_scored':0,'self_checks_passed':True,'elapsed_seconds':time.time()-started,'command':f'ATEN_CPU_CAPABILITY=avx2 PYTHONPATH=<matching dependencies> python -m chapter5.diagnostics.public_dev_p0_20261011.diagnose --repo {root} --state {state} --output {out}','files':{p.name:sha_file(p) for p in sorted(out.iterdir())}}
    write(out/'verification.json',receipt)
    print(json.dumps(totals,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
