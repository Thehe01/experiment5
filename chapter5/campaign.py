"""Bounded Dev selection, shared baselines and a single locked Test evaluation."""
import argparse
import collections
import itertools
import json
import platform
import random
import statistics
import traceback
from pathlib import Path
import torch
from chapter5.core import digest, filtered_rank, summarize_ranks
from chapter5.io import atomic_json, append_event, read_json, sha_file
from chapter5.model import Graph, train, restore_best, evaluate, scores_by_head, code_binding


def baseline_scores(graph, kind):
    if kind not in ('frequency','cwe_frequency'):
        raise ValueError('unknown baseline')
    train_heads=set(graph['split']['train'])
    counts=collections.Counter(e['tail'] for e in graph['edges'] if e['relation']=='exploited_by' and e['head'] in train_heads)
    cwes=collections.defaultdict(set)
    for e in graph['edges']:
        if e['relation']=='instantiates':
            cwes[e['head']].add(e['tail'])
    conditional=collections.defaultdict(collections.Counter)
    for e in graph['edges']:
        if e['relation']=='exploited_by' and e['head'] in train_heads:
            for w in cwes[e['head']]:
                conditional[w][e['tail']]+=1
    out={}
    for node in graph['nodes']:
        if node['type']!='Vulnerability':
            continue
        head=node['id']
        available=[conditional[w] for w in sorted(cwes[head]) if sum(conditional[w].values())]
        out[head]={t:(sum(c[t] for c in available)/len(available) if kind=='cwe_frequency' and available else counts[t])
                   for t in graph['techniques']}
    return out


def evaluate_scores(graph, scores, role):
    truth=collections.defaultdict(set)
    for e in graph.get('evaluation_targets',graph['edges']):
        if e['relation']=='exploited_by':
            truth[e['head']].add(e['tail'])
    rows=[{'head':h,'tail':t,'rank':filtered_rank(scores[h],truth[h],t)} for h in graph['split'][role] for t in sorted(truth[h])]
    return summarize_ranks(rows),rows


def seed_summary(records):
    keys=('mrr','hits@1','hits@3','hits@10')
    result={'seeds':[r['seed'] for r in records], 'runs':records}
    result['mean']={k:statistics.mean(r['metrics'][k] for r in records) for k in keys}
    result['std']={k:statistics.stdev(r['metrics'][k] for r in records) if len(records)>1 else 0. for k in keys}
    techniques=sorted({t for r in records for t in r['metrics']['by_technique']})
    result['by_technique']={t:{'queries':records[0]['metrics']['by_technique'][t]['queries'],
                            'mrr_mean':statistics.mean(r['metrics']['by_technique'][t]['mrr'] for r in records),
                            'mrr_std':statistics.stdev(r['metrics']['by_technique'][t]['mrr'] for r in records) if len(records)>1 else 0.} for t in techniques}
    return result


def paired_interval(rows_a, rows_b, seed=20261010, draws=5000):
    def by_cve(runs):
        per_run=[]
        for rows in runs:
            values=collections.defaultdict(list)
            for row in rows:
                values[row['head']].append(1./row['rank'])
            per_run.append({h:statistics.mean(v) for h,v in values.items()})
        return {h:statistics.mean(run[h] for run in per_run) for h in per_run[0]}
    a,b=by_cve(rows_a),by_cve(rows_b)
    if set(a)!=set(b):
        raise ValueError('paired CVE domains differ')
    differences=[b[h]-a[h] for h in sorted(a)]
    rng=random.Random(seed)
    values=sorted(statistics.mean(rng.choices(differences,k=len(differences))) for _ in range(draws))
    return {'delta_mrr':statistics.mean(differences),'percentile95':[values[int(.025*draws)],values[int(.975*draws)-1]],
            'draws':draws,'seed':seed,'unit':'CVE; average across fixed training seeds first',
            'limitation':'Conditional descriptive interval on one frozen small holdout; not independent dataset replication.'}


def run(graph,cfg,directory,supplementary=None):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    signature=digest({'graph':graph,'supplementary':supplementary,'config':cfg,'code':code_binding(),
                      'python':platform.python_version(),'torch':torch.__version__})
    header=directory/'campaign.json'
    if header.exists() and read_json(header)['binding']!=signature:
        raise ValueError('campaign input/code/runtime binding mismatch')
    atomic_json(header,{'binding':signature,'max_tuning_configs_per_model':8,'final_seeds':cfg['final_seeds'],
                        'max_epochs':cfg['max_epochs'],'patience':cfg['patience'],'model_api_calls':0})
    final=directory/'result.json'
    if final.exists():
        result=read_json(final)
        if result['binding']!=signature:
            raise ValueError('final evaluation binding mismatch')
        # Verify all restored files against a separate byte manifest before reusing completed evaluation.
        for name,sha in read_json(directory/'evaluation-bindings.json').items():
            if sha_file(directory/name)!=sha:
                raise ValueError('completed evaluation file binding mismatch')
        return result
    keys=sorted(cfg['grid'])
    grid=[dict(zip(keys,values)) for values in itertools.product(*(cfg['grid'][k] for k in keys))]
    if not 1<=len(grid)<=8 or len(set(cfg['final_seeds']))!=len(cfg['final_seeds']):
        raise ValueError('configuration or seed budget invalid')
    choices={}
    for arm in ('distmult','rgcn'):
        scores=[]
        for index,params in enumerate(grid):
            atomic_json(directory/'status.json',{'phase':'tuning','arm':arm,'config_index':index,'budget':len(grid)})
            print(json.dumps({'phase':'tuning','arm':arm,'config_index':index,'budget':len(grid)}),flush=True)
            result=train(graph,arm,params,cfg,cfg['tuning_seed'],directory/'tuning'/arm/str(index))
            scores.append((result['dev']['mrr'],index,params))
        best=max(scores,key=lambda row:(row[0],-row[1]))
        choices[arm]={'config_index':best[1],'params':best[2],'dev_mrr':best[0]}
    selection={'binding':signature,'sequence':1,'rule':'max macro-CVE Dev MRR; tie: first canonical configuration',
               'choices':choices,'final_seeds':cfg['final_seeds'],'arms':cfg['learning_arms'],
               'supplementary_arms':['distmult','rgcn'] if supplementary else []}
    selection_path=directory/'selection.json'
    if selection_path.exists() and read_json(selection_path)!=selection:
        raise ValueError('frozen model selection changed')
    atomic_json(selection_path,selection)
    jobs=[]
    for arm in cfg['learning_arms']:
        params=choices['distmult' if arm=='distmult' else 'rgcn']['params']
        for seed in cfg['final_seeds']:
            jobs.append(('main',graph,arm,params,seed,directory/'final'/arm/str(seed)))
    if supplementary:
        for arm in ('distmult','rgcn'):
            for seed in cfg['final_seeds']:
                jobs.append(('supplementary',supplementary,arm,choices[arm]['params'],seed,directory/'supplementary'/arm/str(seed)))
    for layer,g,arm,params,seed,path in jobs:
        atomic_json(directory/'status.json',{'phase':'training','layer':layer,'arm':arm,'seed':seed})
        print(json.dumps({'phase':'training','layer':layer,'arm':arm,'seed':seed}),flush=True)
        train(g,arm,params,cfg,seed,path)
    # No Test ranking is computed before every selected job has completed.
    atomic_json(directory/'status.json',{'phase':'evaluating_locked_test','selection_sha256':sha_file(selection_path)})
    layers={'main':graph}
    if supplementary:
        layers['supplementary']=supplementary
    reports={};all_rows={};ensemble=collections.defaultdict(lambda:collections.defaultdict(float))
    for layer,g in layers.items():
        reports[layer]={};all_rows[layer]={}
        for kind in ('frequency','cwe_frequency'):
            metrics,rows=evaluate_scores(g,baseline_scores(g,kind),'test')
            filename='ranks/'+layer+'/'+kind+'.json';atomic_json(directory/filename,rows)
            reports[layer][kind]=seed_summary([{'seed':None,'metrics':metrics,'ranks':filename}])
            all_rows[layer][kind]=[rows]
    for layer,g,arm,params,seed,path in jobs:
        net,typed=restore_best(g,arm,params,cfg,seed,path)
        metrics,rows=evaluate(net,typed,'test')
        filename='ranks/'+layer+'/'+arm+'/'+str(seed)+'.json';atomic_json(directory/filename,rows)
        reports[layer].setdefault(arm,{'records':[]})['records'].append({'seed':seed,'metrics':metrics,'ranks':filename})
        all_rows[layer].setdefault(arm,[]).append(rows)
        if layer=='main' and arm=='rgcn':
            for head,scores in scores_by_head(net,typed,g['split']['test']).items():
                for tail,score in scores.items():
                    ensemble[head][tail]+=score/len(cfg['final_seeds'])
    for layer in layers:
        for arm in list(reports[layer]):
            if 'records' in reports[layer][arm]:
                reports[layer][arm]=seed_summary(reports[layer][arm]['records'])
    typed=Graph(graph)
    suggestions=[]
    for head,scores in sorted(ensemble.items()):
        unknown=sorted(((t,v) for t,v in scores.items() if t not in typed.truth[head]),key=lambda x:(-x[1],x[0]))[:10]
        suggestions.extend({'head':head,'relation':'exploited_by','tail':tail,'score':score,'rank':i+1,
                            'state':'UNVERIFIED','score_kind':'mean raw DistMult score across '+str(len(cfg['final_seeds']))+' preregistered R-GCN seeds',
                            'binding':signature} for i,(tail,score) in enumerate(unknown))
    atomic_json(directory/'unverified_candidates.json',suggestions)
    comparisons={arm:paired_interval(all_rows['main']['distmult'],all_rows['main'][arm]) for arm in cfg['learning_arms'] if arm!='distmult'}
    result={'binding':signature,'sequence':2,'phase':'evaluation_complete','test':reports['main'],
            'supplementary_test':reports.get('supplementary'), 'selection_sha256':sha_file(selection_path),
            'paired_cve_intervals_against_distmult':comparisons,'model_api_calls':0,
            'prediction_state':'UNVERIFIED','graph_sha256':digest(graph),
            'limitations':['Transductive relation recovery, not unseen-node prediction or demonstrated real exploitation.',
                           'Official explicit statement admission and inherited labels; no invented independent human IAA.',
                           'Rare techniques can remain train-only. NVD/citation failures and pre-split isolated CVEs are reported.',
                           'C4 prediction supplement has only 21 legacy Dev documents; official expansion remains shared.']}
    atomic_json(final,result)
    bindings={str(p.relative_to(directory)):sha_file(p) for p in sorted(directory.rglob('*'))
              if p.is_file() and (p.name in ('checkpoint.pt','result.json','selection.json','unverified_candidates.json') or 'ranks' in p.parts)}
    atomic_json(directory/'evaluation-bindings.json',bindings)
    atomic_json(directory/'status.json',{'phase':'evaluation_complete','binding':signature,'model_api_calls':0})
    lines=['# 第五章实验结果','', '主指标：filtered macro-CVE MRR；分数为固定 Test 上五种子均值及样本标准差。','',
           '| 实验臂 | MRR | 标准差 | Hits@1 | Hits@3 | Hits@10 |','|---|---:|---:|---:|---:|---:|']
    for arm,record in reports['main'].items():
        m=record['mean'];lines.append('| '+arm+' | '+f"{m['mrr']:.4f} | {record['std']['mrr']:.4f} | {m['hits@1']:.4f} | {m['hits@3']:.4f} | {m['hits@10']:.4f}"+' |')
    lines+=['','最终排名、逐技术统计、描述性区间及限制见 result.json。预测候选仅为 UNVERIFIED，不属于事实图。']
    (directory/'report.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'phase':'evaluation_complete','binding':signature,'model_api_calls':0}),flush=True)
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',default='.');p.add_argument('--out',required=True);p.add_argument('--config',default='chapter5/config.json')
    a=p.parse_args();root=Path(a.out);cfg=read_json(a.config)
    try:
        from chapter5.collect import collect
        from chapter5.supplement import build_supplementary
        collect(Path(a.repo),root/'data',cfg)
        graph=read_json(root/'data/graph.json')
        supplementary=build_supplementary(Path(a.repo),graph,root/'supplementary-input')
        run(graph,cfg,root/'models',supplementary)
        atomic_json(root/'status.json',{'phase':'evaluation_complete','protocol':cfg['protocol'],'model_api_calls':0})
    except Exception as exc:
        atomic_json(root/'status.json',{'phase':'failed','error':str(exc),'traceback':traceback.format_exc(),'model_api_calls':0})
        raise


if __name__=='__main__':
    main()
