"""Frozen 36-unit development campaign; no reserved evaluation route."""
import argparse
import collections
import json
import statistics
import time
from pathlib import Path
from chapter5.core import digest
from chapter5.io import atomic_json, read_json, sha_file
from chapter5.public_data.verify import verify as verify_package, read_package
from chapter5.public_dev.core import folds, fold_graph, labels, baseline_scores, evaluate_scores
from chapter5.public_dev.model import train

ROOT=Path(__file__).parent


def promotion_gate(results, baselines, cfg):
    selected=[r for r in results if r['arm']=='rgcn_mixed']
    if len(selected)!=9 or len({(r['fold'],r['seed']) for r in selected})!=9:
        raise ValueError('gate requires nine unique fold/seed units')
    deltas=[r['dev']['mrr']-baselines[str(r['fold'])]['mrr'] for r in selected]
    major=[r['dev']['major_macro_mrr']-baselines[str(r['fold'])]['major_macro_mrr'] for r in selected
           if r['dev']['major_macro_mrr'] is not None and baselines[str(r['fold'])]['major_macro_mrr'] is not None]
    delta=statistics.mean(deltas);macro=statistics.mean(major) if len(major)==9 else None
    wins=sum(d>0 for d in deltas);g=cfg['gate']
    passed=delta+1e-12>=g['mean_delta_mrr'] and wins>=g['wins_of_nine'] and macro is not None and macro+1e-12>=g['major_macro_delta_min']
    return {'passed':passed,'mean_delta_mrr':delta,'wins_of_nine':wins,'major_macro_delta':macro,
            'unit_deltas':deltas,'meaning':'development promotion only','reserved_holdout_evaluated':False,'confirmation_training_started':False}


def claim_unit(ledger, unit, budget):
    if unit not in ledger['allowed']:raise ValueError('unregistered unit')
    if unit in ledger['units']:return False
    if len(ledger['units'])>=budget:raise ValueError('unique training budget exhausted')
    ledger['units'][unit]={'status':'reserved'}
    return True


def load_inputs(repo,cfg):
    package=Path(repo)/cfg['data_package']
    if sha_file(package)!=cfg['data_sha256']:raise ValueError('pinned package byte mismatch')
    audit=verify_package(package)
    if (audit['eligible_cves'],audit['curated_target_edges'],audit['supervised_techniques'],audit['candidate_techniques'])!=(1035,2332,174,697):
        raise ValueError('registered public sample counts mismatch')
    files=read_package(package);graph=json.loads(files['graph.json']);split=json.loads(files['development-split.json'])
    pool=set(split['train'])|set(split['dev'])
    if len(pool)!=cfg['development_cves'] or len(split['reserved_holdout'])!=cfg['reserved_cves']:
        raise ValueError('registered group size mismatch')
    # Evaluation annotations only. PublicGraph uses only IDs, types and registered edges.
    graph['evaluation_stages']={};graph['evaluation_label_sources']={}
    for line in files['records.jsonl'].splitlines():
        r=json.loads(line)
        if r['id'] not in pool:continue
        graph['evaluation_label_sources'][r['id']]=r['label_sources']
        for t in r['techniques']:
            graph['evaluation_stages'][r['id']+'|'+t]=[s for s in ('exploitation_techniques','primary_impact','secondary_impact') if t in r[s]]
    return graph,split,audit


def source_files(repo):
    repo=Path(repo)
    paths=list((repo/'chapter5').glob('*.py'))+list((repo/'chapter5/public_dev').glob('*.py'))
    paths += [repo/'chapter5/public_dev'/n for n in ('config.json','spec.md','plan.md','README.md')]
    paths += [repo/'chapter5/requirements-cpu.txt',repo/'chapter5/public_data/verify.py',repo/'.github/workflows/chapter5-public-dev.yml']
    return {p.relative_to(repo).as_posix():sha_file(p) for p in sorted(paths)}


def prepare(repo):
    repo=Path(repo);cfg=read_json(ROOT/'config.json');graph,split,audit=load_inputs(repo,cfg)
    fs=folds(graph,split,cfg['fold_seeds']);truth=labels(graph)
    summaries=[]
    for f in fs:
        train=set(f['train']);dev=set(f['dev'])
        if len(train)!=725 or len(dev)!=155:raise ValueError('registered fold sizes')
        support=collections.Counter(t for c in f['train'] for t in truth[c])
        summaries.append({'fold':f['fold'],'train_cves':len(train),'dev_cves':len(dev),'train_edges':sum(len(truth[c]) for c in train),'dev_edges':sum(len(truth[c]) for c in dev),'train_supervised_techniques':len(support),'train_support':dict(sorted(support.items()))})
    groups={'folds':fs,'reserved_ids':split['reserved_holdout'],'summaries':summaries,
            'dev_overlap':{f'{i}-{j}':len(set(fs[i]['dev'])&set(fs[j]['dev'])) for i in range(3) for j in range(i+1,3)},
            'strategy':'three repeated grouped stratified holdouts; not disjoint K-fold'}
    atomic_json(ROOT/'folds.json',groups)
    units=[{'id':f"f{f['fold']}-{arm}-s{seed}",'fold':f['fold'],'arm':arm,'seed':seed} for f in fs for arm in cfg['arms'] for seed in cfg['development_seeds']]
    if len(units)!=cfg['training_unit_budget']:raise ValueError('unit budget mismatch')
    registration={'protocol':cfg['protocol'],'config_sha256':sha_file(ROOT/'config.json'),'data_sha256':cfg['data_sha256'],'folds_sha256':sha_file(ROOT/'folds.json'),'source_files':source_files(repo),'units':units,'model_api_calls':0,'reserved_holdout_evaluation':False,'confirmation_training_budget':0,'package_verification':audit}
    atomic_json(ROOT/'registration.json',registration)
    return verify_registration(repo)


def verify_registration(repo):
    repo=Path(repo);cfg=read_json(ROOT/'config.json');reg=read_json(ROOT/'registration.json')
    if reg['config_sha256']!=sha_file(ROOT/'config.json') or reg['folds_sha256']!=sha_file(ROOT/'folds.json') or reg['source_files']!=source_files(repo):
        raise ValueError('frozen development registration/code mismatch')
    if cfg['reserved_holdout_evaluation'] or cfg['confirmation_training_budget'] or cfg['model_api_call_budget'] or cfg['data_download_budget']:
        raise ValueError('unregistered evaluation/network budget')
    graph,split,audit=load_inputs(repo,cfg);groups=read_json(ROOT/'folds.json')
    if groups['folds']!=folds(graph,split,cfg['fold_seeds']) or groups['reserved_ids']!=split['reserved_holdout']:
        raise ValueError('frozen folds mismatch')
    expected=[{'id':f"f{f['fold']}-{arm}-s{seed}",'fold':f['fold'],'arm':arm,'seed':seed} for f in groups['folds'] for arm in cfg['arms'] for seed in cfg['development_seeds']]
    if reg['units']!=expected or len(expected)!=36:raise ValueError('frozen unit inventory mismatch')
    return {'phase':'offline_registration_verified','training_units_registered':36,'model_training_runs':0,'reserved_holdout_evaluated':False,'model_api_calls':0,'registration_sha256':sha_file(ROOT/'registration.json'),'folds':groups['summaries'],'dev_overlap':groups['dev_overlap'],'package':audit}


def freeze_baselines(graphs,cfg,directory):
    directory=Path(directory);summary=directory/'summary.json';receipt=directory/'receipt.json'
    signature=digest({'graphs':graphs,'config':cfg,'registration':sha_file(ROOT/'registration.json')})
    if receipt.exists():
        info=read_json(receipt)
        if info['binding']!=signature or any(sha_file(directory/n)!=h for n,h in info['files'].items()):raise ValueError('baseline frozen outputs mismatch')
        return read_json(summary)
    if directory.exists() and any(directory.iterdir()):raise ValueError('partial baseline output; refuse blind re-score')
    directory.mkdir(parents=True,exist_ok=True);all_metrics={}
    candidates=[('frequency',None),('cwe_frequency',None)]+[('smoothed_cwe',a) for a in cfg['smoothing_alphas']]+[('neighbor_vote',None)]
    for name,alpha in candidates:
        key=name+(f'-{alpha}' if alpha is not None else '')
        all_metrics[key]={}
        for i,graph in enumerate(graphs):
            metrics,rows=evaluate_scores(graph,baseline_scores(graph,name,alpha or 1),major_support=cfg['major_technique_train_support'])
            all_metrics[key][str(i)]=metrics;atomic_json(directory/f'{key}-f{i}-ranks.json',rows)
    mean=lambda k:statistics.mean(v['mrr'] for v in all_metrics[k].values())
    alpha=max(cfg['smoothing_alphas'],key=lambda a:mean(f'smoothed_cwe-{a}'))
    families=['frequency','cwe_frequency',f'smoothed_cwe-{alpha}','neighbor_vote']
    best=max(families,key=mean)
    result={'binding':signature,'selected_smoothing_alpha':alpha,'best_baseline':best,'mean_mrr':{k:mean(k) for k in all_metrics},'metrics':all_metrics,'selected':all_metrics[best],'selection':'one global alpha and family by three-fold mean Dev MRR; fixed listed tie order','reserved_holdout_evaluated':False}
    atomic_json(summary,result)
    atomic_json(receipt,{'binding':signature,'files':{p.name:sha_file(p) for p in sorted(directory.glob('*.json')) if p.name!='receipt.json'}})
    print(json.dumps({'phase':'baselines_frozen','best_baseline':best,'alpha':alpha,'mean_mrr':result['mean_mrr']}),flush=True)
    return result


def run(repo,state,seconds):
    repo,state=Path(repo),Path(state);verification=verify_registration(repo);cfg=read_json(ROOT/'config.json')
    if seconds!=cfg['slot_seconds']:raise ValueError('execution duration changed')
    deadline=time.monotonic()+seconds;state.mkdir(parents=True,exist_ok=True)
    signature=verification['registration_sha256'];binding_path=state/'input-binding.json'
    if binding_path.exists():
        if read_json(binding_path)['registration_sha256']!=signature:raise ValueError('restored registration mismatch')
    else:
        atomic_json(binding_path,{'registration_sha256':signature,'data_sha256':cfg['data_sha256']})
        for n in ('config.json','folds.json','registration.json'):atomic_json(state/n,read_json(ROOT/n))
    graph,split,_=load_inputs(repo,cfg);groups=read_json(ROOT/'folds.json')
    graphs=[fold_graph(graph,f,groups['reserved_ids']) for f in groups['folds']]
    reg=read_json(ROOT/'registration.json');ledger_path=state/'unit-ledger.json'
    ledger=read_json(ledger_path) if ledger_path.exists() else {'allowed':[u['id'] for u in reg['units']],'units':{},'registration_sha256':signature}
    if ledger['allowed']!=[u['id'] for u in reg['units']] or ledger['registration_sha256']!=signature or len(ledger['units'])>36:raise ValueError('unit ledger inventory mismatch')
    baselines=freeze_baselines(graphs,cfg,state/'baselines');results=[]
    for unit in reg['units']:
        uid=unit['id'];directory=state/'units'/uid
        if time.monotonic()>=deadline and uid not in ledger['units']:break
        existed=uid in ledger['units'];claim_unit(ledger,uid,cfg['training_unit_budget']);atomic_json(ledger_path,ledger)
        if existed and not (directory/'checkpoint.pt').exists():raise ValueError('previously reserved unit missing checkpoint')
        print(json.dumps({'phase':'unit_started_or_resumed','unit':uid,'unique_reserved_units':len(ledger['units'])}),flush=True)
        result=train(graphs[unit['fold']],unit['arm'],cfg,unit['seed'],directory,deadline=deadline)
        ledger['units'][uid]={'status':result['status'],'epoch':result['epoch'],'binding':result['binding']}
        atomic_json(ledger_path,ledger)
        if result['status']=='checkpointed':break
        results.append(dict(result,fold=unit['fold'],unit=uid))
    complete=len(results)==36
    status={'phase':'development_complete' if complete else 'continuation_needed','registered_units':36,'reserved_units':len(ledger['units']),'completed_units':sum(v['status']=='trained' for v in ledger['units'].values()),'model_api_calls':0,'reserved_holdout_evaluated':False,'confirmation_training_started':False,'registration_sha256':signature}
    if complete:
        gate=promotion_gate(results,baselines['selected'],cfg);status['promotion_gate']=gate
        comparison={'status':status,'baselines':baselines,'results':results,'arm_summary':{a:{'mean_dev_mrr':statistics.mean(r['dev']['mrr'] for r in results if r['arm']==a),'min_dev_mrr':min(r['dev']['mrr'] for r in results if r['arm']==a),'max_dev_mrr':max(r['dev']['mrr'] for r in results if r['arm']==a)} for a in cfg['arms']},'dev_overlap':groups['dev_overlap']}
        atomic_json(state/'comparison.json',comparison)
        lines=['# 公开潜在关联开发比较','',f"完成36个登记训练单位；最强简单基线：{baselines['best_baseline']}。",'', '| 方法 | 九单位平均 Dev MRR |','|---|---:|']
        lines += [f"| {a} | {v['mean_dev_mrr']:.6f} |" for a,v in comparison['arm_summary'].items()]
        lines += ['',f"开发进阶门槛：{'通过' if gate['passed'] else '未通过'}；平均MRR差 {gate['mean_delta_mrr']:.6f}，改善 {gate['wins_of_nine']}/9。",'','三组重复分组划分有交叠，九单位不视为九个独立数据集。每个单位按Dev早停并报告最佳Dev，属于开发成绩。公开标签代表潜在利用/影响关联；CPE为reported背景。155个reserved CVE未评分，模型API调用0，确认实验未启动。']
        (state/'report.md').write_text('\n'.join(lines)+'\n')
    atomic_json(state/'status.json',status);print(json.dumps(status,ensure_ascii=False),flush=True)
    return status


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['prepare','verify','run']);p.add_argument('--repo',default='.');p.add_argument('--state');p.add_argument('--seconds',type=int,default=14400);a=p.parse_args()
    if a.command=='prepare':r=prepare(a.repo)
    elif a.command=='verify':r=verify_registration(a.repo)
    else:r=run(a.repo,a.state,a.seconds)
    print(json.dumps(r,ensure_ascii=False,sort_keys=True),flush=True)

if __name__=='__main__':main()
