"""Paired data expansion campaign. No reserved/final evaluation route."""
import argparse
import collections
import json
import platform
from pathlib import Path
import statistics
import time
import torch
from chapter5.core import digest
from chapter5.io import atomic_json, read_json, sha_file
from chapter5.public_dev.core import labels, baseline_scores, evaluate_scores
from chapter5.public_dev.model import PublicGraph, train
from chapter5.resolved_dev.data import read_package, make_fold, fixed_major, paired_summary

ROOT=Path(__file__).parent

def claim_unit(ledger, unit, budget):
    if unit not in ledger['allowed']:raise ValueError('unregistered unit')
    if unit in ledger['units']:return False
    if len(ledger['units'])>=budget:raise ValueError('unique training budget exhausted')
    ledger['units'][unit]={'status':'reserved'};return True

def expected_units(cfg):
    if cfg['arms']!=['distmult_mixed','rgcn_mixed'] or cfg['conditions']!=['base','augmented']:raise ValueError('unregistered methods or conditions')
    units=[{'id':f'f{f}-{a}-s{s}-{c}','fold':f,'arm':a,'seed':s,'condition':c}
           for f in range(3) for a in cfg['arms'] for s in cfg['development_seeds'] for c in cfg['conditions']]
    if len(units)!=cfg['training_unit_budget'] or len({u['id'] for u in units})!=len(units):raise ValueError('unit budget/inventory mismatch')
    return units

def data_gate(paired, cfg):
    p=paired['rgcn_mixed'];g=cfg['gate']
    if p['pair_count']!=9:raise ValueError('gate requires nine pairs')
    passed=(p['mean_delta_mrr']+1e-12>=g['mean_delta_mrr'] and p['wins']>=g['wins_of_nine']
            and p['mean_delta_major_macro'] is not None and p['mean_delta_major_macro']+1e-12>=g['major_macro_delta_min'])
    return {'passed':passed,'meaning':'development_data_expansion_gate_only','reserved_evaluation_started':False,
            'mean_delta_mrr':p['mean_delta_mrr'],'wins_of_nine':p['wins'],'fixed_major_macro_delta':p['mean_delta_major_macro']}

def source_files(repo):
    repo=Path(repo)
    paths=[]
    for d in ['chapter5','chapter5/public_dev','chapter5/expanded_dev','chapter5/resolved_dev']:
        paths += [p for p in (repo/d).glob('*.py') if not p.name.startswith('test_')]
    paths += [repo/p for p in ['chapter5/requirements-cpu.txt','chapter5/resolved_dev/spec.md','chapter5/resolved_dev/plan.md','chapter5/resolved_dev/README.md','.github/workflows/chapter5-resolved-dev.yml']]
    return {p.relative_to(repo).as_posix():sha_file(p) for p in sorted(paths)}

def load_inputs(repo,cfg):
    base,external,groups,audit=read_package(Path(repo)/cfg['data_package'],cfg['data_sha256'])
    if len(external)!=856 or len(base['techniques'])!=31 or len(groups['reserved_ids'])!=155:raise ValueError('registered input count mismatch')
    if audit['source_sha256']['source_resolved_v3']!=cfg['source_resolved_v3_sha256']:raise ValueError('v3 source lineage mismatch')
    if len(groups['folds'])!=3 or len(audit['quarantined_original_ids'])!=12:raise ValueError('v3 registered split/quarantine mismatch')
    graphs={}
    for f in groups['folds']:
        for c in cfg['conditions']:
            graph=make_fold(base,external,f,c,groups['reserved_ids'],cfg['major_technique_train_support'])
            expected=next(s for s in audit['summaries'] if s['fold']==f['fold'] and s['condition']==c)
            if digest(graph)!=expected['graph_sha256']:raise ValueError('registered graph projection mismatch')
            if len(graph['split']['train'])!=cfg[c+'_training_cves_per_fold'][f['fold']] or len(graph['split']['dev'])!=cfg['validation_cves_per_fold'][f['fold']]:raise ValueError('registered role counts changed')
            graph_ids={n['id'] for n in graph['nodes']}
            if graph_ids&(set(groups['reserved_ids'])|set(audit['quarantined_original_ids'])):raise ValueError('protected node in runtime graph')
            graphs[(c,f['fold'])]=graph
    return graphs,groups,audit

def prepare(repo):
    repo=Path(repo);cfg=read_json(ROOT/'config.json')
    if (ROOT/'registration.json').exists():return verify_registration(repo)
    graphs,groups,audit=load_inputs(repo,cfg)
    reg={'protocol':cfg['protocol'],'config_sha256':sha_file(ROOT/'config.json'),'data_sha256':cfg['data_sha256'],
         'units':expected_units(cfg),'source_files':source_files(repo),'data_integration':audit,
         'model_api_calls':0,'reserved_holdout_evaluation':False,'confirmation_training_budget':0}
    atomic_json(ROOT/'registration.json',reg);return verify_registration(repo)

def verify_registration(repo):
    repo=Path(repo);cfg=read_json(ROOT/'config.json');reg=read_json(ROOT/'registration.json')
    if reg['config_sha256']!=sha_file(ROOT/'config.json') or reg['source_files']!=source_files(repo) or reg['units']!=expected_units(cfg):raise ValueError('frozen registration/config/source mismatch')
    if reg['protocol']!=cfg['protocol'] or reg['data_sha256']!=cfg['data_sha256']:raise ValueError('frozen protocol/data mismatch')
    if cfg['model_api_call_budget'] or cfg['data_download_budget'] or cfg['reserved_holdout_evaluation'] or cfg['confirmation_training_budget']:raise ValueError('unregistered network/reserved/confirmation budget')
    if platform.python_version()!='3.12.14' or torch.__version__!='2.9.1+cpu':raise ValueError('registered Python/Torch CPU mismatch')
    torch.set_num_threads(cfg['threads'])
    graphs,groups,audit=load_inputs(repo,cfg)
    if reg['data_integration']!=audit:raise ValueError('frozen integration audit mismatch')
    # Construct real numerical input graphs, never fit them during offline preparation.
    for graph in graphs.values():
        pg=PublicGraph(graph,'mixed');held={pg.ids[c] for c in graph['split']['dev']}
        if any(r==2 and s in held or r==7 and d in held for s,d,r in pg.message_edges):raise ValueError('held target message leakage')
    return {'phase':'offline_registration_verified','registered_training_units':36,'external_train_cves':856,
            'candidate_parent_techniques':31,'supervised_train_per_fold':{'base':cfg['base_training_cves_per_fold'],'augmented':cfg['augmented_training_cves_per_fold']},
            'scored_dev_per_fold':cfg['validation_cves_per_fold'],'graph_dev_per_fold':cfg['original_validation_cves_per_fold'],'reserved_cves':155,'reserved_nodes_in_run_graph':0,
            'registration_sha256':sha_file(ROOT/'registration.json'),'package_sha256':cfg['data_sha256'],
            'model_training_runs':0,'model_api_calls':0,'reserved_holdout_evaluated':False}

def freeze_baselines(graphs,cfg,directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    signature=digest({'graphs':{f'{c}-f{f}':digest(g) for (c,f),g in graphs.items()},'config':cfg})
    summary=directory/'summary.json';receipt=directory/'receipt.json'
    if summary.exists() or receipt.exists():
        if not summary.exists() or not receipt.exists():raise ValueError('incomplete baseline state')
        r=read_json(receipt)
        if r['binding']!=signature or any(sha_file(directory/n)!=h for n,h in r['files'].items()):raise ValueError('baseline receipt/binding mismatch')
        return read_json(summary)
    if any(directory.iterdir()):raise ValueError('unreceipted existing baseline outputs')
    choices=[('frequency',None),('cwe_frequency',None)]+[('smoothed_cwe',a) for a in cfg['smoothing_alphas']]+[('neighbor_vote',None)]
    metrics={}
    for kind,alpha in choices:
        key=kind+(f'-{alpha}' if alpha is not None else '');metrics[key]={}
        for (c,f),graph in sorted(graphs.items()):
            m,rows=evaluate_scores(graph,baseline_scores(graph,kind,alpha or 1),major_support=cfg['major_technique_train_support'])
            metrics[key][f'{c}-f{f}']=fixed_major(m,graph['fixed_major'])
            atomic_json(directory/f'{key}-{c}-f{f}-ranks.json',rows)
    joint_mean=lambda key:statistics.mean(v['mrr'] for v in metrics[key].values())
    alpha=max(cfg['smoothing_alphas'],key=lambda a:joint_mean(f'smoothed_cwe-{a}'))
    families=['frequency','cwe_frequency',f'smoothed_cwe-{alpha}','neighbor_vote']
    best={c:max(families,key=lambda key:statistics.mean(metrics[key][f'{c}-f{f}']['mrr'] for f in range(3))) for c in cfg['conditions']}
    result={'binding':signature,'selected_smoothing_alpha':alpha,'best_baseline':best,'metrics':metrics,
            'selection':'one alpha by joint six-condition/fold Dev mean; best family per condition by three-fold mean; fixed listed tie order',
            'paired_delta_mrr':{key:statistics.mean(metrics[key][f'augmented-f{f}']['mrr']-metrics[key][f'base-f{f}']['mrr'] for f in range(3)) for key in families},
            'reserved_holdout_evaluated':False}
    atomic_json(summary,result);atomic_json(receipt,{'binding':signature,'files':{p.name:sha_file(p) for p in sorted(directory.glob('*.json')) if p.name!='receipt.json'}})
    print(json.dumps({'phase':'baselines_frozen','alpha':alpha,'best_by_condition':best}),flush=True);return result

def run(repo,state,seconds):
    repo,state=Path(repo),Path(state);v=verify_registration(repo);cfg=read_json(ROOT/'config.json')
    if seconds!=cfg['slot_seconds']:raise ValueError('registered execution duration changed')
    deadline=time.monotonic()+seconds;state.mkdir(parents=True,exist_ok=True);signature=v['registration_sha256']
    binding_path=state/'input-binding.json'
    if binding_path.exists():
        if read_json(binding_path)['registration_sha256']!=signature:raise ValueError('restored registration mismatch')
    else:
        atomic_json(binding_path,{'registration_sha256':signature,'data_sha256':cfg['data_sha256']})
        for name in ['config.json','registration.json']:atomic_json(state/name,read_json(ROOT/name))
    graphs,groups,_=load_inputs(repo,cfg);reg=read_json(ROOT/'registration.json');ledger_path=state/'unit-ledger.json'
    ledger=read_json(ledger_path) if ledger_path.exists() else {'allowed':[u['id'] for u in reg['units']],'units':{},'registration_sha256':signature}
    if ledger['allowed']!=[u['id'] for u in reg['units']] or ledger['registration_sha256']!=signature or len(ledger['units'])>36:raise ValueError('unit ledger binding/inventory mismatch')
    baselines=freeze_baselines(graphs,cfg,state/'baselines');results=[]
    for unit in reg['units']:
        uid=unit['id'];directory=state/'units'/uid
        if time.monotonic()>=deadline and uid not in ledger['units']:break
        existed=uid in ledger['units'];claim_unit(ledger,uid,36);atomic_json(ledger_path,ledger)
        if existed and not (directory/'checkpoint.pt').exists():raise ValueError('reserved unit missing checkpoint; no reset')
        print(json.dumps({'phase':'unit_started_or_resumed','unit':uid,'unique_reserved_units':len(ledger['units'])}),flush=True)
        graph=graphs[(unit['condition'],unit['fold'])]
        result=train(graph,unit['arm'],cfg,unit['seed'],directory,deadline=deadline)
        ledger['units'][uid]={'status':result['status'],'epoch':result['epoch'],'binding':result['binding']};atomic_json(ledger_path,ledger)
        if result['status']=='checkpointed':break
        results.append(dict(result,unit=uid,fold=unit['fold'],condition=unit['condition'],dev=fixed_major(result['dev'],graph['fixed_major'])))
    complete=len(results)==36
    status={'phase':'development_complete' if complete else 'continuation_needed','registered_units':36,
            'reserved_units':len(ledger['units']),'completed_units':sum(r['status']=='trained' for r in ledger['units'].values()),
            'model_api_calls':0,'reserved_holdout_evaluated':False,'confirmation_training_started':False,'registration_sha256':signature}
    if complete:
        paired=paired_summary(results,reg['units']);gate=data_gate(paired,cfg);status['data_expansion_gate']=gate
        against={}
        for arm in cfg['arms']:
            values=[r for r in results if r['arm']==arm and r['condition']=='augmented']
            deltas=[r['dev']['mrr']-baselines['metrics'][baselines['best_baseline']['augmented']][f'augmented-f{r["fold"]}']['mrr'] for r in values]
            against[arm]={'mean_delta_mrr':statistics.mean(deltas),'wins_of_nine':sum(d>0 for d in deltas),'unit_deltas':deltas}
        comparison={'status':status,'paired_data_effect':paired,'augmented_vs_best_simple':against,'baselines':baselines,'results':results,'source_dev_overlap':groups['dev_overlap']}
        atomic_json(state/'comparison.json',comparison)
        lines=['# v3来源统一与争议隔离后的31父技术配对比较','', '完成36个登记单位；每折同Dev147/147/148，对比base Train691/691/690及augmented Train1547/1547/1546。','',
               '|方法|原数据MRR|扩展数据MRR|配对差|改善数|','|---|---:|---:|---:|---:|']
        lines += [f'|{a}|{p["mean_base_mrr"]:.6f}|{p["mean_augmented_mrr"]:.6f}|{p["mean_delta_mrr"]:.6f}|{p["wins"]}/9|' for a,p in paired.items()]
        lines += ['',f'数据扩展开发门槛：{"通过" if gate["passed"] else "未通过"}。',
                  '','31父技术任务与原697细/父混合候选不同，不能直接比较旧分数增幅。v3每折图Dev152/152/153中5无此范围标签，报告147/152、147/152、148/153覆盖；12个UNKNOWN所属CVE整体隔离。旧Dev150结果不能与新结果直接算增幅；partial缺失不是确认负例。三重复折有交叠，Dev参与早停及基线选择，成绩属于回顾性开发；2026背景不是2022时点输入。',
                  '','155保留CVE节点/边已从运行图排除且未评分。原训练结果与登记保持，科学预算本轮闭合，不自动新臂/确认实验。']
        (state/'report.md').write_text('\n'.join(lines)+'\n')
    atomic_json(state/'status.json',status);print(json.dumps(status,ensure_ascii=False),flush=True);return status

def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['prepare','verify','run']);p.add_argument('--repo',default='.');p.add_argument('--state');p.add_argument('--seconds',type=int,default=14400);a=p.parse_args()
    result=prepare(a.repo) if a.command=='prepare' else verify_registration(a.repo) if a.command=='verify' else run(a.repo,a.state,a.seconds)
    print(json.dumps(result,ensure_ascii=False,sort_keys=True),flush=True)

if __name__=='__main__':main()
