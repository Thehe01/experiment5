"""Nine registered checkpoint replays, then cache-only independent result audit."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import zipfile
from chapter5.io import atomic_json, read_json, sha_file
from chapter5.core import digest
from chapter5.public_dev.core import evaluate_scores
from chapter5.resolved_dev.data import fixed_major
from .campaign import PREFIX, verify, inputs, publish
from .core import paired


def error(a,b):
    if isinstance(a,dict):return max([0.]+[error(v,b[k]) for k,v in a.items()])
    if isinstance(a,list):
        if len(a)!=len(b):raise ValueError('list inventory mismatch')
        return max([0.]+[error(x,y) for x,y in zip(a,b)])
    if isinstance(a,(int,float)) and not isinstance(a,bool):return abs(a-b)
    if a!=b:raise ValueError('metadata mismatch')
    return 0.


def replay(repo,state):
    import torch
    from chapter5.model import load_state
    from chapter5.public_dev.model import PublicGraph
    from .model import ContextPoolPredictor,candidate_scores,binding
    repo,state=Path(repo),Path(state);root=repo/PREFIX;cfg=read_json(root/'config.json');reg=read_json(root/'registration.json');saved=root/'runs'
    verify(repo);graphs,_,_=inputs(repo,cfg);oldcfg=read_json(repo/'chapter5/resolved_dev/config.json');ledger=read_json(saved/'ledger.json')
    if ledger['state'] not in ('training_complete','complete'):raise ValueError('nine trainings must be complete before replay')
    if any(r['status'] in ('reserved','UNKNOWN') for r in ledger['checkpoint_replays'].values()):raise ValueError('uncertain checkpoint replay; do not repeat')
    torch.set_num_threads(2);torch.use_deterministic_algorithms(True)
    for u in reg['units']:
        uid=u['id'];row=ledger['checkpoint_replays'][uid];directory=state/'units'/uid;receipt=directory/'replay.json'
        if row['status']=='done':
            if sha_file(receipt)!=row['receipt_sha256']:raise ValueError('successful replay receipt changed')
            continue
        if row['status']!='planned':raise ValueError('unregistered replay state')
        signature=binding(graphs[u['fold']],cfg,oldcfg,u['seed']);checkpoint=load_state(directory/'checkpoint.pt',signature)
        pg=PublicGraph(graphs[u['fold']],'mixed');net=ContextPoolPredictor(pg,'distmult',cfg['params'],cfg);net.load_state_dict(checkpoint['best_model'])
        row['status']='reserved';atomic_json(saved/'ledger.json',ledger);publish(repo,'Reserve candidate checkpoint verification forward '+uid)
        try:
            scores,abstained=candidate_scores(net,pg,graphs[u['fold']]['split']['dev'])
            difference=error(scores,read_json(directory/'scores.json'))
            if abstained or difference!=0.:raise ValueError('candidate checkpoint score replay mismatch')
            atomic_json(receipt,{'unit':uid,'binding':signature,'checkpoint_sha256':sha_file(directory/'checkpoint.pt'),'score_sha256':sha_file(directory/'scores.json'),'max_score_error':difference,'verification_forward':1,'abstained':[]})
            row.update(status='done',receipt_sha256=sha_file(receipt));atomic_json(saved/'ledger.json',ledger)
            # Replay receipt is saved separately, keeping the already-closed unit archive immutable.
            atomic_json(saved/(uid+'-replay.json'),read_json(receipt));publish(repo,'Persist candidate checkpoint replay verification '+uid)
        except BaseException:
            row['status']='UNKNOWN';ledger['state']='stopped_replay_unknown';atomic_json(saved/'ledger.json',ledger)
            try:publish(repo,'Stop uncertain candidate checkpoint replay '+uid)
            except Exception:pass
            raise
    ledger['state']='complete';atomic_json(saved/'ledger.json',ledger);publish(repo,'Close9 candidate checkpoint verification forwards')


def audit(repo,state,persist):
    repo,state=Path(repo),Path(state);root=repo/PREFIX;cfg=read_json(root/'config.json');reg=read_json(root/'registration.json');saved=root/'runs'
    verify(repo);graphs,_,_=inputs(repo,cfg);ledger=read_json(saved/'ledger.json');comparison=read_json(saved/'comparison.json');baseline=read_json(root/'baseline-inputs.json')
    if ledger['state']!='complete' or any(v['status']!='done' for v in ledger['units'].values()) or any(v['status']!='done' for v in ledger['checkpoint_replays'].values()):raise ValueError('incomplete scientific units/replays')
    if ledger['budget']!=9 or ledger['historical_diagnosis_forward']!=288:raise ValueError('ledger accounting changed')
    results=[];max_error=0.
    for u in reg['units']:
        uid=u['id'];d=state/'units'/uid;r=read_json(d/'result.json');scores=read_json(d/'scores.json');receipt=read_json(d/'completed.json');cp=read_json(d/'checkpoint.pt.receipt.json');g=graphs[u['fold']]
        if any(sha_file(d/n)!=h for n,h in receipt['files'].items()) or sha_file(d/'checkpoint.pt')!=cp['sha256']:raise ValueError('unit receipt/hash mismatch')
        if r['binding']!=cp['binding'] or r['binding']!=receipt['binding']:raise ValueError('unit binding mismatch')
        if len(scores)!=len(g['split']['dev']) or r['coverage']!=1. or r['abstained']:raise ValueError('full registered Dev coverage required')
        metrics,rows=evaluate_scores(g,scores,major_support=cfg['major_technique_train_support']);metrics=fixed_major(metrics,g['fixed_major'])
        e=error(metrics,r['dev']);max_error=max(max_error,e)
        if e>1e-12 or rows!=read_json(d/'ranks.json'):raise ValueError('independent score/rank audit failed')
        logs=[json.loads(line) for line in (d/'epochs.jsonl').read_text().splitlines()]
        if len(logs)!=r['epoch'] or [x['epoch'] for x in logs]!=list(range(1,r['epoch']+1)):raise ValueError('epoch history incomplete')
        best=-1.;best_epoch=0;patience=0
        for x in logs:
            if x['dev_mrr']>best+cfg['min_improvement']:best=x['dev_mrr'];best_epoch=x['epoch'];patience=0
            else:patience+=1
        if best_epoch!=r['best_epoch'] or abs(best-r['dev']['mrr'])>1e-12:raise ValueError('early-stop selection mismatch')
        if r['stopping_reason']=='patience' and patience!=30 or r['stopping_reason']=='max_epochs' and r['epoch']!=500:raise ValueError('stopping rule mismatch')
        if r['optimization_forwards']!=r['epoch'] or r['dev_scoring_forwards']!=r['epoch']+1:raise ValueError('epoch forward accounting mismatch')
        if read_json(saved/(uid+'-replay.json'))['max_score_error']!=0.:raise ValueError('checkpoint replay failed')
        results.append(dict(r,unit=uid,fold=u['fold']))
    p=paired(results,baseline,cfg['gate'])
    if error(p,comparison['paired'])>1e-12:raise ValueError('paired/gate arithmetic mismatch')
    output={'result':'passed','training_units':9,'checkpoint_verification_forwards':9,'historical_diagnostic_forwards_unchanged':288,'model_api_calls':0,'reserved_scoring':False,'coverage':1.,'cache_metric_max_error':max_error,'paired':p,'optimization_forwards':sum(r['optimization_forwards'] for r in results),'dev_scoring_forwards':sum(r['dev_scoring_forwards'] for r in results),'epoch_range':[min(r['epoch'] for r in results),max(r['epoch'] for r in results)],'registration_sha256':sha_file(root/'registration.json'),'interpretation':'retrospective transductive Dev candidate, not independent final Test or confirmation'}
    atomic_json(saved/'verification.json',output)
    lines=['# v3 base context-pool候选：9单位完成','','旧诊断288次保持，新训练单位9、独立最佳checkpoint重放9；优化与每epoch Dev评分forward另行计量。155保留组未评分。旧36单位未重训。','','|比较|结果|','|---|---:|',f"|原base DistMult平均MRR|{p['mean_baseline_mrr']:.6f}|",f"|context-pool平均MRR|{p['mean_candidate_mrr']:.6f}|",f"|配对平均ΔMRR|{p['mean_delta_mrr']:+.6f}|",f"|改善配对|{p['wins']}/9|",f"|主要23类宏ΔMRR|{p['mean_delta_major_macro']:+.6f}|",f"|相对Neighbor vote平均ΔMRR|{p['neighbor_mean_delta']:+.6f}|",f"|超过Neighbor vote|{p['neighbor_wins']}/9|",f"|预注册开发门槛|{'通过' if p['development_gate_passed'] else '未通过'}|",'','评分覆盖率100%；全部缓存评分重算及9个最佳checkpoint分数重放通过。三折有交叠，Dev用于早停与候选开发；背景辅助边仍包括已知Dev背景，属于传导协议。结果不证明新CVE归纳能力或独立测试增益。','','本轮按固定9单位闭合；不自动调参、扩容、打开reserved、启动确认训练或合并main。原冻结结果与账本不改变。']
    (saved/'report.md').write_text('\n'.join(lines)+'\n')
    # All original unit archives remain byte-stable. An additional portable package contains full new state.
    files=[]
    for u in reg['units']:files += [p for p in sorted((state/'units'/u['id']).rglob('*')) if p.is_file()]
    destination=saved/'complete-evidence.zip'
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for f in files:z.write(f,f.relative_to(state).as_posix())
        for f in [root/'config.json',root/'registration.json',root/'baseline-inputs.json',saved/'ledger.json',saved/'comparison.json',saved/'verification.json',saved/'report.md']:
            z.write(f,'metadata/'+f.name)
    atomic_json(saved/'evidence-manifest.json',{'archive_sha256':sha_file(destination),'archive_bytes':destination.stat().st_size,'state_files':{f.relative_to(state).as_posix():{'sha256':sha_file(f),'bytes':f.stat().st_size} for f in files},'checkpoint_count':9,'units':9})
    if persist:publish(repo,'Audit and archive9-unit context-pool candidate with fixed development gate')
    print(json.dumps(output,ensure_ascii=False),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['replay','audit']);p.add_argument('--repo',default='.');p.add_argument('--state',required=True);p.add_argument('--persist',action='store_true');a=p.parse_args()
    if a.command=='replay':replay(a.repo,a.state)
    else:audit(a.repo,a.state,a.persist)
