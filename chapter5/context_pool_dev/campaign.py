"""Registered nine-unit base candidate with durable checkpoints and unit budget."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from chapter5.core import digest
from chapter5.io import atomic_json, read_json, sha_file
from chapter5.archive import pack_state, restore_state
from chapter5.resolved_dev.data import read_package, make_fold
from .core import context_index, claim, paired

PREFIX='chapter5/context_pool_dev'
BRANCH='codex/chapter5-public-dev-20261011'


def inputs(repo,cfg):
    base,external,groups,audit=read_package(Path(repo)/cfg['data_package'],cfg['data_sha256'])
    graphs={f['fold']:make_fold(base,external,f,'base',groups['reserved_ids']) for f in groups['folds']}
    return graphs,groups,audit


def verify(repo):
    repo=Path(repo);root=repo/PREFIX;cfg=read_json(root/'config.json');reg=read_json(root/'registration.json')
    if sha_file(root/'config.json')!=reg['config_sha256'] or sha_file(root/'registration.json')!=read_json(root/'launch.json')['registration_sha256']:raise ValueError('candidate config/registration/launch mismatch')
    if cfg['training_unit_budget']!=9 or cfg['model_api_call_budget'] or cfg['reserved_holdout_evaluation'] or cfg['confirmation_training_budget']:raise ValueError('candidate scope/budget mismatch')
    if cfg['gate']!={'mean_delta_mrr':0.02,'wins_of_nine':6,'major_macro_delta_min':-0.01}:raise ValueError('candidate gate changed')
    for p,h in reg['files_sha256'].items():
        if sha_file(repo/p)!=h:raise ValueError('candidate source changed: '+p)
    old=read_json(repo/'chapter5/resolved_dev/registration.json')
    if sha_file(repo/'chapter5/resolved_dev/registration.json')!=reg['original_registration_sha256']:raise ValueError('original scientific registration changed')
    for p,h in old['source_files'].items():
        if sha_file(repo/p)!=h:raise ValueError('original source changed: '+p)
    graphs,groups,audit=inputs(repo,cfg)
    protected=set(groups['reserved_ids'])|set(audit['quarantined_original_ids'])|{'CVE-2017-0493','CVE-2019-7287'}
    if len(protected)!=169:raise ValueError('protected inventory')
    coverage=[]
    for f,g in graphs.items():
        if digest(g)!=reg['graphs'][str(f)]:raise ValueError('candidate base graph changed')
        if {n['id'] for n in g['nodes']}&protected:raise ValueError('protected runtime node')
        ctx=context_index(g)
        for role in ('train','dev'):
            ids=g['split'][role]
            if any(not any(ctx[c].values()) for c in ids):raise ValueError('registered actual query context coverage changed')
            coverage.append({'fold':f,'role':role,'n':len(ids),'coverage':1.})
    units=[{'id':f'f{f}-context_pool_mixed-s{s}','fold':f,'seed':s} for f in range(3) for s in [20261021,20261022,20261023]]
    if reg['units']!=units:raise ValueError('candidate unit inventory changed')
    return {'result':'offline_verified','registered_units':9,'graphs':3,'protected_ids':169,'coverage':coverage,'new_training':0,'new_forward':0,'historical_diagnosis_forward':288}


def publish(repo,message):
    def git(*args,capture=False):return subprocess.run(['git','-C',str(repo),*args],check=True,text=True,stdout=subprocess.PIPE if capture else None).stdout
    if git('branch','--show-current',capture=True).strip()!=BRANCH:raise ValueError('wrong execution branch')
    git('add','--',PREFIX)
    paths=git('diff','--cached','--name-only',capture=True).splitlines()
    if any(not p.startswith(PREFIX+'/') for p in paths):raise ValueError('out-of-scope staged mutation')
    if paths:
        git('commit','-m',message);git('push','origin','HEAD:refs/heads/'+BRANCH)


def run(repo,state):
    from chapter5.resolved_dev.campaign import verify_registration
    from .model import train
    from chapter5.public_dev.model import binding as original_binding
    repo,state=Path(repo),Path(state);root=repo/PREFIX
    verify(repo);verify_registration(repo)
    cfg=read_json(root/'config.json');reg=read_json(root/'registration.json');old_cfg=read_json(repo/'chapter5/resolved_dev/config.json')
    graphs,_,_=inputs(repo,cfg);signature=sha_file(root/'registration.json');saved=root/'runs';saved.mkdir(exist_ok=True)
    baseline=read_json(root/'baseline-inputs.json')
    for unit in reg['units']:
        prior=baseline['models'][f"f{unit['fold']}-distmult_mixed-s{unit['seed']}-base"]
        if original_binding(graphs[unit['fold']],'distmult_mixed',old_cfg,unit['seed'])!=prior['binding']:raise ValueError('frozen baseline numerical runtime binding differs')
    ledger_path=saved/'ledger.json'
    if ledger_path.exists():
        ledger=read_json(ledger_path)
        if ledger['registration_sha256']!=signature or ledger['budget']!=9 or set(ledger['units'])!={u['id'] for u in reg['units']}:raise ValueError('existing budget ledger changed; refuse reset')
        if any(v['status'] in ('reserved','running','UNKNOWN') for v in ledger['units'].values()):raise ValueError('uncertain previous training; explicit reconciliation required')
    else:
        ledger={'schema':'context-pool-unique-training-ledger-v1','registration_sha256':signature,'budget':9,'historical_diagnosis_forward':288,'state':'active','units':{u['id']:{'status':'planned'} for u in reg['units']},'checkpoint_replays':{u['id']:{'status':'planned'} for u in reg['units']}}
        atomic_json(ledger_path,ledger);publish(repo,'Initialize independent9-unit context-pool training ledger')
    state.mkdir(parents=True,exist_ok=True);results=[];deadline=time.monotonic()+cfg['slot_seconds']
    for unit in reg['units']:
        uid=unit['id'];directory=state/'units'/uid;archive=saved/uid;row=ledger['units'][uid]
        if row['status']=='done':
            if not (archive/'manifest.json').exists():raise ValueError('successful unit missing persistent archive')
            restore_state(archive,directory)
            info=read_json(directory/'completed.json')
            if any(sha_file(directory/n)!=h for n,h in info['files'].items()):raise ValueError('successful unit cache changed')
            r=read_json(directory/'result.json');results.append(dict(r,unit=uid,fold=unit['fold']));continue
        resumed=row['status']=='checkpointed'
        if resumed:
            restore_state(archive,directory)
        else:
            claim(ledger,uid);row.update(run_id=os.environ['GITHUB_RUN_ID'],attempt=os.environ['GITHUB_RUN_ATTEMPT'])
            atomic_json(ledger_path,ledger);publish(repo,'Reserve context-pool training unit '+uid)
        def persist(status,checkpoint_state):
            manifest=pack_state(directory,archive)
            row.update(status=status,epoch=checkpoint_state['epoch'],optimization_forwards=checkpoint_state['optimization_forwards'],dev_scoring_forwards=checkpoint_state['dev_scoring_forwards'],archive_sha256=manifest['source_sha256'],checkpoint_sha256=sha_file(directory/'checkpoint.pt'))
            atomic_json(ledger_path,ledger);publish(repo,'Persist context-pool '+uid+' epoch'+str(checkpoint_state['epoch'])+' '+status)
        try:
            r=train(graphs[unit['fold']],cfg,old_cfg,unit['seed'],directory,persist,deadline)
        except BaseException:
            row['status']='UNKNOWN';ledger['state']='stopped_unknown';atomic_json(ledger_path,ledger)
            try:publish(repo,'Stop uncertain context-pool unit '+uid)
            except Exception:pass
            raise
        if r['status']=='checkpointed':
            ledger['state']='continuation_needed';atomic_json(ledger_path,ledger);publish(repo,'Close known-checkpoint context-pool slot without budget reset');return
        results.append(dict(r,unit=uid,fold=unit['fold']))
    baseline=read_json(root/'baseline-inputs.json');summary=paired(results,baseline,cfg['gate'])
    output={'protocol':cfg['protocol'],'registration_sha256':signature,'results':results,'paired':summary,'training_units':9,'coverage':1.,'reserved_holdout_evaluated':False,'diagnostic_forward_prior':288,'optimization_forwards':sum(r['optimization_forwards'] for r in results),'dev_scoring_forwards':sum(r['dev_scoring_forwards'] for r in results),'model_api_calls':0}
    ledger['state']='training_complete';atomic_json(ledger_path,ledger);atomic_json(saved/'comparison.json',output);publish(repo,'Complete all9 context-pool units and fixed paired development comparison')
    print(json.dumps({'phase':'training_complete','units':9,'paired':summary,'optimization_forwards':output['optimization_forwards'],'dev_scoring_forwards':output['dev_scoring_forwards']},ensure_ascii=False),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['verify','run']);p.add_argument('--repo',default='.');p.add_argument('--state');a=p.parse_args()
    if a.command=='verify':print(json.dumps(verify(a.repo),ensure_ascii=False))
    else:
        if not a.state:raise ValueError('state is required')
        run(a.repo,a.state)
