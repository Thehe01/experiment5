"""Recover publication failure using saved success, never retrain or replay it."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from chapter5.io import atomic_json,read_json,sha_file
from chapter5.archive import restore_state
from chapter5.context_pool_dev.campaign import verify as scientific_verify,inputs

PREFIX='chapter5/context_pool_recovery_20261012'
SOURCE='chapter5/context_pool_dev'
BRANCH='codex/chapter5-public-dev-20261011'


def reconcile(receipt,row,inventory,receipt_sha):
    if row['status']!='UNKNOWN' or row['receipt_sha256']!=receipt_sha:raise ValueError('uncertain receipt hash')
    if receipt['verification_forward']!=1 or receipt['max_score_error']!=0 or receipt.get('abstained'):raise ValueError('not a saved successful single forward')
    for a,b in [('unit','unit'),('binding','binding'),('checkpoint_sha256','checkpoint_sha256'),('score_sha256','scores_sha256')]:
        if receipt[a]!=inventory[b]:raise ValueError('receipt input/output binding mismatch')
    return dict(copy.deepcopy(row),status='done',original_status='UNKNOWN',reconciled_from_saved_receipt=True)


def verify(repo):
    repo=Path(repo);root=repo/PREFIX;reg=read_json(root/'registration.json')
    scientific_verify(repo)
    if sha_file(repo/SOURCE/'registration.json')!=reg['scientific_registration_sha256']:raise ValueError('scientific registration changed')
    for name,h in reg['files_sha256'].items():
        if sha_file(repo/name)!=h:raise ValueError('recovery input changed '+name)
    if sha_file(root/'registration.json')!=read_json(root/'launch.json')['registration_sha256']:raise ValueError('recovery launch mismatch')
    old=read_json(root/'original-stopped-ledger.json');inventory={x['unit']:x for x in read_json(root/'state-inventory.json')};receipt=read_json(root/'reconciled-first-receipt.json')
    first=receipt['unit'];reconcile(receipt,old['checkpoint_replays'][first],inventory[first],sha_file(root/'reconciled-first-receipt.json'))
    remaining=[u for u,v in old['checkpoint_replays'].items() if v['status']=='planned']
    if len(remaining)!=8 or reg['remaining_original_replay_budget']!=8 or reg['original_replay_budget']!=9 or reg['already_executed_replays']!=1 or reg['new_training_budget']!=0:raise ValueError('original budget reconciliation failed')
    return {'result':'offline_recovery_verified','trained_units_reused':9,'already_executed_replay_reconciled':1,'remaining_replays':8,'new_training':0,'old_UNKNOWN_snapshot_unchanged':True}


def publish(repo,message):
    def git(*args,capture=False):return subprocess.run(['git','-C',str(repo),*args],check=True,text=True,stdout=subprocess.PIPE if capture else None).stdout
    if git('branch','--show-current',capture=True).strip()!=BRANCH:raise ValueError('wrong branch')
    git('add','--',PREFIX);paths=git('diff','--cached','--name-only',capture=True).splitlines()
    if any(not p.startswith(PREFIX+'/') for p in paths):raise ValueError('out-of-scope recovery mutation')
    if paths:
        git('commit','-m',message)
        git('push','--no-thin','origin','HEAD:refs/heads/'+BRANCH)


def run(repo,state):
    import torch
    from chapter5.model import load_state
    from chapter5.public_dev.model import PublicGraph
    from chapter5.context_pool_dev.model import ContextPoolPredictor,candidate_scores,binding
    from chapter5.context_pool_dev.verify_results import error,audit
    from chapter5.resolved_dev.campaign import verify_registration
    repo,state=Path(repo),Path(state);root=repo/PREFIX;verify(repo);verify_registration(repo)
    cfg=read_json(repo/SOURCE/'config.json');science=read_json(repo/SOURCE/'registration.json');old_cfg=read_json(repo/'chapter5/resolved_dev/config.json');graphs,_,_=inputs(repo,cfg)
    inventory={x['unit']:x for x in read_json(root/'state-inventory.json')};original=read_json(root/'original-stopped-ledger.json')
    state.mkdir(parents=True,exist_ok=True)
    for u in science['units']:
        d=state/'units'/u['id'];restore_state(repo/SOURCE/'runs'/u['id'],d)
        if sha_file(d/'checkpoint.pt')!=inventory[u['id']]['checkpoint_sha256'] or sha_file(d/'scores.json')!=inventory[u['id']]['scores_sha256']:raise ValueError('restored successful unit state mismatch')
    ledger_path=root/'ledger.json'
    if ledger_path.exists():
        ledger=read_json(ledger_path)
        if ledger['recovery_registration_sha256']!=sha_file(root/'registration.json') or any(v['status'] in ('reserved','UNKNOWN') for v in ledger['checkpoint_replays'].values()):raise ValueError('uncertain recovery; no automatic replay')
    else:
        ledger=copy.deepcopy(original);first=read_json(root/'reconciled-first-receipt.json');uid=first['unit']
        ledger['checkpoint_replays'][uid]=reconcile(first,original['checkpoint_replays'][uid],inventory[uid],sha_file(root/'reconciled-first-receipt.json'))
        ledger.update(state='recovery_active',recovery_registration_sha256=sha_file(root/'registration.json'),source_stopped_ledger_sha256=sha_file(root/'original-stopped-ledger.json'),new_training=0,already_executed_replays=1,new_replays_consumed=0)
        atomic_json(ledger_path,ledger);atomic_json(root/'receipts'/f'{uid}-replay.json',first);publish(repo,'Reconcile already executed checkpoint success without repeating forward')
    torch.set_num_threads(2);torch.use_deterministic_algorithms(True)
    for u in science['units']:
        uid=u['id'];row=ledger['checkpoint_replays'][uid];d=state/'units'/uid
        if row['status']=='done':continue
        if row['status']!='planned' or ledger['new_replays_consumed']>=8:raise ValueError('remaining original replay allocation exhausted')
        signature=binding(graphs[u['fold']],cfg,old_cfg,u['seed']);checkpoint=load_state(d/'checkpoint.pt',signature)
        pg=PublicGraph(graphs[u['fold']],'mixed');net=ContextPoolPredictor(pg,'distmult',cfg['params'],cfg);net.load_state_dict(checkpoint['best_model'])
        row['status']='reserved';ledger['new_replays_consumed']+=1;atomic_json(ledger_path,ledger);publish(repo,'Reserve remaining original checkpoint verification '+uid)
        try:
            scores,abstained=candidate_scores(net,pg,graphs[u['fold']]['split']['dev']);e=error(scores,read_json(d/'scores.json'))
            if e!=0 or abstained:raise ValueError('checkpoint replay mismatch')
            receipt={'unit':uid,'binding':signature,'checkpoint_sha256':sha_file(d/'checkpoint.pt'),'score_sha256':sha_file(d/'scores.json'),'max_score_error':e,'verification_forward':1,'abstained':[]}
            p=root/'receipts'/f'{uid}-replay.json';atomic_json(p,receipt);row.update(status='done',receipt_sha256=sha_file(p));atomic_json(ledger_path,ledger);publish(repo,'Persist remaining original checkpoint verification '+uid)
        except BaseException:
            row['status']='UNKNOWN';ledger['state']='stopped_recovery_unknown';atomic_json(ledger_path,ledger)
            try:publish(repo,'Stop uncertain recovery verification '+uid)
            except Exception:pass
            raise
    ledger['state']='complete';atomic_json(ledger_path,ledger);publish(repo,'Close original9 checkpoint replays: reconciled1 plus new8')
    # A private sparse view lets the frozen auditor read the reconciled ledger.
    # The original UNKNOWN ledger and scientific outputs in the real checkout stay untouched.
    view=Path(tempfile.mkdtemp(prefix='context-pool-audit-'))
    for p in repo.iterdir():
        if p.name not in ('.git','chapter5'):(view/p.name).symlink_to(p.resolve(),target_is_directory=p.is_dir())
    (view/'chapter5').mkdir()
    for p in (repo/'chapter5').iterdir():
        if p.name!='context_pool_dev':(view/'chapter5'/p.name).symlink_to(p.resolve(),target_is_directory=p.is_dir())
    cv=view/SOURCE;cv.mkdir()
    for p in (repo/SOURCE).iterdir():
        if p.is_file():shutil.copy2(p,cv/p.name)
    out=cv/'runs';out.mkdir();shutil.copy2(repo/SOURCE/'runs/comparison.json',out/'comparison.json');atomic_json(out/'ledger.json',ledger)
    for p in (root/'receipts').glob('*-replay.json'):shutil.copy2(p,out/p.name)
    audit(view,state,False)
    (root/'results').mkdir(exist_ok=False)
    for n in ('verification.json','report.md','complete-evidence.zip','evidence-manifest.json'):shutil.copy2(out/n,root/'results'/n)
    atomic_json(root/'completion.json',{'result':'passed','trained_units_reused':9,'new_training':0,'original_replay_budget':9,'already_executed_replay_reconciled':1,'remaining_replays_executed':8,'replay_total':9,'original_stopped_ledger_unchanged':sha_file(repo/SOURCE/'runs/ledger.json')==sha_file(root/'original-stopped-ledger.json'),'recovery_ledger_sha256':sha_file(ledger_path),'verification_sha256':sha_file(root/'results/verification.json'),'archive_sha256':sha_file(root/'results/complete-evidence.zip')})
    publish(repo,'Audit and fully archive frozen9-unit candidate through reconciled execution')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['verify','run']);p.add_argument('--repo',default='.');p.add_argument('--state');a=p.parse_args()
    if a.command=='verify':print(json.dumps(verify(a.repo)))
    else:run(a.repo,a.state)
