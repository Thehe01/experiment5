"""Durable CPU slot reservation and bounded state archive."""
import argparse
import json
import os
from pathlib import Path
from chapter5.archive import git,commit_outputs,pack_state,restore_state,check_previous_session
from chapter5.io import read_json,atomic_json
from chapter5.resolved_dev.campaign import verify_registration
PREFIX='chapter5/resolved_dev/runs/'


def sync(repo,branch):
    git(repo,'fetch','origin',branch)
    changed=git(repo,'diff','--name-only','HEAD','FETCH_HEAD',capture=True).splitlines()
    forbidden=[p for p in changed if not p.startswith(PREFIX) and p!='EXPERIMENT_PLAN.md']
    if forbidden:raise ValueError('remote frozen source changed: '+','.join(forbidden))
    git(repo,'merge','--ff-only','FETCH_HEAD')


def reserve(repo,state,cfg,branch,run_id,attempt,slot):
    repo,state=Path(repo),Path(state)
    if branch!=cfg['activation_branch']:raise ValueError('unexpected activation branch')
    if slot<1 or slot>cfg['max_execution_slots']:raise ValueError('execution slot budget exhausted')
    if state.exists() and any(state.iterdir()):raise ValueError('runner state already exists')
    sync(repo,branch);verification=verify_registration(repo)
    launch=read_json(repo/'chapter5/resolved_dev/launch.json')
    if launch['registration_sha256']!=verification['registration_sha256']:raise ValueError('launch registration mismatch')
    diff=git(repo,'diff','--name-only',launch['source_commit'],'HEAD',capture=True).splitlines()
    if any(p!='chapter5/resolved_dev/launch.json' and p!='EXPERIMENT_PLAN.md' and not p.startswith(PREFIX) for p in diff):
        raise ValueError('launch source commit mismatch')
    saved=repo/PREFIX/cfg['protocol'];session_path=saved/'session.json'
    previous=read_json(session_path) if session_path.exists() else None
    check_previous_session(previous)
    if previous:
        if previous['phase']!='continuation_needed':raise ValueError('previous execution does not permit continuation')
        if previous['slot']+1!=slot:raise ValueError('execution slot order mismatch')
        if previous['run_id']!=run_id or previous['attempt']!=attempt:raise ValueError('new workflow attempt needs explicit recovery registration')
        if not (saved/'manifest.json').exists():raise ValueError('previous session missing durable archive')
        restore_state(saved,state)
    elif slot!=1:raise ValueError('first execution must be slot one')
    elif (saved/'manifest.json').exists():raise ValueError('unregistered preexisting archive')
    session={'status':'active','phase':'reserved','protocol':cfg['protocol'],'run_id':run_id,'attempt':attempt,'slot':slot,'registration_sha256':verification['registration_sha256'],'source_commit':launch['source_commit']}
    atomic_json(session_path,session)
    # This push precedes all training; uncertain jobs cannot be silently reset.
    commit_outputs(repo,saved,branch,f'Reserve source-resolved development CPU slot {slot} run {run_id}/{attempt}')
    state.mkdir(parents=True,exist_ok=True);atomic_json(state/'execution.json',session)
    print(json.dumps({'phase':'durably_reserved','slot':slot,'run_id':run_id,'restored':bool(previous),'model_api_calls':0}),flush=True)
    return session


def close(repo,state,cfg,branch,run_id,attempt,slot,successful):
    repo,state=Path(repo),Path(state);saved=repo/PREFIX/cfg['protocol']
    session=read_json(saved/'session.json')
    if session['status']!='active' or (session['run_id'],session['attempt'],session['slot'])!=(run_id,attempt,slot):
        raise ValueError('execution session ownership mismatch')
    status=read_json(state/'status.json') if (state/'status.json').exists() else {'phase':'failed_before_campaign_status'}
    if not successful:status=dict(status,phase='failed')
    if successful and status['phase'] not in ('development_complete','continuation_needed'):raise ValueError('invalid campaign close phase')
    session=dict(session,status='closed',phase=status['phase'],campaign=status)
    atomic_json(state/'status.json',status);atomic_json(state/'execution.json',session)
    sync(repo,branch)
    pack_state(state,saved)
    atomic_json(saved/'session.json',session);atomic_json(saved/'status.json',status)
    if (state/'comparison.json').exists():atomic_json(saved/'comparison.json',read_json(state/'comparison.json'))
    if (state/'report.md').exists():(saved/'report.md').write_bytes((state/'report.md').read_bytes())
    commit_outputs(repo,saved,branch,f'Archive source-resolved development CPU slot {slot} run {run_id}/{attempt}')
    output=os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output,'a') as f:f.write(f"phase={status['phase']}\nclosed=true\n")
    print(json.dumps({'phase':'durably_closed','slot':slot,'campaign':status}),flush=True)
    return session


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['reserve','close']);p.add_argument('--repo',default='.');p.add_argument('--state',required=True);p.add_argument('--slot',required=True,type=int);p.add_argument('--successful',choices=['true','false'],default='false');a=p.parse_args()
    repo=Path(a.repo);cfg=read_json(repo/'chapter5/resolved_dev/config.json')
    args=(repo,Path(a.state),cfg,cfg['activation_branch'],os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],a.slot)
    if a.command=='reserve':reserve(*args)
    else:close(*args,a.successful=='true')

if __name__=='__main__':main()
