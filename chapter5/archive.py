"""Checksummed persistent state, with durable reservation before source requests."""
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from chapter5.core import digest
from chapter5.io import atomic_json, read_json, sha_file

LIMIT=2*1024*1024*1024
PART_BYTES=4*1024*1024


def check_previous_session(session):
    if session and session.get('status')!='closed':
        raise ValueError('uncertain previous runner state; restore its original evidence before resuming')


def pack_state(root,destination):
    root,destination=Path(root),Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    if destination.resolve().is_relative_to(root.resolve()):
        raise ValueError('archive cannot be nested inside its source')
    handle=tempfile.NamedTemporaryFile(suffix='.zip',delete=False)
    path=Path(handle.name);handle.close()
    try:
        with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for file in sorted(root.rglob('*')):
                if not file.is_file():
                    continue
                relative=file.relative_to(root).as_posix()
                if file.is_symlink() or '..' in Path(relative).parts:
                    raise ValueError('unsafe state file')
                info=zipfile.ZipInfo(relative,date_time=(1980,1,1,0,0,0))
                info.compress_type=zipfile.ZIP_DEFLATED
                with file.open('rb') as source,z.open(info,'w',force_zip64=True) as target:
                    shutil.copyfileobj(source,target,1024*1024)
        if path.stat().st_size>LIMIT:
            raise ValueError('state archive exceeds declared 2 GiB bound')
        parts=[]
        with path.open('rb') as stream:
            for index,body in enumerate(iter(lambda:stream.read(PART_BYTES),b'')):
                name=f'state.part-{index:03d}'
                (destination/name).write_bytes(body)
                parts.append({'path':name,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()})
        keep={p['path'] for p in parts}
        for old in destination.glob('state.part-*'):
            if old.name not in keep:
                old.unlink()
        manifest={'schema':'chapter5-state-parts-v1','source_bytes':path.stat().st_size,'source_sha256':sha_file(path),'parts':parts}
        atomic_json(destination/'manifest.json',manifest)
        return manifest
    finally:
        path.unlink(missing_ok=True)


def restore_state(source,destination):
    source,destination=Path(source),Path(destination)
    manifest=read_json(source/'manifest.json')
    if manifest['schema']!='chapter5-state-parts-v1' or manifest['source_bytes']>LIMIT:
        raise ValueError('invalid archive manifest')
    bodies=[]
    for part in manifest['parts']:
        name=Path(part['path'])
        if name.is_absolute() or len(name.parts)!=1 or not name.name.startswith('state.part-'):
            raise ValueError('unsafe archive part path')
        raw=(source/name).read_bytes()
        if len(raw)!=part['bytes'] or hashlib.sha256(raw).hexdigest()!=part['sha256']:
            raise ValueError('state archive part integrity failure')
        bodies.append(raw)
    raw=b''.join(bodies)
    if len(raw)!=manifest['source_bytes'] or hashlib.sha256(raw).hexdigest()!=manifest['source_sha256']:
        raise ValueError('state archive integrity failure')
    destination.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names=[m.filename for m in z.infolist()]
        if len(names)!=len(set(names)) or sum(m.file_size for m in z.infolist())>LIMIT or len(names)>100000:
            raise ValueError('unsafe archive size or duplicate members')
        for member in z.infolist():
            path=Path(member.filename)
            if path.is_absolute() or '..' in path.parts or not path.parts:
                raise ValueError('unsafe ZIP member')
            if (member.external_attr>>16)&0o170000==0o120000:
                raise ValueError('symlink ZIP member forbidden')
            target=destination/path
            if target.exists():
                raise ValueError('refuse to overwrite existing restored state')
            if member.is_dir():
                target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with z.open(member) as source,target.open('wb') as output:
                shutil.copyfileobj(source,output,1024*1024)
    return manifest


def git(repo,*args,capture=False):
    result=subprocess.run(['git','-C',str(repo),*args],check=True,stdout=subprocess.PIPE if capture else None)
    return result.stdout.decode().strip() if capture else None


def sync(repo,branch):
    # A concurrent code change is never pulled into a running scientific job.
    git(repo,'fetch','origin',branch)
    changed=git(repo,'diff','--name-only','HEAD','FETCH_HEAD','--','chapter5','.github/workflows/chapter5-cpu-v1.yml',capture=True)
    forbidden=[p for p in changed.splitlines() if p and not p.startswith('chapter5/runs/') and p!='chapter5/launch.json']
    if forbidden:
        raise ValueError('remote experiment code changed during execution: '+','.join(forbidden))
    git(repo,'merge','--ff-only','FETCH_HEAD')


def commit_outputs(repo,path,branch,message):
    git(repo,'config','user.name','chapter5-experiment')
    git(repo,'config','user.email','chapter5-experiment@users.noreply.github.com')
    git(repo,'add','--',str(path.relative_to(repo)))
    if not git(repo,'diff','--cached','--name-only',capture=True):
        return
    git(repo,'commit','-m',message+' [skip ci]')
    git(repo,'push','origin','HEAD:refs/heads/'+branch)


def reserve(repo,state,cfg,branch):
    sync(repo,branch)
    saved=repo/'chapter5/runs'/cfg['protocol']
    session_path=saved/'session.json'
    previous=read_json(session_path) if session_path.exists() else None
    check_previous_session(previous)
    if (saved/'manifest.json').exists():
        restore_state(saved,state)
    elif previous:
        raise ValueError('previous session has no durable archive')
    run_id=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
    session={'status':'active','protocol':cfg['protocol'],'run_id':run_id,'attempt':attempt,
             'source_commit':os.environ['GITHUB_SHA'],'config_sha256':digest(cfg),
             'previous_archive_sha256':read_json(saved/'manifest.json')['source_sha256'] if (saved/'manifest.json').exists() else None}
    atomic_json(session_path,session)
    commit_outputs(repo,saved,branch,'Reserve Chapter 5 CPU execution '+run_id+'/'+attempt)
    state.mkdir(parents=True,exist_ok=True)
    atomic_json(state/'execution.json',session)
    print(json.dumps({'phase':'reserved','run_id':run_id,'attempt':attempt,'restored':bool(previous),'model_api_calls':0}),flush=True)


def close(repo,state,cfg,branch):
    saved=repo/'chapter5/runs'/cfg['protocol']
    session=read_json(saved/'session.json')
    if session['status']!='active' or session['run_id']!=os.environ['GITHUB_RUN_ID'] or session['attempt']!=os.environ['GITHUB_RUN_ATTEMPT']:
        raise ValueError('runner reservation mismatch')
    manifest=pack_state(state,saved)
    phase=read_json(state/'status.json') if (state/'status.json').exists() else {'phase':'interrupted_before_status'}
    session.update(status='closed',archive_sha256=manifest['source_sha256'],phase=phase.get('phase'),model_api_calls=0)
    atomic_json(saved/'session.json',session)
    atomic_json(saved/'status.json',phase)
    for original,name in ((state/'data/freeze.json','data-freeze.json'),(state/'models/result.json','result.json'),(state/'models/report.md','report.md')):
        if original.exists():
            shutil.copyfile(original,saved/name)
    # Remote management edits are allowed; scientific inputs are checked by sync.
    sync(repo,branch)
    commit_outputs(repo,saved,branch,'Archive Chapter 5 state '+session['run_id']+'/'+session['attempt'])
    print(json.dumps({'phase':'state_archived','source_sha256':manifest['source_sha256'],'parts':len(manifest['parts']),
                      'experiment_phase':phase.get('phase'),'model_api_calls':0}),flush=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['reserve','close','restore'])
    p.add_argument('--repo',default='.');p.add_argument('--state',required=True);p.add_argument('--config',default='chapter5/config.json')
    p.add_argument('--branch',default='codex/chapter5-v1-20261010');p.add_argument('--archive')
    a=p.parse_args();repo=Path(a.repo).resolve();state=Path(a.state).resolve();cfg=read_json(a.config)
    if a.action=='restore':
        restore_state(Path(a.archive),state);return
    if a.branch!='codex/chapter5-v1-20261010' or os.environ.get('GITHUB_REPOSITORY')!='Thehe01/experiment4':
        raise ValueError('unexpected execution repository/branch')
    if a.action=='reserve':
        reserve(repo,state,cfg,a.branch)
    else:
        close(repo,state,cfg,a.branch)


if __name__=='__main__':
    main()
