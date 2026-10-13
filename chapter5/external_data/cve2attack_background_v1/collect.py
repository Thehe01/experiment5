"""Bounded, resumable official NVD metadata acquisition. No secrets needed."""
import argparse
import datetime
import json
from pathlib import Path
import time
import urllib.request
from enrich import read_candidates, parse_response, digest, json_bytes, CANDIDATE_SHA

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()

def collect(candidates,cache):
    ids=[r['id'] for r in read_candidates(candidates)];cache=Path(cache);cache.mkdir(parents=True,exist_ok=True)
    path=cache/'manifest.json'
    if path.exists():
        manifest=json.loads(path.read_bytes())
        if manifest['candidate_sha256']!=CANDIDATE_SHA: raise ValueError('Cannot reuse mismatching input')
    else: manifest={'source':'NVD_CVE_API_2.0','candidate_sha256':CANDIDATE_SHA,'started_at':now(),
                   'min_request_interval_seconds':6.1,'max_attempts_per_batch':3,'batches':[],'attempts':[]}
    last=0;changed=False
    for i in range(0,len(ids),100):
        chunk=ids[i:i+100];batch=i//100
        old=next((b for b in manifest['batches'] if b['batch']==batch),None)
        if old:
            if old['requested_ids']!=chunk:raise ValueError('Resume ID mismatch')
            if old['status']=='ok':
                raw=(cache/old['response_file']).read_bytes()
                if digest(raw)!=old['response_sha256']:raise ValueError('Resume SHA mismatch')
                parse_response(raw,chunk)
            print('reused batch',batch,flush=True);continue
        url='https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds='+','.join(chunk)
        b={'batch':batch,'requested_ids':chunk,'url':url,'status':'failed',
           'error':'attempt_budget_exhausted_after_prior_in_flight_requests','fetched_at':now()}
        changed=True
        for attempt in range(3):
            # Record intent before sending; abandoned attempts consume this bounded ledger.
            used=sum(x['batch']==batch for x in manifest['attempts'])
            if used>=3:break
            delay=max(0,6.1-(time.monotonic()-last))
            if delay:time.sleep(delay)
            last=time.monotonic();a={'batch':batch,'attempt':used+1,'sent_at':now(),'status':'in_flight'}
            manifest['attempts'].append(a);path.write_bytes(json_bytes(manifest))
            try:
                req=urllib.request.Request(url,headers={'User-Agent':'experiment4-offline-metadata/1.0','Accept':'application/json'})
                with urllib.request.urlopen(req,timeout=30) as response:
                    raw=response.read(32*1024*1024+1)
                    if len(raw)>32*1024*1024:raise ValueError('Response size limit')
                    returned=parse_response(raw,chunk)
                    name=f'batch-{batch:02d}-attempt-{used+1}.json';(cache/name).write_bytes(raw)
                    b.update(status='ok',response_file=name,response_sha256=digest(raw),bytes=len(raw),
                             fetched_at=now(),returned_count=len(returned),http_status=response.status)
                    a.update(status='ok',completed_at=now(),response_file=name,response_sha256=digest(raw))
                break
            except Exception as error:
                a.update(status='failed',completed_at=now(),error=type(error).__name__+': '+str(error))
                b.update(error=a['error'],fetched_at=now())
                print('attempt failed',batch,used+1,a['error'],flush=True)
            finally:path.write_bytes(json_bytes(manifest))
        manifest['batches'].append(b);path.write_bytes(json_bytes(manifest))
        print('batch',batch,b['status'],'returned',b.get('returned_count'), 'of',len(chunk),flush=True)
    if changed or 'completed_at' not in manifest:
        manifest['completed_at']=now();path.write_bytes(json_bytes(manifest))
    return {'batches':len(manifest['batches']),'attempts':len(manifest['attempts']),
            'ok':sum(b['status']=='ok' for b in manifest['batches'])}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--candidates',required=True);p.add_argument('--cache',required=True)
    a=p.parse_args();print(json.dumps(collect(a.candidates,a.cache)))
