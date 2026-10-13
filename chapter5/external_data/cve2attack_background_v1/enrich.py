"""CVE2ATT&CK metadata enrichment; no scientific model operations."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import re

CANDIDATE_SHA = '3d50c15b49ac811839c402a8bf519430e15b4c75cea7ab8667110cc0e0ee3281'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def json_bytes(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode()

def read_candidates(path):
    raw=Path(path).read_bytes()
    if digest(raw)!=CANDIDATE_SHA: raise ValueError('Candidate input SHA mismatch')
    rows=[json.loads(l) for l in raw.splitlines() if l]
    if len(rows)!=860 or len({r['id'] for r in rows})!=860: raise ValueError('Candidate ID/count mismatch')
    return sorted(rows,key=lambda r:r['id'])

def parse_response(raw, requested):
    obj=json.loads(raw)
    if obj.get('format')!='NVD_CVE' or obj.get('version')!='2.0': raise ValueError('Unexpected NVD response format')
    items=obj.get('vulnerabilities')
    if not isinstance(items,list) or obj.get('totalResults')!=len(items) or obj.get('startIndex')!=0:
        raise ValueError('Incomplete or malformed batch')
    records={}
    for item in items:
        r=item['cve']; identifier=r['id']
        if identifier not in requested or identifier in records: raise ValueError('Unexpected or duplicate returned ID')
        records[identifier]=r
    return records

def cpe_family(value):
    if not isinstance(value,str): return None
    # Exactly the original graph adapter product-family parsing rule.
    parts,part,escaped=[],'',False
    for ch in value:
        if ch==':' and not escaped: parts.append(part);part=''
        else: part+=ch
        escaped=(not escaped) if ch=='\\' else False
    parts.append(part)
    if len(parts)!=13 or parts[:2]!=['cpe','2.3'] or parts[2] not in ('a','o','h'): return None
    if not parts[3] or not parts[4] or parts[3] in ('*','-') or parts[4] in ('*','-'): return None
    return ':'.join(parts[:5]+['*']*8)

def cpe_matches(obj,path='/configurations'):
    if isinstance(obj,list):
        for i,item in enumerate(obj): yield from cpe_matches(item,path+'/'+str(i))
    elif isinstance(obj,dict):
        for i,item in enumerate(obj.get('cpeMatch',[])):
            yield path+'/cpeMatch/'+str(i),item
        for k in ('nodes','children'):
            if k in obj: yield from cpe_matches(obj[k],path+'/'+k)

def enrich_record(candidate, record, provenance):
    if record.get('id')!=candidate['id']: raise ValueError('Metadata CVE identity mismatch')
    e=copy.deepcopy(candidate)
    evidence=[];unparsed=[];groups=collections.defaultdict(set)
    for wi,w in enumerate(record.get('weaknesses',[])):
        for di,d in enumerate(w.get('description',[])):
            value=d.get('value','')
            entry={'path':f'/weaknesses/{wi}/description/{di}', 'source':w.get('source'),
                   'type':w.get('type'),'lang':d.get('lang'),'value':value}
            if re.fullmatch(r'CWE-[1-9][0-9]*',value):
                evidence.append(entry);groups[w.get('source')].add(value)
            else: unparsed.append(entry)
    cpes=[];invalid=[];environment=0
    for path,m in cpe_matches(record.get('configurations',[])):
        if m.get('vulnerable') is not True:
            environment+=1;continue
        criteria=m.get('criteria');family=cpe_family(criteria)
        ev={'path':path,'match':copy.deepcopy(m),'family':family}
        if family: cpes.append(ev)
        else: invalid.append(ev)
    e.update(cwe_ids=sorted({x['value'] for x in evidence}), cwes=sorted({x['value'] for x in evidence}),
             cwe_evidence=evidence, unparsed_cwes=unparsed,
             cwe_source_disagreement=len({tuple(sorted(v)) for v in groups.values()})>1,
             cpes=sorted({x['match']['criteria'] for x in cpes}),
             cpe_families=sorted({x['family'] for x in cpes}), cpe_evidence=cpes,
             invalid_cpes=invalid, environment_cpe_count=environment,
             nvd_configurations=copy.deepcopy(record.get('configurations',[])),
             metadata_provenance=copy.deepcopy(provenance)|{'published':record.get('published'),
                 'lastModified':record.get('lastModified'),'vulnStatus':record.get('vulnStatus'),
                 'sourceIdentifier':record.get('sourceIdentifier')},
             metadata_as_of='current_snapshot_not_2022_historical', integration_status='not_integrated')
    e['graph_ready']=bool(e['cwe_ids'] or e['cpe_families']) and record.get('vulnStatus','').lower()!='rejected'
    e['metadata_status']=('rejected_source_record' if record.get('vulnStatus','').lower()=='rejected'
                          else 'background_ready' if e['graph_ready'] else 'no_usable_background')
    e['graph_context_status']=e['metadata_status']
    return e

def classify(candidate, record, provenance):
    if record is not None: return enrich_record(candidate,record,provenance)
    e=copy.deepcopy(candidate)
    e.update(metadata_status='fetch_failed' if provenance.get('fetch_error') else 'not_found',
             graph_ready=False, cwe_ids=[],cpe_families=[],metadata_provenance=copy.deepcopy(provenance),
             integration_status='not_integrated',metadata_as_of='current_snapshot_not_2022_historical')
    e['graph_context_status']=e['metadata_status']
    return e

def load_snapshot(cache,candidates):
    cache=Path(cache);manifest=json.loads((cache/'manifest.json').read_bytes())
    if manifest['candidate_sha256']!=CANDIDATE_SHA: raise ValueError('Snapshot input SHA mismatch')
    wanted={r['id'] for r in candidates};records={};provenance={}
    for b in manifest['batches']:
        ids=b['requested_ids']
        if not ids or not set(ids)<=wanted or set(ids)&set(provenance): raise ValueError('Snapshot ID partition mismatch')
        p={k:b[k] for k in ('url','fetched_at') if k in b}
        if b['status']=='ok':
            raw=(cache/b['response_file']).read_bytes()
            if digest(raw)!=b['response_sha256']: raise ValueError('Response SHA mismatch')
            records.update(parse_response(raw,ids))
            p.update(response_file=b['response_file'],response_sha256=b['response_sha256'])
        else: p['fetch_error']=b['error']
        for identifier in ids: provenance[identifier]=p
    if set(provenance)!=wanted: raise ValueError('Snapshot does not cover all candidates')
    return records,provenance,manifest

def build(candidates_path,cache,out):
    candidates=read_candidates(candidates_path);records,prov,snapshot=load_snapshot(cache,candidates)
    out=Path(out)
    if out.exists() and any(out.iterdir()): raise ValueError('Output directory must be empty')
    rows=[classify(c,records.get(c['id']),prov[c['id']]) for c in candidates]
    ready=[r for r in rows if r['graph_ready']];pending=[r for r in rows if not r['graph_ready']]
    edges=[]
    for r in ready:
        for t in r['cwe_ids']:edges.append({'head':r['id'],'relation':'has_reported_cwe','tail':t,'source':'nvd_reported_metadata'})
        for t in r['cpe_families']:edges.append({'head':r['id'],'relation':'has_reported_cpe','tail':t,'source':'nvd_reported_metadata'})
    # These are background edges only, never targets or new split assignments.
    summary={'input_candidates':len(rows),'found_in_nvd':len(records),'graph_ready':len(ready),
             'pending':len(pending),'status_counts':dict(collections.Counter(r['metadata_status'] for r in rows)),
             'both_cwe_cpe':sum(bool(r['cwe_ids']) and bool(r['cpe_families']) for r in ready),
             'cwe_only':sum(bool(r['cwe_ids']) and not r['cpe_families'] for r in ready),
             'cpe_only':sum(not r['cwe_ids'] and bool(r['cpe_families']) for r in ready),
             'cwe_source_disagreement':sum(r.get('cwe_source_disagreement',False) for r in rows),
             'invalid_cpe_records':sum(bool(r.get('invalid_cpes')) for r in rows),
             'background_edges':len(edges),'technique_associations_ready':sum(len(r['techniques']) for r in ready),
             'ready_technique_support':dict(sorted(collections.Counter(t for r in ready for t in r['techniques']).items())),
             'unique_cwe_ids':len({t for r in ready for t in r['cwe_ids']}),
             'unique_cpe_families':len({t for r in ready for t in r['cpe_families']}),
             'training_units':0,'model_api_calls':0,'reserved_scoring':0,'integration_started':False,
             'as_of':'2026_current_metadata_not_2022_historical'}
    out.mkdir(parents=True,exist_ok=True)
    for name,data in [('enriched-candidates.jsonl',rows),('graph-ready-candidates.jsonl',ready),
                      ('pending-review.jsonl',pending),('background-edges.jsonl',edges)]:
        (out/name).write_bytes(b''.join(json_bytes(r) for r in data))
    (out/'audit.json').write_bytes(json_bytes(summary))
    manifest={'candidate_sha256':CANDIDATE_SHA,'snapshot_manifest_sha256':digest((Path(cache)/'manifest.json').read_bytes()),
              'code_sha256':digest(Path(__file__).read_bytes()),'files':{p.name:digest(p.read_bytes()) for p in sorted(out.iterdir())}}
    (out/'manifest.json').write_bytes(json_bytes(manifest))
    return summary

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--candidates',required=True);p.add_argument('--cache',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();print(json.dumps(build(a.candidates,a.cache,a.out),ensure_ascii=False,sort_keys=True))
