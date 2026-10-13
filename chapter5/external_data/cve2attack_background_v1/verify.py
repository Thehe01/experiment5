"""Independent raw-response and frozen-input audit; does not import enrich."""
import argparse
import ast
import collections
import hashlib
import json
from pathlib import Path
import re
import zipfile

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def rows(p):return [json.loads(l) for l in Path(p).read_bytes().splitlines() if l]
def walk(obj,path='/configurations'):
    if isinstance(obj,list):
        for i,x in enumerate(obj):yield from walk(x,path+'/'+str(i))
    elif isinstance(obj,dict):
        for i,x in enumerate(obj.get('cpeMatch',[])):yield path+'/cpeMatch/'+str(i),x
        for key in ['nodes','children']:
            if key in obj:yield from walk(obj[key],path+'/'+key)

def audit(candidate_path,cache,out,public_zip,fold_path,adapter_path):
    assert sha(candidate_path)=='3d50c15b49ac811839c402a8bf519430e15b4c75cea7ab8667110cc0e0ee3281'
    assert sha(public_zip)=='c00660f6d37cfefa2af35513ed785ca0e77f880746f34220edb204c353bfadbf'
    assert sha(fold_path)=='5fda5590c0b25448718f99381f0e35b4eac6ecf1cf9abc956fe964d0561f8190'
    assert sha(adapter_path)=='20391164132d6d9e4f4e2a1a30bd45dd7f3a29a6b7106cae484efd0f731cc922'
    # Use the original graph adapter's parser as a separate acceptance oracle.
    tree=ast.parse(Path(adapter_path).read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='cpe_family')
    scope={};exec(compile(ast.Module(body=[fn],type_ignores=[]),'<frozen-adapter>','exec'),scope)
    family=scope['cpe_family']
    candidates={r['id']:r for r in rows(candidate_path)};ids=set(candidates);assert len(ids)==860
    cache=Path(cache);out=Path(out);snapshot=json.loads((cache/'manifest.json').read_bytes());raw={};sources={}
    assert sha(cache/'manifest.json')=='e44ac6171c276513184ffab76d6a24be5887805b0e07753873498b47f705db09'
    assert snapshot['candidate_sha256']==sha(candidate_path)
    for b in snapshot['batches']:
        requested=set(b['requested_ids']);assert requested<=ids and not requested&set(sources)
        assert b['url']=='https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds='+','.join(b['requested_ids'])
        if b['status']=='ok':
            p=cache/b['response_file'];assert sha(p)==b['response_sha256'];obj=json.loads(p.read_bytes())
            assert obj['format']=='NVD_CVE' and obj['version']=='2.0' and obj['startIndex']==0
            assert obj['totalResults']==len(obj['vulnerabilities'])==b['returned_count']
            seen=set()
            for item in obj['vulnerabilities']:
                r=item['cve'];assert r['id'] in requested and r['id'] not in seen
                seen.add(r['id']);raw[r['id']]=r
        for identifier in requested:sources[identifier]=b
    assert set(sources)==ids
    actual=rows(out/'enriched-candidates.jsonl');assert len(actual)==860 and {r['id'] for r in actual}==ids
    ready=[];edges=[];counts=collections.Counter()
    for e in actual:
        identifier=e['id'];c=candidates[identifier];b=sources[identifier];r=raw.get(identifier)
        for key,value in c.items():
            if key not in {'cpes','cwes','graph_ready','graph_context_status'}:assert e[key]==value,(identifier,key)
        assert e['integration_status']=='not_integrated' and e['metadata_as_of']=='current_snapshot_not_2022_historical'
        assert e['metadata_provenance']['url']==b['url'] and e['metadata_provenance']['fetched_at']==b['fetched_at']
        if r is None:
            expected='fetch_failed' if b['status']!='ok' else 'not_found'
            assert not e['graph_ready'] and not e['cpes'] and not e['cwes']
        else:
            assert e['metadata_provenance']['response_sha256']==b['response_sha256']
            assert e['metadata_provenance']['lastModified']==r.get('lastModified')
            expected_cwe=[];unparsed=[];by_source=collections.defaultdict(set)
            for wi,w in enumerate(r.get('weaknesses',[])):
                for di,d in enumerate(w.get('description',[])):
                    entry={'path':f'/weaknesses/{wi}/description/{di}','source':w.get('source'),
                           'type':w.get('type'),'lang':d.get('lang'),'value':d.get('value','')}
                    if re.fullmatch(r'CWE-[1-9][0-9]*',entry['value']):
                        expected_cwe.append(entry);by_source[w.get('source')].add(entry['value'])
                    else:unparsed.append(entry)
            assert e['cwe_evidence']==expected_cwe and e['unparsed_cwes']==unparsed
            assert e['cwe_ids']==e['cwes']==sorted({v['value'] for v in expected_cwe})
            assert e['cwe_source_disagreement']==(len({tuple(sorted(v)) for v in by_source.values()})>1)
            expected_cpe=[];invalid=[];environment=0
            for path,match in walk(r.get('configurations',[])):
                if match.get('vulnerable') is not True:environment+=1;continue
                f=family(match.get('criteria',''))
                ev={'path':path,'match':match,'family':f}
                (expected_cpe if f else invalid).append(ev)
            assert e['nvd_configurations']==r.get('configurations',[]) and e['environment_cpe_count']==environment
            assert e['cpe_evidence']==expected_cpe and e['invalid_cpes']==invalid
            assert e['cpes']==sorted({v['match']['criteria'] for v in expected_cpe})
            assert e['cpe_families']==sorted({v['family'] for v in expected_cpe})
            reject=r.get('vulnStatus','').lower()=='rejected'
            expected='rejected_source_record' if reject else 'background_ready' if e['cwe_ids'] or e['cpe_families'] else 'no_usable_background'
            assert e['graph_ready']==(expected=='background_ready')
        assert e['metadata_status']==e['graph_context_status']==expected
        counts[expected]+=1
        if e['graph_ready']:
            ready.append(e)
            for t in e['cwe_ids']:edges.append({'head':identifier,'relation':'has_reported_cwe','tail':t,'source':'nvd_reported_metadata'})
            for t in e['cpe_families']:edges.append({'head':identifier,'relation':'has_reported_cpe','tail':t,'source':'nvd_reported_metadata'})
    assert ready==rows(out/'graph-ready-candidates.jsonl')
    assert [r for r in actual if not r['graph_ready']]==rows(out/'pending-review.jsonl')
    assert edges==rows(out/'background-edges.jsonl')
    audit=json.loads((out/'audit.json').read_bytes());assert audit['graph_ready']==len(ready) and audit['background_edges']==len(edges)
    assert audit['status_counts']==dict(counts)
    assert audit['technique_associations_ready']==sum(len(r['techniques']) for r in ready)
    assert audit['ready_technique_support']==dict(collections.Counter(t for r in ready for t in r['techniques']))
    assert audit['training_units']==audit['model_api_calls']==audit['reserved_scoring']==0 and not audit['integration_started']
    manifest=json.loads((out/'manifest.json').read_bytes())
    assert manifest['candidate_sha256']==sha(candidate_path) and manifest['snapshot_manifest_sha256']==sha(cache/'manifest.json')
    assert manifest['code_sha256']==sha(Path(__file__).with_name('enrich.py'))
    for name,digest in manifest['files'].items():assert sha(out/name)==digest
    z=zipfile.ZipFile(public_zip);public={r['id'] for r in [json.loads(l) for l in z.read('source-records.jsonl').splitlines()]}
    exposure=set(json.loads(z.read('exposure.json'))['excluded_union'])
    folds=json.loads(Path(fold_path).read_bytes());reserved=set(folds['reserved_ids'])
    assert len(reserved)==155 and not ids&reserved and not ids&public and not ids&exposure
    for fold in folds['folds']:assert not ids&set(fold['train']) and not ids&set(fold['dev'])
    attempts=snapshot['attempts'];assert len(attempts)<=27
    for b in snapshot['batches']:assert len(b['requested_ids'])<=100 and sum(a['batch']==b['batch'] for a in attempts)<=3
    return {'result':'passed','candidates':860,'raw_records':len(raw),'graph_ready':len(ready),'background_edges':len(edges),
            'status_counts':dict(counts),'reserved_ids':155,'reserved_overlap':0,'public_source_overlap':0,'recorded_exposure_overlap':0,
            'source_evidence':'every_CWE_CPE_located_in_hashed_NVD_response','original_adapter_family_parity':True,
            'original_text_labels_and_role_preserved':True,'candidate_sha256':sha(candidate_path),
            'public_zip_sha256':sha(public_zip),'folds_sha256':sha(fold_path),'source_manifest_sha256':sha(cache/'manifest.json'),
            'model_api_calls':0,'training_units':0,'reserved_scoring':0}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for key in ['candidates','cache','out','public-zip','folds','adapter','receipt']:p.add_argument('--'+key,required=True)
    a=p.parse_args();result=audit(a.candidates,a.cache,a.out,a.public_zip,a.folds,a.adapter)
    Path(a.receipt).write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
