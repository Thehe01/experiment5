"""Collect once, audit source statements and freeze a target-independent graph."""
import argparse
import collections
import concurrent.futures
import gzip
import hashlib
import json
from pathlib import Path
from chapter5.core import cves, deduplicate, digest, extract_attack, grouped_split, nvd_context, training_edges, TYPES, ENDPOINTS
from chapter5.io import BindingError, atomic_json, download, read_json, sha_file
from chapter5.model import code_binding


def c4_inputs(repo):
    split = read_json(repo/'data/train_dev_test_split_v7.json')
    manifest = read_json(repo/'data/dataset_freeze_manifest_v6.json')
    exposure_index = read_json(repo/'data/convergence_c3_v1/known_exposure_index.json')
    exposed, contexts, targets, bindings = set(), [], [], {}
    ids = split['train'] + split['dev']
    for doc_id in ids:
        path = repo/'data/annotations/gold'/f'{doc_id}.json'
        expected = manifest['gold_document_sha256'][doc_id]
        if sha_file(path) != expected:
            raise ValueError('frozen C4 Gold hash mismatch: '+doc_id)
        bindings[str(path.relative_to(repo))] = expected
        doc = read_json(path); exposed |= cves(doc['text'])
        entities = {e['id']:e for e in doc['entities']}
        for r in doc['relations']:
            head, tail = entities.get(r['head']), entities.get(r['tail'])
            if not head or not tail or not head.get('normalized_id') or not tail.get('normalized_id'):
                continue
            evidence = r.get('evidence', '')
            if not evidence or evidence not in doc['text']:
                continue
            item = {'head':head['normalized_id'],'relation':r['type'],'tail':tail['normalized_id'],
                    'layer':'c4_frozen_gold','document':doc_id,'source_sha256':expected,'evidence':evidence,
                    'verification':'inherited_frozen_label_with_exact_evidence','human_iaa':False}
            (targets if r['type']=='exploited_by' else contexts).append(item)
    # Raw and metadata only, including historical corpus exposure. Never read old Test annotations.
    for item in exposure_index['repository_source_inventory']:
        path = repo/item['path']
        if not path.exists():
            raise ValueError('exposure inventory source missing: '+item['path'])
        raw = path.read_bytes()
        blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if blob != item['git_blob_sha']:
            raise ValueError('exposure source Git blob mismatch: '+item['path'])
        bindings[item['path']] = hashlib.sha256(raw).hexdigest()
        if path.suffix=='.gz':
            raw=gzip.decompress(raw)
        exposed |= cves(raw.decode('utf-8',errors='replace'))
    for item in exposure_index.get('supplement_records', []):
        exposed |= cves(json.dumps(item))
    # Also account for publicly visible IDs in the legacy annotation filenames, without opening those files.
    exposed |= cves(json.dumps(split))
    return contexts, targets, exposed, bindings


def collect(repo, out, cfg):
    out=Path(out); out.mkdir(parents=True,exist_ok=True)
    frozen=out/'freeze.json'
    if frozen.exists():
        f=read_json(frozen)
        if f['config_sha256']!=digest(cfg) or f['graph_sha256']!=sha_file(out/'graph.json') or f['split_sha256']!=sha_file(out/'split.json') or f['code'] != code_binding():
            raise ValueError('frozen graph/config mismatch')
        for path,sha in read_json(out/'graph.json')['c4_bindings'].items():
            if sha_file(repo/path)!=sha:
                raise BindingError('frozen inherited source changed: '+path)
        return f
    atomic_json(out/'status.json', {'phase':'collecting','protocol':cfg['protocol']})
    attack, receipt=download(cfg['attack_url'],out/'sources/attack.json',cfg,cfg['attack_sha256'])
    parsed=extract_attack(read_json(attack))
    old_context,old_targets,exposed,bindings=c4_inputs(repo)
    targets=deduplicate(parsed['targets']+old_targets)
    atomic_json(out/'admitted_targets.json',targets)
    atomic_json(out/'pending.json',parsed['pending'])
    atomic_json(out/'source_admission.json', {'official_statements':len(parsed['targets']), 'official_unique_edges':len(deduplicate(parsed['targets'])),
                 'inherited_target_statements':len(old_targets),'pending':len(parsed['pending']), 'independent_human_iaa':False})
    cve_ids=sorted({e['head'] for e in targets})
    contexts=old_context+parsed['context']; failures=[]
    for i,cve in enumerate(cve_ids):
        url='https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='+cve
        try:
            path,nvd_receipt=download(url,out/'sources/nvd'/f'{cve}.json',cfg,min_interval=cfg['nvd_interval_seconds'])
            records=read_json(path).get('vulnerabilities',[])
            if len(records)!=1 or records[0]['cve']['id']!=cve:
                raise ValueError('NVD identity or cardinality mismatch')
            for e in nvd_context(records[0]['cve']):
                # The complete conditions remain in the bound raw record, avoiding quadratic JSON duplication.
                conditions=e.pop('configuration',None)
                if conditions is not None:
                    e['configuration_sha256']=digest(conditions)
                    e['conditions_location']='sources/nvd/'+cve+'.json#/vulnerabilities/0/cve/configurations'
                contexts.append(dict(e,source_sha256=nvd_receipt['sha256']))
        except BindingError:
            raise
        except (RuntimeError,ValueError,json.JSONDecodeError) as exc:
            failures.append({'cve':cve,'error':str(exc)})
        atomic_json(out/'collection-progress.json', {'completed':i+1,'total':len(cve_ids),'failures':failures})
        print(json.dumps({'phase':'nvd','completed':i+1,'total':len(cve_ids),'cve':cve,'failures':len(failures)}),flush=True)
    # Citation checks corroborate source retrieval; they are not represented as human semantic agreement.
    references={r['url'] for e in parsed['targets'] for r in e.get('citations',[]) if r.get('url')}
    def reference(url):
        try:
            reference_cfg=dict(cfg,response_limit_bytes=8*1024*1024)
            path,rc=download(url,out/'sources/references'/hashlib.sha256(url.encode()).hexdigest(),reference_cfg)
            binary=any(k in rc['content_type'] for k in ('pdf','image/','octet-stream'))
            return {'url':url,'sha256':rc['sha256'],'status':'binary_saved_not_semantically_checked' if binary else 'retrieved',
                    'mentioned_cves':[] if binary else sorted(cves(path.read_text(errors='replace')))}
        except BindingError:
            raise
        except (RuntimeError,ValueError) as exc:
            return {'url':url,'status':'unavailable','error':str(exc)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg['reference_workers']) as pool:
        checked=list(pool.map(reference,sorted(references)))
    atomic_json(out/'reference_checks.json',checked)
    contexts=deduplicate(contexts)
    # Model eligibility is declared before splitting, based solely on existing non-target context.
    contextual={e['head'] for e in contexts if e['relation'] in ('affects','instantiates')}
    isolated=sorted({e['head'] for e in targets}-contextual)
    eligible=[e for e in targets if e['head'] not in isolated]
    split=grouped_split(eligible,exposed,cfg['split_seed'])
    edges=deduplicate(contexts+eligible)
    nodes={}
    for e in edges:
        a,b=ENDPOINTS[e['relation']]
        for key,tp in ((e['head'],TYPES[a]),(e['tail'],TYPES[b])):
            if key in nodes and nodes[key]!=tp:
                raise ValueError('node type conflict')
            nodes[key]=tp
    for t in parsed['techniques']:
        nodes[t]='AttackTechnique'
    graph={'nodes':[{'id':n,'type':nodes[n]} for n in sorted(nodes)], 'edges':edges,'split':split,
           'techniques':parsed['techniques'], 'exposed_cves':sorted(exposed),'excluded_isolated_cves':isolated,
           'attack_version':cfg['attack_version'],'source_attack_sha256':receipt['sha256'],
           'c4_bindings':bindings,'label_basis':'official_explicit_records_and_inherited_frozen_Gold',
           'human_iaa':False,'nvd_failures':failures,'reference_retrieval_counts':dict(collections.Counter(r['status'] for r in checked))}
    training_edges(edges,split)
    atomic_json(out/'graph.json',graph)
    atomic_json(out/'split.json',split)
    counts={role:{'cves':len(split[role]),'edges':sum(e['head'] in split[role] and e['relation']=='exploited_by' for e in edges)} for role in ('train','dev','test')}
    freeze={'protocol':cfg['protocol'],'config_sha256':digest(cfg),'graph_sha256':sha_file(out/'graph.json'),'code':code_binding(),
            'split_sha256':sha_file(out/'split.json'),'counts':counts,'node_count':len(nodes),
            'target_count':len(eligible),'technique_labels':dict(collections.Counter(e['tail'] for e in eligible)),
            'isolated_cves_excluded':len(isolated),'leakage_check':'passed','phase':'data_frozen','human_iaa':False,
            'note':'Independent Chapter5 relation-recovery holdout; does not reopen Chapter4 formal/Test gates.'}
    atomic_json(frozen,freeze); atomic_json(out/'status.json',freeze)
    print(json.dumps(freeze),flush=True)
    return freeze


def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',default='.');p.add_argument('--out',required=True);p.add_argument('--config',default='chapter5/config.json')
    a=p.parse_args();collect(Path(a.repo),Path(a.out),read_json(a.config))


if __name__=='__main__':
    main()
