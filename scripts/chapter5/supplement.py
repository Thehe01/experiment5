"""Real frozen C4 predictions as a separate, explicitly noisy graph overlay."""
import collections
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from chapter5.core import ENDPOINTS, TYPES, deduplicate, digest, training_edges
from chapter5.io import BindingError, atomic_json, read_json, sha_file

C4_SHA='4e5eb2f25f93f5451846844f45fc34dfbfc69f8155d9ca3d11ee4de98dd94ab9'


def valid_id(value,kind,candidates):
    if not isinstance(value,str):
        return False
    if kind=='Vulnerability':
        return bool(re.fullmatch(r'CVE-\d{4}-\d{4,}',value))
    if kind=='Weakness':
        return bool(re.fullmatch(r'CWE-\d+',value))
    if kind=='Configuration':
        return len(re.split(r'(?<!\\):',value))==13 and value.startswith(('cpe:2.3:a:','cpe:2.3:o:','cpe:2.3:h:'))
    if kind=='AttackTechnique':
        return value in candidates
    return False  # C4 extracts only the first four types; mappings stay independently frozen.


def prediction_overlay(graph,predictions,archive_sha):
    nodes={n['id']:n['type'] for n in graph['nodes']}
    accepted,rejected=[],[]
    for doc_id,body in predictions.items():
        entities={e['id']:e for e in body['entities']}
        source_sha=digest(body)
        for r in body['relations']:
            relation=r.get('type')
            if relation not in ENDPOINTS:
                rejected.append({'document':doc_id,'reason':'unknown_relation'});continue
            a,b=ENDPOINTS[relation]
            head,tail=entities.get(r.get('head')),entities.get(r.get('tail'))
            if not head or not tail or head.get('type')!=TYPES[a] or tail.get('type')!=TYPES[b]:
                rejected.append({'document':doc_id,'reason':'missing_or_mistyped_endpoint'});continue
            h,t=head.get('normalized_id'),tail.get('normalized_id')
            if not valid_id(h,TYPES[a],graph['techniques']) or not valid_id(t,TYPES[b],graph['techniques']):
                rejected.append({'document':doc_id,'reason':'unusable_normalized_id','head':h,'tail':t});continue
            nodes[h],nodes[t]=TYPES[a],TYPES[b]
            accepted.append({'head':h,'relation':relation,'tail':t,'layer':'c4_frozen_prediction',
                             'state':'UNVERIFIED','document':doc_id,'prediction_json_sha256':source_sha,
                             'source_archive_sha256':archive_sha,'evidence':r.get('evidence')})
    inherited=[]
    for e in graph['edges']:
        provenance=[p for p in e.get('provenance',[]) if p.get('layer')!='c4_frozen_gold']
        if provenance:
            inherited.append(dict(e,provenance=provenance))
    targets=[e for e in graph['edges'] if e['relation']=='exploited_by']
    edges=deduplicate(inherited+accepted)
    result=dict(graph,nodes=[{'id':n,'type':nodes[n]} for n in sorted(nodes)],edges=edges,
                evaluation_targets=targets,layer='supplementary_noisy_prediction_overlay',human_iaa=False,
                label_basis='main_frozen_verified_targets_for_evaluation_only',c4_prediction_archive_sha256=archive_sha)
    training_edges(edges,graph['split'])
    covered={e['head'] for e in accepted if e['relation'] in ('affects','instantiates','exploited_by')}
    report={'status':'available','prediction_documents':len(predictions),'accepted_mentions':len(accepted),
            'unique_prediction_edges':len(deduplicate(accepted)),'rejected':rejected,
            'prediction_targets_not_used_for_training':sum(e['relation']=='exploited_by' and e['head'] not in graph['split']['train'] for e in deduplicate(accepted)),
            'covered_target_cves':{role:len(covered&set(graph['split'][role])) for role in ('train','dev','test')},
            'source_archive_sha256':archive_sha,'graph_sha256':digest(result),
            'scope':'21 legacy Dev predictions replace C4 Gold edges; official ATT&CK/NVD expansion shared. Main verified holdout labels remain evaluation-only.',
            'limitation':'Coverage-limited graph-noise sensitivity analysis, not a complete end-to-end predicted graph or independent C4 Test evaluation.'}
    return result,report


def build_supplementary(repo,graph,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    root=repo/'results/convergence_c4_v1/final_result_v1'
    manifest_path=root/'archive_parts/manifest.json'
    if not manifest_path.exists():
        atomic_json(out/'status.json',{'status':'unavailable','reason':'real frozen C4 prediction archive is absent'})
        return None
    manifest=read_json(manifest_path)
    if manifest['source_sha256']!=C4_SHA:
        raise BindingError('unexpected C4 prediction archive')
    chunks=[]
    for part in manifest['parts']:
        path=Path(part['path'])
        if path.is_absolute() or '..' in path.parts:
            raise BindingError('unsafe source archive path')
        raw=(root/path).read_bytes()
        if len(raw)!=part['bytes'] or hashlib.sha256(raw).hexdigest()!=part['sha256']:
            raise BindingError('C4 archive part mismatch')
        chunks.append(raw)
    raw=b''.join(chunks)
    if len(raw)!=manifest['source_bytes'] or hashlib.sha256(raw).hexdigest()!=C4_SHA:
        raise BindingError('C4 archive SHA256 mismatch')
    ids=read_json(repo/'data/train_dev_test_split_v7.json')['dev']
    if len(ids)!=21:
        raise BindingError('unexpected frozen C4 Dev scope')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        expected={f'dev_evaluation/predictions/ProTeGi_Full/{doc}.json' for doc in ids}
        actual={n for n in z.namelist() if n.startswith('dev_evaluation/predictions/ProTeGi_Full/') and not n.endswith('/')}
        if actual!=expected:
            raise BindingError('C4 real prediction coverage mismatch')
        predictions={doc:json.loads(z.read(f'dev_evaluation/predictions/ProTeGi_Full/{doc}.json')) for doc in ids}
    result,report=prediction_overlay(graph,predictions,C4_SHA)
    atomic_json(out/'graph.json',result);atomic_json(out/'status.json',report)
    print(json.dumps({'phase':'supplementary_input','documents':21,'prediction_edges':report['unique_prediction_edges'],
                      'covered_target_cves':report['covered_target_cves']}),flush=True)
    return result
