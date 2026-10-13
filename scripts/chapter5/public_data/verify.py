"""Validate the exported package without reusing its adaptation logic."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import zipfile


def read_package(path):
    path = Path(path)
    if path.is_dir():
        return {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or any('/' in n or '\\' in n or n in ('.','..') for n in names):
            raise ValueError('invalid package member names')
        if sum(i.file_size for i in z.infolist()) > 64 * 1024 * 1024:
            raise ValueError('package too large')
        return {n: z.read(n) for n in names}


def verify(path):
    files = read_package(path)
    manifest = json.loads(files['manifest.json'])
    if set(files) != {'manifest.json', *manifest['files']}:
        raise ValueError('package file inventory mismatch')
    for name, info in manifest['files'].items():
        raw = files[name]
        if len(raw) != info['bytes'] or hashlib.sha256(raw).hexdigest() != info['sha256']:
            raise ValueError('package digest mismatch: ' + name)
    parsed = {n: json.loads(b) for n, b in files.items() if n.endswith('.json')}
    records = [json.loads(line) for line in files['records.jsonl'].splitlines() if line]
    safe_source = [json.loads(line) for line in files['source-records.jsonl'].splitlines() if line]
    ids = {r['id'] for r in records}
    if len(ids) != len(records) or len({r['id'] for r in safe_source}) != len(safe_source):
        raise ValueError('duplicate sample identity')
    forbidden = {'techniques_derived', 'cwes_predicted'}
    if any(forbidden & r.keys() for r in records + safe_source):
        raise ValueError('forbidden weak/predicted source fields')
    source_by_id = {r['id']: r for r in safe_source}
    for r in records:
        src = source_by_id.get(r['id'])
        if not src or set(r['source_techniques']) != set(src['techniques']):
            raise ValueError('curated source lineage mismatch')
        changes = {c['from']:c['to'] for c in r['label_changes']}
        if set(r['techniques']) != {changes.get(t,t) for t in src['techniques']}:
            raise ValueError('unexpected curated label change')
        stages = ('exploitation_techniques','primary_impact','secondary_impact')
        for stage in stages:
            if set(r[stage]) != {changes.get(t,t) for t in src[stage]}:
                raise ValueError('stage label lineage mismatch')
        if set(r['unclassified_techniques']) != set(r['techniques']) - {t for k in stages for t in r[k]}:
            raise ValueError('unclassified label mismatch')
    split = parsed['development-split.json']
    groups = [set(split[k]) for k in ('train','dev','reserved_holdout')]
    if set.union(*groups) != ids or any(groups[i] & groups[j] for i in range(3) for j in range(i)):
        raise ValueError('split coverage or overlap')
    exposure = set(parsed['exposure.json']['excluded_union'])
    if ids & exposure:
        raise ValueError('known exposure in external pool')
    graph = parsed['graph.json']; train = parsed['training-edges.json']
    candidates = set(graph['techniques'])
    truth = {(r['id'],t) for r in records for t in r['techniques']}
    edges = graph['edges']; target = graph['target_relation']
    if target != 'potentially_associated_with':
        raise ValueError('public target semantics changed')
    if {(e['head'],e['tail']) for e in edges if e['relation'] == target} != truth:
        raise ValueError('graph targets do not equal curated labels')
    node_types = {n['id']: n['type'] for n in graph['nodes']}
    endpoints = {'potentially_associated_with': ('Vulnerability','AttackTechnique'),
                 'has_reported_cwe': ('Vulnerability','Weakness'),
                 'has_reported_cpe': ('Vulnerability','Configuration'),
                 'implies': ('AttackTechnique','AttackTactic'),
                 'belongs_to_phase': ('AttackTactic','KillChainPhase')}
    edge_keys = {(e['head'],e['relation'],e['tail']) for e in edges}
    if len(edge_keys) != len(edges):
        raise ValueError('duplicate graph edge')
    for e in edges:
        if e['relation'] not in endpoints:
            raise ValueError('unknown or target-derived stage relation')
        ht, tt = endpoints[e['relation']]
        if node_types.get(e['head']) != ht or node_types.get(e['tail']) != tt:
            raise ValueError('edge endpoint type mismatch')
        if e.get('derived_from_target') or any(p.get('derived_from_target') for p in e.get('provenance', [])):
            raise ValueError('target-derived background')
    if {n for n,t in node_types.items() if t == 'AttackTechnique'} != candidates:
        raise ValueError('candidate node inventory mismatch')
    if any(t not in candidates for _,t in truth):
        raise ValueError('curated target outside candidates')
    train_expected = {k for k in edge_keys if k[1] != target or k[0] in groups[0]}
    if {(e['head'],e['relation'],e['tail']) for e in train} != train_expected or len(train) != len(train_expected):
        raise ValueError('held labels in training or incomplete training background')
    total_labels = {t for _,t in truth}
    train_labels = {t for c,t in truth if c in groups[0]}
    if total_labels != train_labels:
        raise ValueError('held label absent from Train')
    audit = parsed['audit.json']
    if audit['graph_eligible_cves'] != len(ids) or audit['eligible_edges'] != len(truth) or audit['source_rows'] != len(safe_source):
        raise ValueError('audit count mismatch')
    if audit['new_model_training_runs'] or audit['model_api_calls']:
        raise ValueError('preparation package reports model execution')
    return {'phase':'verified_data_preparation', 'source_cves':len(safe_source), 'eligible_cves':len(ids),
            'curated_target_edges':len(truth), 'candidate_techniques':len(candidates),
            'supervised_techniques':len(total_labels),
            'groups':{k:len(split[k]) for k in ('train','dev','reserved_holdout')},
            'graph_nodes':len(node_types), 'graph_edges':len(edges), 'training_edges':len(train),
            'relation_counts':dict(collections.Counter(e['relation'] for e in edges)),
            'reserved_holdout_evaluated':False, 'model_training_runs':0, 'model_api_calls':0,
            'human_iaa':False, 'file_hashes_checked':len(manifest['files'])}


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('package');a=p.parse_args()
    print(json.dumps(verify(a.package),ensure_ascii=False,indent=2,sort_keys=True))
