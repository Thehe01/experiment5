"""Independent offline integration checks; no model fitting or scoring."""
import argparse
import json
from pathlib import Path
import tempfile
import torch
from chapter5.core import digest
from chapter5.io import atomic_json,read_json,sha_file
from chapter5.public_dev.core import labels
from chapter5.public_dev.model import PublicGraph
from chapter5.resolved_dev.data import build_package,read_package
from chapter5.resolved_dev.campaign import ROOT,verify_registration,load_inputs

def verify(repo,receipt):
    repo=Path(repo);cfg=read_json(ROOT/'config.json');reg=read_json(ROOT/'registration.json')
    result=verify_registration(repo);graphs,groups,audit=load_inputs(repo,cfg)
    if len(reg['units'])!=36 or len({u['id'] for u in reg['units']})!=36:raise ValueError('unit inventory')
    protected=set(groups['reserved_ids'])|set(audit['quarantined_original_ids'])|{'CVE-2017-0493','CVE-2019-7287'}
    if len(protected)!=169:raise ValueError('protected ID inventory')
    checks=[]
    for (condition,fold),graph in sorted(graphs.items()):
        ids={n['id'] for n in graph['nodes']};truth=labels(graph)
        if ids&protected or any(e['head'] in protected or e['tail'] in protected for e in graph['edges']):raise ValueError('protected graph contamination')
        if len(graph['fixed_major'])!=23:raise ValueError('major scope')
        if graph['split']['dev']!=graphs[('base',fold)]['split']['dev'] or graph['fixed_major']!=graphs[('base',fold)]['fixed_major']:raise ValueError('paired scope')
        pg=PublicGraph(graph,'mixed');held={pg.ids[c] for c in graph['split']['dev']}
        if any(r==2 and h in held for h,r,t in pg.positive.tolist()):raise ValueError('held target positive leakage')
        if any(r==2 and h in held or r==7 and t in held for h,t,r in pg.message_edges):raise ValueError('held target message leakage')
        torch.manual_seed(20261021);negative=pg.negative_samples(10)
        if pg._known(negative).any():raise ValueError('known positive negative sample')
        target=negative[negative[:,1]==2]
        train={pg.ids[c] for c in graph['split']['train']}
        if set(target[:,0].tolist())-train or set(target[:,2].tolist())-set(pg.candidates.tolist()):raise ValueError('negative role/domain leak')
        if len(target)!=len(pg.target_positives)*10:raise ValueError('negative count')
        if pg.last_sampling_stats['target_full']!=pg.last_sampling_stats['target_seen']:raise ValueError('mixed allocation')
        checks.append({'condition':condition,'fold':fold,'graph_sha256':digest(graph),
            'train':len(graph['split']['train']),'dev':len(graph['split']['dev']),
            'dev_positive_classes':len({t for c in graph['split']['dev'] for t in truth[c]}),
            'train_background_only':len(graph['coverage']['train_background_only']),
            'dev_background_only':len(graph['coverage']['dev_background_only']),
            'fixed_major':graph['fixed_major'],'sampling':pg.last_sampling_stats,
            'held_target_positive_and_message_edges':0,'protected_nodes_and_edges':0})
    base,external,_,_=read_package(repo/cfg['data_package'],cfg['data_sha256'])
    if sum(len(r['cwe_ids']) for r in external)!=804 or sum(len(r['cpe_families']) for r in external)!=2353:raise ValueError('v3 selected background mismatch')
    if sum(len(labels(base)[c]) for c in labels(base))+sum(len(r['techniques']) for r in external)!=3144:raise ValueError('v3 target conservation')
    with tempfile.TemporaryDirectory() as tmp:
        tmp=Path(tmp);rebuilt=tmp/'rebuilt.zip'
        rebuilt_audit=build_package(repo/'chapter5/expanded_dev/data/paired-parent-v1.zip',
            repo/'chapter5/external_data/source_resolution_v3_20261011/source-resolved-candidates-v3.zip',rebuilt)
        if rebuilt.read_bytes()!=(repo/cfg['data_package']).read_bytes():raise ValueError('non-deterministic package')
        try:build_package(repo/'chapter5/expanded_dev/data/paired-parent-v1.zip',repo/'chapter5/external_data/source_resolution_v3_20261011/source-resolved-candidates-v3.zip',rebuilt)
        except ValueError as e:
            if 'overwrite' not in str(e):raise
        else:raise ValueError('overwrite accepted')
        tampered=tmp/'tampered.zip';tampered.write_bytes(rebuilt.read_bytes()+b'X')
        try:read_package(tampered,cfg['data_sha256'])
        except ValueError:pass
        else:raise ValueError('tampered runtime accepted')
    out={'phase':'offline_v3_integration_verified','registration':result,'graphs':checks,
         'runtime_package_rebuilt_byte_identical':True,'runtime_tamper_rejected':True,'overwrite_rejected':True,
         'source_resolved_v3_sha256':cfg['source_resolved_v3_sha256'],'package_sha256':cfg['data_sha256'],
         'protected_ids':169,'known_unknown_pairs_admitted':0,'external_cwe_edges':804,'external_cpe_edges':2353,
         'target_edges':3144,'scored_dev_unique_cves':233,'scored_dev_occurrences':442,
         'scientific_model_training_runs':0,'model_api_calls':0,'reserved_holdout_evaluated':False}
    atomic_json(receipt,out);return out

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',default='.');p.add_argument('--receipt',required=True);a=p.parse_args()
    out=verify(a.repo,a.receipt);print(json.dumps({'phase':out['phase'],'registration_sha256':out['registration']['registration_sha256'],'graphs':len(out['graphs'])}))
