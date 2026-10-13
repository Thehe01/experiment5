"""Independent comparison to source bytes; imports no new data projection code."""
import collections
import hashlib
import json
from pathlib import Path
import zipfile

def sha(data):return hashlib.sha256(data).hexdigest()

def verify(old_path,external_path,runtime_path,folds_path):
    assert sha(Path(old_path).read_bytes())=='c00660f6d37cfefa2af35513ed785ca0e77f880746f34220edb204c353bfadbf'
    assert sha(Path(external_path).read_bytes())=='0a8dadff1e03dbe55520a77783523016dcb2d97d8f716f3253255f1b33748e6b'
    assert sha(Path(runtime_path).read_bytes())=='224edc37ab105644bec932ab54dc1071783c35fd124728d5a2645c1f00274d10'
    assert sha(Path(folds_path).read_bytes())=='5fda5590c0b25448718f99381f0e35b4eac6ecf1cf9abc956fe964d0561f8190'
    old=zipfile.ZipFile(old_path);ext=zipfile.ZipFile(external_path);run=zipfile.ZipFile(runtime_path)
    source=json.loads(old.read('graph.json'));groups=json.loads(Path(folds_path).read_bytes());reserved=set(groups['reserved_ids'])
    records=[json.loads(l) for l in ext.read('data/graph-ready-candidates.jsonl').splitlines()];scope=set(records[0]['label_scope'])
    graph=json.loads(run.read('base-graph.json'));additional=[json.loads(l) for l in run.read('external-records.jsonl').splitlines()]
    audit=json.loads(run.read('audit.json'));manifest=json.loads(run.read('manifest.json'))
    assert run.read('folds.json')==Path(folds_path).read_bytes()
    for name,digest in manifest['files'].items():assert sha(run.read(name))==digest
    public={json.loads(l)['id'] for l in old.read('source-records.jsonl').splitlines()}
    exposure=set(json.loads(old.read('exposure.json'))['excluded_union'])
    assert len(records)==len(additional)==858 and len(scope)==31
    ids={r['id'] for r in additional};assert not ids&(reserved|public|exposure)
    original={r['id']:r for r in records}
    for r in additional:
        assert r=={k:original[r['id']][k] for k in r}
        assert r['metadata_status']=='background_ready' and r['graph_ready']
        assert set(r['techniques'])<=scope and r['metadata_provenance']['response_sha256']
    expected_edges=set()
    for e in source['edges']:
        h,t,r=e['head'],e['tail'],e['relation']
        if h in reserved or t in reserved:continue
        if r=='potentially_associated_with':
            t=t.split('.')[0]
            if t not in scope:continue
        if r=='implies':
            h=h.split('.')[0]
            if h not in scope:continue
        expected_edges.add((h,r,t))
    edges=[(e['head'],e['relation'],e['tail']) for e in graph['edges']]
    assert len(edges)==len(set(edges)) and set(edges)==expected_edges
    nodes={n['id']:n['type'] for n in graph['nodes']}
    expected_cves={n['id'] for n in source['nodes'] if n['type']=='Vulnerability'}-reserved
    assert {n for n,t in nodes.items() if t=='Vulnerability'}==expected_cves and len(expected_cves)==880
    assert not set(nodes)&reserved
    assert {n for n,t in nodes.items() if t=='AttackTechnique'}==scope==set(graph['techniques'])
    assert all(h in nodes and t in nodes for h,r,t in edges)
    expected_nodes=set(v for h,r,t in expected_edges for v in (h,t))|expected_cves|scope
    assert set(nodes)==expected_nodes
    truth=collections.defaultdict(set)
    for h,r,t in expected_edges:
        if r=='potentially_associated_with':truth[h].add(t)
    result=[]
    for f in groups['folds']:
        train={c for c in f['train'] if truth[c]};dev={c for c in f['dev'] if truth[c]}
        assert len(train)==700 and len(dev)==150 and not train&dev
        support=collections.Counter(t for c in train for t in truth[c]);major=sorted(t for t,n in support.items() if n>=10)
        extra=collections.Counter(t for r in additional for t in r['techniques']);aug=support+extra
        assert len(major)==23 and len(aug)==31 and min(aug.values())==17
        for condition in ['base','augmented']:
            summary=next(s for s in audit['summaries'] if s['fold']==f['fold'] and s['condition']==condition)
            counter=support if condition=='base' else aug
            assert summary['train_support']==dict(counter)
            assert summary['fixed_major']==major and summary['dev_targets']==sum(len(truth[c]) for c in dev)
            assert summary['train_targets']==sum(counter.values()) and summary['train']==(700 if condition=='base' else 1558)
        result.append({'fold':f['fold'],'original_train':725,'original_dev':155,'base_supervised_train':700,'augmented_supervised_train':1558,
                       'scored_dev':150,'dev_query_coverage':150/155,'fixed_major_eligible':23,
                       'dev_candidate_techniques_evaluable':len({t for c in dev for t in truth[c]}),
                       'dev_techniques_no_positive':sorted(scope-{t for c in dev for t in truth[c]}),
                       'augmented_minimum_train_support':17})
    return {'result':'passed','source_target_and_background_edge_sets_exact':True,'external_projection_exact':True,
            'external_cves':858,'external_target_edges':sum(len(r['techniques']) for r in additional),
            'reserved_cves':155,'reserved_runtime_node_overlap':0,'public_source_overlap':0,'recorded_exposure_overlap':0,
            'source_development_background_cves':880,'scope_parent_techniques':31,'folds':result,'training_runs':0,
            'source_runtime_sha256':sha(Path(runtime_path).read_bytes()),'metadata_as_of':'2026_current_not_2022_historical'}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser()
    for key in ['old','external','runtime','folds','receipt']:p.add_argument('--'+key,required=True)
    a=p.parse_args();result=verify(a.old,a.external,a.runtime,a.folds)
    Path(a.receipt).write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n');print(json.dumps(result,ensure_ascii=False))
