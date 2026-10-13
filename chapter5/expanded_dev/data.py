"""Frozen data projection and paired graphs; no model fitting."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import statistics
import zipfile
from chapter5.core import digest
from chapter5.public_dev.core import TARGET, RELATIONS, labels

OLD_SHA='c00660f6d37cfefa2af35513ed785ca0e77f880746f34220edb204c353bfadbf'
EXTERNAL_SHA='0a8dadff1e03dbe55520a77783523016dcb2d97d8f716f3253255f1b33748e6b'
FOLDS_SHA='5fda5590c0b25448718f99381f0e35b4eac6ecf1cf9abc956fe964d0561f8190'

def encoded(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def project_base(graph, reserved, scope):
    reserved,scope=set(reserved),set(scope)
    if not scope or any('.' in t for t in scope):raise ValueError('parent candidate scope required')
    active={n['id'].split('.')[0] for n in graph['nodes'] if n['type']=='AttackTechnique'}
    if not scope<=active:raise ValueError('scope outside frozen active techniques')
    edges={}
    for e in graph['edges']:
        if e.get('derived_from_target') or any(p.get('derived_from_target') for p in e.get('provenance',[])):
            raise ValueError('target-derived context forbidden')
        if e['relation'] not in RELATIONS:raise ValueError('unknown or precomputed inverse relation')
        h,t=e['head'],e['tail'];r=e['relation']
        if h in reserved or t in reserved:continue
        if r==TARGET:
            t=t.split('.')[0]
            if t not in scope:continue
        elif r=='implies':
            h=h.split('.')[0]
            if h not in scope:continue
        edges[(h,r,t)]={'head':h,'relation':r,'tail':t,'layer':e.get('layer','frozen_public_graph')}
    used={v for h,r,t in edges for v in (h,t)}|scope
    nodes={}
    for n in graph['nodes']:
        identifier=n['id'].split('.')[0] if n['type']=='AttackTechnique' else n['id']
        if identifier in reserved or n['type']=='AttackTechnique' and identifier not in scope:continue
        # All old development CVE nodes retained, including those without scoped labels.
        if identifier not in used and n['type']!='Vulnerability':continue
        value={'id':identifier,'type':n['type']}
        if identifier in nodes and nodes[identifier]!=value:raise ValueError('node type collision')
        nodes[identifier]=value
    if any(h not in nodes or t not in nodes for h,r,t in edges):raise ValueError('missing edge node')
    return {'nodes':[nodes[k] for k in sorted(nodes)],'edges':[edges[k] for k in sorted(edges)],
            'techniques':sorted(scope),'target_relation':TARGET,'attack_version':graph.get('attack_version'),
            'label_semantics':'source_curated_potential_association_not_observed_incident',
            'independent_human_iaa':False,'label_granularity':'parent','missing_labels_are_confirmed_negatives':False}

def make_fold(base, external, fold, condition, reserved, major_support=10):
    if condition not in ('base','augmented'):raise ValueError('unknown data condition')
    reserve=set(reserved);oldnodes={n['id'] for n in base['nodes']};domain=set(base['techniques'])
    external_ids=[r['id'] for r in external]
    if len(external_ids)!=len(set(external_ids)) or set(external_ids)&(oldnodes|reserve):raise ValueError('external ID overlap')
    for r in external:
        if not r.get('graph_ready') or r.get('metadata_status')=='rejected_source_record':raise ValueError('unready external source')
        if not r['techniques'] or not set(r['techniques'])<=domain or any('.' in t for t in r['techniques']):raise ValueError('external parent label scope')
        if not r['cwe_ids'] and not r['cpe_families']:raise ValueError('external missing background')
    tr,dv=set(fold['train']),set(fold['dev'])
    if tr&dv or (tr|dv)&reserve or not (tr|dv)<=oldnodes:raise ValueError('role overlap or absent query')
    truth=labels(base);train=sorted(c for c in tr if truth[c]);dev=sorted(c for c in dv if truth[c])
    if not train or not dev:raise ValueError('empty scoped development role')
    support=collections.Counter(t for c in train for t in truth[c]);major=sorted(t for t,n in support.items() if n>=major_support)
    graph=copy.deepcopy(base);nodes={n['id']:n for n in graph['nodes']};edges={(e['head'],e['relation'],e['tail']):e for e in graph['edges']}
    if condition=='augmented':
        for r in external:
            nodes[r['id']]={'id':r['id'],'type':'Vulnerability'}
            for relation,values,kind in [('has_reported_cwe',r['cwe_ids'],'Weakness'),('has_reported_cpe',r['cpe_families'],'Configuration'),(TARGET,r['techniques'],'AttackTechnique')]:
                for value in values:
                    if value in nodes and nodes[value]['type']!=kind:raise ValueError('external node type collision')
                    nodes[value]={'id':value,'type':kind}
                    edges[(r['id'],relation,value)]={'head':r['id'],'relation':relation,'tail':value,'layer':'cve2attack_curated_target' if relation==TARGET else 'nvd_reported_metadata'}
        train=sorted(train+external_ids)
    graph.update(nodes=[nodes[k] for k in sorted(nodes)],edges=[edges[k] for k in sorted(edges)],
                 split={'train':train,'dev':dev},reserved_ids=sorted(reserve),condition=condition,fold=fold['fold'],
                 fixed_major=major,coverage={'original_train':len(tr),'original_dev':len(dv),
                 'train_background_only':sorted(c for c in tr if not truth[c]),'dev_background_only':sorted(c for c in dv if not truth[c]),
                 'base_supervised_train':sum(bool(truth[c]) for c in tr),'scored_dev':len(dev),
                 'external_train':len(external) if condition=='augmented' else 0})
    return graph

def fixed_major(metrics, eligible):
    out=copy.deepcopy(metrics);available=[t for t in eligible if t in out['by_technique']]
    out['dynamic_major_macro_mrr']=out.get('major_macro_mrr')
    out['major_macro_mrr']=statistics.mean(out['by_technique'][t]['mrr'] for t in available) if available else None
    out['major_eligible']=list(eligible);out['major_unavailable']=sorted(set(eligible)-set(available))
    out['major_definition']='fixed_base_Train_support_per_fold'
    return out

def paired_summary(results, units):
    expected={u['id']:u for u in units}
    if len(expected)!=len(units) or len(results)!=len(units) or {r['unit'] for r in results}!=set(expected):raise ValueError('complete unique registered results required')
    grouped={}
    for r in results:
        u=expected[r['unit']]
        if r['status']!='trained' or any(r[k]!=u[k] for k in ('arm','fold','seed','condition')):raise ValueError('unit metadata mismatch')
        key=(r['arm'],r['fold'],r['seed'])
        if r['condition'] in grouped.setdefault(key,{}):raise ValueError('duplicate result pair')
        grouped[key][r['condition']]=r
    out={}
    for arm in sorted({u['arm'] for u in units}):
        pairs=[]
        for (a,f,s),g in sorted(grouped.items()):
            if a!=arm:continue
            if set(g)!=set(['base','augmented']):raise ValueError('incomplete paired data conditions')
            b,v=g['base']['dev'],g['augmented']['dev']
            pairs.append({'fold':f,'seed':s,'base_mrr':b['mrr'],'augmented_mrr':v['mrr'],
                          'delta_mrr':v['mrr']-b['mrr'],'delta_major_macro':v['major_macro_mrr']-b['major_macro_mrr'] if b['major_macro_mrr'] is not None and v['major_macro_mrr'] is not None else None})
        macros=[p['delta_major_macro'] for p in pairs if p['delta_major_macro'] is not None]
        out[arm]={'pairs':pairs,'pair_count':len(pairs),'mean_base_mrr':statistics.mean(p['base_mrr'] for p in pairs),
                  'mean_augmented_mrr':statistics.mean(p['augmented_mrr'] for p in pairs),
                  'mean_delta_mrr':statistics.mean(p['delta_mrr'] for p in pairs),'wins':sum(p['delta_mrr']>0 for p in pairs),
                  'mean_delta_major_macro':statistics.mean(macros) if len(macros)==len(pairs) else None}
    return out

def build_package(old_package, external_package, folds_path, destination):
    raws=[Path(p).read_bytes() for p in (old_package,external_package,folds_path)]
    if [sha(r) for r in raws]!=[OLD_SHA,EXTERNAL_SHA,FOLDS_SHA]:raise ValueError('frozen source byte mismatch')
    old=zipfile.ZipFile(old_package);ext=zipfile.ZipFile(external_package)
    pm=json.loads(ext.read('package-manifest.json'))
    for name,v in pm['files'].items():
        raw=ext.read(name)
        if len(raw)!=v['bytes'] or sha(raw)!=v['sha256']:raise ValueError('source member mismatch')
    original=[json.loads(l) for l in ext.read('data/graph-ready-candidates.jsonl').splitlines()]
    if len(original)!=858 or len({r['id'] for r in original})!=858:raise ValueError('external count mismatch')
    groups=json.loads(raws[2]);reserve=groups['reserved_ids'];scope=original[0]['label_scope']
    public={json.loads(l)['id'] for l in old.read('source-records.jsonl').splitlines()};exposed=set(json.loads(old.read('exposure.json'))['excluded_union'])
    if {r['id'] for r in original}&(public|exposed|set(reserve)):raise ValueError('external contamination')
    if any(r['label_scope']!=scope or not r['graph_ready'] for r in original) or len(scope)!=31:raise ValueError('external candidate scope mismatch')
    graph=project_base(json.loads(old.read('graph.json')),reserve,scope)
    external=[{k:r[k] for k in ('id','techniques','cwe_ids','cpe_families','graph_ready','metadata_status','metadata_provenance','provenance','source_commit')} for r in original]
    summaries=[]
    for f in groups['folds']:
        pair={c:make_fold(graph,external,f,c,reserve) for c in ('base','augmented')}
        if any(len(pair[c]['split']['dev'])!=150 for c in pair) or len(pair['base']['split']['train'])!=700 or len(pair['augmented']['split']['train'])!=1558:raise ValueError('scoped role counts changed')
        for c,g in pair.items():
            counts=collections.Counter(t for h in g['split']['train'] for t in labels(g)[h])
            summaries.append({'condition':c,'fold':f['fold'],'train':len(g['split']['train']),'dev':len(g['split']['dev']),
                              'train_targets':sum(counts.values()),'dev_targets':sum(len(labels(g)[h]) for h in g['split']['dev']),
                              'train_support':dict(sorted(counts.items())),'fixed_major':g['fixed_major'],'coverage':g['coverage'],'graph_sha256':digest(g),
                              'nodes':len(g['nodes']),'edges':len(g['edges'])})
    audit={'source_sha256':dict(zip(['original_public_zip','external_enriched_zip','original_folds'],[sha(r) for r in raws])),
           'external_cves':858,'external_target_edges':sum(len(r['techniques']) for r in external),'candidate_domain':scope,
           'reserved_ids':len(reserve),'reserved_nodes_and_edges_present':0,'external_public_overlap':0,'external_exposure_overlap':0,
           'summaries':summaries,'data_conditions':['base','augmented'],'source_semantics':'partial_parent_potential_association',
           'new_metadata_as_of':'2026_current_not_2022_historical','model_training_runs':0}
    members={'base-graph.json':encoded(graph),'external-records.jsonl':b''.join(encoded(r) for r in external),'folds.json':raws[2],'audit.json':encoded(audit)}
    members['manifest.json']=encoded({'files':{n:sha(b) for n,b in sorted(members.items())},'source_sha256':audit['source_sha256']})
    destination=Path(destination)
    if destination.exists():raise ValueError('refuse package overwrite')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,raw in sorted(members.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;z.writestr(info,raw,compresslevel=9)
    return audit|{'package_sha256':sha(destination.read_bytes()),'package_bytes':destination.stat().st_size}

def read_package(path, expected_sha):
    raw=Path(path).read_bytes()
    if sha(raw)!=expected_sha:raise ValueError('runtime package SHA mismatch')
    with zipfile.ZipFile(path) as z:
        if set(z.namelist())!={'base-graph.json','external-records.jsonl','folds.json','audit.json','manifest.json'}:raise ValueError('runtime package members')
        values={n:z.read(n) for n in z.namelist()}
    manifest=json.loads(values['manifest.json'])
    for n,h in manifest['files'].items():
        if sha(values[n])!=h:raise ValueError('runtime member SHA mismatch')
    graph=json.loads(values['base-graph.json']);external=[json.loads(l) for l in values['external-records.jsonl'].splitlines()];groups=json.loads(values['folds.json'])
    return graph,external,groups,json.loads(values['audit.json'])

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('old-package','external-package','folds','destination'):p.add_argument('--'+n,required=True)
    a=p.parse_args();print(json.dumps(build_package(a.old_package,a.external_package,a.folds,a.destination),ensure_ascii=False))
