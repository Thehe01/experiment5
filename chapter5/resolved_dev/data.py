"""v3 admission adapter; training is handled by the frozen shared engine."""
import argparse
import collections
import copy
import json
from pathlib import Path
import zipfile
from chapter5.core import digest
from chapter5.public_dev.core import labels
from chapter5.expanded_dev.data import read_package, make_fold, fixed_major, paired_summary, encoded, sha

PARENT_SHA='224edc37ab105644bec932ab54dc1071783c35fd124728d5a2645c1f00274d10'
V3_SHA='eb7f7434b61d2abeb5741b27758ac17f1e5f145ca62057e9ded364dc44bb56ac'

def admitted_views(base, rows, groups, preview):
    identifiers=[r['id'] for r in rows]
    if len(identifiers)!=len(set(identifiers)):raise ValueError('duplicate usable ID')
    if set(identifiers)&set(groups['reserved_ids']):raise ValueError('reserved usable ID')
    old={n['id'] for n in base['nodes'] if n['type']=='Vulnerability'}
    domain=set(base['techniques']);truth=labels(base);original={};external=[]
    for r in rows:
        if r.get('unknown_labels'):raise ValueError('UNKNOWN cannot be admitted')
        if r.get('admission_status')!='USABLE_KNOWN_DISPUTES_EXCLUDED':raise ValueError('unusable admission status')
        if set(r['candidate_domain'])!=domain or not set(r['techniques'])<=domain:raise ValueError('candidate scope mismatch')
        if r['role']=='original_development_pool':
            if r['id'] not in old:raise ValueError('original role outside old pool')
            if set(r['techniques'])!=set(truth[r['id']]):raise ValueError('original labels changed')
            for rel,key in [('has_reported_cwe','cwe_ids'),('has_reported_cpe','cpe_families')]:
                values={e['tail'] for e in base['edges'] if e['head']==r['id'] and e['relation']==rel}
                if values!=set(r[key]):raise ValueError('original context changed')
            original[r['id']]=r
        elif r['role']=='external_train_only':
            if r['id'] in old:raise ValueError('external role overlaps old pool')
            if not r['techniques'] or not (r['cwe_ids'] or r['cpe_families']):raise ValueError('unready external source')
            external.append(dict(copy.deepcopy(r),graph_ready=True,metadata_status='v3_source_resolved'))
        else:raise ValueError('unsupported usable role')
    excluded=old-set(original);graph=copy.deepcopy(base)
    graph['nodes']=[n for n in graph['nodes'] if n['id'] not in excluded]
    graph['edges']=[e for e in graph['edges'] if e['head'] not in excluded and e['tail'] not in excluded]
    graph['data_version']='chapter5-source-resolution-v3-20261011'
    graph['quarantined_ids']=sorted(excluded)
    graph['independent_human_iaa']=False
    folds=[];ext_ids={r['id'] for r in external}
    if len(preview['folds'])!=len(groups['folds']):raise ValueError('preview fold count mismatch')
    for f in groups['folds']:
        matching=[p for p in preview['folds'] if p['fold']==f['fold']]
        if len(matching)!=1:raise ValueError('preview fold inventory mismatch')
        p=matching[0];tr=sorted(set(f['train'])-excluded);dv=sorted(set(f['dev'])-excluded)
        if set(tr)&set(dv) or set(tr)|set(dv)!=set(original):raise ValueError('original role coverage mismatch')
        if p['source_split_seed']!=f['seed'] or set(p['train'])!=set(tr)|ext_ids or set(p['dev'])!=set(dv):raise ValueError('preview role mismatch')
        if set(p['supervised_train'])!={c for c in tr if truth[c]}|ext_ids or set(p['scored_dev'])!={c for c in dv if truth[c]}:raise ValueError('preview supervised role mismatch')
        folds.append(dict(f,train=tr,dev=dv))
    out={'reserved_ids':groups['reserved_ids'],'folds':folds,
         'strategy':'three repeated grouped stratified holdouts filtered by v3 admission; not independent K-fold',
         'dev_overlap':{f'{a["fold"]}-{b["fold"]}':len(set(a['dev'])&set(b['dev'])) for i,a in enumerate(folds) for b in folds[i+1:]}}
    out['scored_dev_unique_cves']=len({c for f in folds for c in f['dev'] if truth[c]})
    out['scored_dev_occurrences']=sum(sum(bool(truth[c]) for c in f['dev']) for f in folds)
    return graph,sorted(external,key=lambda r:r['id']),out

def build_package(parent_package,v3_package,destination):
    base,_,groups,_=read_package(parent_package,PARENT_SHA)
    raw=Path(v3_package).read_bytes()
    if sha(raw)!=V3_SHA:raise ValueError('v3 frozen source byte mismatch')
    with zipfile.ZipFile(v3_package) as z:
        manifest=json.loads(z.read('outputs/manifest.json'))
        for name,v in manifest['files'].items():
            member=z.read('outputs/'+name)
            if len(member)!=v['bytes'] or sha(member)!=v['sha256']:raise ValueError('v3 source member mismatch')
        rows=[json.loads(l) for l in z.read('outputs/usable-records.jsonl').splitlines()]
        full=[json.loads(l) for l in z.read('outputs/full-records.jsonl').splitlines()]
        quarantine=[json.loads(l) for l in z.read('outputs/quarantine.jsonl').splitlines()]
        preview=json.loads(z.read('outputs/folds-usable-preview.json'))
    if len(rows)!=1724 or len(full)!=1736 or len(quarantine)!=14:raise ValueError('v3 registered source counts changed')
    base,external,groups=admitted_views(base,rows,groups,preview)
    if len(external)!=856 or len(base['quarantined_ids'])!=12:raise ValueError('v3 registered admission counts changed')
    summaries=[]
    for f in groups['folds']:
        pair={c:make_fold(base,external,f,c,groups['reserved_ids']) for c in ('base','augmented')}
        if pair['base']['split']['dev']!=pair['augmented']['split']['dev']:raise ValueError('paired Dev mismatch')
        for c,g in pair.items():
            counts=collections.Counter(t for h in g['split']['train'] for t in labels(g)[h])
            summaries.append({'condition':c,'fold':f['fold'],'train':len(g['split']['train']),'dev':len(g['split']['dev']),
                'train_targets':sum(counts.values()),'dev_targets':sum(len(labels(g)[h]) for h in g['split']['dev']),
                'train_support':dict(sorted(counts.items())),'fixed_major':g['fixed_major'],'coverage':g['coverage'],
                'graph_sha256':digest(g),'nodes':len(g['nodes']),'edges':len(g['edges'])})
    expected={'base':[691,691,690],'augmented':[1547,1547,1546]}
    for s in summaries:
        if s['train']!=expected[s['condition']][s['fold']] or s['dev']!=[147,147,148][s['fold']]:raise ValueError('v3 registered role counts changed')
        if len(s['fixed_major'])!=23:raise ValueError('v3 fixed major scope changed')
    audit={'source_sha256':{'previous_parent_runtime':PARENT_SHA,'source_resolved_v3':V3_SHA},
        'external_cves':856,'old_usable_cves':868,'usable_cves':1724,'labeled_cves':1694,
        'external_target_edges':sum(len(r['techniques']) for r in external),
        'external_cwe_edges':sum(len(r['cwe_ids']) for r in external),'external_cpe_edges':sum(len(r['cpe_families']) for r in external),
        'candidate_domain':base['techniques'],'reserved_ids':len(groups['reserved_ids']),
        'quarantined_original_ids':base['quarantined_ids'],'quarantine_total':14,'summaries':summaries,
        'data_conditions':['base','augmented'],'source_semantics':'partial_parent_potential_association',
        'scored_dev_unique_cves':groups['scored_dev_unique_cves'],'scored_dev_occurrences':groups['scored_dev_occurrences'],
        'independent_human_iaa':False,'new_metadata_as_of':'2026_current_not_2022_historical','model_training_runs':0}
    members={'base-graph.json':encoded(base),'external-records.jsonl':b''.join(encoded(r) for r in external),
             'folds.json':encoded(groups),'audit.json':encoded(audit)}
    members['manifest.json']=encoded({'files':{n:sha(b) for n,b in sorted(members.items())},'source_sha256':audit['source_sha256']})
    destination=Path(destination)
    if destination.exists():raise ValueError('refuse package overwrite')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,member in sorted(members.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            z.writestr(info,member,compresslevel=9)
    return audit|{'package_sha256':sha(destination.read_bytes()),'package_bytes':destination.stat().st_size}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ['parent-package','v3-package','destination']:p.add_argument('--'+n,required=True)
    a=p.parse_args();print(json.dumps(build_package(a.parent_package,a.v3_package,a.destination),ensure_ascii=False))
