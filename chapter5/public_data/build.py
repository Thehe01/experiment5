"""Build once from pinned Parquet and existing frozen background, offline."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile
from chapter5.public_data.adapter import SOURCE_FIELDS, adapt, split_groups, training_view
from chapter5.public_data.verify import verify


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(obj):
    return (json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()


def checked(path, expected):
    raw=Path(path).read_bytes()
    if sha(raw) != expected:
        raise ValueError('input digest mismatch: '+Path(path).name)
    return raw


def build(source_dir, v1_graph, attack, out, config):
    import pyarrow.parquet as pq
    source_dir=Path(source_dir); out=Path(out)
    rows=[]
    for split in ('train','test'):
        item=config['parquet'][split]
        path=source_dir/item['filename']; checked(path,item['sha256'])
        part=pq.read_table(path).to_pylist()
        if len(part)!=item['rows']:
            raise ValueError('Parquet row count mismatch')
        rows.extend(dict(r,public_split=split) for r in part)
    graph=json.loads(checked(v1_graph,config['v1_graph_sha256']))
    bundle=json.loads(checked(attack,config['attack_sha256']))
    if graph['source_attack_sha256'] != config['attack_sha256'] or graph['attack_version'] != '19.2':
        raise ValueError('v1 background version binding mismatch')
    result=adapt(rows,bundle,graph)
    if result['audit']['source_rows'] != config['expected_source_rows']:
        raise ValueError('unexpected source cardinality')
    if result['quarantine']:
        raise ValueError('source has invalid label rows; independent review required before freezing')
    split=split_groups(result['records'],config['split_seed'])
    train=training_view(result['graph'],split)
    exposure_groups={
        'v1_labeled':sorted({e['head'] for e in graph['edges'] if e['relation']=='exploited_by'}),
        'v1_graph':sorted(n['id'] for n in graph['nodes'] if n['type']=='Vulnerability'),
        'recorded_exposure':sorted(graph['exposed_cves'])}
    exposure={'groups':exposure_groups,'excluded_union':sorted(set().union(*(set(v) for v in exposure_groups.values()))),
              'scope':'repository-recorded only; public dataset labels have been accessed for data audit'}
    safe_rows=[{k:r[k] for k in SOURCE_FIELDS} for r in sorted(rows,key=lambda r:r['id'])]
    payloads={'source-records.jsonl':b''.join(encode(r) for r in safe_rows),
              'records.jsonl':b''.join(encode(r) for r in result['records'])}
    for name, data in {'graph':result['graph'],'training-edges':train,'development-split':split,
                       'audit':result['audit'],'exposure':exposure,'excluded':result['excluded'],
                       'quarantine':result['quarantine'],'no-context':result['no_context'],
                       'v1-overlap-label-review':result['comparisons']}.items():
        payloads[name+'.json']=encode(data)
    # Labels needing review stay in the curated potential task; they are not adjudicated incident facts.
    reviews=[{'id':r['id'],'unclassified_techniques':r['unclassified_techniques'],
              'unparsed_cwes':r['unparsed_cwes'],'invalid_cpes':r['invalid_cpes'],
              'label_changes':r['label_changes']}
             for r in result['all_records']
             if any(r[k] for k in ('unclassified_techniques','unparsed_cwes','invalid_cpes','label_changes'))]
    payloads['metadata-review.json']=encode(reviews)
    module=Path(__file__).parent
    code={p.name:sha(p.read_bytes()) for p in sorted(module.glob('*.py'))}
    code['chapter5/core.py']=sha((module.parent/'core.py').read_bytes())
    manifest={'protocol':'chapter5-public-potential-data-v1-20261011','config':config,
              'code_sha256':code, 'label_source':'CIRCL and CTID curated mappings',
              'license_notice':'Curated mappings Apache-2.0; descriptions CC-BY-4.0; MITRE ATT&CK terms apply. Derived GPL chain fields and predicted CWE are omitted.',
              'files':{n:{'bytes':len(b),'sha256':sha(b)} for n,b in sorted(payloads.items())}}
    payloads['manifest.json']=encode(manifest)
    if out.exists():
        if {p.name:p.read_bytes() for p in out.iterdir() if p.is_file()} != payloads:
            raise ValueError('existing output differs; refuse overwrite')
        verify(out)
    else:
        out.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=out.parent) as tmp:
            staged=Path(tmp)/'data';staged.mkdir()
            for name,raw in payloads.items():
                (staged/name).write_bytes(raw)
            verify(staged)
            staged.rename(out)
    archive=out.with_suffix('.zip')
    with tempfile.NamedTemporaryFile(dir=out.parent,delete=False) as tmp:
        temp_path=Path(tmp.name)
    try:
        with zipfile.ZipFile(temp_path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for name,raw in sorted(payloads.items()):
                info=zipfile.ZipInfo(name,date_time=(2026,10,11,0,0,0))
                info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644 << 16
                z.writestr(info,raw,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
        verify(temp_path)
        if archive.exists() and archive.read_bytes()!=temp_path.read_bytes():
            raise ValueError('existing archive differs; refuse overwrite')
        if not archive.exists():
            temp_path.replace(archive)
    finally:
        temp_path.unlink(missing_ok=True)
    return dict(verify(out),archive_sha256=sha(archive.read_bytes()),archive_bytes=archive.stat().st_size)


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for k in ('source-dir','v1-graph','attack','out'):
        p.add_argument('--'+k,required=True)
    p.add_argument('--config',default=str(Path(__file__).with_name('config.json')))
    a=p.parse_args()
    print(json.dumps(build(a.source_dir,a.v1_graph,a.attack,a.out,json.loads(Path(a.config).read_text())),ensure_ascii=False,sort_keys=True,indent=2))
