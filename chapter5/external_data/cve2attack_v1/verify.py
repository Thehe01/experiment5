"""Independent validation of pre-integration outputs against the bound raw inputs."""
import argparse
import collections
import csv
import hashlib
import json
import unicodedata
import zipfile
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def lines(path):
    return [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-dir', type=Path, required=True)
    p.add_argument('--public-package', type=Path, required=True)
    p.add_argument('--folds', type=Path, required=True)
    p.add_argument('--registry', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    manifest = json.loads((a.out/'manifest.json').read_text())
    for name, expected in manifest['files'].items():
        assert digest((a.out/name).read_bytes()) == expected, name
    assert digest(a.public_package.read_bytes()) == manifest['public_package_sha256']
    assert digest(a.folds.read_bytes()) == manifest['folds_sha256']
    assert digest(a.registry.read_bytes()) == manifest['registry_sha256']
    for name, expected in manifest['source_sha256'].items():
        assert digest((a.source_dir/name).read_bytes()) == expected, name
    registry = json.loads(a.registry.read_text())
    mapping = {m['source_name']: m['technique_id'] for m in registry['mapping']}
    raw = collections.defaultdict(list)
    for split in ('train', 'test'):
        with (a.source_dir/f'X_{split}.csv').open(encoding='utf-8', newline='') as f: xs = list(csv.DictReader(f))
        with (a.source_dir/f'y_{split}.csv').open(encoding='utf-8', newline='') as f: ys = list(csv.DictReader(f))
        assert len(xs) == len(ys)
        for index, (x, y) in enumerate(zip(xs, ys), 1):
            raw[x['Name'].strip()].append({'text': x['Text'], 'labels': {mapping[k] for k,v in y.items() if v=='1'},
                                           'split': split, 'row': index})
    with zipfile.ZipFile(a.public_package) as z:
        public = {json.loads(s)['id']: json.loads(s) for s in z.read('source-records.jsonl').decode().splitlines()}
        current = {json.loads(s)['id']: json.loads(s) for s in z.read('records.jsonl').decode().splitlines()}
        exposed = set(json.loads(z.read('exposure.json'))['excluded_union'])
        graph = json.loads(z.read('graph.json'))
    folds = json.loads(a.folds.read_text())
    reserved = set(folds['reserved_ids'])
    candidate_rows = lines(a.out/'new-text-candidates.jsonl')
    excluded_rows = lines(a.out/'excluded-cves.jsonl')
    quarantine_rows = lines(a.out/'quarantine-cves.jsonl')
    normalized = lines(a.out/'normalized-cves.jsonl')
    ids = [{r['id'] for r in group} for group in (candidate_rows, excluded_rows, quarantine_rows)]
    assert all(len(group)==len(group_ids) for group,group_ids in zip((candidate_rows,excluded_rows,quarantine_rows),ids))
    assert not any(ids[i] & ids[j] for i in range(3) for j in range(i))
    assert set.union(*ids) == set(raw) == {r['id'] for r in normalized}
    assert len(normalized) == len(raw)
    assert not ids[0] & (set(public) | exposed | reserved)
    normalize = lambda s: ' '.join(unicodedata.normalize('NFKC', s).casefold().split())
    public_text = {normalize(r['description']) for r in public.values()}
    source_positives = 0
    for candidate in candidate_rows:
        observations = raw[candidate['id']]
        assert set(candidate['techniques']) == observations[0]['labels']
        assert all(r['labels'] == observations[0]['labels'] for r in observations)
        assert candidate['description'] in {r['text'] for r in observations}
        assert normalize(candidate['description']) not in public_text
        assert all('.' not in t and t in graph['techniques'] for t in candidate['techniques'])
        assert candidate['cpes'] == candidate['cwes'] == [] and candidate['graph_ready'] is False
        assert candidate['missing_labels_are_confirmed_negatives'] is False
        assert candidate['role'] == 'unassigned_external_development_candidate'
        assert {(r['source_split'],r['source_row']) for r in candidate['provenance']} == {(r['split'],r['row']) for r in observations}
        source_positives += len(observations[0]['labels'])
    audit = json.loads((a.out/'audit.json').read_text())
    assert audit['unique_external_cves']==len(raw)
    assert audit['source_rows']==sum(map(len,raw.values()))
    assert audit['new_text_candidates']==len(candidate_rows)
    assert audit['new_candidate_positive_links']==source_positives
    assert audit['overlap_reserved_ids']==len(set(raw)&reserved)
    assert audit['classification_counts']==dict(collections.Counter(r['status'] for r in normalized))
    reviews = lines(a.out/'development-label-review.jsonl')
    assert not {r['id'] for r in reviews} & reserved
    assert {r['id'] for r in reviews} == set(raw) & (set(current)-reserved)
    protection = json.loads((a.out/'fold-protection.json').read_text())
    for record, fold in zip(protection, folds['folds']):
        assert set(record['candidate_ids']) == ids[0]
        assert not ids[0] & (set(fold['dev'])|reserved)
        assert not any(record[k] for k in record if k.startswith('overlap_'))
    supports = json.loads((a.out/'support-preview.json').read_text())
    for record,fold in zip(supports,folds['folds']):
        count = collections.Counter()
        for c in fold['train']:
            for t in {t.partition('.')[0] for t in current[c]['techniques']}: count[t]+=1
        assert record['current_train_parent_support']==dict(count)
        expected = count.copy()
        for c in candidate_rows:
            for t in set(c['techniques']): expected[t]+=1
        assert record['hypothetical_augmented_parent_support']==dict(expected)
    receipt = {'status':'passed', 'checks':'source_hashes_row_coordinates_partition_labels_parent_scope_description_collision_fold_protection_train_only_support',
               'source_rows': audit['source_rows'], 'unique_external_cves':len(raw),
               'new_text_candidates':len(candidate_rows),'new_candidate_positive_links':source_positives,
               'protected_candidate_overlap':0,'reserved_label_reviews':0,'new_graph_ready_cves':0,
               'source_hashes_unchanged':True,'model_api_calls':0,'new_training_runs':0,'reserved_scoring_runs':0}
    print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__': main()
