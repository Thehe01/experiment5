"""Offline pre-integration preparation; never trains or scores a model."""
import argparse
import collections
import csv
import hashlib
import json
import re
import unicodedata
import zipfile
from pathlib import Path


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def git_sha(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def normalized_text(text):
    return ' '.join(unicodedata.normalize('NFKC', text).casefold().split())


def mapping_dict(registry):
    entries = registry['mapping']
    result = {r['source_name']: r['technique_id'] for r in entries}
    if len(result) != len(entries) or len(set(result.values())) != len(result):
        raise ValueError('duplicate or ambiguous label mapping')
    if any(not re.fullmatch(r'T\d{4}', t) for t in result.values()):
        raise ValueError('source mapping must retain parent technique granularity')
    return result


def read_rows(source_dir, registry):
    source_dir = Path(source_dir)
    mapping = mapping_dict(registry)
    rows = []
    for split in ('train', 'test'):
        xfile, yfile = f'X_{split}.csv', f'y_{split}.csv'
        with (source_dir / xfile).open(encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            if reader.fieldnames != ['Name', 'Text']:
                raise ValueError('unexpected X columns')
            xs = list(reader)
        with (source_dir / yfile).open(encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)) or set(headers) != set(mapping):
                raise ValueError('unexpected or duplicate label columns')
            ys = list(reader)
        if len(xs) != len(ys):
            raise ValueError('paired X/y row count mismatch')
        for i, (x, y) in enumerate(zip(xs, ys), 1):
            if None in x or None in y or any(v is None for v in (*x.values(), *y.values())):
                raise ValueError('CSV row width mismatch')
            if any(v not in ('0', '1') for v in y.values()):
                raise ValueError('non-binary label')
            rows.append({'id': x['Name'].strip(), 'description': x['Text'],
                         'techniques': sorted(mapping[k] for k, v in y.items() if v == '1'),
                         'source_split': split, 'source_row': i,
                         'source_x_file': xfile, 'source_y_file': yfile})
    return rows


def parent_set(techniques, active_ids):
    parents = {t.split('.')[0] for t in techniques}
    if not parents <= active_ids:
        raise ValueError('parent IDs absent from frozen active candidate graph')
    return parents


def thresholds(counts):
    return {str(n): sum(v >= n for v in counts.values()) for n in (1, 5, 10, 15, 20)}


def prepare(rows, public_records, current_records, exposure_ids, folds, registry, active_ids):
    mapping = mapping_dict(registry)
    scope = set(mapping.values())
    if not scope <= active_ids:
        raise ValueError('mapped labels absent from frozen active candidate graph')
    public = {r['id']: r for r in public_records}
    current = {r['id']: r for r in current_records}
    if len(public) != len(public_records) or len(current) != len(current_records):
        raise ValueError('duplicate existing source ID')
    if not set(current) <= set(public):
        raise ValueError('current pool outside bound public source')
    reserved = set(folds['reserved_ids'])
    if len(reserved) != len(folds['reserved_ids']) or not reserved <= set(current):
        raise ValueError('invalid reserved IDs')
    development = set(current) - reserved
    for fold in folds['folds']:
        train, dev = set(fold['train']), set(fold['dev'])
        if len(train) != len(fold['train']) or len(dev) != len(fold['dev']):
            raise ValueError('duplicate fold IDs')
        if train & dev or (train | dev) & reserved:
            raise ValueError('fold role overlap')
        if train | dev != development:
            raise ValueError('fold membership differs from bound development pool')
    exposure_ids = set(exposure_ids)
    public_text = collections.defaultdict(set)
    for c, r in public.items():
        if normalized_text(r['description']):
            public_text[normalized_text(r['description'])].add(c)
    grouped = collections.defaultdict(list)
    for row in rows:
        grouped[row['id']].append(row)
    output = {k: [] for k in ('normalized', 'new_candidates', 'excluded', 'quarantine',
                               'duplicate_reviews', 'overlap_reviews', 'description_reviews',
                               'support_preview', 'fold_protection')}
    for c, variants in sorted(grouped.items()):
        provenance = [{k: v for k, v in r.items() if k.startswith('source_')} for r in variants]
        descriptions = sorted({r['description'] for r in variants})
        labels = sorted({tuple(sorted(set(r['techniques']))) for r in variants})
        invalid = (not re.fullmatch(r'CVE-\d{4}-\d{4,}', c) or
                   any(not normalized_text(t) for t in descriptions) or
                   any(not ts or not set(ts) <= scope for ts in labels))
        normalized_descriptions = {normalized_text(t) for t in descriptions}
        conflict = len(labels) > 1 or len(normalized_descriptions) > 1
        if len(variants) > 1:
            output['duplicate_reviews'].append({
                'id': c, 'source_rows': len(variants), 'provenance': provenance,
                'description_conflict': len(normalized_descriptions) > 1,
                'label_conflict': len(labels) > 1, 'label_variants': [list(t) for t in labels],
                'resolution': 'unadjudicated_variants' if conflict else 'identical_observation_collapsed'})
        reasons = []
        if c in reserved: reasons.append('reserved_id')
        if c in current: reasons.append('current_graph_pool')
        if c in public: reasons.append('complete_public_source')
        if c in exposure_ids: reasons.append('recorded_exposure')
        if invalid: reasons.append('invalid_record')
        if conflict: reasons.append('duplicate_variant_conflict')
        collisions = sorted({pc for t in normalized_descriptions for pc in public_text[t]} - {c})
        if collisions: reasons.append('public_description_collision')
        if c in reserved:
            status = 'reserved_id_excluded'
        elif c in current:
            status = 'current_pool_overlap_excluded'
        elif c in public:
            status = 'public_source_overlap_excluded'
        elif c in exposure_ids:
            status = 'recorded_exposure_excluded'
        elif invalid:
            status = 'invalid_record_quarantined'
        elif conflict:
            status = 'duplicate_variant_quarantined'
        elif collisions:
            status = 'public_description_collision_quarantined'
        else:
            status = 'new_text_candidate'
        norm = next(iter(normalized_descriptions)) if len(normalized_descriptions) == 1 else None
        record = {'id': c, 'status': status, 'reasons': reasons,
                  'description': descriptions[0] if len(descriptions) == 1 else None,
                  'description_variants': descriptions, 'description_group': sha256(norm.encode()) if norm else None,
                  'techniques': list(labels[0]) if len(labels) == 1 else None,
                  'label_variants': [list(ts) for ts in labels], 'provenance': provenance,
                  'cpes': [], 'cwes': [], 'graph_ready': False,
                  'graph_context_status': 'missing_graph_context_not_inferred',
                  'label_scope': sorted(scope), 'label_granularity': 'parent',
                  'label_semantics': 'source_curated_potential_association_not_observed_incident',
                  'missing_labels_are_confirmed_negatives': False,
                  'role': 'unassigned_external_development_candidate' if status == 'new_text_candidate' else 'audit_only',
                  'source_dataset': 'CVE2ATT&CK_2022',
                  'source_commit': registry.get('source_commit'), 'independent_human_iaa': False}
        # A normalized-equivalent repeated observation may retain the longest raw expression.
        if status == 'new_text_candidate' and record['description'] is None:
            record['description'] = max(descriptions, key=lambda t: (len(t), t))
        output['normalized'].append(record)
        target = ('new_candidates' if status == 'new_text_candidate' else
                  'quarantine' if status.endswith('_quarantined') else 'excluded')
        output[target].append(record)
        if collisions:
            output['description_reviews'].append({'id': c, 'matching_public_ids': collisions,
                                                   'status': status, 'method': 'NFKC_casefold_whitespace_exact'})
        # Reserved target labels are never compared or used for class support decisions.
        if c in development:
            shared = parent_set(current[c]['techniques'], active_ids) & scope
            variant_differences = [{'external_labels': list(ts),
                                   'external_only_labels': sorted(set(ts) - shared),
                                   'public_only_labels': sorted(shared - set(ts))} for ts in labels]
            output['overlap_reviews'].append({
                'id': c, 'public_shared_parent_labels': sorted(shared),
                'external_only_labels': variant_differences[0]['external_only_labels'] if len(labels) == 1 else None,
                'public_only_labels': variant_differences[0]['public_only_labels'] if len(labels) == 1 else None,
                'label_variant_differences': variant_differences,
                'public_outside_shared_scope': sorted(parent_set(current[c]['techniques'], active_ids) - scope),
                'status': 'unadjudicated_set_difference_not_automatically_label_error'})
    candidates = output['new_candidates']
    new_ids = {r['id'] for r in candidates}
    if new_ids & (set(public) | exposure_ids | reserved):
        raise ValueError('protected ID in candidate output')
    increments = collections.Counter(t for r in candidates for t in set(r['techniques']))
    for fold in folds['folds']:
        raw = collections.Counter(t for c in fold['train'] for t in set(current[c]['techniques']))
        parent = collections.Counter(t for c in fold['train'] for t in parent_set(current[c]['techniques'], active_ids))
        hypothetical = parent + increments
        output['support_preview'].append({
            'fold': fold['fold'], 'current_train_cves': len(fold['train']),
            'external_text_candidates': len(candidates),
            'current_train_fine_support': dict(sorted(raw.items())),
            'current_train_parent_support': dict(sorted(parent.items())),
            'new_external_parent_support': dict(sorted(increments.items())),
            'hypothetical_augmented_parent_support': dict(sorted(hypothetical.items())),
            'current_fine_classes_by_min_support': thresholds(raw),
            'current_parent_classes_by_min_support': thresholds(parent),
            'hypothetical_parent_classes_by_min_support': thresholds(hypothetical),
            'status': 'support_preview_only_no_training_or_class_selection'})
        output['fold_protection'].append({
            'fold': fold['fold'], 'candidate_ids': sorted(new_ids),
            'overlap_dev_ids': sorted(new_ids & set(fold['dev'])),
            'overlap_reserved_ids': sorted(new_ids & reserved),
            'overlap_public_ids': sorted(new_ids & set(public)),
            'overlap_recorded_exposure_ids': sorted(new_ids & exposure_ids)})
    statuses = collections.Counter(r['status'] for r in output['normalized'])
    duplicate_groups = collections.Counter(r['description_group'] for r in candidates)
    output['audit'] = {
        'source_rows': len(rows), 'unique_external_cves': len(grouped),
        'duplicate_extra_rows': len(rows) - len(grouped),
        'source_duplicate_cves': len(output['duplicate_reviews']),
        'duplicate_label_conflict_cves': sum(r['label_conflict'] for r in output['duplicate_reviews']),
        'overlap_complete_public_source': len(set(grouped) & set(public)),
        'overlap_current_graph_pool': len(set(grouped) & set(current)),
        'overlap_reserved_ids': len(set(grouped) & reserved),
        'overlap_recorded_exposure': len(set(grouped) & exposure_ids),
        'outside_public_and_exposure': len(set(grouped) - set(public) - exposure_ids),
        'classification_counts': dict(sorted(statuses.items())),
        'new_text_candidates': len(candidates), 'new_graph_ready_cves': 0,
        'new_candidate_positive_links': sum(increments.values()),
        'new_candidate_label_kinds': len(increments),
        'source_label_kinds': len(scope), 'candidate_parent_support': dict(sorted(increments.items())),
        'new_shared_description_groups': sum(n > 1 for n in duplicate_groups.values()),
        'development_overlap_reviews': len(output['overlap_reviews']),
        'development_label_difference_cves': sum(any(v['external_only_labels'] or v['public_only_labels']
                                                   for v in r['label_variant_differences']) for r in output['overlap_reviews']),
        'model_api_calls': 0, 'new_training_runs': 0, 'reserved_scoring_runs': 0,
        'canonical_label_changes': 0, 'independent_human_iaa': False}
    return output


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--public-package', type=Path, required=True)
    parser.add_argument('--folds', type=Path, required=True)
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    registry = json.loads(args.registry.read_text())
    if args.out.exists() and any(args.out.iterdir()):
        raise ValueError('refuse to overwrite an existing preparation')
    if sha256(args.public_package.read_bytes()) != cfg['public_package_sha256']:
        raise ValueError('frozen public package hash mismatch')
    if git_sha(args.folds.read_bytes()) != cfg['folds_git_blob_sha']:
        raise ValueError('frozen folds Git blob hash mismatch')
    input_hashes = {}
    for entry in cfg['source_files']:
        raw = (args.source_dir / entry['name']).read_bytes()
        if git_sha(raw) != entry['git_blob_sha'] or len(raw) != entry['bytes']:
            raise ValueError('source file binding mismatch: ' + entry['name'])
        input_hashes[entry['name']] = sha256(raw)
    if sha256(args.registry.read_bytes()) != cfg['registry_sha256']:
        raise ValueError('registry binding mismatch')
    rows = read_rows(args.source_dir, registry)
    with zipfile.ZipFile(args.public_package) as z:
        bound_manifest = json.loads(z.read('manifest.json'))
        for entry in bound_manifest['files']:
            # Support the existing manifest representation only after binding the outer ZIP.
            if isinstance(entry, str):
                name, expected = entry, bound_manifest['files'][entry]
                if isinstance(expected, dict): expected = expected['sha256']
            else:
                name, expected = entry['path'], entry['sha256']
            if sha256(z.read(name)) != expected:
                raise ValueError('bound package member digest mismatch: ' + name)
        graph = json.loads(z.read('graph.json'))
        public = [json.loads(line) for line in z.read('source-records.jsonl').decode().splitlines()]
        current = [json.loads(line) for line in z.read('records.jsonl').decode().splitlines()]
        exposure = json.loads(z.read('exposure.json'))['excluded_union']
    folds = json.loads(args.folds.read_text())
    if (len(rows), len(public), len(current), len(graph['techniques']), len(folds['reserved_ids'])) != tuple(cfg['expected_counts']):
        raise ValueError('unexpected source or current data scope')
    output = prepare(rows, public, current, exposure, folds, registry, set(graph['techniques']))
    args.out.mkdir(parents=True, exist_ok=True)
    names = {'normalized': 'normalized-cves.jsonl', 'new_candidates': 'new-text-candidates.jsonl',
             'excluded': 'excluded-cves.jsonl', 'quarantine': 'quarantine-cves.jsonl',
             'duplicate_reviews': 'duplicate-review.jsonl', 'overlap_reviews': 'development-label-review.jsonl',
             'description_reviews': 'description-review.jsonl'}
    for key, name in names.items():
        (args.out / name).write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in output[key]), encoding='utf-8')
    for key in ('audit', 'support_preview', 'fold_protection'):
        (args.out / (key.replace('_', '-') + '.json')).write_bytes(json_bytes(output[key]))
    manifest = {'protocol': cfg['protocol'], 'config': cfg, 'source_sha256': input_hashes,
                'public_package_sha256': sha256(args.public_package.read_bytes()),
                'folds_sha256': sha256(args.folds.read_bytes()), 'registry_sha256': sha256(args.registry.read_bytes()),
                'prepare_code_sha256': sha256(Path(__file__).read_bytes()),
                'files': {p.name: sha256(p.read_bytes()) for p in sorted(args.out.iterdir())}}
    (args.out / 'manifest.json').write_bytes(json_bytes(manifest))
    print(json.dumps(output['audit'], ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
