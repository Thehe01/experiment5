"""Independent recovery audit: stdlib only; no checkpoint deserialization or forward.

This is new recovery code, not a byte reconstruction of the lost diagnosis.
Run with --root containing source/, state/, original/, and metadata JSON.
Outputs are created once; an existing output directory is refused.
"""
import argparse
import collections
import hashlib
import importlib.abc
import json
import math
from pathlib import Path
import platform
import random
import statistics
import sys


class NoModelImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == 'torch' or fullname.startswith('torch.') or fullname.endswith(('.model', '.campaign')):
            raise ImportError('model runtime is forbidden in this recovery audit: ' + fullname)
        return None


sys.meta_path.insert(0, NoModelImports())


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git_blob(path):
    raw = Path(path).read_bytes()
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def write(root, name, value):
    (root / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n')


def numeric_difference(a, b):
    if isinstance(a, dict):
        return max([0.] + [numeric_difference(v, b[k]) for k, v in a.items()])
    if isinstance(a, (float, int)) and not isinstance(a, bool):
        assert math.isfinite(a) and math.isfinite(b)
        return abs(a - b)
    assert a == b
    return 0.


def rank_rows(scores, truth):
    rows = []
    for c in sorted(scores):
        for t in sorted(truth[c]):
            eligible = [v for x, v in scores[c].items() if x == t or x not in truth[c]]
            value = scores[c][t]
            rank = 1. + sum(v > value for v in eligible) + (sum(v == value for v in eligible) - 1.) / 2.
            rows.append({'head': c, 'tail': t, 'rank': rank})
    return rows


def independent_scores(graph, kind, alpha, truth, ctx):
    train = graph['split']['train']
    domain = sorted(graph['techniques'])
    count = collections.Counter(t for c in train for t in truth[c])
    prior = {t: count[t] / len(train) for t in domain}
    members = collections.defaultdict(set)
    for c in train:
        for w in ctx['has_reported_cwe'][c]:
            members[w].add(c)
    wc = {w: collections.Counter(t for c in cs for t in truth[c]) for w, cs in members.items()}
    def jac(a, b):
        return len(a & b) / len(a | b) if a | b else 0.
    out = {}
    for c in graph['split']['dev']:
        ws = ctx['has_reported_cwe'][c]
        if kind == 'frequency' or kind == 'cwe_frequency' and not ws:
            out[c] = {t: count[t] for t in domain}
        elif kind == 'cwe_frequency':
            out[c] = {t: sum(wc.get(w, {}).get(t, 0) for w in sorted(ws)) for t in domain}
        elif kind == 'smoothed_cwe':
            out[c] = {t: sum((wc.get(w, {}).get(t, 0) + alpha * prior[t]) / (len(members[w]) + alpha) for w in sorted(ws)) / len(ws) for t in domain} if ws else dict(prior)
        else:
            weights = {x: .5 * jac(ctx['has_reported_cpe'][c], ctx['has_reported_cpe'][x]) + .5 * jac(ctx['has_reported_cwe'][c], ctx['has_reported_cwe'][x]) for x in train}
            total = sum(weights.values())
            out[c] = {t: sum(v for x, v in weights.items() if t in truth[x]) / total for t in domain} if total else dict(prior)
    return out


def main(root, destination):
    assert not destination.exists(), 'refuse output overwrite'
    source, state = root / 'source', root / 'state'
    sys.path.insert(0, str(source))
    from chapter5.core import digest, summarize_ranks
    from chapter5.public_dev.core import context, labels, evaluate_scores
    from chapter5.resolved_dev.data import read_package, make_fold, fixed_major, paired_summary
    from chapter5.archive import pack_state
    cfg = read(source / 'chapter5/resolved_dev/config.json')
    reg = read(source / 'chapter5/resolved_dev/registration.json')
    tree = {e['path']: e for e in read(root / 'activation-tree.json')['tree']}
    for path, expected in reg['source_files'].items():
        assert sha(source / path) == expected and git_blob(source / path) == tree[path]['sha'], path
    assert sha(source / 'chapter5/resolved_dev/config.json') == reg['config_sha256']
    assert sha(source / 'chapter5/resolved_dev/registration.json') == 'ac19948da5d31cfede901073af08dbbc49c2b99950ff48e3f96bea334e075e5e'
    for name in ('config.json', 'registration.json'):
        assert (source / 'chapter5/resolved_dev' / name).read_bytes() == (state / name).read_bytes()
    assert sha(root / 'original-artifact.zip') == '15f7f7705188877b68edb2cdd754a92f0e1619427dd827df78701bfc7b6bb6b4'
    assert (root / 'original-artifact.zip').stat().st_size == 212090493
    assert git_blob(state / 'comparison.json') == 'ab39bcb6f32e00102bd9ef08a8d4187bc12c9ac2'
    base, external, groups, audit = read_package(source / cfg['data_package'], cfg['data_sha256'])
    assert audit == reg['data_integration'] and len(external) == 856
    protected = set(groups['reserved_ids']) | set(audit['quarantined_original_ids']) | {'CVE-2017-0493', 'CVE-2019-7287'}
    assert len(protected) == 169
    graphs = {}
    for f in groups['folds']:
        for c in cfg['conditions']:
            g = make_fold(base, external, f, c, groups['reserved_ids'], cfg['major_technique_train_support'])
            expected = next(s for s in audit['summaries'] if s['condition'] == c and s['fold'] == f['fold'])
            assert digest(g) == expected['graph_sha256']
            assert not {n['id'] for n in g['nodes']} & protected
            assert len(g['split']['dev']) == cfg['validation_cves_per_fold'][f['fold']]
            graphs[(c, f['fold'])] = g
    comp = read(state / 'comparison.json')
    status, execution, ledger = [read(state / n) for n in ('status.json', 'execution.json', 'unit-ledger.json')]
    assert status == comp['status'] == execution['campaign']
    assert execution == read(root / 'original/session.json')
    assert execution['status'] == 'closed' and execution['phase'] == 'development_complete'
    assert status['completed_units'] == status['registered_units'] == status['reserved_units'] == 36
    assert not status['reserved_holdout_evaluated'] and not status['confirmation_training_started']
    assert status['model_api_calls'] == 0 and not status['data_expansion_gate']['passed']
    allowed = {u['id']: u for u in reg['units']}
    results = {r['unit']: r for r in comp['results']}
    assert len(results) == len(comp['results']) == 36
    assert set(results) == set(allowed) == set(ledger['units']) == set(ledger['allowed'])
    model_error, rank_count = 0., 0
    for uid, result in results.items():
        d = state / 'units' / uid
        receipt, checkpoint = read(d / 'completed.json'), read(d / 'checkpoint.pt.receipt.json')
        assert receipt['binding'] == checkpoint['binding'] == result['binding'] == ledger['units'][uid]['binding']
        assert sha(d / 'checkpoint.pt') == checkpoint['sha256']
        assert checkpoint['epoch'] == result['epoch'] == ledger['units'][uid]['epoch']
        assert ledger['units'][uid]['status'] == result['status'] == 'trained'
        for n, h in receipt['files'].items():
            assert sha(d / n) == h
        raw_result = read(d / 'result.json')
        assert all(result[k] == v for k, v in raw_result.items() if k != 'dev')
        assert fixed_major(raw_result['dev'], graphs[(result['condition'], result['fold'])]['fixed_major']) == result['dev']
        rows = read(d / 'ranks.json'); rank_count += len(rows)
        g = graphs[(result['condition'], result['fold'])]; truth = labels(g)
        assert {(x['head'], x['tail']) for x in rows} == {(c, t) for c in g['split']['dev'] for t in truth[c]}
        assert len(rows) == len({(x['head'], x['tail']) for x in rows})
        assert not {r['head'] for r in rows} & protected
        error = numeric_difference(summarize_ranks(rows), result['dev'])
        model_error = max(model_error, error)
        assert error < 1e-12
        major = statistics.mean(result['dev']['by_technique'][t]['mrr'] for t in g['fixed_major'])
        assert abs(major - result['dev']['major_macro_mrr']) < 1e-12
        assert result['stopping_reason'] == 'patience' and result['epoch'] - result['best_epoch'] == 30
    assert rank_count == 11868
    paired = paired_summary(comp['results'], reg['units'])
    assert numeric_difference(paired, comp['paired_data_effect']) < 1e-12
    br = read(state / 'baselines/receipt.json')
    for name, h in br['files'].items():
        assert sha(state / 'baselines' / name) == h
    assert br['binding'] == comp['baselines']['binding'] == digest({'graphs': {f'{c}-f{f}': digest(g) for (c, f), g in graphs.items()}, 'config': cfg})
    baseline_error, baseline_count = 0., 0
    neighbor_scores = {}
    for (condition, fold), g in graphs.items():
        truth, ctx = labels(g), context(g)
        for kind, alpha in [('frequency', 1), ('cwe_frequency', 1), ('neighbor_vote', 1)] + [('smoothed_cwe', a) for a in cfg['smoothing_alphas']]:
            family = f'smoothed_cwe-{alpha}' if kind == 'smoothed_cwe' else kind
            scores = independent_scores(g, kind, alpha, truth, ctx)
            rows = rank_rows(scores, truth)
            assert rows == read(state / 'baselines' / f'{family}-{condition}-f{fold}-ranks.json')
            metrics, official_rows = evaluate_scores(g, scores)
            metrics = fixed_major(metrics, g['fixed_major'])
            assert rows == official_rows
            error = numeric_difference(metrics, comp['baselines']['metrics'][family][f'{condition}-f{fold}'])
            assert error < 1e-12
            baseline_error = max(baseline_error, error); baseline_count += 1
            if kind == 'neighbor_vote':
                neighbor_scores[(condition, fold)] = scores
    assert baseline_count == 36
    distribution = []
    for fold in range(3):
        item = {'fold': fold}
        for condition in cfg['conditions']:
            g = graphs[(condition, fold)]; truth = labels(g)
            counters = {r: collections.Counter(t for c in g['split'][r] for t in truth[c]) for r in ('train', 'dev')}
            tv = .5 * sum(abs(counters['train'][t] / sum(counters['train'].values()) - counters['dev'][t] / sum(counters['dev'].values())) for t in g['techniques'])
            item[condition] = {'tv_train_dev_target_edges': tv, 'train': dict(sorted(counters['train'].items())), 'dev': dict(sorted(counters['dev'].items()))}
        distribution.append(item)
    ext_ids = {r['id'] for r in external}
    old_ids = {n['id'] for n in base['nodes'] if n['type'] == 'Vulnerability' and labels(base)[n['id']]}
    years = {name: {'n': len(ids), 'numbered_2020_2022': sum(2020 <= int(c.split('-')[1]) <= 2022 for c in ids), 'fraction': sum(2020 <= int(c.split('-')[1]) <= 2022 for c in ids) / len(ids)} for name, ids in [('old_labeled', old_ids), ('external', ext_ids)]}
    base_ctx = context(graphs[('augmented', 0)])
    cwe_support = {name: collections.Counter(w for c in ids for w in base_ctx['has_reported_cwe'][c]) for name, ids in [('old', old_ids), ('external', ext_ids)]}
    shared_cwe = sorted(w for w in set(cwe_support['old']) & set(cwe_support['external']) if min(cwe_support['old'][w], cwe_support['external'][w]) >= 10)
    source_rows = []
    def jac(a, b):
        return len(a & b) / len(a | b) if a | b else 0.
    for fold in range(3):
        g = graphs[('augmented', fold)]; truth, ctx = labels(g), context(g)
        for c in g['split']['dev']:
            totals = {'old': 0., 'external': 0.}; overlap = {'old': 0., 'external': 0.}; new_cwe = 0.
            vote_mass = {s: {t: 0. for t in g['techniques']} for s in ('old', 'external')}
            for x in g['split']['train']:
                cwe = .5 * jac(ctx['has_reported_cwe'][c], ctx['has_reported_cwe'][x])
                cpe = .5 * jac(ctx['has_reported_cpe'][c], ctx['has_reported_cpe'][x])
                weight = cwe + cpe; name = 'external' if x in ext_ids else 'old'
                totals[name] += weight
                overlap[name] += weight * len(truth[c] & truth[x]) / len(truth[c])
                for t in truth[x]: vote_mass[name][t] += weight
                if name == 'external': new_cwe += cwe
            rr = {condition: statistics.mean(1. / r['rank'] for r in rank_rows({c: neighbor_scores[(condition, fold)][c]}, truth)) for condition in cfg['conditions']}
            group = 'both' if all(totals.values()) else 'old_only' if totals['old'] else 'external_only' if totals['external'] else 'neither'
            compatibility = {s: sum(vote_mass[s][t] for t in truth[c]) / sum(vote_mass[s].values()) if sum(vote_mass[s].values()) else None for s in vote_mass}
            decomp_error = max(abs(neighbor_scores[('augmented', fold)][c][t] - sum(vote_mass[s][t] for s in vote_mass) / sum(totals.values())) for t in g['techniques']) if sum(totals.values()) else 0.
            assert decomp_error < 1e-12
            source_rows.append({'fold': fold, 'cve': c, 'group': group, 'old_weight': totals['old'], 'external_weight': totals['external'], 'external_cwe_weight': new_cwe, 'external_share': totals['external'] / sum(totals.values()) if sum(totals.values()) else 0., 'weighted_query_label_recall': {s: overlap[s] / totals[s] if totals[s] else None for s in totals}, 'weighted_compatibility_with_observed_dev_labels': compatibility, 'source_label_vote_mass': vote_mass, 'max_decomposition_error': decomp_error, 'base_mrr': rr['base'], 'augmented_mrr': rr['augmented'], 'delta_mrr': rr['augmented'] - rr['base']})
    assert len(source_rows) == 442 and len({x['cve'] for x in source_rows}) == 233
    assert not {x['cve'] for x in source_rows} & protected
    paired_source = [r for r in source_rows if r['group'] == 'both']
    source_summary = {'occurrences': len(source_rows), 'unique_cves': 233, 'mean_external_share_all_occurrences': statistics.mean(r['external_share'] for r in source_rows), 'external_cwe_fraction_of_total_external_weight': sum(r['external_cwe_weight'] for r in source_rows) / sum(r['external_weight'] for r in source_rows), 'paired_overlap_n': len(paired_source), 'paired_weighted_compatibility_with_observed_dev_labels': {s: statistics.mean(r['weighted_compatibility_with_observed_dev_labels'][s] for r in paired_source) for s in ('old', 'external')}, 'compatibility_definition': 'sum_x weight(x)*|labels(x) intersect observed_dev_labels| / sum_x weight(x)*|labels(x)|; partial-label overlap, not semantic accuracy', 'max_vote_decomposition_error': max(r['max_decomposition_error'] for r in source_rows), 'groups': {name: {'n': sum(r['group'] == name for r in source_rows), 'mean_delta_mrr': statistics.mean(r['delta_mrr'] for r in source_rows if r['group'] == name)} for name in ('both', 'old_only', 'external_only', 'neither')}, 'directions': {'down': sum(r['delta_mrr'] < 0 for r in source_rows), 'up': sum(r['delta_mrr'] > 0 for r in source_rows), 'same': sum(r['delta_mrr'] == 0 for r in source_rows)}}
    for fold in range(3):
        mean_delta = statistics.mean(r['delta_mrr'] for r in source_rows if r['fold'] == fold)
        expected = comp['baselines']['metrics']['neighbor_vote'][f'augmented-f{fold}']['mrr'] - comp['baselines']['metrics']['neighbor_vote'][f'base-f{fold}']['mrr']
        assert abs(mean_delta - expected) < 1e-12
    donor_maps = []
    for fold in range(3):
        ids = sorted(graphs[('base', fold)]['split']['dev'])
        random.Random(20261012 + fold).shuffle(ids)
        mapping = {c: ids[(i + 1) % len(ids)] for i, c in enumerate(ids)}
        assert set(mapping) == set(mapping.values()) and all(c != d for c, d in mapping.items())
        donor_maps.append({'fold': fold, 'seed': 20261012 + fold, 'method': 'shuffle then cyclic successor; new recovery version, not original lost donor mapping', 'mapping': dict(sorted(mapping.items()))})
    destination.mkdir(parents=True)
    rebuilt = pack_state(state, root / 'rebuilt-original')
    original_manifest = read(root / 'original/manifest.json')
    assert rebuilt == original_manifest
    assert rebuilt['source_sha256'] == '2fd3c6b2bebf7ba50337f7a29383588e90adbfca7669c5811a4461ace26b0a28'
    prefix = 'chapter5/resolved_dev/runs/chapter5-resolved-dev-v3-20261011/'
    for part in rebuilt['parts']:
        assert git_blob(root / 'rebuilt-original' / part['path']) == tree[prefix + part['path']]['sha']
        assert part['bytes'] == tree[prefix + part['path']]['size']
    write(destination, 'archive-verification.json', {'artifact_sha256': sha(root / 'original-artifact.zip'), 'artifact_bytes': 212090493, 'members': 298, 'checkpoint_receipts_verified': 36, 'rebuilt_manifest_exact_match': True, 'rebuilt_zip_sha256': rebuilt['source_sha256'], 'rebuilt_zip_bytes': rebuilt['source_bytes'], 'parts': len(rebuilt['parts']), 'all_part_sha256_and_git_blob_sha_matched': True, 'new_forward': 0})
    write(destination, 'source-distribution.json', {'folds': distribution, 'mean_tv': {condition: statistics.mean(r[condition]['tv_train_dev_target_edges'] for r in distribution) for condition in cfg['conditions']}, 'cve_number_years_not_publication_or_annotation_dates': years, 'both_sources_cwe_at_least_10_cves': shared_cwe})
    write(destination, 'neighbor-source-rows.json', source_rows)
    write(destination, 'neighbor-source-summary.json', source_summary)
    write(destination, 'proposed-replay-donors.json', donor_maps)
    write(destination, 'verification.json', {'result': 'passed_no_model_recovery', 'python': platform.python_version(), 'frozen_source_git_sha_and_sha256_verified': 28, 'graphs_rebuilt_and_bound': 6, 'protected_ids': 169, 'completed_units': 36, 'model_rank_rows_recovered': rank_count, 'model_metrics_from_original_ranks_max_error': model_error, 'baseline_independent_formula_cases': baseline_count, 'baseline_ranks_exact_match': True, 'baseline_metrics_max_error': baseline_error, 'paired_summary': paired, 'raw_model_scores_replayed': False, 'checkpoint_deserialization': False, 'frozen_completion_verifier_executed': False, 'reason_frozen_completion_verifier_not_run': 'Torch 2.9.1+cpu is absent; independent stdlib audit was used, without weakening its frozen runtime gate', 'numeric_runtime_binding_recomputed': False, 'new_training': 0, 'new_forward': 0, 'new_model_api_calls': 0, 'reserved_evaluation': False, 'historical_diagnostic_forward_consumed': 144, 'historical_per_forward_ledger_available': False, 'diagnostic_score_caches_recovered': 0})
    print(json.dumps({'result': 'passed_no_model_recovery', 'model_ranks': rank_count, 'baseline_cases': baseline_count, 'source_rows': len(source_rows), 'archive_parts': len(rebuilt['parts']), 'model_rank_metrics_max_error': model_error, 'baseline_metrics_max_error': baseline_error, 'tv_means': {c: statistics.mean(r[c]['tv_train_dev_target_edges'] for r in distribution) for c in cfg['conditions']}, 'neighbor_summary': source_summary, 'new_forward': 0}, ensure_ascii=False))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--root', required=True, type=Path)
    p.add_argument('--destination', required=True, type=Path)
    a = p.parse_args()
    main(a.root.resolve(), a.destination.resolve())
