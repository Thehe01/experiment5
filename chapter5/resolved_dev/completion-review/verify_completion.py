"""Read-only completion audit. No fitting, checkpoint replay, or reserved scoring."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
from chapter5.resolved_dev.campaign import verify_registration, load_inputs
from chapter5.public_dev.model import binding
from chapter5.public_dev.core import labels
from chapter5.core import digest


def read(path):
    return json.loads(Path(path).read_text())


def git_blob(path):
    raw = Path(path).read_bytes()
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def verify(repo, inputs, evidence=None):
    assert os.environ.get('ATEN_CPU_CAPABILITY') == 'avx2', 'Use the registered workflow CPU setting: ATEN_CPU_CAPABILITY=avx2'
    repo, inputs = Path(repo), Path(inputs)
    evidence = Path(evidence) if evidence else inputs
    cfg = read(repo / 'chapter5/resolved_dev/config.json')
    reg = read(repo / 'chapter5/resolved_dev/registration.json')
    offline = verify_registration(repo)
    comparison = read(inputs / 'comparison.json')
    status, session = read(inputs / 'status.json'), read(inputs / 'session.json')
    manifest = read(inputs / 'manifest.json')
    tree = {e['path']: e for e in read(evidence / 'remote-tree.json')['tree']}
    workflow = read(evidence / 'run.json')
    assert workflow['run']['id'] == 38152196348 and workflow['run']['run_attempt'] == 1
    assert workflow['run']['status'] == 'completed' and workflow['run']['conclusion'] == 'success'
    assert workflow['run']['head_sha'] == '244e217428e23c9bd019084171de40c49999c389'
    jobs = {j['name']:j for j in workflow['jobs']['jobs']}
    assert jobs['verify']['conclusion'] == jobs['slot1']['conclusion'] == 'success'
    assert jobs['slot2']['conclusion'] == jobs['slot3']['conclusion'] == 'skipped'
    assert git_blob(inputs / 'comparison.json') == 'ab39bcb6f32e00102bd9ef08a8d4187bc12c9ac2'
    assert status == comparison['status'] == session['campaign']
    assert session['status'] == 'closed' and session['phase'] == status['phase'] == 'development_complete'
    assert session['run_id'] == '38152196348' and session['attempt'] == '1' and session['slot'] == 1
    assert session['source_commit'] == '4f379b612b3d6cce5f8237b8103e866909ca7988'
    assert status['completed_units'] == status['registered_units'] == status['reserved_units'] == 36
    assert status['registration_sha256'] == offline['registration_sha256']
    assert not status['reserved_holdout_evaluated'] and not status['confirmation_training_started'] and status['model_api_calls'] == 0
    for path in reg['source_files']:
        assert git_blob(repo / path) == tree[path]['sha'], path
    for path in ['chapter5/resolved_dev/config.json', 'chapter5/resolved_dev/registration.json', cfg['data_package']]:
        assert git_blob(repo / path) == tree[path]['sha'], path
    graphs, _, _ = load_inputs(repo, cfg)
    units = {u['id']: u for u in reg['units']}
    results = {r['unit']: r for r in comparison['results']}
    assert len(comparison['results']) == len(results) == 36 and set(results) == set(units)
    log_units = re.findall(r'"phase": "unit_started_or_resumed", "unit": "([^"]+)"', (evidence / 'execution-evidence.log').read_text())
    assert len(log_units) == len(set(log_units)) == 36 and set(log_units) == set(units)
    near = lambda a, b: abs(a - b) < 1e-12
    group_error, macro_error = 0., 0.
    for uid, result in results.items():
        unit = units[uid]
        assert all(result[k] == unit[k] for k in ['arm', 'fold', 'seed', 'condition'])
        assert result['status'] == 'trained' and not result['reserved_holdout_evaluated']
        graph = graphs[(unit['condition'], unit['fold'])]
        assert result['binding'] == binding(graph, unit['arm'], cfg, unit['seed']), uid
        metrics = result['dev']
        assert metrics['queries'] == len(graph['split']['dev']) == cfg['validation_cves_per_fold'][unit['fold']]
        assert metrics['edges'] == sum(len(labels(graph)[h]) for h in graph['split']['dev'])
        assert len(metrics['by_technique']) == 28 and len(metrics['major_eligible']) == 23 and not metrics['major_unavailable']
        assert metrics['major_eligible'] == graph['fixed_major']
        # MRR is first averaged within each CVE, then across CVEs. Disjoint
        # background groups can reconstruct this mean; technique edge weights cannot.
        groups = [g for g in metrics['groups'].values() if g]
        assert sum(g['queries'] for g in groups) == metrics['queries']
        reconstructed = sum(g['queries'] * g['mrr'] for g in groups) / metrics['queries']
        macro = statistics.mean(metrics['by_technique'][t]['mrr'] for t in graph['fixed_major'])
        assert near(reconstructed, metrics['mrr']) and near(macro, metrics['major_macro_mrr'])
        group_error = max(group_error, abs(reconstructed - metrics['mrr']))
        macro_error = max(macro_error, abs(macro - metrics['major_macro_mrr']))
        assert result['stopping_reason'] == 'patience' and result['epoch'] - result['best_epoch'] == 30 and result['epoch'] <= 500
    paired = {}
    for arm in cfg['arms']:
        pairs = []
        for fold in range(3):
            for seed in cfg['development_seeds']:
                base = results[f'f{fold}-{arm}-s{seed}-base']['dev']
                augmented = results[f'f{fold}-{arm}-s{seed}-augmented']['dev']
                assert base['major_eligible'] == augmented['major_eligible']
                pairs.append({'base_mrr': base['mrr'], 'augmented_mrr': augmented['mrr'], 'delta_mrr': augmented['mrr'] - base['mrr'], 'delta_major_macro': augmented['major_macro_mrr'] - base['major_macro_mrr']})
        p = {'pair_count': 9, 'mean_base_mrr': statistics.mean(v['base_mrr'] for v in pairs), 'mean_augmented_mrr': statistics.mean(v['augmented_mrr'] for v in pairs), 'mean_delta_mrr': statistics.mean(v['delta_mrr'] for v in pairs), 'mean_delta_major_macro': statistics.mean(v['delta_major_macro'] for v in pairs), 'wins': sum(v['delta_mrr'] > 0 for v in pairs)}
        assert all(near(value, comparison['paired_data_effect'][arm][key]) for key, value in p.items())
        assert all(near(v[key], comparison['paired_data_effect'][arm]['pairs'][i][key]) for i, v in enumerate(pairs) for key in ['delta_mrr', 'delta_major_macro'])
        paired[arm] = p
    baseline = comparison['baselines']
    metrics = baseline['metrics']
    alpha = max(cfg['smoothing_alphas'], key=lambda a: statistics.mean(v['mrr'] for v in metrics[f'smoothed_cwe-{a}'].values()))
    assert alpha == baseline['selected_smoothing_alpha']
    assert baseline['binding'] == digest({'graphs':{f'{c}-f{f}':digest(g) for (c,f),g in graphs.items()},'config':cfg})
    families = ['frequency', 'cwe_frequency', f'smoothed_cwe-{alpha}', 'neighbor_vote']
    means = {name: {condition: statistics.mean(metrics[name][f'{condition}-f{f}']['mrr'] for f in range(3)) for condition in cfg['conditions']} for name in families}
    for condition in cfg['conditions']:
        assert max(families, key=lambda name: means[name][condition]) == baseline['best_baseline'][condition]
    for name in families:
        assert near(means[name]['augmented'] - means[name]['base'], baseline['paired_delta_mrr'][name])
    for arm in cfg['arms']:
        augmented = [r for r in results.values() if r['arm'] == arm and r['condition'] == 'augmented']
        deltas = [r['dev']['mrr'] - metrics[baseline['best_baseline']['augmented']][f'augmented-f{r["fold"]}']['mrr'] for r in augmented]
        assert near(statistics.mean(deltas), comparison['augmented_vs_best_simple'][arm]['mean_delta_mrr'])
        assert sum(d > 0 for d in deltas) == comparison['augmented_vs_best_simple'][arm]['wins_of_nine']
    p = paired['rgcn_mixed']; gate = cfg['gate']
    passed = p['mean_delta_mrr'] + 1e-12 >= gate['mean_delta_mrr'] and p['wins'] >= gate['wins_of_nine'] and p['mean_delta_major_macro'] + 1e-12 >= gate['major_macro_delta_min']
    assert passed == status['data_expansion_gate']['passed']
    prefix = 'chapter5/resolved_dev/runs/chapter5-resolved-dev-v3-20261011/'
    assert sum(p['bytes'] for p in manifest['parts']) == manifest['source_bytes'] <= 2*1024*1024*1024
    assert [p['path'] for p in manifest['parts']] == [f'state.part-{i:03d}' for i in range(len(manifest['parts']))]
    assert {p for p in tree if p.startswith(prefix+'state.part-')} == {prefix+p['path'] for p in manifest['parts']}
    assert all(re.fullmatch(r'[0-9a-f]{64}',p['sha256']) for p in manifest['parts'])
    for part in manifest['parts']:
        assert tree[prefix + part['path']]['size'] == part['bytes']
        assert tree[prefix + part['path']]['type']=='blob' and re.fullmatch(r'[0-9a-f]{40}',tree[prefix + part['path']]['sha'])
    return {'result': 'passed', 'run_id': 38152196348, 'completed_units': 36, 'execution_log_unique_units': 36, 'unit_numeric_bindings_verified': 36, 'frozen_source_git_blobs_verified': len(reg['source_files']), 'registration_sha256': offline['registration_sha256'], 'dev_queries': cfg['validation_cves_per_fold'], 'evaluable_classes': 28, 'fixed_major_classes': 23, 'group_reconstruction_mrr_max_error': group_error, 'fixed_major_macro_max_error': macro_error, 'paired_summary': paired, 'baseline_means': means, 'best_baseline': baseline['best_baseline'], 'alpha': alpha, 'augmented_vs_best_simple': comparison['augmented_vs_best_simple'], 'data_gate': status['data_expansion_gate'], 'all_stopping_reasons': 'patience', 'epoch_range': [min(r['epoch'] for r in results.values()), max(r['epoch'] for r in results.values())], 'archive_parts': len(manifest['parts']), 'archive_bytes': manifest['source_bytes'], 'archive_part_names_sizes_git_blobs_verified': True, 'archive_zip_part_sha256_recomputed': False, 'raw_ranks_and_checkpoints_replayed': False, 'new_training_runs': 0, 'new_model_api_calls': 0, 'reserved_holdout_evaluated': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--evidence')
    parser.add_argument('--receipt', required=True)
    args = parser.parse_args()
    output = verify(args.repo, args.inputs, args.evidence)
    Path(args.receipt).write_text(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print(json.dumps(output, ensure_ascii=False))
