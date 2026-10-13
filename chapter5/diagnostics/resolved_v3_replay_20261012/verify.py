"""Independent cache-only scoring audit; no Torch import or model forward."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import zipfile
from .helpers import check_cache, shape, consumed
from .runner import PREFIX, read, sha, write, validate, publish
from chapter5.core import digest
from chapter5.public_dev.core import evaluate_scores
from chapter5.resolved_dev.data import read_package, make_fold, fixed_major


def difference(a, b):
    if isinstance(a, dict): return max([0.] + [difference(v, b[k]) for k, v in a.items()])
    if isinstance(a, list):
        if len(a) != len(b): raise ValueError('list length mismatch')
        return max([0.] + [difference(x, y) for x, y in zip(a, b)])
    if isinstance(a, (int, float)) and not isinstance(a, bool): return abs(a - b)
    if a != b: raise ValueError('metric metadata mismatch')
    return 0.


def main(repo, state, persist):
    repo, state = Path(repo), Path(state); root = repo / PREFIX
    reg = validate(repo); signature = sha(root / 'registration.json'); ledger = read(root / 'ledger.json')
    if ledger['registration_sha256'] != signature or ledger['state'] != 'complete' or consumed(ledger) != 144 or any(a['status'] != 'done' for a in ledger['actions'].values()): raise ValueError('incomplete or uncertain ledger')
    if ledger['historical_forward_consumed'] != 144 or ledger['additional_consumed'] != 144 or ledger['cumulative_consumed'] != 288: raise ValueError('usage reconciliation mismatch')
    cfg = read(repo / 'chapter5/resolved_dev/config.json')
    base, external, groups, audit = read_package(repo / cfg['data_package'], cfg['data_sha256'])
    protected = set(groups['reserved_ids']) | set(audit['quarantined_original_ids']) | {'CVE-2017-0493', 'CVE-2019-7287'}
    graphs = {(c, f['fold']): make_fold(base, external, f, c, groups['reserved_ids']) for f in groups['folds'] for c in cfg['conditions']}
    caches, all_error, original_error, rank_rows = {}, 0., 0., 0
    expected_files = {a['id'] + '.json' for a in reg['actions']}
    if {p.name for p in (root / 'scores').glob('*.json')} != expected_files: raise ValueError('score file inventory mismatch')
    comparison = read(state / 'comparison.json'); originals = {r['unit']: r for r in comparison['results']}
    for action in reg['actions']:
        aid = action['id']; path = root / 'scores' / (aid + '.json')
        if sha(path) != ledger['actions'][aid]['cache_sha256']: raise ValueError('score cache hash mismatch')
        cache = read(path); g = graphs[(action['condition'], action['fold'])]
        check_cache(cache, aid, signature, g['split']['dev'], g['techniques'])
        if set(cache['scores']) & protected: raise ValueError('protected score query')
        if cache['original_graph_sha256'] != digest(g) or cache['unit_binding'] != action['unit_binding'] or cache['modified_graph_sha256'] != ledger['actions'][aid]['modified_graph_sha256']: raise ValueError('cache input binding')
        metrics, rows = evaluate_scores(g, cache['scores']); metrics = fixed_major(metrics, g['fixed_major'])
        err = difference(metrics, cache['metrics']); all_error = max(all_error, err)
        if err > 1e-12 or rows != cache['ranks']: raise ValueError('cached score recomputation mismatch')
        if action['variant'] == 'original':
            if rows != read(state / 'units' / action['unit'] / 'ranks.json'): raise ValueError('original ranks changed')
            original_error = max(original_error, difference(metrics, originals[action['unit']]['dev'])); rank_rows += len(rows)
        caches[aid] = cache
    if original_error > 1e-12 or rank_rows != 11868: raise ValueError('original metric replay mismatch')
    unit_summary = []
    for uid, original in originals.items():
        g = graphs[(original['condition'], original['fold'])]; base_scores = caches[uid + '__original']['scores']
        s = shape(base_scores)
        common = evaluate_scores(g, s['common_scores'])[0]['mrr']; residual = evaluate_scores(g, s['residual_scores'])[0]['mrr']
        top = lambda row: set(sorted(row, key=lambda t: (-row[t], t))[:3])
        item = {'unit': uid, 'arm': original['arm'], 'condition': original['condition'], 'fold': original['fold'], 'seed': original['seed'], 'original_mrr': original['dev']['mrr'], 'shared_energy_fraction': s['shared_energy_fraction'], 'common_only_mrr': common, 'residual_mrr': residual, 'interventions': {}}
        for variant in ('cwe', 'cpe', 'joint'):
            scores = caches[uid + '__' + variant]['scores']
            delta = max(abs(scores[c][t] - base_scores[c][t]) for c in scores for t in scores[c])
            if original['arm'] == 'distmult_mixed' and delta != 0: raise ValueError('DistMult static-input invariance failed')
            item['interventions'][variant] = {'mrr': caches[uid + '__' + variant]['metrics']['mrr'], 'top3_set_change_fraction': statistics.mean(top(scores[c]) != top(base_scores[c]) for c in scores), 'maximum_score_difference': delta}
        unit_summary.append(item)
    summary = {}
    for arm in cfg['arms']:
        summary[arm] = {}
        for condition in cfg['conditions']:
            rows = [r for r in unit_summary if r['arm'] == arm and r['condition'] == condition]
            summary[arm][condition] = {k: statistics.mean(r[k] for r in rows) for k in ('original_mrr', 'shared_energy_fraction', 'common_only_mrr', 'residual_mrr')}
            summary[arm][condition]['interventions'] = {v: {'mean_mrr': statistics.mean(r['interventions'][v]['mrr'] for r in rows), 'mean_top3_set_change_fraction': statistics.mean(r['interventions'][v]['top3_set_change_fraction'] for r in rows)} for v in ('cwe', 'cpe', 'joint')}
    result = {'result': 'passed', 'verified_caches': 144, 'original_units': 36, 'original_rank_rows': rank_rows, 'original_metric_max_error': original_error, 'cached_score_metric_max_error': all_error, 'historical_forward_consumed': 144, 'additional_forward_consumed': 144, 'cumulative_forward_consumed': 288, 'new_training': 0, 'model_api': 0, 'reserved_scoring': False, 'protected_ids': len(protected), 'registration_sha256': signature, 'donor_version': 'new recovery version; not a reconstruction of lost original donor map', 'diagnostic_scope': 'fixed-weight transductive input sensitivity; not causal training attribution or independent final Test', 'summary': summary}
    write(root / 'verification.json', result); write(root / 'per-unit-summary.json', unit_summary)
    lines = ['# v3独立诊断重证据完成', '', '历史144次forward保留，本次新增144次，累计288。原36训练单位没有重训。144分数缓存、逐行动预留/完成记录、哈希均永久保存在此新路径。新donor与丢失原映射不能视为相同实验字节。', '', '原36检查点11,868排名逐条匹配，完整指标最大误差：' + str(original_error) + '。固定权重传导图诊断不识别训练因果贡献，Dev参与选择，不是独立盲测。', '', '|模型/条件|原MRR|共同形状占比|仅共同形状MRR|去共同形状MRR|', '|---|---:|---:|---:|---:|']
    for arm in cfg['arms']:
        for condition in cfg['conditions']:
            r = summary[arm][condition]; lines.append(f"|{arm}/{condition}|{r['original_mrr']:.6f}|{r['shared_energy_fraction']:.2%}|{r['common_only_mrr']:.6f}|{r['residual_mrr']:.6f}|")
    lines += ['', '|R-GCN条件|换CWE MRR/Top3变化|换CPE MRR/Top3变化|联合MRR/Top3变化|', '|---|---:|---:|---:|']
    for condition in cfg['conditions']:
        row = summary['rgcn_mixed'][condition]['interventions']; lines.append('|' + condition + '|' + '|'.join(f"{row[v]['mean_mrr']:.6f} / {row[v]['mean_top3_set_change_fraction']:.2%}" for v in ('cwe', 'cpe', 'joint')) + '|')
    lines += ['', '共同形状能量以每查询中心化/population std标准化后计算，不是准确率、注意力或因果贡献百分比。直接去共同偏好伤害MRR；不单独判定为过平滑。DistMult三干预分数完全不变，为固定CVE ID向量推断结构预期，不能推出训练未利用背景。', '', '原扩容开发失败判定保持。155保留组未评分，9单位候选未实现/登记/训练，main及两个activation分支未移动。完整新证据ZIP及manifest见同目录；原丢失diagnostic-evidence.zip未伪造。']
    (root / 'report.md').write_text('\n'.join(lines) + '\n')
    files = [root / 'registration.json', root / 'donors.json', root / 'ledger.json', root / 'verification.json', root / 'per-unit-summary.json', root / 'report.md'] + sorted((root / 'scores').glob('*.json'))
    for name in reg['files_sha256']:
        path = repo / name
        if path not in files: files.append(path)
    files.append(root / 'launch.json')
    member_name = lambda p: p.relative_to(root).as_posix() if p.is_relative_to(root) else 'workflow/' + p.name
    destination = root / 'complete-evidence.zip'
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in files:
            info = zipfile.ZipInfo(member_name(path), date_time=(1980, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, path.read_bytes(), compresslevel=9)
    write(root / 'manifest.json', {'schema': 'independent-diagnosis-recovery-evidence-v1', 'archive_sha256': sha(destination), 'archive_bytes': destination.stat().st_size, 'archive_members': len(files), 'files': {member_name(p): {'sha256': sha(p), 'bytes': p.stat().st_size} for p in files}, 'original_lost_archive_reconstructed': False})
    if persist: publish(repo, 'Verify and archive all144 independent diagnosis recovery score caches')
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--repo', default='.'); p.add_argument('--state', required=True); p.add_argument('--persist', action='store_true'); a = p.parse_args()
    main(a.repo, a.state, a.persist)
