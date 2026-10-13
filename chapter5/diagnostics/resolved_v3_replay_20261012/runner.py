"""New frozen-checkpoint diagnosis recovery. No training and no model API.

Each action reserves and pushes its ledger BEFORE one score batch. A reserved,
failed or UNKNOWN action is never automatically repeated. Every completed cache
is pushed with its receipt. Existing successful caches are checksum-verified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from .helpers import VARIANTS, consumed, reserve, permute, check_cache

PREFIX = 'chapter5/diagnostics/resolved_v3_replay_20261012'
BRANCH = 'codex/chapter5-public-dev-20261011'


def read(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    with tmp.open('w') as f:
        f.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'); f.flush(); os.fsync(f.fileno())
    tmp.replace(path)


def validate(repo):
    repo = Path(repo); root = repo / PREFIX; reg = read(root / 'registration.json')
    if read(root / 'launch.json')['registration_sha256'] != sha(root / 'registration.json'): raise ValueError('launch registration mismatch')
    if reg['historical_forward_consumed'] != 144 or reg['additional_forward_budget'] != 144 or reg['training_budget'] or reg['model_api_budget'] or reg['reserved_scoring']:
        raise ValueError('unregistered scope/budget')
    if len(reg['actions']) != 144 or len({a['id'] for a in reg['actions']}) != 144: raise ValueError('action inventory')
    old = read(repo / 'chapter5/resolved_dev/registration.json')
    expected = {(u['id'], v) for u in old['units'] for v in VARIANTS}
    if {(a['unit'], a['variant']) for a in reg['actions']} != expected: raise ValueError('action coverage')
    for name, h in reg['files_sha256'].items():
        if sha(repo / name) != h: raise ValueError('frozen recovery file mismatch: ' + name)
    for name, h in old['source_files'].items():
        if sha(repo / name) != h: raise ValueError('original scientific source mismatch: ' + name)
    if sha(repo / 'chapter5/resolved_dev/registration.json') != reg['scientific_registration_sha256']: raise ValueError('scientific registration mismatch')
    cfg = read(repo / 'chapter5/resolved_dev/config.json')
    if sha(repo / cfg['data_package']) != cfg['data_sha256']: raise ValueError('original data mismatch')
    from chapter5.core import digest
    from chapter5.resolved_dev.data import read_package, make_fold
    base, external, groups, audit = read_package(repo / cfg['data_package'], cfg['data_sha256'])
    protected = set(groups['reserved_ids']) | set(audit['quarantined_original_ids']) | {'CVE-2017-0493', 'CVE-2019-7287'}
    donors = {r['fold']: r['mapping'] for r in read(root / 'donors.json')}
    for f in groups['folds']:
        for condition in cfg['conditions']:
            g = make_fold(base, external, f, condition, groups['reserved_ids'])
            if {n['id'] for n in g['nodes']} & protected: raise ValueError('protected runtime graph')
            actions = [a for a in reg['actions'] if a['fold'] == f['fold'] and a['condition'] == condition]
            if any(a['original_graph_sha256'] != digest(g) for a in actions): raise ValueError('registered action graph binding')
            immutable = lambda graph: [e for e in graph['edges'] if e['head'] not in set(g['split']['dev']) or e['relation'] not in ('has_reported_cwe', 'has_reported_cpe')]
            for variant in VARIANTS:
                modified = permute(g, donors[f['fold']], variant)
                if modified['nodes'] != g['nodes'] or immutable(modified) != immutable(g): raise ValueError('intervention changed protected Train/target structure')
    return reg


def publish(repo, message):
    # Only this new evidence path can be changed by the runner.
    def git(*args, capture=False):
        return subprocess.run(['git', '-C', str(repo), *args], check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout
    if git('branch', '--show-current', capture=True).strip() != BRANCH: raise ValueError('wrong execution branch')
    git('add', '--', PREFIX)
    changed = git('diff', '--cached', '--name-only', capture=True).splitlines()
    if any(not p.startswith(PREFIX + '/') for p in changed): raise ValueError('out-of-scope staged mutation')
    if not changed: return
    git('commit', '-m', message)
    # A non-fast-forward failure stops; no reset, force, or merge is attempted.
    git('push', 'origin', 'HEAD:refs/heads/' + BRANCH)


def run(repo, state):
    import torch
    from chapter5.core import digest
    from chapter5.model import load_state, scores_by_head
    from chapter5.public_dev.model import PublicGraph, PublicPredictor, binding
    from chapter5.public_dev.core import evaluate_scores
    from chapter5.resolved_dev.data import fixed_major
    from chapter5.resolved_dev.campaign import verify_registration, load_inputs
    repo, state = Path(repo), Path(state); root = repo / PREFIX
    reg = validate(repo); signature = sha(root / 'registration.json')
    verify_registration(repo)  # exact registered Python/Torch/build input guards
    cfg = read(repo / 'chapter5/resolved_dev/config.json')
    graphs, groups, audit = load_inputs(repo, cfg)
    protected = set(groups['reserved_ids']) | set(audit['quarantined_original_ids']) | {'CVE-2017-0493', 'CVE-2019-7287'}
    if len(protected) != 169: raise ValueError('protection inventory')
    donors = {r['fold']: r['mapping'] for r in read(root / 'donors.json')}
    path = root / 'ledger.json'
    if path.exists():
        ledger = read(path)
        if ledger['registration_sha256'] != signature or ledger['budget'] != 144 or ledger['historical_forward_consumed'] != 144 or set(ledger['actions']) != {a['id'] for a in reg['actions']}:
            raise ValueError('existing ledger binding mismatch; refuse reset')
    else:
        if (root / 'scores').exists(): raise ValueError('unregistered existing caches')
        ledger = {'schema': 'diagnosis-recovery-forward-ledger-v1', 'registration_sha256': signature, 'historical_forward_consumed': 144, 'budget': 144, 'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'state': 'active', 'actions': {a['id']: {'status': 'planned'} for a in reg['actions']}}
        write(path, ledger); publish(repo, 'Initialize independent diagnosis recovery ledger; retain historical 144')
    if any(a['status'] in ('reserved', 'UNKNOWN', 'failed') for a in ledger['actions'].values()): raise ValueError('uncertain prior forward; manual reconciliation required')
    torch.set_num_threads(2); torch.use_deterministic_algorithms(True)
    active_unit, net = None, None
    started = time.monotonic()
    for action in reg['actions']:
        aid, uid, variant = action['id'], action['unit'], action['variant']
        graph = graphs[(action['condition'], action['fold'])]
        cache_path = root / 'scores' / (aid + '.json')
        if ledger['actions'][aid]['status'] == 'done':
            if sha(cache_path) != ledger['actions'][aid]['cache_sha256']: raise ValueError('existing successful cache was changed')
            check_cache(read(cache_path), aid, signature, graph['split']['dev'], graph['techniques'])
            continue
        if time.monotonic() - started > reg['wall_time_seconds']: raise ValueError('registered wall-time stop before reservation')
        if cache_path.exists(): raise ValueError('unreceipted cache; reconcile without replay')
        if uid != active_unit:
            cp = state / 'units' / uid / 'checkpoint.pt'
            if sha(cp) != action['checkpoint_sha256']: raise ValueError('checkpoint inventory hash')
            expected = binding(graph, action['arm'], cfg, action['seed'])
            if expected != action['unit_binding']: raise ValueError('original numerical runtime binding changed')
            checkpoint = load_state(cp, expected)
            original_pg = PublicGraph(graph, 'mixed')
            net = PublicPredictor(original_pg, action['arm'].split('_')[0], cfg['params'], cfg)
            net.load_state_dict(checkpoint['best_model']); active_unit = uid
        modified = permute(graph, donors[action['fold']], variant)
        if set(modified['split']['dev']) & protected or modified['nodes'] != graph['nodes']: raise ValueError('protected/numeric node mapping changed')
        pg = PublicGraph(modified, 'mixed')
        if pg.names != original_pg.names or pg.candidate_names != original_pg.candidate_names: raise ValueError('numerical index changed')
        if digest(graph) != action['original_graph_sha256']: raise ValueError('original graph binding')
        reserve(ledger, aid)
        ledger['actions'][aid].update(reserved_at=time.time(), run_id=os.environ['GITHUB_RUN_ID'], attempt=os.environ['GITHUB_RUN_ATTEMPT'], modified_graph_sha256=digest(modified))
        ledger['additional_consumed'] = consumed(ledger); ledger['cumulative_consumed'] = 144 + consumed(ledger)
        write(path, ledger)
        publish(repo, 'Reserve diagnosis forward ' + aid)  # must finish before scores_by_head
        try:
            scores = scores_by_head(net, pg, graph['split']['dev'])  # exactly one encode/scoring batch
            metrics, rows = evaluate_scores(graph, scores)
            metrics = fixed_major(metrics, graph['fixed_major'])
            cache = {'action': aid, 'unit': uid, 'variant': variant, 'registration_sha256': signature, 'unit_binding': action['unit_binding'], 'original_graph_sha256': digest(graph), 'modified_graph_sha256': digest(modified), 'scores': scores, 'metrics': metrics, 'ranks': rows}
            check_cache(cache, aid, signature, graph['split']['dev'], graph['techniques'])
            if variant == 'original' and rows != read(state / 'units' / uid / 'ranks.json'): raise ValueError('original checkpoint ranks failed exact replay')
            write(cache_path, cache)
            ledger['actions'][aid].update(status='done', cache_sha256=sha(cache_path), completed_at=time.time())
            write(path, ledger); publish(repo, 'Persist diagnosis scores ' + aid)
            print(json.dumps({'phase': 'forward_durable', 'done': sum(x['status'] == 'done' for x in ledger['actions'].values()), 'new_consumed': consumed(ledger), 'cumulative': 144 + consumed(ledger), 'action': aid}), flush=True)
        except BaseException:
            # May have executed; count it and prohibit replay. If push is unavailable,
            # the already-pushed reserved record remains an equivalent stop gate.
            ledger['actions'][aid]['status'] = 'UNKNOWN'; ledger['state'] = 'stopped_unknown'
            write(path, ledger)
            try: publish(repo, 'Stop uncertain diagnosis forward ' + aid)
            except Exception: pass
            raise
    ledger['state'] = 'complete'; write(path, ledger); publish(repo, 'Close diagnosis recovery ledger at new144 cumulative288')


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('command', choices=['validate', 'run']); p.add_argument('--repo', default='.'); p.add_argument('--state')
    a = p.parse_args()
    if a.command == 'validate':
        reg = validate(a.repo); print(json.dumps({'offline_registration_valid': True, 'actions': len(reg['actions']), 'historical': 144, 'additional_budget': 144, 'new_forward': 0}))
    else:
        if not a.state: raise ValueError('completed state required')
        run(a.repo, a.state)
