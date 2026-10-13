"""Recovery ledger, graph interventions, and score checks; stdlib only."""
import copy
import math

VARIANTS = ('original', 'cwe', 'cpe', 'joint')


def consumed(ledger):
    return sum(a['status'] != 'planned' for a in ledger['actions'].values())


def reserve(ledger, action):
    if action not in ledger['actions']: raise ValueError('unregistered action')
    row = ledger['actions'][action]
    if row['status'] == 'done': return False
    if row['status'] != 'planned': raise ValueError('uncertain/failed action cannot be automatically replayed')
    if consumed(ledger) >= ledger['budget']: raise ValueError('additional forward budget exhausted')
    row['status'] = 'reserved'
    return True


def permute(graph, mapping, variant):
    if variant not in VARIANTS: raise ValueError('unregistered intervention')
    dev = set(graph['split']['dev'])
    if set(mapping) != dev or set(mapping.values()) != dev or any(c == d for c, d in mapping.items()):
        raise ValueError('donor must be a fixed no-self-loop Dev bijection')
    out = copy.deepcopy(graph)
    if variant == 'original': return out
    relations = {'has_reported_cwe'} if variant == 'cwe' else {'has_reported_cpe'} if variant == 'cpe' else {'has_reported_cwe', 'has_reported_cpe'}
    bundles = {(c, r): [] for c in dev for r in relations}
    for e in graph['edges']:
        if (e['head'], e['relation']) in bundles: bundles[(e['head'], e['relation'])].append(e)
    out['edges'] = [e for e in out['edges'] if not (e['head'] in dev and e['relation'] in relations)]
    for c in sorted(dev):
        for r in sorted(relations):
            out['edges'].extend(dict(copy.deepcopy(e), head=c) for e in bundles[(mapping[c], r)])
    return out


def check_cache(cache, action, registration, heads, candidates):
    if cache.get('action') != action or cache.get('registration_sha256') != registration:
        raise ValueError('cache binding mismatch')
    scores = cache.get('scores', {})
    if set(scores) != set(heads): raise ValueError('cache query/protection mismatch')
    for row in scores.values():
        if set(row) != set(candidates) or any(not math.isfinite(v) for v in row.values()):
            raise ValueError('cache candidate/nonfinite mismatch')


def shape(scores):
    domain = sorted(next(iter(scores.values())))
    rows, empty = {}, 0
    for c, s in scores.items():
        if set(s) != set(domain) or any(not math.isfinite(v) for v in s.values()): raise ValueError('invalid shape scores')
        mu = sum(s.values()) / len(domain)
        std = math.sqrt(sum((s[t] - mu)**2 for t in domain) / len(domain))
        if std == 0: empty += 1
        rows[c] = {t: (s[t] - mu) / std if std else 0. for t in domain}
    common = {t: sum(s[t] for s in rows.values()) / len(rows) for t in domain}
    total = sum(v*v for row in rows.values() for v in row.values())
    energy = len(rows) * sum(v*v for v in common.values())
    return {'shared_energy_fraction': energy / total if total else 0., 'constant_queries': empty, 'common_scores': {c: dict(common) for c in rows}, 'residual_scores': {c: {t: row[t] - common[t] for t in domain} for c, row in rows.items()}}
