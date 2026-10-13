"""Registered public graph, baselines and grouped development folds."""
import collections
import copy
import random
from chapter5.core import filtered_rank, summarize_ranks

RELATIONS = ('has_reported_cpe', 'has_reported_cwe', 'potentially_associated_with', 'implies', 'belongs_to_phase')
TARGET = RELATIONS[2]


def labels(graph):
    out = collections.defaultdict(set)
    for e in graph['edges']:
        if e['relation'] == TARGET:
            out[e['head']].add(e['tail'])
    return out


def folds(graph, source_split, seeds):
    reserved = set(source_split['reserved_holdout'])
    pool = set(source_split['train']) | set(source_split['dev'])
    if reserved & pool or len(pool) != len(source_split['train'])+len(source_split['dev']):
        raise ValueError('source role overlap')
    truth = labels(graph); size = len(source_split['dev'])
    support = collections.Counter(t for c in pool for t in truth[c])
    result = []
    for i, seed in enumerate(seeds):
        if i == 0:
            selected = list(source_split['dev'])
        else:
            rng = random.Random(seed)
            remaining = sorted(pool); rng.shuffle(remaining)
            counts = support.copy(); observed = collections.Counter(); selected = []
            while len(selected) < size:
                valid = [c for c in remaining if all(counts[t] > 1 for t in truth[c])]
                if not valid:
                    raise ValueError('cannot preserve Train technique support')
                chosen = max(valid, key=lambda c: sum((size*support[t]/len(pool)-observed[t])/support[t] for t in sorted(truth[c])))
                selected.append(chosen); remaining.remove(chosen)
                for t in truth[chosen]:
                    counts[t] -= 1; observed[t] += 1
        split = {'train': sorted(pool-set(selected)), 'dev': sorted(selected), 'seed': seed, 'fold': i}
        if set(t for c in split['train'] for t in truth[c]) != set(support):
            raise ValueError('fold lost Train technique support')
        result.append(split)
    return result


def fold_graph(graph, split, reserved):
    train, dev, reserve = set(split['train']), set(split['dev']), set(reserved)
    if train & dev or (train | dev) & reserve:
        raise ValueError('development role overlap')
    out = copy.deepcopy(graph); out['edges'] = []
    for e in graph['edges']:
        if e.get('derived_from_target') or any(p.get('derived_from_target') for p in e.get('provenance', [])):
            raise ValueError('target-derived background')
        r = e['relation']
        if r == TARGET+'_inverse':
            # Inverse messages are built only after Train masking, never admitted as input.
            if e['tail'] not in train:
                continue
            raise ValueError('precomputed target inverse forbidden')
        if r not in RELATIONS:
            raise ValueError('unregistered relation '+r)
        if r == TARGET and e['head'] not in train | dev:
            continue
        out['edges'].append(copy.deepcopy(e))
    out['split'] = {k: copy.deepcopy(split[k]) for k in ('train','dev')}
    out['reserved_ids'] = sorted(reserve)
    out.pop('evaluation_targets', None)
    if any(not labels(out)[c] for c in train | dev):
        raise ValueError('empty development query truth')
    return out


def context(graph):
    ctx = {r: collections.defaultdict(set) for r in RELATIONS[:2]}
    for e in graph['edges']:
        if e['relation'] in ctx:
            ctx[e['relation']][e['head']].add(e['tail'])
    return ctx


def baseline_scores(graph, kind, alpha=1):
    if kind not in ('frequency','cwe_frequency','smoothed_cwe','neighbor_vote') or alpha <= 0:
        raise ValueError('unregistered baseline')
    train = graph['split']['train']; truth = labels(graph); ctx = context(graph)
    tech = sorted(graph['techniques'])
    counts = collections.Counter(t for c in train for t in truth[c])
    prior = {t: counts[t]/len(train) for t in tech}
    w_members = collections.defaultdict(set)
    for c in train:
        for w in ctx[RELATIONS[1]][c]:
            w_members[w].add(c)
    w_counts = {w: collections.Counter(t for c in members for t in truth[c]) for w, members in w_members.items()}
    def jaccard(a, b):
        return len(a & b)/len(a | b) if a | b else 0.
    out = {}
    for c in graph['split']['dev']:
        if c in set(graph.get('reserved_ids', [])):
            raise ValueError('Dev only scoring')
        ws = ctx[RELATIONS[1]][c]
        if kind == 'frequency':
            out[c] = {t: counts[t] for t in tech}
        elif kind == 'cwe_frequency':
            out[c] = {t: sum(w_counts.get(w, {}).get(t, 0) for w in ws) for t in tech} if ws else {t: counts[t] for t in tech}
        elif kind == 'smoothed_cwe':
            out[c] = {t: sum((w_counts.get(w, {}).get(t,0)+alpha*prior[t])/(len(w_members[w])+alpha) for w in ws)/len(ws) for t in tech} if ws else dict(prior)
        else:
            weights = {x: sum(.5*jaccard(ctx[r][c],ctx[r][x]) for r in RELATIONS[:2]) for x in train}
            total = sum(weights.values())
            out[c] = {t: sum(v for x,v in weights.items() if t in truth[x])/total for t in tech} if total else dict(prior)
    return out


def evaluate_scores(graph, scores, role='dev', major_support=10):
    if role != 'dev' or set(scores) != set(graph['split']['dev']) or set(scores) & set(graph.get('reserved_ids', [])):
        raise ValueError('Dev only scoring')
    truth = labels(graph); domain = set(graph['techniques'])
    if any(set(v) != domain for v in scores.values()):
        raise ValueError('candidate domain mismatch')
    rows = [{'head':h, 'tail':t, 'rank':filtered_rank(scores[h],truth[h],t)} for h in sorted(scores) for t in sorted(truth[h])]
    metrics = summarize_ranks(rows)
    support = collections.Counter(t for c in graph['split']['train'] for t in truth[c])
    major = sorted(t for t,n in support.items() if n >= major_support)
    available = [t for t in major if t in metrics['by_technique']]
    metrics['major_macro_mrr'] = sum(metrics['by_technique'][t]['mrr'] for t in available)/len(available) if available else None
    metrics['major_eligible'] = major; metrics['major_unavailable'] = sorted(set(major)-set(available))
    ctx = context(graph); shared = set().union(*(ctx[r][c] for r in RELATIONS[:2] for c in graph['split']['train']))
    group_heads = {
        'background_shared': {c for c in scores if any(ctx[r][c] & shared for r in RELATIONS[:2])},
        'background_unshared': {c for c in scores if not any(ctx[r][c] & shared for r in RELATIONS[:2])},
    }
    metrics['groups'] = {k: summarize_ranks([x for x in rows if x['head'] in hs]) if hs else None for k,hs in group_heads.items()}
    metrics['frequency_groups'] = {}
    for name,low,high in [('singleton',1,1),('rare',2,4),('medium',5,9),('major',10,10**9)]:
        rr = [x for x in rows if low <= support[x['tail']] <= high]
        metrics['frequency_groups'][name] = summarize_ranks(rr) if rr else None
    stage_rows = collections.defaultdict(list)
    stage_index = graph.get('evaluation_stages', {})
    for row in rows:
        sources = set(stage_index.get(row['head']+'|'+row['tail'], []))
        for stage in sources or {'uncategorized'}:
            stage_rows[stage].append(row)
    metrics['source_groups'] = {k:summarize_ranks(v) for k,v in sorted(stage_rows.items())}
    label_sources = graph.get('evaluation_label_sources', {})
    source_rows = collections.defaultdict(list)
    for row in rows:
        for source in label_sources.get(row['head'], ['unrecorded']):
            source_rows[source].append(row)
    metrics['label_source_groups'] = {k:summarize_ranks(v) for k,v in sorted(source_rows.items())}
    top = [t for c in sorted(scores) for t in sorted(domain,key=lambda t:(-scores[c][t],t))[:3]]
    metrics['raw_top3_unique'] = len(set(top))
    metrics['raw_top3_counts'] = dict(sorted(collections.Counter(top).items()))
    return metrics, rows
