"""Deterministic provenance, graph boundaries and filtered ranking."""
import collections
import hashlib
import json
import math
import random
import re

RELATIONS = ('affects', 'instantiates', 'exploited_by', 'implies', 'belongs_to_phase')
TYPES = ('Vulnerability', 'Configuration', 'Weakness', 'AttackTechnique', 'AttackTactic', 'KillChainPhase')
ENDPOINTS = {'affects': (0, 1), 'instantiates': (0, 2), 'exploited_by': (0, 3), 'implies': (3, 4), 'belongs_to_phase': (4, 5)}
CVE = re.compile(r'\bCVE[- ](\d{4})[- ](\d{4,})\b', re.I)
EXPLOIT = re.compile(r'\b(?:exploit(?:ed|s|ing|ation)?|leveraged?\s+(?:the\s+)?(?:vulnerabilit|CVE)|used?\s+(?:the\s+)?(?:vulnerabilit|CVE))', re.I)
NEGATED = re.compile(r'\b(?:not|never|without)\s+(?:\w+\s+){0,2}exploit|\b(?:could|might|potentially|hypothetical)\b', re.I)
SCOPE_SHIFT = re.compile(r'\b(?:mention(?:ed|s)?|report(?:ed|s)?|referenc(?:e|ed|es)|patch(?:ed|es)?|fix(?:ed|es)?|discuss(?:ed|es)?)\b', re.I)
PHASE_MAP = {'reconnaissance': ['Reconnaissance'], 'resource-development': ['Weaponization'],
             'initial-access': ['Delivery', 'Exploitation'], 'execution': ['Exploitation'],
             'persistence': ['Installation'], 'privilege-escalation': ['Installation'],
             'defense-evasion': ['Installation'], 'stealth': ['Installation'], 'defense-impairment': ['Installation'],
             'command-and-control': ['CommandAndControl'], 'credential-access': ['ActionsOnObjectives'],
             'discovery': ['ActionsOnObjectives'], 'lateral-movement': ['ActionsOnObjectives'],
             'collection': ['ActionsOnObjectives'], 'exfiltration': ['ActionsOnObjectives'], 'impact': ['ActionsOnObjectives']}


def digest(obj):
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def cves(text):
    return {'CVE-'+m[0]+'-'+m[1] for m in CVE.findall(text)}


def external_id(obj):
    return next((r.get('external_id') for r in obj.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)


def direct_cve_scope(text, cve):
    # Conservative lexical scope: exploit in another clause or citation is not an annotation.
    clauses = re.split(r';|\s+(?:but|whereas)\s+|,\s+(?:and|while)\s+(?!CVE[- ])', text, flags=re.I)
    for clause in clauses:
        for match in CVE.finditer(clause):
            if 'CVE-'+match[1]+'-'+match[2] != cve:
                continue
            before = [m for m in EXPLOIT.finditer(clause) if m.start() <= match.start()]
            if before and not SCOPE_SHIFT.search(clause[before[-1].start():match.end()]):
                return True
            following = clause[match.end():]
            if re.match(r'\s*(?:\([^)]*\)\s*)?(?:vulnerability\s+)?(?:was|is|has been|had been)\s+(?:actively\s+)?exploited\b', following, re.I):
                return True
    return False


def deduplicate(edges):
    result = {}
    for e in edges:
        key = (e['head'], e['relation'], e['tail'])
        if key not in result:
            result[key] = {'head': key[0], 'relation': key[1], 'tail': key[2], 'provenance': []}
        attrs = {k: v for k, v in e.items() if k not in ('head', 'relation', 'tail', 'provenance')}
        sources = e.get('provenance', []) + ([attrs] if attrs else [])
        for source in sources:
            if source not in result[key]['provenance']:
                result[key]['provenance'].append(source)
    return [result[k] for k in sorted(result)]


def extract_attack(bundle):
    active = [o for o in bundle['objects'] if not o.get('revoked') and not o.get('x_mitre_deprecated')]
    techniques = {o['id']: o for o in active if o['type'] == 'attack-pattern' and external_id(o)}
    tactics = {o['x_mitre_shortname']: o for o in active if o['type'] == 'x-mitre-tactic' and external_id(o)}
    context, targets, pending = [], [], []
    for t in techniques.values():
        for p in t.get('kill_chain_phases', []):
            name = p['phase_name']
            if name not in tactics:
                continue
            ta = external_id(tactics[name])
            context.append({'head': external_id(t), 'relation': 'implies', 'tail': ta, 'source_record': t['id'], 'layer': 'official_mapping'})
            # Fixed, target-independent union; Initial Access is intentionally not made one-to-one.
            for phase in PHASE_MAP.get(name, []):
                context.append({'head': ta, 'relation': 'belongs_to_phase', 'tail': phase,
                                'layer': 'rule_alignment', 'rule': 'chapter3-table3-3-static-union-v1',
                                'technique_context': external_id(t), 'source_record': tactics[name]['id']})
    for r in active:
        if r['type'] != 'relationship' or r.get('relationship_type') != 'uses' or r.get('target_ref') not in techniques:
            continue
        desc = r.get('description', '')
        if not cves(desc):
            continue
        t = techniques[r['target_ref']]
        direct_technique = t['name'].startswith('Exploitation ') or t['name'] == 'Exploit Public-Facing Application'
        # Each sentence is adjudicated separately. Never propagate a CVE across an unrelated sentence.
        for sentence in re.split(r'(?<=[.!?])\s+(?=[A-Z])|\n+', desc):
            body = re.sub(r'\(Citation:[^)]*\)', '', sentence)
            for cve in sorted(cves(sentence)):
                item = {'head': cve, 'relation': 'exploited_by', 'tail': external_id(t),
                        'evidence': sentence, 'source_record': r['id'], 'source_modified': r.get('modified'),
                        'citations': r.get('external_references', []), 'layer': 'official_procedure',
                        'verification': 'official_explicit_statement_deterministic_admission', 'human_iaa': False}
                reason = ('non_exploitation_technique' if not direct_technique else
                          'citation_only_cve' if cve not in cves(body) else
                          'negated_or_hypothetical' if NEGATED.search(body) else
                          'no_direct_cve_exploit_scope' if not direct_cve_scope(body,cve) else None)
                if reason:
                    pending.append(dict(item, exclusion_reason=reason))
                else:
                    targets.append(item)
    return {'techniques': sorted(external_id(t) for t in techniques.values()), 'targets': targets,
            'pending': pending, 'context': deduplicate(context)}


def nvd_context(record):
    out, cve = [], record['id']
    for w in record.get('weaknesses', []):
        for d in w.get('description', []):
            if re.fullmatch(r'CWE-\d+', d.get('value', '')):
                out.append({'head': cve, 'relation': 'instantiates', 'tail': d['value'], 'layer': 'official_nvd', 'source': w.get('source')})
    def walk(node, config):
        for match in node.get('cpeMatch', []):
            if match.get('vulnerable') is not True:
                continue
            # Split unescaped colons: escaped product characters remain part of the CPE component.
            parts = re.split(r'(?<!\\):', match.get('criteria', ''))
            if len(parts) != 13 or parts[:2] != ['cpe', '2.3']:
                continue
            family = ':'.join(parts[:5] + ['*'] * 8)
            out.append({'head': cve, 'relation': 'affects', 'tail': family, 'layer': 'official_nvd',
                        'match': match, 'configuration': config})
        for child in node.get('children', []) + node.get('nodes', []):
            walk(child, config)
    for config in record.get('configurations', []):
        walk(config, config)
    return out


def grouped_split(targets, exposed, seed=20261010):
    labels = collections.defaultdict(set)
    for t in targets:
        labels[t['head']].add(t['tail'])
    ids = sorted(labels)
    if len(ids) < 10:
        raise ValueError('insufficient CVE groups for train/dev/test')
    rng = random.Random(seed)
    desired = max(1, round(len(ids) * .15))
    eligible = [c for c in ids if c not in exposed]
    if len(eligible) < desired:
        raise ValueError('insufficient unexposed CVE groups for new final Test')
    remaining = set(ids)
    counts = collections.Counter(t for c in ids for t in labels[c])
    def pick(candidates, size):
        candidates = sorted(candidates)
        rng.shuffle(candidates)
        selected, observed = [], collections.Counter()
        while len(selected) < size:
            valid = [c for c in candidates if all(counts[t] > 1 for t in labels[c])]
            if not valid:
                raise ValueError('cannot hold out groups while preserving training technique coverage')
            c = max(valid, key=lambda c: sum((size * sum(t in labels[x] for x in ids) / len(ids) - observed[t]) /
                                            max(1, sum(t in labels[x] for x in ids)) for t in labels[c]))
            selected.append(c); candidates.remove(c); remaining.remove(c)
            for t in labels[c]:
                counts[t] -= 1; observed[t] += 1
        return sorted(selected)
    test = pick(eligible, desired)
    dev = pick(remaining, desired)
    return {'train': sorted(remaining), 'dev': dev, 'test': test, 'seed': seed,
            'strategy': 'CVE-grouped-stratified-new-Test-v1', 'test_exposure_scope': 'repository-recorded-Chapter4-corpus-and-supplements'}


def training_edges(edges, split, remove=()):
    train = set(split['train'])
    result = [e for e in edges if e['relation'] not in remove and
              not (e['relation'] == 'exploited_by' and e['head'] not in train) and
              not (e['relation'] == 'exploited_by_inverse' and e['tail'] not in train)]
    check_no_leakage(result, split)
    return result


def check_no_leakage(edges, split):
    groups = [set(split[k]) for k in ('train', 'dev', 'test')]
    if any(groups[i] & groups[j] for i in range(3) for j in range(i)):
        raise ValueError('group overlap leakage')
    held = groups[1] | groups[2]
    for e in edges:
        if e.get('derived_from_target') or any(p.get('derived_from_target') for p in e.get('provenance', [])):
            raise ValueError('target-derived context is forbidden')
        if (e['relation'] == 'exploited_by' and e['head'] in held) or (e['relation'] == 'exploited_by_inverse' and e['tail'] in held):
            raise ValueError('held target edge leakage')


def filtered_rank(scores, truth, target):
    if target not in scores or any(not math.isfinite(float(v)) for v in scores.values()):
        raise ValueError('missing target or nonfinite score')
    candidates = [v for t, v in scores.items() if t == target or t not in truth]
    value = scores[target]
    higher = sum(v > value for v in candidates)
    tied = sum(v == value for v in candidates)
    return 1. + higher + (tied - 1.) / 2.


def summarize_ranks(rows):
    if not rows:
        raise ValueError('empty evaluation')
    def macro(items):
        by_head = collections.defaultdict(list)
        for r in items:
            by_head[r['head']].append(float(r['rank']))
        out = {'queries': len(by_head), 'edges': len(items)}
        out['mrr'] = sum(sum(1 / v for v in ranks) / len(ranks) for ranks in by_head.values()) / len(by_head)
        for k in (1, 3, 10):
            out['hits@'+str(k)] = sum(sum(v <= k for v in ranks) / len(ranks) for ranks in by_head.values()) / len(by_head)
        return out
    out = macro(rows)
    tails = sorted({r['tail'] for r in rows})
    out['by_technique'] = {t: macro([r for r in rows if r['tail'] == t]) for t in tails}
    return out
