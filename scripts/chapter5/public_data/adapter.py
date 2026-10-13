"""Independent audit and adaptation of curated public labels; no model scoring."""
import collections
import random
import re
from chapter5.core import PHASE_MAP

STAGES = ('exploitation_techniques', 'primary_impact', 'secondary_impact')
TARGET = 'potentially_associated_with'
LABEL_RELATIONS = {TARGET, *STAGES, 'exploitation_method'}
SOURCE_FIELDS = ('id', 'title', 'description', 'techniques', *STAGES, 'cwes', 'cpes',
                 'affected_products', 'cvss_vector', 'cvss_version', 'attack_version',
                 'label_sources', 'public_split')
LIST_FIELDS = ('techniques', *STAGES, 'cwes', 'cpes', 'affected_products', 'label_sources')


def external_id(obj):
    return next((r.get('external_id') for r in obj.get('external_references', [])
                 if r.get('source_name') == 'mitre-attack'), None)


def cpe_family(value):
    # A colon preceded by an odd number of backslashes is escaped.
    parts, part, escaped = [], '', False
    for ch in value:
        if ch == ':' and not escaped:
            parts.append(part); part = ''
        else:
            part += ch
        escaped = (not escaped) if ch == '\\' else False
    parts.append(part)
    if len(parts) != 13 or parts[:2] != ['cpe', '2.3'] or parts[2] not in ('a', 'o', 'h'):
        return None
    if not parts[3] or not parts[4] or parts[3] in ('*', '-') or parts[4] in ('*', '-'):
        return None
    return ':'.join(parts[:5] + ['*'] * 8)


def attack_index(bundle, graph):
    objects = {o['id']: o for o in bundle['objects']}
    patterns = {external_id(o): o for o in objects.values()
                if o['type'] == 'attack-pattern' and external_id(o)}
    active = {t: o for t, o in patterns.items()
              if not o.get('revoked') and not o.get('x_mitre_deprecated')
              and 'enterprise-attack' in o.get('x_mitre_domains', ['enterprise-attack'])}
    if set(active) != set(graph['techniques']):
        raise ValueError('frozen candidate universe mismatch')
    successors = collections.defaultdict(set)
    for o in objects.values():
        if o['type'] == 'relationship' and o.get('relationship_type') == 'revoked-by':
            successors[o['source_ref']].add(o['target_ref'])

    def normalize(t):
        seen = set()
        current = patterns.get(t)
        while current is not None:
            name = external_id(current)
            if name in active:
                return name
            if current['id'] in seen:
                raise ValueError('cyclic revoked-by chain: ' + t)
            seen.add(current['id'])
            refs = successors[current['id']]
            if len(refs) > 1:
                raise ValueError('ambiguous revoked-by chain: ' + t)
            current = objects.get(next(iter(refs))) if refs else None
        return None
    return active, normalize


def make_graph(records, bundle, active):
    nodes = {t: 'AttackTechnique' for t in active}
    edges = {}
    def add(h, relation, t, ht, tt, layer):
        for n, tp in ((h, ht), (t, tt)):
            if n in nodes and nodes[n] != tp:
                raise ValueError('node type conflict')
            nodes[n] = tp
        edges[(h, relation, t)] = {'head': h, 'relation': relation, 'tail': t, 'layer': layer}
    for r in records:
        for t in r['techniques']:
            add(r['id'], TARGET, t, 'Vulnerability', 'AttackTechnique', 'ctid_curated_potential_mapping')
        for w in r['cwe_ids']:
            add(r['id'], 'has_reported_cwe', w, 'Vulnerability', 'Weakness', 'circl_reported_metadata')
        for p in r['cpe_families']:
            add(r['id'], 'has_reported_cpe', p, 'Vulnerability', 'Configuration', 'circl_reported_metadata')
    tactics = {o['x_mitre_shortname']: external_id(o) for o in bundle['objects']
               if o['type'] == 'x-mitre-tactic' and not o.get('revoked')
               and not o.get('x_mitre_deprecated') and external_id(o)}
    for t, obj in active.items():
        for phase in obj.get('kill_chain_phases', []):
            tactic = tactics.get(phase['phase_name'])
            if not tactic:
                continue
            add(t, 'implies', tactic, 'AttackTechnique', 'AttackTactic', 'frozen_attack_definition')
            for stage in PHASE_MAP.get(phase['phase_name'], []):
                add(tactic, 'belongs_to_phase', stage, 'AttackTactic', 'KillChainPhase', 'fixed_v1_phase_alignment_rule')
    return {'nodes': [{'id': n, 'type': nodes[n]} for n in sorted(nodes)],
            'edges': [edges[k] for k in sorted(edges)], 'techniques': sorted(active),
            'target_relation': TARGET, 'attack_version': '19.2',
            'label_semantics': 'potential_exploitation_and_impact_not_observed_incident',
            'independent_human_iaa': False}


def adapt(rows, bundle, graph):
    active, normalize = attack_index(bundle, graph)
    v1_labels = collections.defaultdict(set)
    for e in graph['edges']:
        if e['relation'] == 'exploited_by':
            v1_labels[e['head']].add(e['tail'])
    known = {'v1_labeled': set(v1_labels),
             'v1_graph': {n['id'] for n in graph['nodes'] if n['type'] == 'Vulnerability'},
             'recorded_exposure': set(graph['exposed_cves'])}
    excluded = set().union(*known.values())
    ids, all_records, records, quarantine, no_context, excluded_rows, comparisons = set(), [], [], [], [], [], []
    for raw in sorted(rows, key=lambda r: str(r.get('id', ''))):
        c = raw.get('id')
        if not isinstance(c, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', c):
            quarantine.append({'id': c, 'reason': 'invalid_cve_id'}); continue
        if c in ids:
            raise ValueError('duplicate CVE: ' + str(c))
        ids.add(c)
        if any(not isinstance(raw.get(k), list) or any(not isinstance(v, str) for v in raw[k]) for k in LIST_FIELDS):
            quarantine.append({'id': c, 'reason': 'invalid_list_field'}); continue
        if any(not isinstance(raw.get(k), str) for k in ('title','description','attack_version','public_split','cvss_vector','cvss_version')):
            quarantine.append({'id': c, 'reason': 'invalid_string_field'}); continue
        if raw['attack_version'] != '19.1' or raw['public_split'] not in ('train','test'):
            quarantine.append({'id': c, 'reason': 'unexpected_source_version_or_split'}); continue
        if not raw['label_sources'] or not set(raw['label_sources']) <= {'ctid_cve','ctid_kev'}:
            quarantine.append({'id': c, 'reason': 'unknown_label_source'}); continue
        if not raw['description'].strip() or not raw['techniques']:
            quarantine.append({'id': c, 'reason': 'empty_description_or_labels'}); continue
        if any(set(raw[k]) - set(raw['techniques']) for k in STAGES):
            quarantine.append({'id': c, 'reason': 'stage_not_in_curated_union'}); continue
        mapped = {t: normalize(t) for t in set(raw['techniques'])}
        if any(t is None for t in mapped.values()):
            quarantine.append({'id': c, 'reason': 'inactive_or_unknown_technique',
                               'labels': sorted(t for t, v in mapped.items() if v is None)}); continue
        r = {k: raw[k] for k in SOURCE_FIELDS}
        r['source_attack_version'] = r.pop('attack_version')
        r['attack_version'] = '19.2'
        r['source_techniques'] = sorted(set(raw['techniques']))
        r['techniques'] = sorted(set(mapped.values()))
        for k in STAGES:
            r[k] = sorted({mapped[t] for t in raw[k]})
        r['unclassified_techniques'] = sorted(set(r['techniques']) - {t for k in STAGES for t in r[k]})
        r['label_changes'] = [{'from': t, 'to': v} for t, v in sorted(mapped.items()) if t != v]
        r['cwe_ids'] = sorted({'CWE-' + m[1] for v in raw['cwes']
                               if (m := re.match(r'^CWE-(\d+)(?:\s|:|$)', v))})
        r['unparsed_cwes'] = sorted({v for v in raw['cwes'] if not re.match(r'^CWE-\d+(?:\s|:|$)', v)})
        r['cpe_families'] = sorted({p for v in raw['cpes'] if (p := cpe_family(v))})
        r['invalid_cpes'] = sorted({v for v in raw['cpes'] if cpe_family(v) is None})
        r['exclusion_reasons'] = sorted(k for k, v in known.items() if c in v)
        all_records.append(r)
        if c in v1_labels:
            comparisons.append({'id': c, 'v1_observed_labels': sorted(v1_labels[c]),
                                'public_potential_labels': r['techniques'],
                                'v1_labels_missing_from_public': sorted(v1_labels[c] - set(r['techniques'])),
                                'public_extra_labels': sorted(set(r['techniques']) - v1_labels[c]),
                                'status': 'scope_difference_for_review_not_adjudicated_error'})
        if c in excluded:
            excluded_rows.append({'id': c, 'reasons': r['exclusion_reasons']})
        elif not r['cwe_ids'] and not r['cpe_families']:
            no_context.append(r)
        else:
            records.append(r)
    counts = collections.Counter(t for r in all_records for t in r['techniques'])
    pool_counts = collections.Counter(t for r in records for t in r['techniques'])
    audit = {'phase': 'data_prepared_no_training', 'source_rows': len(rows), 'source_unique_cves': len(ids),
             'valid_rows': len(all_records), 'curated_edges': sum(counts.values()), 'distinct_labels': len(counts),
             'labels_at_least_5': sum(v >= 5 for v in counts.values()),
             'overlap': {**{k: len(ids & v) for k, v in known.items()}, 'excluded_union': len(ids & excluded)},
             'outside_known_union': len(ids - excluded), 'graph_eligible_cves': len(records),
             'eligible_edges': sum(pool_counts.values()), 'eligible_labels': len(pool_counts),
             'no_context_cves': len(no_context), 'quarantine_rows': len(quarantine),
             'all_stages_empty': sum(not any(r[k] for k in STAGES) for r in all_records),
             'with_unclassified_labels': sum(bool(r['unclassified_techniques']) for r in all_records),
             'unparsed_cwe_rows': sum(bool(r['unparsed_cwes']) for r in all_records),
             'no_numeric_cwe_rows': sum(not r['cwe_ids'] for r in all_records),
             'invalid_cpe_rows': sum(bool(r['invalid_cpes']) for r in all_records),
             'migrated_label_rows': sum(bool(r['label_changes']) for r in all_records),
             'top_labels': counts.most_common(15), 'eligible_top_labels': pool_counts.most_common(15),
             'eligible_label_counts': dict(sorted(pool_counts.items())),
             'label_source_groups': dict(collections.Counter('+'.join(sorted(r['label_sources'])) for r in all_records)),
             'source_split_counts': dict(collections.Counter(r['public_split'] for r in all_records)),
             'v1_overlap_comparisons': len(comparisons),
             'v1_overlap_with_missing_labels': sum(bool(c['v1_labels_missing_from_public']) for c in comparisons),
             'independent_human_iaa': False, 'new_model_training_runs': 0, 'model_api_calls': 0}
    return {'records': records, 'all_records': all_records, 'quarantine': quarantine,
            'no_context': no_context, 'excluded': excluded_rows, 'comparisons': comparisons,
            'audit': audit, 'graph': make_graph(records, bundle, active)}


def split_groups(records, seed=20261011):
    labels = {r['id']: set(r['techniques']) for r in records}
    if len(labels) != len(records) or len(records) < 10 or any(not v for v in labels.values()):
        raise ValueError('insufficient, duplicate or unlabeled CVE groups')
    totals = collections.Counter(t for ts in labels.values() for t in ts)
    remaining_counts = totals.copy()
    remaining = set(labels)
    rng = random.Random(seed)
    size = max(1, round(len(records) * .15))
    def pick():
        candidates = sorted(remaining); rng.shuffle(candidates)
        selected, seen = [], collections.Counter()
        while len(selected) < size:
            valid = [c for c in candidates if all(remaining_counts[t] > 1 for t in labels[c])]
            if not valid:
                raise ValueError('cannot reserve groups preserving Train label coverage')
            c = max(valid, key=lambda c: sum((size * totals[t] / len(labels) - seen[t]) / totals[t] for t in sorted(labels[c])))
            selected.append(c); candidates.remove(c); remaining.remove(c)
            for t in labels[c]:
                remaining_counts[t] -= 1; seen[t] += 1
        return sorted(selected)
    reserved = pick(); dev = pick()
    return {'train': sorted(remaining), 'dev': dev, 'reserved_holdout': reserved, 'seed': seed,
            'strategy': 'CVE_grouped_preserve_train_labels_70_15_15',
            'reserved_status': 'not_scored_not_certified_as_formal_test',
            'exposure_scope': 'v1_graph_and_recorded_repository_exposure_only'}


def training_view(graph, split):
    roles = [set(split[k]) for k in ('train', 'dev', 'reserved_holdout')]
    if any(roles[i] & roles[j] for i in range(3) for j in range(i)):
        raise ValueError('CVE group overlap')
    train, held = roles[0], roles[1] | roles[2]
    output = []
    for e in graph['edges']:
        if e.get('derived_from_target') or any(p.get('derived_from_target') for p in e.get('provenance', [])):
            raise ValueError('target-derived background is forbidden')
        rel = e['relation']; inverse = rel.endswith('_inverse')
        base = rel[:-8] if inverse else rel
        if base == 'exploited_by':
            raise ValueError('observed exploited_by is not a public potential label')
        if base in LABEL_RELATIONS:
            c = e['tail'] if inverse else e['head']
            if c in held:
                continue
            if c not in train:
                raise ValueError('target CVE outside registered groups')
        output.append(e)
    return output
