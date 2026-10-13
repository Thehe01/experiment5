"""Context admission, unique-unit budget, and preregistered acceptance."""
import collections
import copy
import statistics


def context_index(graph):
    types={n['id']:n['type'] for n in graph['nodes']}
    if len(types)!=len(graph['nodes']):raise ValueError('duplicate node')
    ctx={n:{'cwe':set(),'cpe':set()} for n,t in types.items() if t=='Vulnerability'}
    for e in graph['edges']:
        if e['relation'] not in ('has_reported_cwe','has_reported_cpe'):continue
        channel,kind=('cwe','Weakness') if e['relation']=='has_reported_cwe' else ('cpe','Configuration')
        if e['head'] not in ctx or types.get(e['tail'])!=kind:raise ValueError('missing/unusable context node')
        ctx[e['head']][channel].add(e['tail'])
    return {c:{k:sorted(v) for k,v in row.items()} for c,row in ctx.items()}


def claim(ledger,uid):
    if uid not in ledger['units']:raise ValueError('unregistered unit')
    state=ledger['units'][uid]['status']
    if state in ('done','checkpointed'):return False
    if state!='planned':raise ValueError('uncertain unit cannot be automatically retrained')
    if sum(v['status']!='planned' for v in ledger['units'].values())>=ledger['budget']:raise ValueError('unique-unit budget exhausted')
    ledger['units'][uid]['status']='reserved';return True


def gate(p,thresholds):
    if p['pair_count']!=9:raise ValueError('nine complete pairs required')
    return p['mean_delta_mrr']+1e-12>=thresholds['mean_delta_mrr'] and p['wins']>=thresholds['wins_of_nine'] and p['mean_delta_major_macro']+1e-12>=thresholds['major_macro_delta_min']


def penalize_abstentions(metrics,total):
    out=copy.deepcopy(metrics)
    covered=metrics['queries']
    if not total or covered>total:raise ValueError('invalid coverage denominator')
    for k in ['mrr','hits@1','hits@3','hits@10']:out[k]=metrics[k]*covered/total
    out.update(queries=total,covered_queries=covered,coverage=covered/total)
    return out


def paired(results,baseline,gate_thresholds):
    if len(results)!=9 or len({r['unit'] for r in results})!=9:raise ValueError('complete nine results required')
    rows=[]
    for r in sorted(results,key=lambda r:(r['fold'],r['seed'])):
        b=baseline['models'][f"f{r['fold']}-distmult_mixed-s{r['seed']}-base"]
        n=baseline['neighbor'][str(r['fold'])]
        rows.append({'fold':r['fold'],'seed':r['seed'],'baseline_mrr':b['mrr'],'candidate_mrr':r['dev']['mrr'],'delta_mrr':r['dev']['mrr']-b['mrr'],'delta_major_macro':r['dev']['major_macro_mrr']-b['major_macro_mrr'],'candidate_minus_neighbor':r['dev']['mrr']-n['mrr']})
    p={'pair_count':9,'mean_baseline_mrr':statistics.mean(r['baseline_mrr'] for r in rows),'mean_candidate_mrr':statistics.mean(r['candidate_mrr'] for r in rows),'mean_delta_mrr':statistics.mean(r['delta_mrr'] for r in rows),'wins':sum(r['delta_mrr']>0 for r in rows),'mean_delta_major_macro':statistics.mean(r['delta_major_macro'] for r in rows),'neighbor_mean_delta':statistics.mean(r['candidate_minus_neighbor'] for r in rows),'neighbor_wins':sum(r['candidate_minus_neighbor']>0 for r in rows),'pairs':rows}
    p['development_gate_passed']=gate(p,gate_thresholds);return p
