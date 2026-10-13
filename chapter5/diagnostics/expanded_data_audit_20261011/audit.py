"""Read-only, development-only audit; no fitting or model inference.

Run from repository root with PYTHONPATH=source (or local extracted source root).
All input bytes bound to protocol.json; never writes original inputs/results.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
import math
from pathlib import Path
import statistics as st
import zipfile

from chapter5.core import digest
from chapter5.expanded_dev.data import read_package, make_fold
from chapter5.public_dev.core import labels, context, RELATIONS

HERE = Path(__file__).resolve().parent
CONFIGS = ("frequency", "cwe_frequency", "smoothed_cwe-1",
           "smoothed_cwe-5", "smoothed_cwe-10", "neighbor_vote")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def gitsha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def check(ok, message):
    if not ok:
        raise ValueError(message)


def rows(raw):
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def mean(xs):
    return st.mean(xs) if xs else None


def jac(a, b):
    return len(a & b) / len(a | b) if a | b else 0.


def describe(ids, truth, ctx):
    ids = sorted(ids)
    counts = Counter(t for c in ids for t in truth[c])
    pairs = Counter("|".join(ts) for c in ids
                    for ts in itertools.combinations(sorted(truth[c]), 2))
    out = {"cves": len(ids), "label_edges": sum(counts.values()),
           "label_counts": dict(sorted(counts.items())),
           "label_prevalence": {t: n/len(ids) for t,n in sorted(counts.items())},
           "cardinality_counts": dict(sorted(Counter(len(truth[c]) for c in ids).items())),
           "mean_cardinality": mean([len(truth[c]) for c in ids]),
           "cve_id_year_counts": dict(sorted(Counter(c.split("-")[1] for c in ids).items())),
           "cve_id_2020_2022_fraction": sum(c.split("-")[1] in ("2020","2021","2022") for c in ids)/len(ids),
           "cooccurrences": dict(sorted(pairs.items()))}
    for r in RELATIONS[:2]:
        values = set().union(*(ctx[r][c] for c in ids))
        degrees = [len(ctx[r][c]) for c in ids]
        out[r] = {"present_cves": sum(bool(x) for x in degrees),
                  "missing_cves": sum(not x for x in degrees),
                  "unique_values": len(values), "edges": sum(degrees),
                  "mean_degree": mean(degrees), "median_degree": st.median(degrees),
                  "max_degree": max(degrees)}
    out["both_background_cves"] = sum(all(ctx[r][c] for r in RELATIONS[:2]) for c in ids)
    return out


def distribution_distance(a, b, domain):
    # Distributions over label edges, not probabilities of independent classes.
    sa, sb = sum(a.values()), sum(b.values())
    p, q = [a[t]/sa for t in domain], [b[t]/sb for t in domain]
    m = [(x+y)/2 for x,y in zip(p,q)]
    kl = lambda x: sum(v*math.log2(v/z) for v,z in zip(x,m) if v)
    return {"total_variation": sum(abs(x-y) for x,y in zip(p,q))/2,
            "jensen_shannon_bits": (kl(p)+kl(q))/2}


def evaluate(scores, truth, major):
    perq, pert, ranks = {}, defaultdict(list), {}
    hits = {k: [] for k in (1,3,10)}
    for c in sorted(scores):
        cr = {}
        for t in sorted(truth[c]):
            v = scores[c][t]
            other = [s for x,s in scores[c].items() if x == t or x not in truth[c]]
            rank = 1 + sum(s > v for s in other) + (sum(s == v for s in other)-1)/2
            cr[t] = rank
            pert[t].append(rank)
        ranks[c] = cr
        perq[c] = mean([1/r for r in cr.values()])
        for k in hits:
            hits[k].append(mean([float(r <= k) for r in cr.values()]))
    by = {t: {"mrr": mean([1/r for r in rs]), "queries": len(rs), "edges":len(rs),
              **{"hits@"+str(k):mean([float(r <= k) for r in rs]) for k in hits}}
          for t,rs in sorted(pert.items())}
    top = Counter(t for c in sorted(scores)
                  for t in sorted(scores[c], key=lambda t:(-scores[c][t],t))[:3])
    metrics = {"mrr":mean(list(perq.values())), "queries":len(perq),
               "edges":sum(len(x) for x in ranks.values()), "by_technique":by,
               "major_macro_mrr":mean([by[t]["mrr"] for t in major if t in by]),
               **{"hits@"+str(k):mean(v) for k,v in hits.items()},
               "raw_top3_counts":dict(sorted(top.items())), "raw_top3_unique":len(top)}
    return metrics, perq, ranks


def replay_scores(graph):
    # Formula reimplemented independently; no baseline_scores/evaluate_scores calls.
    train, dev = graph["split"]["train"], graph["split"]["dev"]
    truth, ctx, domain = labels(graph), context(graph), sorted(graph["techniques"])
    counts = Counter(t for c in train for t in truth[c])
    prior = {t:counts[t]/len(train) for t in domain}
    members = defaultdict(set)
    for c in train:
        for w in ctx[RELATIONS[1]][c]:
            members[w].add(c)
    wc = {w:Counter(t for c in cs for t in truth[c]) for w,cs in members.items()}
    out = {k:{} for k in CONFIGS}
    weights = {}
    for q in dev:
        ws = ctx[RELATIONS[1]][q]
        out["frequency"][q] = dict(counts) | {t:counts[t] for t in domain}
        out["cwe_frequency"][q] = {t:sum(wc.get(w,{}).get(t,0) for w in ws) if ws else counts[t] for t in domain}
        for a in (1,5,10):
            out["smoothed_cwe-"+str(a)][q] = {
                t:sum((wc.get(w,{}).get(t,0)+a*prior[t])/(len(members[w])+a) for w in ws)/len(ws) if ws else prior[t]
                for t in domain}
        weights[q] = {x:.5*jac(ctx[RELATIONS[0]][q],ctx[RELATIONS[0]][x])
                         + .5*jac(ctx[RELATIONS[1]][q],ctx[RELATIONS[1]][x]) for x in train}
        total = sum(weights[q].values())
        out["neighbor_vote"][q] = {t:sum(v for x,v in weights[q].items() if t in truth[x])/total if total else prior[t] for t in domain}
    return out, weights


def compare_metrics(actual, saved):
    error = 0.
    for k in ("mrr","hits@1","hits@3","hits@10","major_macro_mrr"):
        error = max(error, abs(actual[k]-saved[k]))
    for k in ("queries","edges","raw_top3_counts","raw_top3_unique"):
        check(actual[k] == saved[k], "baseline replay mismatch: "+k)
    check(set(actual["by_technique"]) == set(saved["by_technique"]), "replay technique domain")
    for t,m in actual["by_technique"].items():
        for k,v in m.items():
            error = max(error, abs(v-saved["by_technique"][t][k]))
    check(error < 1e-12, "baseline numeric replay mismatch")
    return error


def main(a):
    protocol = json.loads((HERE/"protocol.json").read_text())
    out = Path(a.output)
    check(not out.exists(), "refuse output overwrite")
    inputs = {}
    for key,path in (("source_package_sha256",a.old),("enriched_package_sha256",a.enriched),
                     ("runtime_package_sha256",a.runtime)):
        inputs[key] = sha(Path(path).read_bytes())
        check(inputs[key] == protocol[key], "frozen input mismatch: "+key)
    raw = Path(a.comparison).read_bytes()
    inputs["comparison_git_blob"] = gitsha(raw)
    check(inputs["comparison_git_blob"] == protocol["comparison_git_blob"], "comparison byte mismatch")
    comp = json.loads(raw)
    base, external, groups, runtime_audit = read_package(a.runtime, protocol["runtime_package_sha256"])
    protected = set(groups["reserved_ids"])
    oldpool = {n["id"] for n in base["nodes"] if n["type"] == "Vulnerability"}
    check(not protected & oldpool, "reserved graph nodes")
    check(not any(e["head"] in protected or e["tail"] in protected for e in base["edges"]), "reserved graph edges")
    extids = {r["id"] for r in external}
    check(not extids & (oldpool | protected), "external overlap")
    domain = base["techniques"]
    truth, ctx = labels(base), context(base)
    oldpositive = {c for c in oldpool if truth[c]}
    with zipfile.ZipFile(a.old) as z:
        old = {r["id"]:r for r in rows(z.read("records.jsonl")) if r["id"] in oldpool}
    with zipfile.ZipFile(a.enriched) as z:
        package_manifest = json.loads(z.read("package-manifest.json"))
        for n,v in package_manifest["files"].items():
            b = z.read(n)
            check(sha(b) == v["sha256"] and len(b) == v["bytes"], "enriched member hash")
        enriched = rows(z.read("data/graph-ready-candidates.jsonl"))
    check({r["id"] for r in enriched} == extids, "enriched/runtime membership")
    for r in enriched:
        check(r["id"] not in protected, "protected external row")
        e = next(x for x in external if x["id"] == r["id"])
        for k in ("techniques","cwe_ids","cpe_families"):
            check(set(r[k]) == set(e[k]), "runtime source projection")
    pre = Path(a.preprocess)
    pm = json.loads((pre/"outputs/manifest.json").read_text())
    for name in ("normalized-cves.jsonl","development-label-review.jsonl"):
        check(sha((pre/"outputs"/name).read_bytes()) == pm["files"][name], "preprocessing byte mismatch")
    source_files = json.loads((pre/"work/source_files.json").read_text())
    for f in source_files:
        b = (pre/"inputs/cve2attack_original"/f["name"]).read_bytes()
        check(gitsha(b) == f["git_blob_sha"] and len(b) == f["bytes"], "author CSV hash")
    mapping = json.loads((pre/"work/label_mapping.json").read_text())
    check(sorted(m["technique_id"] for m in mapping["mapping"]) == domain, "31 label mapping")
    inputs["source_commit"] = mapping["source_commit"]
    normalized = {r["id"]:r for r in rows((pre/"outputs/normalized-cves.jsonl").read_bytes()) if r["id"] in oldpool}
    review = rows((pre/"outputs/development-label-review.jsonl").read_bytes())
    check(all(r["id"] in oldpool and r["id"] not in protected for r in review), "protected overlap review")
    disputed, direction = [], Counter()
    variants = 0
    for r in review:
        check(set(r["public_shared_parent_labels"]) == truth[r["id"]], "overlap old labels")
        source = normalized[r["id"]]
        check([v["external_labels"] for v in r["label_variant_differences"]] == source["label_variants"], "author label variants")
        changed = False
        for v in r["label_variant_differences"]:
            oe = truth[r["id"]] - set(v["external_labels"])
            ee = set(v["external_labels"]) - truth[r["id"]]
            check(oe == set(v["public_only_labels"]) and ee == set(v["external_only_labels"]), "directional review mismatch")
            variants += 1
            if oe or ee:
                changed = True
                direction["old_superset" if oe and not ee else "external_superset" if ee and not oe else "mixed"] += 1
        if changed:
            disputed.append(r | {"provenance":source["provenance"],"source_commit":source["source_commit"],
                                  "original_stage_fields":{k:old[r["id"]].get(k,[]) for k in ("exploitation_techniques","primary_impact","secondary_impact","unclassified_techniques")},
                                  "original_label_sources":old[r["id"]].get("label_sources",[])})
    overlap = {"unique_development_cves":len(review), "label_variants":variants,
               "ambiguous_cves":sum(len(r["label_variant_differences"]) > 1 for r in review),
               "any_variant_difference_cves":len(disputed), "difference_fraction":len(disputed)/len(review),
               "all_variants_exact_agreement_cves":len(review)-len(disputed),
               "different_variant_direction_counts":dict(direction),
               "old_only_labels_variant_counts":dict(Counter(t for r in review for v in r["label_variant_differences"] for t in v["public_only_labels"])),
               "external_only_labels_variant_counts":dict(Counter(t for r in review for v in r["label_variant_differences"] for t in v["external_only_labels"]))}
    full = make_fold(base,external,groups["folds"][0],"augmented",protected)
    ft, fc = labels(full), context(full)
    cohorts = {"old_positive_pool":describe(oldpositive,ft,fc),
               "external_train_only":describe(extids,ft,fc),
               "old_pool_including_background_only":describe(oldpool,ft,fc)}
    cohorts["old_label_source_counts"] = dict(Counter(s for c in oldpositive for s in old[c].get("label_sources",[])))
    cohorts["external_cwe_source_disagreements"] = sum(bool(r.get("cwe_source_disagreement")) for r in enriched)
    cohorts["old_positive_with_any_stage"] = sum(any(old[c].get(k) for k in ("exploitation_techniques","primary_impact","secondary_impact")) for c in oldpositive)
    shifts = [{"technique":t,"old_count":sum(t in ft[c] for c in oldpositive),
               "external_count":sum(t in ft[c] for c in extids),
               "old_prevalence":sum(t in ft[c] for c in oldpositive)/len(oldpositive),
               "external_prevalence":sum(t in ft[c] for c in extids)/len(extids)} for t in domain]
    for r in shifts:
        r["prevalence_delta"] = r["external_prevalence"]-r["old_prevalence"]
    common = []
    cwes = set().union(*(fc[RELATIONS[1]][c] for c in oldpositive | extids))
    for w in sorted(cwes):
        o = {c for c in oldpositive if w in fc[RELATIONS[1]][c]}
        e = {c for c in extids if w in fc[RELATIONS[1]][c]}
        if min(len(o),len(e)) < protocol["common_cwe_minimum_cohort_support"]:
            continue
        oc, ec = Counter(t for c in o for t in ft[c]), Counter(t for c in e for t in ft[c])
        common.append({"cwe":w,"old_cves":len(o),"external_cves":len(e),
                       **distribution_distance(oc,ec,domain),
                       "old_labels":dict(oc),"external_labels":dict(ec),
                       "old_top3":sorted(oc.items(),key=lambda v:(-v[1],v[0]))[:3],
                       "external_top3":sorted(ec.items(),key=lambda v:(-v[1],v[0]))[:3]})
    common.sort(key=lambda r:(-r["jensen_shannon_bits"],r["cwe"]))
    replays, neighbor, folds = [], [], []
    replay_metrics = defaultdict(dict)
    for f in groups["folds"]:
        graphs = {c:make_fold(base,external,f,c,protected) for c in ("base","augmented")}
        bs, bw = replay_scores(graphs["base"])
        aug, aw = replay_scores(graphs["augmented"])
        bg, ag = graphs["base"], graphs["augmented"]
        expected = {r["condition"]:r for r in runtime_audit["summaries"] if r["fold"] == f["fold"]}
        for c,g in graphs.items():
            check(digest(g) == expected[c]["graph_sha256"], "frozen fold graph digest")
            check(not protected & (set(g["split"]["train"]) | set(g["split"]["dev"])), "protected scoring")
            for kind in CONFIGS:
                scores = (bs if c == "base" else aug)[kind]
                metrics,_,_ = evaluate(scores,ft,g["fixed_major"])
                replay_metrics[kind][c+"-f"+str(f["fold"])] = metrics
                error = compare_metrics(metrics,comp["baselines"]["metrics"][kind][c+"-f"+str(f["fold"])])
                replays.append({"configuration":kind,"condition":c,"fold":f["fold"],"max_metric_error":error,"mrr":metrics["mrr"]})
        bt, bc = labels(bg), context(bg)
        sharedold = {r:set().union(*(bc[r][x] for x in bg["split"]["train"])) for r in RELATIONS[:2]}
        sharednew = {r:set().union(*(fc[r][x] for x in extids)) for r in RELATIONS[:2]}
        folds.append({"fold":f["fold"],"base_train":describe(bg["split"]["train"],ft,fc),
                      "augmented_train":describe(ag["split"]["train"],ft,fc),
                      "dev":describe(bg["split"]["dev"],ft,fc),
                      "new_cves_sharing_any_original_supervised_train_background":sum(any(fc[r][x] & sharedold[r] for r in RELATIONS[:2]) for x in extids),
                      "dev_sharing_original_train_cwe":sum(bool(fc[RELATIONS[1]][x]&sharedold[RELATIONS[1]]) for x in bg["split"]["dev"]),
                      "dev_sharing_external_train_cwe":sum(bool(fc[RELATIONS[1]][x]&sharednew[RELATIONS[1]]) for x in bg["split"]["dev"]),
                      "dev_sharing_original_train_cpe":sum(bool(fc[RELATIONS[0]][x]&sharedold[RELATIONS[0]]) for x in bg["split"]["dev"]),
                      "dev_sharing_external_train_cpe":sum(bool(fc[RELATIONS[0]][x]&sharednew[RELATIONS[0]]) for x in bg["split"]["dev"])})
        _,bp,br = evaluate(bs["neighbor_vote"],ft,bg["fixed_major"])
        _,ap,ar = evaluate(aug["neighbor_vote"],ft,ag["fixed_major"])
        for q in bg["split"]["dev"]:
            oldweights = {x:w for x,w in aw[q].items() if x not in extids}
            newweights = {x:w for x,w in aw[q].items() if x in extids}
            check(oldweights == bw[q], "original neighbor weights changed")
            ow, nw = sum(oldweights.values()),sum(newweights.values())
            mass = {}
            for source,ww in (("old",oldweights),("external",newweights)):
                mass[source] = {t:sum(v for x,v in ww.items() if t in ft[x]) for t in domain}
            total = sum(aw[q].values())
            err = max(abs(aug["neighbor_vote"][q][t]-(mass["old"][t]+mass["external"][t])/total) for t in domain) if total else 0.
            check(err < 1e-12, "neighbor decomposition mismatch")
            compat = {}
            components = {}
            for source,ww in (("old",oldweights),("external",newweights)):
                denom = sum(w*len(ft[x]) for x,w in ww.items())
                compat[source] = sum(w*len(ft[x]&ft[q]) for x,w in ww.items())/denom if denom else None
                components[source] = {r:sum(.5*jac(fc[r][q],fc[r][x]) for x in ww) for r in RELATIONS[:2]}
            top = lambda ss:sorted(domain,key=lambda t:(-ss[t],t))[:3]
            neighbor.append({"fold":f["fold"],"id":q,"observed_labels":sorted(ft[q]),
                             "base_mrr":bp[q],"augmented_mrr":ap[q],"delta_mrr":ap[q]-bp[q],
                             "old_weight":ow,"external_weight":nw,
                             "external_weight_share":nw/(ow+nw) if ow+nw else 0.,
                             "positive_weight_original_neighbors":sum(w>0 for w in oldweights.values()),
                             "positive_weight_external_neighbors":sum(w>0 for w in newweights.values()),
                             "weighted_compatibility_with_observed_dev_labels":compat,
                             "similarity_weight_components":components,
                             "source_label_vote_mass":mass,"max_decomposition_error":err,
                             "base_top3":top(bs["neighbor_vote"][q]),"augmented_top3":top(aug["neighbor_vote"][q]),
                             "base_ranks":br[q],"augmented_ranks":ar[q]})
    ns = {"query_occurrences":len(neighbor), "unique_cves":len({r["id"] for r in neighbor}),
          "mean_delta_mrr":mean([r["delta_mrr"] for r in neighbor]),
          "improved":sum(r["delta_mrr"]>1e-12 for r in neighbor),
          "degraded":sum(r["delta_mrr"] < -1e-12 for r in neighbor),
          "unchanged":sum(abs(r["delta_mrr"])<=1e-12 for r in neighbor),
          "external_vote_share_mean":mean([r["external_weight_share"] for r in neighbor]),
          "external_vote_share_median":st.median(r["external_weight_share"] for r in neighbor),
          "external_vote_majority_occurrences":sum(r["external_weight_share"]>.5 for r in neighbor),
          "compatibility_mean":{s:mean([r["weighted_compatibility_with_observed_dev_labels"][s] for r in neighbor if r["weighted_compatibility_with_observed_dev_labels"][s] is not None]) for s in ("old","external")},
          "max_decomposition_error":max(r["max_decomposition_error"] for r in neighbor),
          "weight_components_total":{s:{k:sum(r["similarity_weight_components"][s][k] for r in neighbor) for k in RELATIONS[:2]} for s in ("old","external")},
          "examples":sorted(neighbor,key=lambda r:(r["delta_mrr"],r["fold"],r["id"]))[:5]}
    baselines = {}
    for kind in CONFIGS:
        b = mean([replay_metrics[kind]["base-f"+str(f["fold"])]["mrr"] for f in groups["folds"]])
        v = mean([replay_metrics[kind]["augmented-f"+str(f["fold"])]["mrr"] for f in groups["folds"]])
        baselines[kind] = {"base_mrr":b,"augmented_mrr":v,"delta_mrr":v-b}
    model = {}
    for arm in sorted({r["arm"] for r in comp["results"]}):
        model[arm] = {"paired":comp["paired_data_effect"][arm],"conditions":{},"per_technique":[]}
        for condition in ("base","augmented"):
            rr = [r for r in comp["results"] if r["arm"] == arm and r["condition"] == condition]
            top = Counter()
            for r in rr:
                top.update(r["dev"]["raw_top3_counts"])
            model[arm]["conditions"][condition] = {"units":len(rr),"top3_counts":dict(top),
                "total_top3_entries":sum(top.values()),"top3_three_most_common_fraction":sum(n for _,n in top.most_common(3))/sum(top.values()),
                "per_unit_unique_min":min(r["dev"]["raw_top3_unique"] for r in rr),
                "per_unit_unique_max":max(r["dev"]["raw_top3_unique"] for r in rr)}
        for t in domain:
            by = {c:[r["dev"]["by_technique"][t]["mrr"] for r in comp["results"] if r["arm"] == arm and r["condition"] == c and t in r["dev"]["by_technique"]] for c in ("base","augmented")}
            if not by["base"]:
                continue
            model[arm]["per_technique"].append({"technique":t,"available_units":len(by["base"]),
                "base_mrr":mean(by["base"]),"augmented_mrr":mean(by["augmented"]),
                "delta_mrr":mean(by["augmented"])-mean(by["base"])})
        model[arm]["per_technique"].sort(key=lambda r:r["delta_mrr"])
    analysis = {"protocol":protocol["protocol"],"inputs":inputs,"protection":{
        "reserved_cves":len(protected),"reserved_labels_compared":0,"reserved_scored":0,
        "external_old_pool_overlap":len(extids&oldpool),"training":0,"model_inference":0,"model_api_calls":0},
        "cohorts":cohorts,"overlap_labels":overlap,"class_shifts":shifts,"common_cwe_label_shift":common,
        "folds":folds,"baseline_replays":replays,"baseline_summary":baselines,
        "neighbor_summary":ns,"model_existing_results":model,
        "limitations":["Descriptive audit after seeing Dev; no final Test or causal identification.",
                       "Three Dev folds overlap; 450 occurrences are not 450 independent CVEs.",
                       "Unobserved labels are not confirmed negatives.",
                       "Conditional CWE differences can reflect coverage, selection, metadata and annotation effects.",
                       "CVE-ID year is not publication date or annotation origin.",
                       "Model scores/checkpoints not rerun; model analysis uses bound saved metrics.",
                       "No manual adjudication of source label or NVD metadata disagreements."]}
    check(len(replays)==protocol["baseline_replay_count"], "replay count")
    check(len(disputed)==73 and len(review)==619, "review count")
    check(len(oldpositive)==850 and len(extids)==858, "cohort count")
    out.mkdir(parents=True)
    (out/"analysis.json").write_text(json.dumps(analysis,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
    for name,data in (("overlap-label-review.jsonl",disputed),("neighbor-vote-decomposition.jsonl",neighbor)):
        (out/name).write_text("".join(json.dumps(r,ensure_ascii=False,sort_keys=True)+"\n" for r in data))
    verification = {"protocol":protocol["protocol"],"passed":True,
        "baseline_replays":len(replays),"max_baseline_metric_error":max(r["max_metric_error"] for r in replays),
        "max_neighbor_decomposition_error":ns["max_decomposition_error"],
        "input_hashes":inputs,"protection":analysis["protection"],
        "audit_script_sha256":sha(Path(__file__).read_bytes()),
        "protocol_sha256":sha((HERE/"protocol.json").read_bytes()),
        "outputs_sha256":{p.name:sha(p.read_bytes()) for p in sorted(out.iterdir())}}
    (out/"verification.json").write_text(json.dumps(verification,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"passed":True,"overlap":overlap,"neighbor":{k:v for k,v in ns.items() if k != "examples"},"common_cwes":len(common),
                      "baseline_summary":baselines,"max_baseline_error":verification["max_baseline_metric_error"]},ensure_ascii=False))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("old","enriched","runtime","comparison","preprocess","output"):
        p.add_argument("--"+name,required=True)
    main(p.parse_args())

