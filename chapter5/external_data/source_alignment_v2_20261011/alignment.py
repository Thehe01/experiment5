"""Development-only source alignment; no fitting, model inference or scoring."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile
from chapter5.core import digest
from chapter5.expanded_dev.data import read_package, make_fold
from chapter5.public_dev.core import labels

HERE=Path(__file__).resolve().parent
TECH=re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
# Only these encountered IDs have pinned official Mobile-domain evidence.
# An arbitrary technique outside the31-class scope is never assumed Mobile.
MOBILE_IDS={"T1404","T1461","T1533"}
STAGES={"Exploitation Technique":"exploitation_technique","Primary Impact":"primary_impact",
        "Secondary Impact":"secondary_impact","Uncategorized":"uncategorized"}
def sha(b):return hashlib.sha256(b).hexdigest()
def gitsha(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def check(ok,message):
    if not ok:raise ValueError(message)
def encoded(x):return (json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def jsonrows(raw):return [json.loads(x) for x in raw.splitlines() if x.strip()]

def resolve_record(cve, original_labels, author_variants, evidence, scope, protected=()):
    check(cve not in set(protected),"protected ID excluded before label inspection")
    scope=set(scope)
    check(scope and all(re.fullmatch(r"T[0-9]{4}",t) for t in scope),"parent scope required")
    variants=[sorted(set(v)) for v in author_variants]
    check(all(set(v)<=scope for v in variants),"author outside registered parent scope")
    ct={e["technique"].split(".")[0] for e in evidence}&scope
    union={t for v in variants for t in v}
    common={"id":cve,"author_variants":variants,"independent_human_iaa":False,
            "missing_labels_are_confirmed_negatives":False}
    if original_labels is not None:
        original=set(original_labels)
        check(original<=scope,"original outside scope")
        check(ct==original,"CTID reconstructed labels disagree with original canonical labels")
        return common|{"status":"ctid_canonical_source_aligned" if variants else "ctid_canonical_retained",
                       "canonical_labels":sorted(ct),"unknown_labels":sorted(union-ct),
                       "author_added_ctid_labels":sorted(ct-union),
                       "source_authority":"pinned_ctid","held_author_labels":[]}
    if evidence:
        if not ct:
            check(all(e["technique"].split(".")[0] in MOBILE_IDS for e in evidence),
                  "unexpected out-of-scope CTID mapping; domain review required")
            return common|{"status":"quarantined_cross_domain","canonical_labels":[],
                           "unknown_labels":[],"author_added_ctid_labels":[],
                           "source_authority":"pinned_ctid_domain_check","held_author_labels":sorted(union)}
        raise ValueError("unexpected new-only CTID Enterprise collision")
    if len({tuple(v) for v in variants})!=1:
        return common|{"status":"quarantined_ambiguous_author","canonical_labels":[],
                       "unknown_labels":[],"author_added_ctid_labels":[],
                       "source_authority":"unresolved_author","held_author_labels":sorted(union)}
    check(bool(union),"empty external-only labels")
    return common|{"status":"external_curated_not_ctid_revalidated","canonical_labels":sorted(union),
                   "unknown_labels":[],"author_added_ctid_labels":[],
                   "source_authority":"frozen_author_csv","held_author_labels":[]}

def read_sources(path, expected_sha, allowed, protected):
    raw=Path(path).read_bytes();check(sha(raw)==expected_sha,"CTID source package byte mismatch")
    out=defaultdict(list)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        manifest=json.loads(z.read("manifest.json"))
        for s in manifest["sources"]:
            b=z.read(s["archive_path"])
            check(sha(b)==s["sha256"] and len(b)==s["bytes"],"source member mismatch")
            if s.get("git_blob_sha"):check(gitsha(b)==s["git_blob_sha"],"source Git blob mismatch")
        metadata={s["kind"]:s for s in manifest["sources"]}
        for index,row in enumerate(csv.DictReader(io.StringIO(z.read("ctid-attack-to-cve.csv").decode("utf-8-sig"))),start=2):
            c=row["CVE ID"].strip()
            if c not in allowed:continue
            check(c not in protected,"protected CTID evidence")
            for column,stage in STAGES.items():
                for match in TECH.finditer(row[column]):
                    out[c].append({"technique":match.group(),"stage":stage,"source":"ctid_cve",
                        "source_git_blob":metadata["attack_to_cve"]["git_blob_sha"],
                        "source_commit":metadata["attack_to_cve"]["commit"],"archive_member":"ctid-attack-to-cve.csv",
                        "csv_record_number":index,"column":column,"phase":row["Phase"],"raw_cell":row[column],
                        "lexical_duplicate_T":match.start()>0 and row[column][match.start()-1]=="T"})
        for index,row in enumerate(json.loads(z.read("ctid-kev.json"))["mapping_objects"]):
            c=row.get("capability_id")
            if c not in allowed:continue
            check(c not in protected,"protected KEV evidence")
            check(TECH.fullmatch(row["attack_object_id"]),"invalid KEV technique")
            out[c].append({"technique":row["attack_object_id"],"stage":row["mapping_type"],"source":"ctid_kev",
                "source_git_blob":metadata["ctid_kev"]["git_blob_sha"],"source_commit":metadata["ctid_kev"]["commit"],
                "archive_member":"ctid-kev.json","mapping_object_index":index,"references":row.get("references",[]),
                "comments":row.get("comments",""),"mapping_status":row.get("status"),
                "mapping_framework_version":row.get("mapping_framework_version")})
    return dict(out),manifest

def build(a):
    p=json.loads((HERE/"protocol.json").read_text())
    out=Path(a.output);check(not out.exists(),"refuse output overwrite")
    for key,path in (("old_package_sha256",a.old),("enriched_package_sha256",a.enriched),
                     ("normalized_author_sha256",a.author),("overlap_review_sha256",a.review)):
        check(sha(Path(path).read_bytes())==p[key],"input byte mismatch: "+key)
    check(gitsha(Path(a.comparison).read_bytes())==p["comparison_git_blob"],"comparison byte mismatch")
    base,external,groups,old_audit=read_package(a.runtime,p["runtime_package_sha256"])
    reserve=set(groups["reserved_ids"]);oldids={n["id"] for n in base["nodes"] if n["type"]=="Vulnerability"}
    extids={r["id"] for r in external};allowed=oldids|extids;scope=base["techniques"];truth=labels(base)
    check(not allowed&reserve and not oldids&extids,"protected or duplicate roles")
    authors={r["id"]:r for r in jsonrows(Path(a.author).read_bytes()) if r["id"] in allowed}
    overlap=jsonrows(Path(a.review).read_bytes());overlapix={r["id"]:r for r in overlap}
    check(all(c in oldids and c not in reserve for c in overlapix),"protected overlap review")
    with zipfile.ZipFile(a.old) as z:
        originals={r["id"]:r for r in jsonrows(z.read("records.jsonl")) if r["id"] in oldids}
    with zipfile.ZipFile(a.enriched) as z:
        enriched={r["id"]:r for r in jsonrows(z.read("data/graph-ready-candidates.jsonl"))}
        cwe_disagreements=jsonrows(z.read("review/cwe-source-review.jsonl"))
    check(set(enriched)==extids,"external source membership mismatch")
    evidence,source_manifest=read_sources(a.sources,p["source_package_sha256"],allowed,reserve)
    records,aligned,resolutions,pending,quarantine=[],[],[],[],[]
    for c in sorted(allowed):
        old=c in oldids;source=originals[c] if old else enriched[c]
        variants=authors[c]["label_variants"] if c in authors else []
        result=resolve_record(c,sorted(truth[c]) if old else None,variants,evidence.get(c,[]),scope,reserve)
        prov={"canonical_source":result["source_authority"],
              "author_csv_rows":authors[c]["provenance"] if c in authors else [],
              "ctid_evidence_count":len(evidence.get(c,[])),
              "original_package_sha256":p["old_package_sha256"] if old else None,
              "enriched_package_sha256":None if old else p["enriched_package_sha256"]}
        if result["status"].startswith("quarantined"):
            quarantine.append(result|{"reason":"Pinned CTID record has no technique in the fixed Enterprise domain; no cross-domain conversion inferred",
                                      "ctid_evidence":evidence.get(c,[]),"metadata_preserved":source,"provenance":prov})
            continue
        records.append({"id":c,"techniques":result["canonical_labels"],"unknown_labels":result["unknown_labels"],
           "label_status":result["status"],"label_semantics":"source_curated_potential_association_not_observed_incident",
           "label_granularity":"parent","candidate_domain":scope,"attack_version":"19.2",
           "cwe_ids":source["cwe_ids"],"cpe_families":source["cpe_families"],"provenance":prov,
           "role":"original_development_pool" if old else "external_train_only",
           "independent_human_iaa":False,"missing_labels_are_confirmed_negatives":False,
           "stage_labels":{s:sorted({e["technique"].split(".")[0] for e in evidence.get(c,[]) if e["stage"]==s and e["technique"].split(".")[0] in scope}) for s in STAGES.values()} if old else None})
        if c in overlapix:
            rr=overlapix[c]
            check(set(rr["public_shared_parent_labels"])==truth[c],"old review mismatch")
            check(variants==[v["external_labels"] for v in rr["label_variant_differences"]],"variant lineage mismatch")
            aligned.append(result|{"original_parent_labels":sorted(truth[c]),"provenance":prov,
                                   "raw_author_labels_unchanged":True,"canonical_views_agree":True})
            if any(set(v)!=truth[c] for v in variants):
                resolutions.append(result|{"original_parent_labels":sorted(truth[c]),"ctid_evidence":evidence.get(c,[]),
                  "source_variant_differences":rr["label_variant_differences"],
                  "resolution_kind":"source_authority_alignment_not_new_semantic_gold","provenance":prov})
            for t in result["unknown_labels"]:
                pending.append({"id":c,"technique":t,"status":"UNKNOWN_author_observation_not_ctid_corroborated",
                                "canonical_positive":False,"confirmed_negative":False,
                                "future_training_negative_exclusion_required":True,
                                "future_evaluation_requires_declared_mask":True,"provenance":prov})
    check(all(set(r["techniques"])==truth[r["id"]] for r in records if r["id"] in oldids),"original label change")
    readyids={r["id"] for r in records if r["role"]=="external_train_only"}
    ready=[r for r in external if r["id"] in readyids]
    unknown={c:sorted({r["technique"] for r in pending if r["id"]==c}) for c in sorted({r["id"] for r in pending})}
    folds=[]
    for f in groups["folds"]:
        b=make_fold(base,ready,f,"base",reserve);g=make_fold(base,ready,f,"augmented",reserve)
        tr,dv=set(g["split"]["train"]),set(g["split"]["dev"]);lt=labels(g)
        counts=Counter(t for c in tr for t in lt[c])
        folds.append({"fold":f["fold"],"original_supervised_train":len(b["split"]["train"]),"external_train":len(ready),
             "candidate_train":len(tr),"scored_dev":len(dv),"candidate_train_support":dict(sorted(counts.items())),
             "fixed_major":g["fixed_major"],"reserved_overlap":len((tr|dv)&reserve),
             "unknown_train_pairs":sum(len(v) for c,v in unknown.items() if c in tr),
             "unknown_dev_pairs":sum(len(v) for c,v in unknown.items() if c in dv),
             "base_graph_digest":digest(b),"candidate_graph_digest":digest(g),
             "scored_dev_ids_unchanged":g["split"]["dev"]==b["split"]["dev"]})
    summary={"protocol":p["protocol"],"original_cves":len(oldids),"original_positive_cves":sum(bool(truth[c]) for c in oldids),
         "external_original_cves":len(extids),"external_candidate_cves":len(ready),"candidate_cves":len(records),
         "candidate_positive_cves":sum(bool(r["techniques"]) for r in records),
         "candidate_label_edges":sum(len(r["techniques"]) for r in records),
         "candidate_label_counts":dict(sorted(Counter(t for r in records for t in r["techniques"]).items())),
         "aligned_overlap_cves":len(aligned),"source_difference_cves_aligned":len(resolutions),
         "canonical_overlap_disagreements":sum(not r["canonical_views_agree"] for r in aligned),
         "author_duplicate_ids_resolved_without_union":[r["id"] for r in aligned if len(r["author_variants"])>1],
         "unknown_author_pairs":len(pending),"unknown_author_cves":len(unknown),
         "quarantine_cves":len(quarantine),"quarantine_ids":[r["id"] for r in quarantine],"original_labels_changed":0,
         "externally_curated_unrevalidated_cves":sum(r["label_status"]=="external_curated_not_ctid_revalidated" for r in records),
         "ctid_lexical_duplicate_T_events":sum(e.get("lexical_duplicate_T",False) for r in resolutions for e in r["ctid_evidence"]),
         "cwe_source_disagreements_preserved":len(cwe_disagreements),"cwe_metadata_changed":0,"folds":folds,
         "human_semantic_adjudication_performed":False,"independent_human_iaa":False,"training_started":False,
         "registered_model_engine_compatible_without_unknown_mask":False,"original_completed_comparison_byte_changed":False,
         "reserved_label_comparison":0,"reserved_scoring":0,"training":0,"model_inference":0,"model_api_calls":0,
         "limits":["Canonical source alignment does not prove semantic completeness.",
                  "The619 overlaps were already excluded from added Train; alignment is not measured improvement.",
                  "856 remaining external labels lack matching CTID adjudication; source distribution shifts persist.",
                  "The92 CWE disputes remain unadjudicated.",
                  "Future training requires integrating UNKNOWN exclusions and freezing a new science protocol."]}
    check(len(aligned)==619 and len(resolutions)==73,"reconciliation coverage")
    check(len(quarantine)==2 and len(pending)==20,"unexpected inventory")
    out.mkdir(parents=True)
    payloads={"records.jsonl":b"".join(encoded(r) for r in records),
              "author-aligned-overlap.jsonl":b"".join(encoded(r) for r in aligned),
              "resolutions.jsonl":b"".join(encoded(r) for r in resolutions),
              "unknown-author-labels.jsonl":b"".join(encoded(r) for r in pending),
              "quarantine.jsonl":b"".join(encoded(r) for r in quarantine),
              "negative-exclusions.json":encoded(unknown),"folds.json":encoded(groups),"summary.json":encoded(summary)}
    for n,b in payloads.items():(out/n).write_bytes(b)
    manifest={"protocol":p["protocol"],"files":{n:{"bytes":len(b),"sha256":sha(b)} for n,b in sorted(payloads.items())},
              "sources":source_manifest,"protocol_sha256":sha((HERE/"protocol.json").read_bytes()),
              "alignment_code_sha256":sha(Path(__file__).read_bytes()),
              "inputs":{k:p[k] for k in ("old_package_sha256","enriched_package_sha256","runtime_package_sha256",
                                       "comparison_git_blob","normalized_author_sha256","overlap_review_sha256","source_package_sha256")}}
    (out/"manifest.json").write_bytes(encoded(manifest));print(json.dumps(summary,ensure_ascii=False));return summary

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("old","enriched","runtime","comparison","author","review","sources","output"):
        p.add_argument("--"+n,required=True)
    build(p.parse_args())


