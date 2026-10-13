"""Independent output/source/role checks and fail-closed/repeatability probes."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text())
def rows(p):return [json.loads(x) for x in Path(p).read_text().splitlines()]
def verify(a):
    out=Path(a.output);m=read(out/"manifest.json");summary=read(out/"summary.json")
    for name,v in m["files"].items():
        assert sha(out/name)==v["sha256"] and (out/name).stat().st_size==v["bytes"]
    assert sha(HERE/"alignment.py")==m["alignment_code_sha256"]
    assert sha(HERE/"protocol.json")==m["protocol_sha256"]
    with zipfile.ZipFile(a.runtime) as z:
        base=json.loads(z.read("base-graph.json"));groups=json.loads(z.read("folds.json"))
        external={r["id"]:r for r in [json.loads(x) for x in z.read("external-records.jsonl").splitlines()]}
        old_audit=json.loads(z.read("audit.json"))
    oldids={n["id"] for n in base["nodes"] if n["type"]=="Vulnerability"}
    reserved=set(groups["reserved_ids"]);scope=set(base["techniques"])
    oldlabels={c:set() for c in oldids};oldcontext={c:{"cwe_ids":set(),"cpe_families":set()} for c in oldids}
    for e in base["edges"]:
        if e["relation"]=="potentially_associated_with":oldlabels[e["head"]].add(e["tail"])
        if e["head"] in oldids and e["relation"] in ("has_reported_cwe","has_reported_cpe"):
            k="cwe_ids" if e["relation"]=="has_reported_cwe" else "cpe_families"
            oldcontext[e["head"]][k].add(e["tail"])
    candidate=rows(out/"records.jsonl");ix={r["id"]:r for r in candidate}
    overlap=rows(out/"author-aligned-overlap.jsonl");ledger=rows(out/"resolutions.jsonl")
    unknown=rows(out/"unknown-author-labels.jsonl");quarantine=rows(out/"quarantine.jsonl")
    source_review=rows(a.review);authors={r["id"]:r for r in rows(a.author) if r["id"] in oldids|set(external)}
    assert len(candidate)==len(ix)==1736 and len(oldids)==880
    assert oldids <= set(ix) and len(set(ix)-oldids)==856
    quarantined={r["id"] for r in quarantine}
    assert quarantined=={"CVE-2017-0493","CVE-2019-7287"}
    assert set(ix)-oldids==set(external)-quarantined
    for rr in (candidate,overlap,ledger,unknown,quarantine):
        assert not {r["id"] for r in rr}&reserved
    rawct=defaultdict(set)
    with zipfile.ZipFile(a.sources) as z:
        cs=list(csv.DictReader(io.StringIO(z.read("ctid-attack-to-cve.csv").decode("utf-8-sig"))))
        ks=json.loads(z.read("ctid-kev.json"))["mapping_objects"]
        for r in cs:
            c=r["CVE ID"]
            if c not in oldids|set(external):continue
            for key in ("Primary Impact","Secondary Impact","Exploitation Technique","Uncategorized"):
                rawct[c].update(t.split(".")[0] for t in re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?",r[key]))
        for r in ks:
            if r["capability_id"] in oldids|set(external):
                rawct[r["capability_id"]].add(r["attack_object_id"].split(".")[0])
        # Evidence pointers must dereference original records, not just look plausible.
        for r in ledger:
            for e in r["ctid_evidence"]:
                if e["source"]=="ctid_cve":
                    record=cs[e["csv_record_number"]-2]
                    assert record["CVE ID"]==r["id"] and record[e["column"]]==e["raw_cell"]
                    assert e["technique"] in re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?",e["raw_cell"])
                else:
                    record=ks[e["mapping_object_index"]]
                    assert record["capability_id"]==r["id"] and record["attack_object_id"]==e["technique"]
                    assert record["references"]==e["references"]
    for c in oldids:
        assert set(ix[c]["techniques"])==oldlabels[c]==rawct[c]&scope
        for k in ("cwe_ids","cpe_families"):assert set(ix[c][k])==oldcontext[c][k]
    for c in set(ix)-oldids:
        assert set(ix[c]["techniques"])==set(external[c]["techniques"])
        for k in ("cwe_ids","cpe_families"):assert set(ix[c][k])==set(external[c][k])
        assert ix[c]["role"]=="external_train_only" and ix[c]["stage_labels"] is None
    assert len(overlap)==len({r["id"] for r in overlap})==619
    assert {r["id"] for r in overlap}=={r["id"] for r in source_review}
    assert len(ledger)==73 and {r["id"] for r in ledger}=={r["id"] for r in source_review if any(v["public_only_labels"] or v["external_only_labels"] for v in r["label_variant_differences"])}
    expectedunknown={(c,t) for c in authors if c in oldids for v in authors[c]["label_variants"] for t in set(v)-oldlabels[c]}
    actualunknown={(r["id"],r["technique"]) for r in unknown}
    assert actualunknown==expectedunknown and len(unknown)==20 and len({c for c,t in actualunknown})==12
    exclusions=read(out/"negative-exclusions.json")
    assert {(c,t) for c,ts in exclusions.items() for t in ts}==actualunknown
    for r in overlap:
        assert set(r["canonical_labels"])==oldlabels[r["id"]]
        assert r["author_variants"]==authors[r["id"]]["label_variants"]
        assert r["provenance"]["author_csv_rows"]==authors[r["id"]]["provenance"]
        assert not set(r["canonical_labels"])&set(r["unknown_labels"])
    for r in unknown:assert r["confirmed_negative"] is False and r["canonical_positive"] is False
    for c in quarantined:assert not rawct[c]&scope and rawct[c] <= {"T1404","T1461","T1533"}
    assert read(out/"folds.json")==groups
    for f,fs in zip(groups["folds"],summary["folds"]):
        oldtrain={c for c in f["train"] if oldlabels[c]}
        train=oldtrain | (set(ix)-oldids);dev={c for c in f["dev"] if oldlabels[c]}
        counts=Counter(t for c in train for t in ix[c]["techniques"])
        assert len(oldtrain)==700 and len(train)==1556 and len(dev)==150
        assert dict(counts)==fs["candidate_train_support"] and min(counts.values())==17
        assert not (train|dev)&reserved
        assert fs["unknown_train_pairs"]==sum(c in train for c,t in actualunknown)
        assert fs["unknown_dev_pairs"]==sum(c in dev for c,t in actualunknown)
        originalgraph=next(x for x in old_audit["summaries"] if x["condition"]=="base" and x["fold"]==f["fold"])
        assert fs["base_graph_digest"]==originalgraph["graph_sha256"]
    assert sum(len(r["techniques"]) for r in candidate)==summary["candidate_label_edges"]==3166
    assert summary["canonical_overlap_disagreements"]==summary["original_labels_changed"]==0
    assert summary["registered_model_engine_compatible_without_unknown_mask"] is False
    paths=[a.old,a.enriched,a.runtime,a.comparison,a.author,a.review,a.sources]
    before={p:sha(p) for p in paths}
    args=[sys.executable,str(HERE/"alignment.py")]
    for n in ("old","enriched","runtime","comparison","author","review","sources"):args+=["--"+n,getattr(a,n)]
    env=dict(os.environ,PYTHONHASHSEED="0");probes=[]
    with tempfile.TemporaryDirectory(prefix="source-alignment-verification-") as td:
        repeat=Path(td)/"repeat"
        cp=subprocess.run(args+["--output",str(repeat)],capture_output=True,text=True,env=env)
        assert cp.returncode==0,cp.stderr
        equal={p.name:p.read_bytes()==(repeat/p.name).read_bytes() for p in out.iterdir()}
        assert all(equal.values()),equal
        cp=subprocess.run(args+["--output",str(out)],capture_output=True,text=True,env=env)
        assert cp.returncode!=0 and "refuse output overwrite" in cp.stderr
        probes.append({"probe":"existing output overwrite","exit_code":cp.returncode,"rejected":True})
        bad=Path(td)/"bad-sources.zip";bad.write_bytes(Path(a.sources).read_bytes()+b"\n")
        ba=list(args);ba[ba.index("--sources")+1]=str(bad);badout=Path(td)/"badout"
        cp=subprocess.run(ba+["--output",str(badout)],capture_output=True,text=True,env=env)
        assert cp.returncode!=0 and "CTID source package byte mismatch" in cp.stderr and not badout.exists()
        probes.append({"probe":"tampered CTID source bytes","exit_code":cp.returncode,"rejected":True})
    assert before=={p:sha(p) for p in paths}
    return {"passed":True,"source_reconstruction_verified_old_cves":880,"aligned_overlap":619,
            "resolution_cves":73,"unknown_pairs":20,"unknown_cves":12,"domain_quarantine":sorted(quarantined),
            "candidate_cves":1736,"candidate_label_edges":3166,"candidate_train_per_fold":1556,"dev_per_fold":150,
            "reserved_label_or_scoring_output":0,"original_labels_changed":0,"cwe_cpe_metadata_changed":0,
            "evidence_pointers_verified":True,"repeat_output_bytes_equal":equal,"negative_probes":probes,
            "frozen_inputs_unchanged":True,"training":0,"model_inference":0,"model_api_calls":0,
            "verification_script_sha256":sha(__file__)}
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("old","enriched","runtime","comparison","author","review","sources","output","receipt"):p.add_argument("--"+n,required=True)
    a=p.parse_args();result=verify(a);Path(a.receipt).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps(result))

