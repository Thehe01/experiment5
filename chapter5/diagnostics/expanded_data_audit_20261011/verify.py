"""Independent artifact arithmetic/protection checks, repeatability and two fail-closed probes."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):
    return json.loads(Path(p).read_text())
def rows(p):
    return [json.loads(x) for x in Path(p).read_text().splitlines()]
def close(a,b):
    assert abs(a-b) < 1e-12, (a,b)
def verify(a):
    result = Path(a.output)
    d, v = read(result/"analysis.json"),read(result/"verification.json")
    for name,h in v["outputs_sha256"].items():
        assert sha(result/name) == h
    assert sha(HERE/"audit.py") == v["audit_script_sha256"]
    assert sha(HERE/"protocol.json") == v["protocol_sha256"]
    with zipfile.ZipFile(a.runtime) as z:
        groups = json.loads(z.read("folds.json"))
    reserve = set(groups["reserved_ids"])
    review,neighbor = rows(result/"overlap-label-review.jsonl"),rows(result/"neighbor-vote-decomposition.jsonl")
    assert len(review)==len({r["id"] for r in review})==73
    assert not ({r["id"] for r in review}|{r["id"] for r in neighbor}) & reserve
    assert len(neighbor)==450 and len({r["id"] for r in neighbor})==237
    assert Counter(r["fold"] for r in neighbor)=={0:150,1:150,2:150}
    for r in neighbor:
        assert r["id"] in groups["folds"][r["fold"]]["dev"]
        for condition in ("base","augmented"):
            close(r[condition+"_mrr"],sum(1/x for x in r[condition+"_ranks"].values())/len(r["observed_labels"]))
        close(r["delta_mrr"],r["augmented_mrr"]-r["base_mrr"])
        if r["old_weight"]+r["external_weight"]:
            close(r["external_weight_share"],r["external_weight"]/(r["old_weight"]+r["external_weight"]))
    delta = sum(r["delta_mrr"] for r in neighbor)/450
    close(delta,d["baseline_summary"]["neighbor_vote"]["delta_mrr"])
    ns = d["neighbor_summary"]
    assert ns["improved"]+ns["degraded"]+ns["unchanged"]==450
    counts = Counter("up" if r["delta_mrr"]>1e-12 else "down" if r["delta_mrr"] < -1e-12 else "same" for r in neighbor)
    assert counts=={"up":ns["improved"],"down":ns["degraded"],"same":ns["unchanged"]}
    assert len(d["baseline_replays"])==36 and max(r["max_metric_error"] for r in d["baseline_replays"]) < 1e-12
    for name in ("old_positive_pool","external_train_only"):
        c = d["cohorts"][name]
        assert sum(c["label_counts"].values())==c["label_edges"]
        assert sum(int(k)*n for k,n in c["cardinality_counts"].items())==c["label_edges"]
        assert sum(c["cardinality_counts"].values())==c["cves"]
        assert sum(c["cve_id_year_counts"].values())==c["cves"]
    inputpaths = [a.old,a.enriched,a.runtime,a.comparison]
    before = {p:sha(p) for p in inputpaths}
    args = [sys.executable,str(HERE/"audit.py")]
    for name in ("old","enriched","runtime","comparison","preprocess"):
        args += ["--"+name,getattr(a,name)]
    env = dict(os.environ,PYTHONHASHSEED="0")
    probes = []
    with tempfile.TemporaryDirectory(prefix="expanded-audit-verify-") as td:
        repeat = Path(td)/"repeat"
        cp = subprocess.run(args+["--output",str(repeat)],capture_output=True,text=True,env=env)
        assert cp.returncode==0, cp.stderr
        same = {p.name:p.read_bytes()==(repeat/p.name).read_bytes() for p in result.iterdir()}
        assert all(same.values()), same
        cp = subprocess.run(args+["--output",str(result)],capture_output=True,text=True,env=env)
        assert cp.returncode!=0 and "refuse output overwrite" in cp.stderr
        probes.append({"action":"overwrite existing audit output","rejected":True,"exit_code":cp.returncode})
        tampered = Path(td)/"comparison.json"
        tampered.write_bytes(Path(a.comparison).read_bytes()+b"\n")
        badargs = list(args)
        badargs[badargs.index("--comparison")+1] = str(tampered)
        failedout = Path(td)/"failed"
        cp = subprocess.run(badargs+["--output",str(failedout)],capture_output=True,text=True,env=env)
        assert cp.returncode!=0 and "comparison byte mismatch" in cp.stderr and not failedout.exists()
        probes.append({"action":"tampered comparison bytes","rejected":True,"exit_code":cp.returncode})
    assert before=={p:sha(p) for p in inputpaths}
    return {"passed":True,"artifact_hashes_verified":True,"queue_protected_overlap":0,
            "neighbor_occurrences":450,"neighbor_unique_cves":237,
            "reconstructed_neighbor_delta_mrr":delta,"repeat_bytes_equal":same,
            "negative_probes":probes,"frozen_input_bytes_unchanged":True,
            "training":0,"model_inference":0,"model_api_calls":0,"reserved_scoring":0,
            "verification_script_sha256":sha(__file__)}
if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for n in ("old","enriched","runtime","comparison","preprocess","output","receipt"):
        p.add_argument("--"+n,required=True)
    a = p.parse_args()
    result = verify(a)
    Path(a.receipt).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,sort_keys=True))

