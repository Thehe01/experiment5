"""Independent arithmetic, preservation, source and deterministic replay checks."""
import collections
import importlib.util
import json
import pathlib
import re
import tempfile
import zipfile

S = importlib.util.spec_from_file_location("v3", pathlib.Path(__file__).with_name("resolution.py"))
R = importlib.util.module_from_spec(S)
S.loader.exec_module(R)

def verify(args):
    out = pathlib.Path(args["output"])
    data = {p.name: p.read_bytes() for p in out.iterdir() if p.is_file()}
    m = json.loads(data["manifest.json"])
    assert set(data) == set(m["files"]) | {"manifest.json"}
    for n, entry in m["files"].items():
        assert len(data[n]) == entry["bytes"] and R.sha(data[n]) == entry["sha256"]
    assert m["protocol_sha256"] == R.sha(pathlib.Path(args["protocol"]).read_bytes())
    for k, digest in m["input_sha256"].items():
        assert R.sha(pathlib.Path(args[k]).read_bytes()) == digest
    with zipfile.ZipFile(args["v2"]) as z:
        old = {r["id"]: r for r in R.jsonl(z.read("outputs/records.jsonl"))}
        uq = R.jsonl(z.read("outputs/unknown-author-labels.jsonl"))
        domain = {r["id"]: r for r in R.jsonl(z.read("outputs/quarantine.jsonl"))}
        old_folds = json.loads(z.read("outputs/folds.json"))
    full = {r["id"]: r for r in R.jsonl(data["full-records.jsonl"])}
    usable = {r["id"]: r for r in R.jsonl(data["usable-records.jsonl"])}
    quarantined = {r["id"]: r for r in R.jsonl(data["quarantine.jsonl"])}
    unknown_ids = {r["id"] for r in uq}
    assert len(full) == 1736 and full.keys() == old.keys()
    assert usable.keys() == full.keys() - unknown_ids and len(usable) == 1724
    assert quarantined.keys() == unknown_ids | domain.keys() and len(quarantined) == 14
    assert all(not r["unknown_labels"] for r in usable.values())
    protected = set(old_folds["reserved_ids"])
    assert not (full.keys() | quarantined.keys()) & protected
    for i, r in full.items():
        for key in old[i]:
            if key != "cwe_ids":
                assert r[key] == old[i][key], (i, key)
        if r["role"] == "original_development_pool":
            assert r["cwe_ids"] == old[i]["cwe_ids"]
        if i in usable:
            assert usable[i] == r
        elif i in unknown_ids:
            assert quarantined[i]["record"] == r
    for i, r in domain.items():
        assert quarantined[i]["v2_quarantine_record"] == r
    assert R.jsonl(data["unknown-pairs-preserved.jsonl"]) == uq
    opinions = R.jsonl(data["technique-review.jsonl"])
    assert len(opinions) == 20 and {(r["id"], r["technique"]) for r in opinions} == {(r["id"], r["technique"]) for r in uq}
    assert all(r["canonical_action"] == "KEEP_UNKNOWN_QUARANTINE_CVE" and not r["canonical_positive"] and not r["confirmed_negative"] and not r["human_semantic_adjudication"] for r in opinions)
    assert collections.Counter(r["finding"] for r in opinions) == {"supports_potential_association": 3, "context_required": 7, "not_supported_by_examined_mechanism": 10}
    primary, source_entries, _ = R.load_sources(args["sources"])
    assert len([n for n in primary if n.startswith("cve/")]) == 107
    assert len([n for n in primary if n.startswith("attack/")]) == 15
    for r in opinions:
        assert source_entries[r["cve_evidence_member"]]["sha256"] == r["primary_sha256"]
        assert source_entries[r["attack_evidence_member"]]["sha256"] == r["attack_sha256"]
    with zipfile.ZipFile(args["enriched"]) as z:
        raw = {item["cve"]["id"]: item["cve"] for name in z.namelist() if name.startswith("raw_nvd/batch-") for item in json.loads(z.read(name))["vulnerabilities"]}
        original_disputes = {r["id"] for r in R.jsonl(z.read("review/cwe-source-review.jsonl"))}
        decisions = R.jsonl(data["cwe-decisions.jsonl"])
        assert len(decisions) == 856 and len({d["id"] for d in decisions}) == 856
        changes = 0
        removed = 0
        for d in decisions:
            cv = raw[d["id"]]
            groups = collections.defaultdict(set)
            for x in cv.get("weaknesses", []):
                for v in x["description"]:
                    if re.fullmatch(r"CWE-\d+", v["value"]):
                        groups[x["source"]].add(v["value"])
            selected = next((src for src in [cv["sourceIdentifier"], R.NVD, R.CISA] if groups.get(src)), None)
            expected = sorted(groups[selected]) if selected else []
            assert d["ids"] == expected and d["source"] == selected
            assert full[d["id"]]["cwe_ids"] == expected
            assert d["original_union"] == old[d["id"]]["cwe_ids"]
            assert d["changed"] == (expected != d["original_union"])
            changes += d["changed"]
            removed += len(d["original_union"]) - len(expected)
            evidence = d["raw_evidence"]
            raw_bytes = z.read(evidence["member"])
            assert R.sha(raw_bytes) == evidence["sha256"]
            assert R.dereference(json.loads(raw_bytes), evidence["cve_pointer"]) == cv
            if selected == R.CISA:
                official = primary[d["official_cve_member"]]
                adp = next(x for x in official["containers"]["adp"] if x["providerMetadata"]["orgId"] == R.CISA)
                official_values = sorted({x["cweId"] for p in adp["problemTypes"] for x in p["descriptions"]})
                assert official_values == expected
            if d["id"] in original_disputes:
                assert d["cna_numeric_values_agree_snapshot"] is True
        assert changes == 89 and removed == 91
        disputes = R.jsonl(data["cwe-dispute-resolutions.jsonl"])
        assert len(disputes) == 92 and {d["id"] for d in disputes} == original_disputes
        assert [d for d in decisions if d["original_source_difference"]] == disputes
    previews = json.loads(data["folds-usable-preview.json"])["folds"]
    external_ids = {i for i, r in full.items() if r["role"] == "external_train_only"}
    for f, old_f in zip(previews, old_folds["folds"]):
        assert set(f["train"]) == (set(old_f["train"]) | external_ids) - unknown_ids
        assert set(f["dev"]) == set(old_f["dev"]) - unknown_ids
        assert not set(f["train"]) & set(f["dev"])
        assert set(f["train"]) | set(f["dev"]) == usable.keys()
        assert not set(f["supervised_train"]) & unknown_ids and not set(f["scored_dev"]) & unknown_ids
        for role, support in [("supervised_train", "train_support"), ("scored_dev", "dev_support")]:
            assert dict(collections.Counter(t for i in f[role] for t in usable[i]["techniques"])) == f[support]
    summary = json.loads(data["summary.json"])
    assert summary["usable_label_counts"] == dict(collections.Counter(t for r in usable.values() for t in r["techniques"]))
    assert summary["usable_label_edges"] == 3144
    assert summary["usable_positive_cves"] == 1694
    assert summary["known_unknown_pairs_in_usable"] == 0
    assert summary["training"] == summary["reserved_scoring"] == summary["AI_labels_added_to_Gold"] == 0
    with tempfile.TemporaryDirectory() as temp:
        rerun = {**args, "output": str(pathlib.Path(temp) / "repeat")}
        R.generate(**rerun)
        repeated = {p.name: p.read_bytes() for p in pathlib.Path(rerun["output"]).iterdir()}
        assert repeated == data
        try:
            R.generate(**rerun)
        except ValueError as error:
            assert "overwrite" in str(error)
        else:
            raise AssertionError("overwrite accepted")
        tamper = pathlib.Path(temp) / "tampered.zip"
        tamper.write_bytes(pathlib.Path(args["sources"]).read_bytes() + b"\n")
        tampered_output = pathlib.Path(temp) / "tampered-output"
        try:
            R.generate(**{**args, "sources": str(tamper), "output": str(tampered_output)})
        except ValueError as error:
            assert "hash" in str(error)
        else:
            raise AssertionError("tamper accepted")
        assert not tampered_output.exists()
    return {"passed": True, "full_records": 1736, "usable_records": 1724, "quarantine": 14, "CWE_disputes_verified": 92, "CWE_sets_changed": 89, "CWE_edges_removed": 91, "unknown_pairs_preserved": 20, "known_unknown_pairs_in_usable": 0, "primary_CVE_records_Git_and_SHA256_checked": 107, "frozen_technique_files_checked": 15, "all_labels_CPE_roles_preserved": True, "original_880_CWE_preserved": True, "fold_filter_and_support_checked": True, "deterministic_output_files": len(data), "overwrite_rejected": True, "input_tamper_rejected": True, "reserved_labels_read_or_scored": 0, "training": 0, "AI_Gold_added": 0, "inputs_sha256": m["input_sha256"]}

if __name__ == "__main__":
    p = R.parser()
    p.add_argument("--receipt", required=True)
    values = vars(p.parse_args())
    receipt = pathlib.Path(values.pop("receipt"))
    if receipt.exists():
        raise ValueError("refuse receipt overwrite")
    result = verify(values)
    receipt.write_bytes(R.encoded(result))
    print(json.dumps(result, sort_keys=True))
