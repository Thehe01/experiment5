"""Independent source-resolution data preparation; no training or scoring."""
import argparse
import collections
import copy
import hashlib
import json
import pathlib
import re
import zipfile

CISA = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
NVD = "nvd@nist.gov"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def encoded(obj):
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()

def lines(rows):
    return b"".join((json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode() for r in rows)

def jsonl(data):
    return [json.loads(x) for x in data.decode().splitlines() if x]

def choose_cwe(source_identifier, evidence, verified_adp=None):
    groups = collections.defaultdict(set)
    for e in evidence:
        if re.fullmatch(r"CWE-[0-9]+", e["value"]):
            groups[e["source"]].add(e["value"])
    if groups.get(source_identifier):
        return {"ids": sorted(groups[source_identifier]), "source": source_identifier, "policy": "nvd_source" if source_identifier == NVD else "assigning_source"}
    if groups.get(NVD):
        return {"ids": sorted(groups[NVD]), "source": NVD, "policy": "nvd_fallback"}
    if groups:
        if len(groups) == 1:
            source = next(iter(groups))
            if set((verified_adp or {}).get(source, [])) == groups[source]:
                return {"ids": sorted(groups[source]), "source": source, "policy": "verified_adp_fallback"}
        raise ValueError("unverified or ambiguous third provider; source review required")
    return {"ids": [], "source": None, "policy": "no_numeric_CWE"}

def partition(records):
    clean, quarantine = [], []
    for r in records:
        (quarantine if r.get("unknown_labels") else clean).append(r)
    return clean, quarantine

def validate_review(unknown, opinions):
    expected = {(r["id"], r["technique"]) for r in unknown}
    pairs = [(r["id"], r["technique"]) for r in opinions]
    if len(set(pairs)) != len(pairs) or set(pairs) != expected:
        raise ValueError("review pair coverage or uniqueness mismatch")
    for r in opinions:
        if r.get("canonical_action") != "KEEP_UNKNOWN_QUARANTINE_CVE" or r.get("human_semantic_adjudication") is not False or r.get("canonical_positive", False) or r.get("confirmed_negative", False):
            raise ValueError("AI opinion cannot be promoted to Gold or confirmed negative")
        if r["finding"] not in {"supports_potential_association", "context_required", "not_supported_by_examined_mechanism"}:
            raise ValueError("unknown review finding")
    return True

def dereference(obj, pointer):
    for key in pointer.lstrip("/").split("/"):
        obj = obj[int(key)] if isinstance(obj, list) else obj[key.replace("~1", "/").replace("~0", "~")]
    return obj

def numeric_cna(record):
    return sorted({d["cweId"] for p in record["containers"]["cna"].get("problemTypes", []) for d in p["descriptions"] if re.fullmatch(r"CWE-[0-9]+", d.get("cweId", ""))})

def load_sources(path):
    with zipfile.ZipFile(path) as z:
        manifest = json.loads(z.read("manifest.json"))
        objects, entries = {}, {}
        if set(z.namelist()) != {x["path"] for x in manifest["files"]} | {"manifest.json"}:
            raise ValueError("source ZIP member mismatch")
        for f in manifest["files"]:
            data = z.read(f["path"])
            if len(data) != f["bytes"] or sha(data) != f["sha256"] or git_sha(data) != f["git_blob_sha"]:
                raise ValueError("source hash mismatch")
            entries[f["path"]] = f
            if f["path"].endswith(".json"):
                objects[f["path"]] = json.loads(data)
    return objects, entries, manifest

def generate(v2, enriched, sources, opinions, protocol, output):
    paths = {"v2": v2, "enriched": enriched, "sources": sources, "opinions": opinions}
    proto = json.loads(pathlib.Path(protocol).read_text())
    if proto["protocol"] != "chapter5-source-resolution-v3-20261011":
        raise ValueError("wrong protocol")
    for k, p in paths.items():
        if sha(pathlib.Path(p).read_bytes()) != proto["input_sha256"][k]:
            raise ValueError("input hash mismatch: " + k)
    out = pathlib.Path(output)
    if out.exists():
        raise ValueError("refuse output overwrite")
    primary, source_files, source_manifest = load_sources(sources)
    with zipfile.ZipFile(v2) as z:
        old = jsonl(z.read("outputs/records.jsonl"))
        unknown = jsonl(z.read("outputs/unknown-author-labels.jsonl"))
        old_quarantine = jsonl(z.read("outputs/quarantine.jsonl"))
        folds = json.loads(z.read("outputs/folds.json"))
    review = json.loads(pathlib.Path(opinions).read_text())
    validate_review(unknown, review)
    protected = set(folds["reserved_ids"])
    if {r["id"] for r in old} & protected:
        raise ValueError("protected ID in samples")
    if any(path.removeprefix("cve/").removesuffix(".json") in protected for path in primary if path.startswith("cve/")):
        raise ValueError("protected ID in primary evidence")
    for r in review:
        cve = primary[r["cve_evidence_member"]]
        tech = primary[r["attack_evidence_member"]]
        if cve["cveMetadata"]["cveId"] != r["id"] or cve["cveMetadata"]["state"] != "PUBLISHED":
            raise ValueError("wrong review CVE identity")
        description = dereference(cve, r["cve_description_pointer"])
        ap = tech["objects"][0]
        if not description.get("value") or ap.get("revoked") or ap.get("x_mitre_deprecated") or not any(e.get("source_name") == "mitre-attack" and e.get("external_id") == r["technique"] for e in ap["external_references"]):
            raise ValueError("wrong frozen ATT&CK definition")
        if not dereference(tech, r["attack_description_pointer"]):
            raise ValueError("empty technique definition")
        r["primary_sha256"] = source_files[r["cve_evidence_member"]]["sha256"]
        r["attack_sha256"] = source_files[r["attack_evidence_member"]]["sha256"]
    external_ids = {r["id"] for r in old if r["role"] == "external_train_only"}
    raw_by_id, raw_paths = {}, {}
    with zipfile.ZipFile(enriched) as z:
        external = {r["id"]: r for r in jsonl(z.read("data/graph-ready-candidates.jsonl")) if r["id"] in external_ids}
        disputes = [r for r in jsonl(z.read("review/cwe-source-review.jsonl")) if r["id"] in external_ids]
        for path in sorted(n for n in z.namelist() if n.startswith("raw_nvd/") and "batch-" in n):
            data = z.read(path)
            for i, item in enumerate(json.loads(data)["vulnerabilities"]):
                cv = item["cve"]
                if cv["id"] in external_ids:
                    if cv["id"] in raw_by_id:
                        raise ValueError("duplicate raw CVE")
                    raw_by_id[cv["id"]] = cv
                    raw_paths[cv["id"]] = {"member": path, "sha256": sha(data), "cve_pointer": "/vulnerabilities/" + str(i) + "/cve"}
    if set(external) != external_ids or set(raw_by_id) != external_ids:
        raise ValueError("external source coverage mismatch")
    dispute_ids = {r["id"] for r in disputes}
    full, decisions = [], []
    for source_record in old:
        r = copy.deepcopy(source_record)
        r["data_version"] = proto["protocol"]
        r["admission_status"] = "QUARANTINED_UNKNOWN_CVE" if r["unknown_labels"] else "USABLE_KNOWN_DISPUTES_EXCLUDED"
        if r["id"] in external_ids:
            e = external[r["id"]]
            raw = raw_by_id[r["id"]]
            for ev in e["cwe_evidence"]:
                item = dereference(raw, ev["path"])
                if item["value"] != ev["value"] or item["lang"] != ev["lang"]:
                    raise ValueError("raw evidence value mismatch")
                group = dereference(raw, ev["path"].split("/description")[0])
                if group["source"] != ev["source"] or group["type"] != ev["type"]:
                    raise ValueError("raw provider mismatch")
            verified_adp = {}
            member = "cve/" + r["id"] + ".json"
            official = primary.get(member)
            cna_check = None
            if official:
                if official["cveMetadata"]["cveId"] != r["id"] or official["cveMetadata"]["state"] != "PUBLISHED":
                    raise ValueError("official identity/status mismatch")
                cached_cna = sorted({x["value"] for x in e["cwe_evidence"] if x["source"] == raw["sourceIdentifier"] and re.fullmatch(r"CWE-[0-9]+", x["value"])})
                cna_check = numeric_cna(official) == cached_cna
                if r["id"] in dispute_ids and not cna_check:
                    raise ValueError("CNA snapshot differs from pinned official record")
                for adp in official["containers"].get("adp", []):
                    if adp["providerMetadata"]["orgId"] == CISA:
                        verified_adp[CISA] = sorted({d["cweId"] for p in adp.get("problemTypes", []) for d in p["descriptions"] if re.fullmatch(r"CWE-[0-9]+", d.get("cweId", ""))})
            choice = choose_cwe(raw["sourceIdentifier"], e["cwe_evidence"], verified_adp)
            r["cwe_ids"] = choice["ids"]
            r["cwe_resolution"] = {**choice, "original_union": source_record["cwe_ids"], "raw_evidence": raw_paths[r["id"]], "semantic_adjudication": False}
            decisions.append({"id": r["id"], **choice, "original_union": source_record["cwe_ids"], "changed": choice["ids"] != source_record["cwe_ids"], "raw_evidence": raw_paths[r["id"]], "all_provider_evidence": e["cwe_evidence"], "official_cve_member": member if official else None, "official_cve_sha256": source_files[member]["sha256"] if official else None, "cna_numeric_values_agree_snapshot": cna_check, "original_source_difference": r["id"] in dispute_ids, "resolution_type": "fixed_provider_policy_not_semantic_truth", "sourceIdentifier": raw["sourceIdentifier"]})
        full.append(r)
    usable, unknown_quarantine = partition(full)
    by_id = {r["id"]: r for r in full}
    quarantine = [{"id": r["id"], "reason": "UNKNOWN_TECHNIQUE_CVE", "record": r} for r in unknown_quarantine]
    quarantine += [{"id": r["id"], "reason": "MOBILE_ENTERPRISE_DOMAIN_V2", "v2_quarantine_record": r} for r in old_quarantine]
    quarantine.sort(key=lambda r: r["id"])
    usable_ids = {r["id"] for r in usable}
    counts = lambda ids: dict(sorted(collections.Counter(t for i in ids for t in by_id[i]["techniques"]).items()))
    fold_previews = []
    for f in folds["folds"]:
        train = sorted((set(f["train"]) | external_ids) & usable_ids)
        dev = sorted(set(f["dev"]) & usable_ids)
        st = [i for i in train if by_id[i]["techniques"]]
        sd = [i for i in dev if by_id[i]["techniques"]]
        fold_previews.append({"fold": f["fold"], "source_split_seed": f["seed"], "train": train, "dev": dev, "supervised_train": st, "scored_dev": sd, "excluded_original_train": sorted(set(f["train"]) - usable_ids), "excluded_original_dev": sorted(set(f["dev"]) - usable_ids), "train_support": counts(st), "dev_support": counts(sd), "old_scoring_protocol_applicable": False})
    changed = [d for d in decisions if d["changed"]]
    stats = {"protocol": proto["protocol"], "full_cves": len(full), "full_positive_cves": sum(bool(r["techniques"]) for r in full), "usable_cves": len(usable), "usable_positive_cves": sum(bool(r["techniques"]) for r in usable), "usable_background_only_cves": sum(not r["techniques"] for r in usable), "usable_original_cves": sum(r["role"] == "original_development_pool" for r in usable), "usable_external_cves": len(external_ids), "usable_label_counts": counts(usable_ids), "usable_label_edges": sum(len(r["techniques"]) for r in usable), "unknown_pairs_preserved": len(unknown), "unknown_cves_quarantined": len(unknown_quarantine), "known_unknown_pairs_in_usable": sum(len(r["unknown_labels"]) for r in usable), "total_quarantine_cves": len(quarantine), "cwe_disputes_source_resolved": len(disputes), "cwe_changed_records": len(changed), "cwe_removed_edges": sum(len(d["original_union"]) - len(d["ids"]) for d in changed), "cwe_provider_policies": dict(collections.Counter(d["policy"] for d in decisions)), "review_findings": dict(collections.Counter(r["finding"] for r in review)), "canonical_technique_labels_changed": 0, "CPE_changed": 0, "original_880_CWE_changed": 0, "AI_labels_added_to_Gold": 0, "human_semantic_adjudication": False, "reserved_scoring": 0, "experimental_model_api_calls": 0, "training": 0, "fold_previews": [{"fold": f["fold"], "train_graph_cves": len(f["train"]), "supervised_train": len(f["supervised_train"]), "dev_graph_cves": len(f["dev"]), "scored_dev": len(f["scored_dev"]), "train_background_only": len(f["train"]) - len(f["supervised_train"]), "dev_background_only": len(f["dev"]) - len(f["scored_dev"]), "min_train_class_support": min(f["train_support"].values()), "dev_positive_classes": len(f["dev_support"]), "excluded_original_train": len(f["excluded_original_train"]), "excluded_original_dev": len(f["excluded_original_dev"])} for f in fold_previews], "limits": ["Zero known unresolved pairs in usable is achieved by quarantine, not complete semantic labeling.", "92 source decisions are provider-priority choices, not independent semantic truth.", "856 externally curated labels remain without independent semantic validation.", "Do not compare new preview Dev147/148 scores directly with frozen Dev150.", "Future experiment requires new data/split/metric/budget registration; no training launched."]}
    exp = proto["expected"]
    if (len(full), len(usable), len(unknown), len(unknown_quarantine), len(old_quarantine), len(disputes), len(changed)) != (exp["full_records"], exp["usable_records"], exp["unknown_pairs"], exp["unknown_cves"], exp["domain_quarantine"], exp["cwe_disputes"], exp["cwe_changed_records"]):
        raise ValueError("expected scope/count mismatch")
    parts = {"full-records.jsonl": lines(full), "usable-records.jsonl": lines(usable), "quarantine.jsonl": lines(quarantine), "cwe-decisions.jsonl": lines(decisions), "cwe-dispute-resolutions.jsonl": lines([d for d in decisions if d["original_source_difference"]]), "technique-review.jsonl": lines(review), "unknown-pairs-preserved.jsonl": lines(unknown), "folds-usable-preview.json": encoded({"kind": "unregistered_new_split_preview", "strategy": folds["strategy"], "folds": fold_previews}), "summary.json": encoded(stats)}
    manifest = {"protocol": proto["protocol"], "input_sha256": proto["input_sha256"], "protocol_sha256": sha(pathlib.Path(protocol).read_bytes()), "sources_manifest_sha256": sha(encoded(source_manifest)), "files": {k: {"bytes": len(b), "sha256": sha(b)} for k, b in sorted(parts.items())}}
    parts["manifest.json"] = encoded(manifest)
    out.mkdir(parents=True)
    for k, b in parts.items():
        (out / k).write_bytes(b)
    return stats

def parser():
    p = argparse.ArgumentParser()
    for name in ["v2", "enriched", "sources", "opinions", "protocol", "output"]:
        p.add_argument("--" + name, required=True)
    return p

if __name__ == "__main__":
    args = vars(parser().parse_args())
    print(json.dumps(generate(**args), ensure_ascii=False, sort_keys=True))
