"""Read-only verification of the imported source bytes and completed evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile


SOURCE_COMMIT = "f30dc71bb0ca0980546b875a108f5725b4ca39db"
DUPLICATE_PATHS = (
    "configs/chapter5", "data/raw/chapter5",
    "data/processed/chapter5-v1-20261010", "scripts/chapter5",
    "reports/chapter5", "results/chapter5-v1-20261010",
)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_path(root: Path, name: str) -> Path:
    relative = Path(name)
    check(not relative.is_absolute() and ".." not in relative.parts,
          f"unsafe path: {name}")
    path = root / relative
    check(path.resolve().is_relative_to(root.resolve()), f"path escapes repository: {name}")
    return path


def verify(repo: Path) -> dict:
    manifest = read(repo / "docs/chapter5/migration-source-manifest.json")
    check(manifest["source_commit"] == SOURCE_COMMIT, "unexpected migration source")
    source_paths = set(manifest["files"])
    for name, expected in manifest["files"].items():
        path = safe_path(repo, name)
        check(path.is_file(), f"missing imported file: {name}")
        raw = path.read_bytes()
        check(len(raw) == expected["bytes"], f"imported size mismatch: {name}")
        check(digest(raw) == expected["sha256"], f"imported SHA-256 mismatch: {name}")
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        check(blob == expected["git_blob_sha1"], f"source Git blob mismatch: {name}")
    actual_chapter5 = {
        path.relative_to(repo).as_posix()
        for path in (repo / "chapter5").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    expected_chapter5 = {name for name in source_paths if name.startswith("chapter5/")}
    check(actual_chapter5 == expected_chapter5, "Chapter5 file inventory changed")
    check(len(expected_chapter5) == 571, "latest Chapter5 inventory must contain 571 files")
    check(len(manifest["changed_chapter5_paths"]) == 479, "latest delta must contain 479 paths")
    for name in DUPLICATE_PATHS:
        check(not (repo / name).exists(), f"duplicate layout remains: {name}")

    part_manifests = parts_checked = 0
    for path in (repo / "chapter5").rglob("manifest.json"):
        value = read(path)
        if "parts" not in value:
            continue
        aggregate = hashlib.sha256()
        size = 0
        part_names = set()
        for part in value["parts"]:
            check(part["path"] not in part_names, f"duplicate archive part: {path}")
            part_names.add(part["path"])
            body = safe_path(path.parent, part["path"]).read_bytes()
            check(len(body) == part["bytes"] and digest(body) == part["sha256"],
                  f"archive part mismatch: {path}/{part['path']}")
            aggregate.update(body)
            size += len(body)
            parts_checked += 1
        check(size == value["source_bytes"] and
              aggregate.hexdigest() == value["source_sha256"],
              f"assembled state archive mismatch: {path}")
        part_manifests += 1

    candidate = repo / "chapter5/context_pool_recovery_20261012"
    evidence = read(candidate / "results/evidence-manifest.json")
    archive = candidate / "results/complete-evidence.zip"
    check(archive.stat().st_size == evidence["archive_bytes"] and
          digest(archive.read_bytes()) == evidence["archive_sha256"], "candidate evidence ZIP mismatch")
    with zipfile.ZipFile(archive) as bundle:
        check(bundle.testzip() is None, "candidate ZIP CRC mismatch")
        names = bundle.namelist()
        check(len(names) == len(set(names)), "duplicate candidate ZIP members")
        state_names = {name for name in names if name.startswith("units/")}
        check(state_names == set(evidence["state_files"]), "candidate ZIP state inventory mismatch")
        for name, expected in evidence["state_files"].items():
            body = bundle.read(name)
            check(len(body) == expected["bytes"] and digest(body) == expected["sha256"],
                  f"candidate state mismatch: {name}")
        checkpoints = sum(name.endswith("/checkpoint.pt") for name in state_names)
        check(checkpoints == evidence["checkpoint_count"] == 9, "candidate checkpoint count mismatch")
    recovery_ledger = read(candidate / "ledger.json")
    check(recovery_ledger["state"] == "complete", "candidate recovery ledger incomplete")
    check(all(row["status"] == "done" for row in recovery_ledger["units"].values()),
          "candidate training units incomplete")
    for uid, row in recovery_ledger["checkpoint_replays"].items():
        receipt_path = candidate / "receipts" / f"{uid}-replay.json"
        check(row["status"] == "done" and digest(receipt_path.read_bytes()) == row["receipt_sha256"],
              f"checkpoint receipt mismatch: {uid}")
        check(read(receipt_path)["max_score_error"] == 0, f"checkpoint replay mismatch: {uid}")

    diagnosis = repo / "chapter5/diagnostics/resolved_v3_replay_20261012"
    evidence = read(diagnosis / "manifest.json")
    archive = diagnosis / "complete-evidence.zip"
    check(archive.stat().st_size == evidence["archive_bytes"] and
          digest(archive.read_bytes()) == evidence["archive_sha256"], "diagnosis evidence ZIP mismatch")
    with zipfile.ZipFile(archive) as bundle:
        check(bundle.testzip() is None, "diagnosis ZIP CRC mismatch")
        names = bundle.namelist()
        check(len(names) == len(set(names)) == evidence["archive_members"], "diagnosis ZIP inventory mismatch")
        check(set(names) == set(evidence["files"]), "diagnosis ZIP manifest inventory mismatch")
        for name, expected in evidence["files"].items():
            body = bundle.read(name)
            check(len(body) == expected["bytes"] and digest(body) == expected["sha256"],
                  f"diagnosis evidence member mismatch: {name}")
    ledger = read(diagnosis / "ledger.json")
    check(ledger["state"] == "complete" and len(ledger["actions"]) == 144,
          "diagnosis ledger incomplete")
    check((ledger["historical_forward_consumed"], ledger["additional_consumed"],
           ledger["cumulative_consumed"]) == (144, 144, 288), "diagnosis forward accounting changed")
    for aid, row in ledger["actions"].items():
        cache = diagnosis / "scores" / f"{aid}.json"
        check(row["status"] == "done" and digest(cache.read_bytes()) == row["cache_sha256"],
              f"diagnosis score cache mismatch: {aid}")
    return {
        "result": "passed", "source_commit": SOURCE_COMMIT,
        "source_files_verified": len(source_paths), "chapter5_files": len(expected_chapter5),
        "latest_chapter5_delta": 479, "state_manifests": part_manifests,
        "state_parts": parts_checked, "candidate_checkpoints": checkpoints,
        "diagnostic_caches": 144, "historical_forward_consumed": 144,
        "additional_forward_consumed": 144, "new_training_runs": 0,
        "new_model_forwards": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(verify(args.repo), indent=2))


if __name__ == "__main__":
    main()
