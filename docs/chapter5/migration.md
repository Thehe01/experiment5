# Chapter5 migration from experiment4

Source: `Thehe01/experiment4@f30dc71bb0ca0980546b875a108f5725b4ca39db`.
The old migration used `54e9d7ab12e71511ebcb54a5e5e03d352935f6a3` and omitted
479 newer Chapter5 paths. All 571 files in the latest source `chapter5/` tree
are now preserved byte for byte.

`chapter5/` is the only implementation and evidence layout. Duplicate
normalization copies from commit `3bdad32` were removed and remain recoverable
through Git history. Code, data, configuration and scientific registration
files keep their source paths and original hashes.

Additional source files include eight Chapter5 execution workflows, two Chapter5
audit scripts, three analysis documents, `EXPERIMENT_PLAN.md`, 217 inherited
inputs required by `chapter5.verify`, and the registered C4 archive manifest.
Other experiment5 data already present before this migration is retained and is
not part of the latest Chapter5 source manifest.
The 217 inputs are 84 Train/Dev Gold files, 130 source inventory files and three
split/exposure/freeze metadata files. Chapter4 Test Gold files and unrelated
Chapter4 runtime implementations are excluded.

[migration-source-manifest.json](migration-source-manifest.json) records the
source Git blob, SHA-256 and size of all 802 imported source files, plus the 479
paths missing from the old migration. Verification checks the complete inventory,
11 state manifests and 114 parts, the nine completed checkpoint archives,
the recovered nine checkpoint receipts, and the 144 diagnostic score caches
and their complete evidence ZIP. Hashes are compared to the manifest, without
rewriting scientific registrations, resetting ledgers or running new scientific
model forwards.

## Local validation

Use Python 3.12.14 and the pinned CPU runtime:

```bash
python -m pip install -r chapter5/requirements-cpu.txt
python -m pip install -r chapter5/public_data/requirements.txt
export ATEN_CPU_CAPABILITY=avx2
export OMP_NUM_THREADS=2
export MKL_NUM_THREADS=2
export PYTHONDONTWRITEBYTECODE=1
python scripts/verify_chapter5_migration.py
python -m chapter5.verify
python -m unittest discover -s chapter5 -t . -p 'test_*.py'
python -m chapter5.context_pool_dev.campaign verify --repo .
python -m chapter5.context_pool_recovery_20261012.recovery verify --repo .
python -m chapter5.diagnostics.resolved_v3_replay_20261012.runner validate --repo .
python -m chapter5.resolved_dev.verify --repo . --receipt /tmp/chapter5-resolved-verification.json
python scripts/verify_chapter5_migration.py
```

The behavior tests use synthetic fixtures. The package rebuild and evidence
checks do not start scientific training or consume diagnostic forward budgets.

## GitHub Actions

`chapter5-migration-verify.yml` is the verification workflow for experiment5
`main`, migration branches and pull requests. It has read-only repository
permissions and runs the checks above.

The eight imported execution workflows are frozen historical evidence. Their
original registration hashes are preserved. They reference experiment4
activation branches, and some original runners enforce the experiment4 repository
identity or fetch historical commits that are absent from experiment5 history.
They are not experiment5 training launchers. A future experiment5 training or
scientific replay needs its own explicit registration and execution setup;
completed ledgers and historical forward budgets remain authoritative.

Migration acceptance validates the existing bytes and reproducible offline
checks. GitHub hosted job results and a newly published cloud snapshot are
separate operations; local validation does not establish either one.
