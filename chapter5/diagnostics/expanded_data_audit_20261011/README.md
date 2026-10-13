# Expanded-source audit v1

Read-only audit after completed development run38134213784. Results and decisions: [report.md](report.md).

No training, model inference/API, metadata refresh, reserved-label comparison or scoring. Uses standard Python library and frozen graph construction modules only; audit.py independently implements baseline formulas and filtered/CVE-macro evaluation.

## Inputs

| Input | Frozen source location |
|---|---|
| Old public package | chapter5/public_data/data/public-potential-v1.zip |
| Enriched858 package | chapter5/external_data/cve2attack_background_v1/delivery.json and its package parts |
| Runtime paired package | chapter5/expanded_dev/data/paired-parent-v1.zip |
| Finished comparison | chapter5/expanded_dev/runs/chapter5-expanded-dev-v1-20261011/comparison.json |
| Author preprocessing outputs/CSV | chapter5/external_data/cve2attack_v1/ and its input artifacts; assemble the CLI directory structure outputs/, work/, inputs/cve2attack_original/ |

Actual bytes are pinned by protocol.json and preprocessing manifest; no fresh source download/normalization is substituted. The metadata-rich input is needed for source-disagreement statistics. Files above may require reconstructing previously saved package parts as documented in their delivery manifests.

## Commands used in this workspace

Run from /workspace/scratch/740249c3d03b. Python3.12.14; no numeric dependencies needed for audit.py or verify.py. Default output is protected from overwrite.

```bash
PYTHONHASHSEED=0 PYTHONPATH=chapter5_integrated/source python chapter5_integrated/source/chapter5/diagnostics/expanded_data_audit_20261011/audit.py --old chapter5_preprocess/inputs/public-potential-v1.zip --enriched CVE2ATTCK_background_enriched_20261011.zip --runtime chapter5_integrated/source/chapter5/expanded_dev/data/paired-parent-v1.zip --comparison chapter5_integrated/completed/comparison.json --preprocess chapter5_preprocess --output chapter5_integrated/source/chapter5/diagnostics/expanded_data_audit_20261011/results

PYTHONPATH=chapter5_integrated/source python chapter5_integrated/source/chapter5/diagnostics/expanded_data_audit_20261011/verify.py --old chapter5_preprocess/inputs/public-potential-v1.zip --enriched CVE2ATTCK_background_enriched_20261011.zip --runtime chapter5_integrated/source/chapter5/expanded_dev/data/paired-parent-v1.zip --comparison chapter5_integrated/completed/comparison.json --preprocess chapter5_preprocess --output chapter5_integrated/source/chapter5/diagnostics/expanded_data_audit_20261011/results --receipt chapter5_integrated/source/chapter5/diagnostics/expanded_data_audit_20261011/artifact-verification.json

ATEN_CPU_CAPABILITY=avx2 PYTHONPATH=chapter5_integrated/source chapter5_integrated/venv/bin/python chapter5_integrated/source/scripts/verify_chapter5_expansion_completion_v1.py --repo chapter5_integrated/source --inputs chapter5_integrated/completed --receipt chapter5_integrated/source/chapter5/diagnostics/expanded_data_audit_20261011/completion-binding-verification.json
```

All3 commands exit0. Last command uses the already installed frozen CPU runtime (Torch2.9.1+cpu); AVX2 mirrors registered workflow. It performs binding/summary/source checks, no fitting or model forward pass. Benign absent-NumPy warning does not affect those checks.

verify.py additionally runs one exact repeat (all4 output files byte identical) and2 negative probes (tampered comparison bytes and existing output overwrite; both exit1). Original input SHA256 unchanged. Verification receipts record the script/protocol/output hashes.

## Outputs

- results/analysis.json: cohorts,31-class shifts,11 common-CWE distributions,6fold graphs,36baseline replays, saved model summaries.
- results/overlap-label-review.jsonl:73 unadjudicated unique CVEs,619 overlap denominator; variant-aware.
- results/neighbor-vote-decomposition.jsonl:450 repeated Dev occurrences/237unique CVEs; both sources' votes, ranks, background contributions.
- results/verification.json: source and output bindings.
- artifact-verification.json: separate arithmetic/protection/repeat/rejection check.
- completion-binding-verification.json: unchanged36model unit/23source and gate verification; no checkpoint/raw model rank replay.

The audit script reads frozen data and writes only a new output directory. It does not import Torch/model code. An existing runtime graph builder is reused to reproduce the registered inputs; baseline scores and metric aggregation are reimplemented independently. Graph reproduction does not make dataset labels complete or valid final Test labels.

