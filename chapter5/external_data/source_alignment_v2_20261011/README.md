# Source alignment v2

Read [report.md](report.md) for the changes and their practical limits. No training, model inference/API, reserved-label comparison or scoring occurred.

## Saved inputs and outputs

- CTID source archive (actual filename **ctid-source-inputs.zip**): exact original CTID CSV and dated KEV JSON, source Git objects, checksums and Apache2 licenses.
- **source-aligned-candidates-v2.zip**:12 members including9 output files, protocol, domain evidence and verification receipt. It contains1736 candidates/856 external Train candidates,619 overlap views,73 source-resolution records,20 UNKNOWN pairs and2 quarantined records.
- delivery.json: package SHA256, size and counts.
- checks.json/checks/: actual RED/GREEN and regression evidence.
- verification.json: independent source-pointer, role, metadata, arithmetic, repeat and rejection checks.
- original-completion-verification.json: original36 units/23 source and failed gate still bound; no checkpoint or model rank replay.

Large output JSONL files are persisted inside the candidate ZIP, rather than duplicated in Git. Extract the ZIP to a fresh directory to inspect outputs/records.jsonl, author-aligned-overlap.jsonl, resolutions.jsonl, negative-exclusions.json and their manifest. The local working output directory is not required for delivery; all its bytes are in the ZIP. Keep the original bytes and create a fresh output directory when rebuilding.

The complete original source package is retained as provenance input, including mappings outside our sample roles. The program selects only the original880 development IDs and858 registered external IDs **before technique extraction**; no reserved labels are compared or scored. Fold protection identifiers are retained only in the role registry.

## Reproduce

Use Python3.12 and existing repository graph modules. The data scripts need no Torch forward pass or model fitting. Current workspace commands (all exit0):

```bash
PYTHONPATH=chapter5_integrated/source python -m unittest discover -s chapter5_integrated/source/chapter5/external_data/source_alignment_v2_20261011 -p test_alignment.py

PYTHONHASHSEED=0 PYTHONPATH=chapter5_integrated/source python chapter5_integrated/source/chapter5/external_data/source_alignment_v2_20261011/alignment.py --old chapter5_preprocess/inputs/public-potential-v1.zip --enriched CVE2ATTCK_background_enriched_20261011.zip --runtime chapter5_integrated/source/chapter5/expanded_dev/data/paired-parent-v1.zip --comparison chapter5_integrated/completed/comparison.json --author chapter5_preprocess/outputs/normalized-cves.jsonl --review chapter5_preprocess/outputs/development-label-review.jsonl --sources chapter5_integrated/source/chapter5/external_data/source_alignment_v2_20261011/ctid-source-inputs.zip --output NEW_OUTPUT_DIR

PYTHONPATH=chapter5_integrated/source python chapter5_integrated/source/chapter5/external_data/source_alignment_v2_20261011/verify.py --old chapter5_preprocess/inputs/public-potential-v1.zip --enriched CVE2ATTCK_background_enriched_20261011.zip --runtime chapter5_integrated/source/chapter5/expanded_dev/data/paired-parent-v1.zip --comparison chapter5_integrated/completed/comparison.json --author chapter5_preprocess/outputs/normalized-cves.jsonl --review chapter5_preprocess/outputs/development-label-review.jsonl --sources chapter5_integrated/source/chapter5/external_data/source_alignment_v2_20261011/ctid-source-inputs.zip --output NEW_OUTPUT_DIR --receipt NEW_RECEIPT.json

ATEN_CPU_CAPABILITY=avx2 PYTHONPATH=chapter5_integrated/source chapter5_integrated/venv/bin/python chapter5_integrated/source/scripts/verify_chapter5_expansion_completion_v1.py --repo chapter5_integrated/source --inputs chapter5_integrated/completed --receipt NEW_BINDING_RECEIPT.json
```

Original graph package: chapter5/public_data/data/public-potential-v1.zip. Enriched background package: chapter5/external_data/cve2attack_background_v1/delivery.json. Original paired runtime package: chapter5/expanded_dev/data/paired-parent-v1.zip. Bound comparison: chapter5/expanded_dev/runs/chapter5-expanded-dev-v1-20261011/comparison.json. Frozen author normalization/review: chapter5/external_data/cve2attack_v1/ input/output artifacts. Existing package manifests explain reconstruction where source files are split/base64 encoded. The CLI accepts arbitrary local file paths; it rejects byte mismatches.

Additional regression commands and actual test counts are in checks.json. Final checks9 source alignment＋19 author preprocessing＋10 original graph data=38. Independent verifier repeats generation (9 files byte-identical), verifies evidence pointers against the full original source bytes and runs2 negative probes; both rejected with exit1. Benign absent-NumPy warning appears when importing the installed Torch runtime for original data/binding checks.

## Future use boundary

Canonical source agreement is not complete semantic truth or human IAA.20 author-only labels remain UNKNOWN. The exported exclusion table must be honored by future negative sampling and a declared evaluation policy; the frozen v1 model engine has not been modified to consume it. The source-aligned package is an independent data version and has no new scientific training registration. The original failed development gate is unchanged.

The619 overlap IDs were already excluded from additional Train; their alignment does not itself change the finished model comparison. Domain quarantine removes only2 known source conflicts.856 remaining external annotations and92 CWE source disputes are not newly adjudicated by this work. Statistical distribution differences remain; no new MRR is claimed.

