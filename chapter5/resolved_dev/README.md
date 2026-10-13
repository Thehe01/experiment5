# Chapter 5 v3 paired source-resolved development

Independent namespace and registration; old scientific files and runs remain frozen.

Offline preparation (no scientific fitting):
```bash
ATEN_CPU_CAPABILITY=avx2 python -m unittest chapter5.resolved_dev.test_data chapter5.resolved_dev.test_campaign chapter5.resolved_dev.test_archive chapter5.public_dev.test_core chapter5.public_dev.test_model -q
ATEN_CPU_CAPABILITY=avx2 python -m chapter5.resolved_dev.campaign prepare --repo .
ATEN_CPU_CAPABILITY=avx2 python -m chapter5.resolved_dev.verify --repo . --receipt /tmp/v3-verify.json
```

Workflow: `.github/workflows/chapter5-resolved-dev.yml`; activation `codex/chapter5-resolved-activation-20261011`. Actual runs are fixed to 36 units and three 240-minute resumable CPU slots. No reserved evaluation route or external model API.

Read spec.md for admission, partial-label semantics, fixed development comparisons and limits. Input artifacts are bound by SHA256 and registration source inventory. Candidate package is not an independent human-label accuracy certificate.
