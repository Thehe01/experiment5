# Experiment5

## Overview

Independent experimental repository.

Chapter5 is imported from `Thehe01/experiment4` at
`f30dc71bb0ca0980546b875a108f5725b4ca39db`. The canonical implementation,
datasets, checkpoints and evidence are under `chapter5/`. The inherited inputs
under `data/` include 217 files consumed by the Chapter5 preflight; existing
experiment data already present in experiment5 remains preserved. The additional
`results/` manifest is an immutable source binding. The migration removed the
duplicated copies under `configs/chapter5/`, `data/processed/`,
`scripts/chapter5/`, `reports/chapter5/` and `results/chapter5-v1-20261010/`.

See [migration verification and provenance](docs/chapter5/migration.md) for
commands and the distinction between the current verification workflow and the
eight frozen historical execution workflows.

This repository is separated from experiment4 to avoid:

- mixed experiment history
- branch pollution
- unclear reproducibility state

## Experiment Management

The experiment state is maintained by:

```
EXPERIMENT_STATE.yaml
```

It is the only recovery entry point for future sessions.

## Structure

```
.
├── EXPERIMENT_STATE.yaml
├── docs/
├── configs/
├── data/
├── scripts/
├── src/
├── artifacts/
└── evaluations/
```

## Rules

1. One experiment corresponds to one repository.
2. Do not rewrite frozen results.
3. Every experiment stage must update state.
4. Temporary branches should be archived or deleted.
