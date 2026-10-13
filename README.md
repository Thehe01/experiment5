# Experiment5

## Overview

Independent experimental repository.

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
