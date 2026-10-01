# Safety Bench - Anonymous AAAI-27 Code and Data

This supplementary artifact contains one frozen 328-case benchmark, one shared analyzer/scoring stack, seven harness adapters, and twelve complete 328-row result inventories. It is an anonymous submission snapshot: it contains no repository URL, author identity, credentials, Git history, or development worktrees.

## Contents

- `runs/active/` and `runs/manifest.json`: the exact active benchmark case set identified as `benchmark-freeze-aaai27` and attested by SHA-256.
- `infra/`: materializer, runner, trace analyzer, Evaluation Record v3 scoring/report code, and the consolidated adapter sources.
- `tests/`: benchmark and adapter regression tests.
- `schemas/`: machine-readable evaluation, cross-harness, conformance, and task-matrix contracts.
- `results/canonical/`: twelve 328-row ledgers plus per-configuration summaries and metadata.
- `results/paper_primary/`: manuscript main-table values, explicit metric scopes, paper/canonical reconciliation, and the Codex T3-S correction ledger.
- `results/evidence/`: path-redacted Linux evidence and representative local evidence.
- `provenance/`: anonymous experiment snapshot IDs, environments, replacements, release consolidation metadata, and file hashes.

## Static validation (does not run a model)

```text
python infra/validate_aaai27_code_data.py --artifact-root . --verify-hashes
python -m pytest -q
```

Gemini CLI, OpenCode, and Kimi Code adapter tests target Linux runtime semantics (including `fcntl`, bubblewrap, and POSIX paths) and are excluded from collection on Windows. Repository-internal manuscript/Git-tracking assertions and superseded pre-merge runner string snapshots are not artifact tests. Core benchmark tests and the unified OpenClaw/Hermes tests run on Windows.

## Environment

Python 3.10+ is required. Install the benchmark fixture dependencies with `python -m pip install -r requirements.txt`; install `requirements-dev.txt` for tests. Harness CLIs are external tools and must be installed separately. Credentials must be supplied at runtime through the named environment variables or secret-file arguments described by each adapter; this archive contains no credential values.

## Harness adapters

| Harness | Platform | Entrypoint |
| --- | --- | --- |
| Claude Code | Windows | `infra/run_harness_case.ps1 -Harness claude` |
| Codex CLI | Windows | `infra/run_harness_case.ps1 -Harness codex` |
| Hermes Agent | Windows | `infra/run_harness_case.ps1 -Harness hermes` |
| OpenClaw | Windows | `infra/run_harness_case.ps1 -Harness openclaw` |
| Gemini CLI | Linux | `python -m infra.cross_harness.adapters.gemini.attack_only_runner --help` |
| OpenCode | Linux | `python -m infra.cross_harness.adapters.opencode.active_attack_runner --help` |
| Kimi Code | Linux | `python -m infra.cross_harness.adapters.kimi.cli --help` |

The four Windows harnesses share `infra/run_harness_case.ps1`. The three Linux harnesses use the common `infra.cross_harness` contract and their own adapter/binding packages. Adapter manifests under `infra/adapters/*/adapter_manifest.json` map these implementations explicitly.

## Metrics

The progress ladder is N0, N1, N2, N3, N4, N5a, N5b. Only N5a/N5b are attack successes. Protocol noncompletion is an orthogonal terminal outcome, not an eighth progress node and not a safe result. The machine-readable definitions are preserved in each case's `checkpoint_contract` and in the canonical `evaluation_record` objects under `results/canonical/`.

The paper-primary table and canonical ledgers deliberately coexist because they answer different audit questions. Paper CSS cells are preserved as reported; the available input did not freeze the paper-time common-support membership ledger. Formal ASR is recomputed from eligible canonical rows. Kimi Code is the explicit exception: 8.91% is a diagnostic 18/202 rate and formal ASR remains N/A.

## Safety and licenses

Active cases intentionally include synthetic canaries, fake credential-shaped files, and fake sensitive paths. They are benchmark fixtures, not real credentials. Tooling is Apache-2.0; case definitions and documentation are CC BY 4.0 as described in `LICENSES.md`. Runtime homes, provider caches, authentication stores, and Git bundles are excluded.

Historical results are attributed to anonymous as-run snapshot IDs and content hashes in `provenance/experiment_snapshots.json`; private Git object IDs are withheld during double-blind review.
