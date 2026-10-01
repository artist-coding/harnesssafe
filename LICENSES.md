# License Mapping

This repository uses a split-license layout for the HarnessSafe experiment framework and the retained Safety Bench artifact.
The root `LICENSE` contains the Apache License 2.0 and applies to source code,
runner scripts, tests, and other executable tooling unless a more specific
mapping below applies.

## Path-Level Mapping

| Paths | License |
| --- | --- |
| `harnesssafe/`, `infra/`, `tests/`, configuration examples, PowerShell runners, Python utilities, repository scripts, and source-code fixtures | Apache License 2.0 |
| `docs/`, generated paper tables, generated summary reports, paper figures, benchmark cards, and public case-study evidence summaries | Creative Commons Attribution 4.0 International |
| `runs/manifest.json`, `runs/active/**/case_meta.json`, task prompts, case metadata, and non-executable benchmark case definitions | Creative Commons Attribution 4.0 International |
| Executable mock servers, tool/MCP fixtures, plugins, and scripts inside benchmark cases | Apache License 2.0 |
| Sanitized files copied into `runs/_artifacts/repro_bundles/` | Same license as the copied source path; generated summaries and tables are CC BY 4.0 |
| Raw traces, honeypot logs, canary-bearing artifacts, local agent homes, credentials, and unpublished run outputs | Not part of the public release unless explicitly included in a sanitized release bundle |

The CC BY 4.0 legal code is available at
https://creativecommons.org/licenses/by/4.0/legalcode.en.

## Responsible-Use Notice

Safety Bench includes adversarial prompts, persistent-poisoning fixtures, and
mock tool/MCP payloads for controlled security evaluation of agent harnesses.
The license grants above do not change the user's responsibility to comply with
applicable law, platform rules, institutional policy, and authorization
boundaries. Do not run benchmark payloads against systems you do not own or do
not have explicit permission to test.

## Attribution

When citing or reusing the benchmark, cite the final `CITATION.cff` metadata
once the public repository URL, artifact URL or DOI, version, release date, and
author list have been finalized.
