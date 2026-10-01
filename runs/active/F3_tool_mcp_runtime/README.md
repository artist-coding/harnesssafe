# tool_mcp_runtime

Tool / MCP poisoning cases for the Idea v2 persistent harness poisoning benchmark.

This suite follows the paper-level chain:

```text
Untrusted Tool/MCP entry
  -> persistent / semi-persistent carrier
  -> delayed benign trigger across a harness boundary
  -> capability-level violation
```

All active cases are `persistent_core` cases. Same-session/runtime-only attacks are useful as low-threshold baselines, but they do not support the core persistent poisoning claim and are not the organizing principle for this suite.

Layer 2 attack methods merge local Tool and MCP cases by attack path. Memory, workspace, registry cache, and schema cache are carriers or boundaries, not separate F3 method names.

See `docs/f3_persistent_core_case_matrix.md` for the generated per-case matrix.

Directory layout mirrors these vectors:

```text
f301_rii/
f302_rdp/
f303_elp/
f304_hpae/
f305_dsp/
f306_tcs/
f307_csc/
f308_xth/
f309_mrp/
f310_ptp/
f311_srcp/
```
