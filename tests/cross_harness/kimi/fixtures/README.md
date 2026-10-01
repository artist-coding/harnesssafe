# Kimi trace fixture provenance

`kimi_0_26_0_wire_static_redacted.jsonl` is a redacted synthetic fixture
derived from the installed `@moonshot-ai/kimi-code` 0.26.0 wire record shapes.
It is not output from an authenticated Kimi model run and is not evidence that
any runtime capability is supported.

The fixture deliberately combines directly shaped Kimi wire records with two
explicit adapter observations:

- `adapter.file_hash_observed` binds a successful `Read` call to an exact hash;
- `adapter.artifact_handoff` records an orchestrator-observed stage boundary.

These adapter records may be emitted only by a future run-local capture layer.
They are not inferred from assistant prose and are kept visibly distinct from
Kimi-native events.

The installed 0.26.0 bundle's `normalizeToolResult` representation omits
`isError` for success and emits boolean `true` for an error. The parser accepts
that omission only for the reviewed version and binary SHA-256, accepts a
boolean when present, and rejects every non-boolean value. The synthetic fixture spells success as
`false` so the status is visually explicit; it is still compatible with the
same wire contract.

`kimi_0_26_0_local_runtime_probe.json` is a redacted evidence bundle from
credential-free, loopback-only runs against a deterministic local OpenAI-style
fixture provider. It is not a benchmark result and contains no model response,
system prompt, MCP payload body, or credential value. The bundle retains only
native event shapes, timestamps, correlation/session/agent identifiers, raw
locators, line counts, and SHA-256 digests.

The capability loader pins this bundle to both Kimi Code `0.26.0` and the exact
resolved executable SHA-256. A version mismatch, binary mismatch, fixture
integrity change, or drift in the tested MCP proxy implementation fails closed
to `UNVALIDATED`.

Session compaction has two independent native observations in the bundle. The
automatic lifecycle establishes the persisted event shape. A second probe ran
`kimi acp` over stdio NDJSON, loaded an exact existing session with
`session/resume`, sent `/compact <instruction>` through `session/prompt`,
observed the native
command advertisement and successful prompt response, and correlated them with
`full_compaction.begin` (`source=manual`), `llm.request`
(`kind=compaction`), `context.apply_compaction`, and
`full_compaction.complete`. Only summary and request-body SHA-256 values are
retained. The ACP auth gate used a run-local dummy token against a loopback
fixture; no external credential or token value is present in the bundle.

The bundle also retains negative isolation evidence. In a credential-free
loopback probe, a native Kimi `Bash` child reported that
`KIMI_MODEL_API_KEY` was present in its inherited environment. It returned only
the classification `PRESENT`, never the value. Consequently, relocating Kimi's
home/config directories or constructing a run-local environment is not a
credential boundary. Formal credentialed execution must keep real provider
credentials outside Kimi (for example, in a run-scoped loopback broker) and
expose only a dummy token to the Kimi process.

Artifact hash provenance is a reviewed composite surface, not a Kimi-native
hash event. Exact-binary loopback probes establish correlated successful
native `Read` and `Write` calls with resolved run-local paths. The pinned
direct-evidence observer and Event IR normalizer then require a per-run
observation over the actual file bytes: a `Read` hash is correlated by call id
and path, while an overwrite `Write` additionally requires the request content
digest to equal the resulting file digest. Numbered `Read` output and
natural-language `Write` results are never treated as the artifact hash. Any
drift in either production implementation, its pinned regression tests, or
absence of the per-run observation fails closed.

Instruction loading is also a composite proof. The runtime bundle contains
only redacted marker-presence and request/wire digests. Its adapter side is
therefore pinned to the complete request-marker chain: the provider request
observer, the direct-evidence observer, and the Event IR normalizer, plus their
three regression-test files. Removing any component or changing any pinned
byte fails closed; a test pin never substitutes for a production pin.

The MCP evidence distinguishes two surfaces:

- native Kimi wire evidence proves run-local MCP configuration and correlated
  tool call/result tracing;
- the adapter-owned transparent stdio proxy proves server health only after a
  correlated successful `initialize`, a correlated successful `tools/list`,
  and a clean owned child exit are validated for that run.

`mcp.tools_discovered` is recorded as discovery only and is never accepted as
health evidence. The checked-in bundle proves the mechanism exists; every
formal run must still validate its own run-local proxy evidence before emitting
`mcp.server_initialized`.
