"""Fail-closed validators for Cross-Harness Contract v1.

The JSON schemas under docs/ are the portable format. These validators add
cross-field and repository-integrity checks that JSON Schema cannot express
cleanly, while keeping the contract usable without a new runtime dependency.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping


TARGET_HARNESSES = frozenset(
    {"claude", "codex", "gemini", "opencode", "kimi", "hermes", "openclaw"}
)
BINDING_SUPPORT_STATUSES = frozenset(
    {"supported", "conditional", "unsupported", "unvalidated"}
)
CAPABILITY_STATUSES = frozenset({"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"})
EXECUTION_OUTCOMES = frozenset(
    {"NOT_RUN", "SCORED", "EXECUTION_INVALID", "MODEL_PROTOCOL_INCOMPLETE"}
)
PROGRESS_NODES = frozenset({"N0", "N1", "N2", "N3", "N4", "N5a", "N5b"})

CAPABILITIES = frozenset(
    {
        "headless_execution",
        "structured_trace",
        "workspace_isolation",
        "instruction_loading",
        "skill_discovery",
        "skill_activation_trace",
        "mcp_configuration",
        "mcp_health_trace",
        "mcp_tool_trace",
        "fresh_process",
        "durable_memory_write",
        "durable_memory_retrieval",
        "session_resume",
        "session_compaction",
        "subagent_delegation",
        "artifact_hash_provenance",
        "control_isolation",
    }
)
EVENT_TYPES = frozenset(
    {
        "instruction.loaded",
        "skill.discovered",
        "skill.activated",
        "mcp.server_initialized",
        "mcp.tool_requested",
        "mcp.tool_result",
        "file.read",
        "file.write",
        "memory.written",
        "memory.retrieved",
        "session.started",
        "session.compacted",
        "session.resumed",
        "agent.spawned",
        "agent.completed",
        "artifact.handoff",
    }
)

_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_BINDING_REQUIRED = frozenset(
    {
        "schema_name",
        "schema_version",
        "case_id",
        "case_meta_sha256",
        "semantic_surface",
        "surface_class",
        "required_capabilities",
        "supported_harnesses",
        "comparison_group",
        "binding_version",
        "harness_native_binding",
    }
)
_EVENT_REQUIRED = frozenset(
    {
        "schema_name",
        "schema_version",
        "event_id",
        "event_type",
        "run_id",
        "case_id",
        "harness",
        "stage",
        "sequence",
        "timestamp",
        "source",
        "attributes",
    }
)


class ContractValidationError(ValueError):
    """Raised when a cross-harness contract fails closed."""


def _fail(path: str, message: str) -> None:
    raise ContractValidationError(f"{path}: {message}")


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(path, "must be an object")
    return value


def _string(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if not allow_empty and not value.strip():
        _fail(path, "must not be empty")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(path, "must be an integer")
    if value < minimum:
        _fail(path, f"must be >= {minimum}")
    return value


def _unique_strings(
    value: Any,
    path: str,
    *,
    allowed: frozenset[str] | None = None,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    if not value and not allow_empty:
        _fail(path, "must not be empty")
    result: list[str] = []
    for index, item in enumerate(value):
        item_value = _string(item, f"{path}[{index}]")
        if allowed is not None and item_value not in allowed:
            _fail(f"{path}[{index}]", f"unknown value {item_value!r}")
        result.append(item_value)
    if len(set(result)) != len(result):
        _fail(path, "must contain unique values")
    return tuple(result)


def _exact_keys(
    value: Mapping[str, Any],
    path: str,
    *,
    required: frozenset[str],
    allowed: frozenset[str],
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - allowed)
    if missing:
        _fail(path, f"missing required keys: {', '.join(missing)}")
    if extra:
        _fail(path, f"unknown keys: {', '.join(extra)}")


def _identifier(value: Any, path: str) -> str:
    result = _string(value, path)
    if not _IDENTIFIER_RE.fullmatch(result):
        _fail(path, "must be a lowercase dotted/snake identifier")
    return result


def _sha256(value: Any, path: str) -> str:
    result = _string(value, path)
    if not _SHA256_RE.fullmatch(result):
        _fail(path, "must be a lowercase SHA-256 hex digest")
    return result


def validate_binding_document(document: Mapping[str, Any]) -> None:
    """Validate one case's versioned cross-harness binding document."""

    root = _mapping(document, "$")
    _exact_keys(
        root,
        "$",
        required=_BINDING_REQUIRED,
        allowed=_BINDING_REQUIRED | {"notes"},
    )
    if root["schema_name"] != "safety_bench_cross_harness_binding":
        _fail("$.schema_name", "must equal safety_bench_cross_harness_binding")
    if root["schema_version"] != 1:
        _fail("$.schema_version", "must equal 1")
    _string(root["case_id"], "$.case_id")
    _sha256(root["case_meta_sha256"], "$.case_meta_sha256")
    _identifier(root["semantic_surface"], "$.semantic_surface")
    if root["surface_class"] not in {"common", "native", "neutral"}:
        _fail("$.surface_class", "must be common, native, or neutral")
    _unique_strings(
        root["required_capabilities"],
        "$.required_capabilities",
        allowed=CAPABILITIES,
    )
    _identifier(root["comparison_group"], "$.comparison_group")
    _integer(root["binding_version"], "$.binding_version", minimum=1)

    support = _mapping(root["supported_harnesses"], "$.supported_harnesses")
    if set(support) != TARGET_HARNESSES:
        _fail(
            "$.supported_harnesses",
            "must declare exactly claude, codex, gemini, opencode, kimi, "
            "hermes, and openclaw",
        )
    for harness_id, raw_entry in support.items():
        path = f"$.supported_harnesses.{harness_id}"
        entry = _mapping(raw_entry, path)
        _exact_keys(
            entry,
            path,
            required=frozenset({"status", "rationale"}),
            allowed=frozenset({"status", "rationale", "conformance_profile"}),
        )
        if entry["status"] not in BINDING_SUPPORT_STATUSES:
            _fail(f"{path}.status", f"unknown status {entry['status']!r}")
        _string(entry["rationale"], f"{path}.rationale")
        if "conformance_profile" in entry:
            _identifier(entry["conformance_profile"], f"{path}.conformance_profile")

    native_bindings = _mapping(
        root["harness_native_binding"], "$.harness_native_binding"
    )
    unknown_bindings = sorted(set(native_bindings) - TARGET_HARNESSES)
    if unknown_bindings:
        _fail(
            "$.harness_native_binding",
            f"unknown harness bindings: {unknown_bindings}",
        )
    for harness_id, raw_binding in native_bindings.items():
        path = f"$.harness_native_binding.{harness_id}"
        binding = _mapping(raw_binding, path)
        _exact_keys(
            binding,
            path,
            required=frozenset(
                {"adapter", "variant_kind", "config", "expected_event_types"}
            ),
            allowed=frozenset(
                {
                    "adapter",
                    "variant_kind",
                    "config",
                    "expected_event_types",
                    "artifact_bindings",
                }
            ),
        )
        _identifier(binding["adapter"], f"{path}.adapter")
        if binding["variant_kind"] not in {"native", "neutral"}:
            _fail(f"{path}.variant_kind", "must be native or neutral")
        _mapping(binding["config"], f"{path}.config")
        _unique_strings(
            binding["expected_event_types"],
            f"{path}.expected_event_types",
            allowed=EVENT_TYPES,
        )
        if "artifact_bindings" in binding:
            _mapping(binding["artifact_bindings"], f"{path}.artifact_bindings")

    for harness_id, support_entry in support.items():
        if (
            support_entry["status"] in {"supported", "conditional"}
            and harness_id not in native_bindings
        ):
            _fail(
                "$.harness_native_binding",
                f"{harness_id} status requires a binding",
            )


def _validate_timestamp(value: Any, path: str) -> None:
    raw = _string(value, path)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        _fail(path, f"must be RFC 3339 compatible: {exc}")
    if parsed.tzinfo is None:
        _fail(path, "must include a timezone")


def _validate_artifact(value: Any, path: str) -> None:
    artifact = _mapping(value, path)
    _exact_keys(
        artifact,
        path,
        required=frozenset({"path", "sha256"}),
        allowed=frozenset({"path", "sha256", "operation"}),
    )
    _string(artifact["path"], f"{path}.path")
    _sha256(artifact["sha256"], f"{path}.sha256")
    if "operation" in artifact and artifact["operation"] not in {
        "read",
        "write",
        "handoff",
    }:
        _fail(f"{path}.operation", "must be read, write, or handoff")


def _validate_tool(value: Any, path: str) -> Mapping[str, Any]:
    tool = _mapping(value, path)
    allowed = frozenset(
        {
            "server",
            "name",
            "call_id",
            "arguments_sha256",
            "result_sha256",
            "status",
        }
    )
    extra = sorted(set(tool) - allowed)
    if extra:
        _fail(path, f"unknown keys: {', '.join(extra)}")
    for key in ("server", "name", "call_id", "status"):
        if key in tool:
            _string(tool[key], f"{path}.{key}")
    for key in ("arguments_sha256", "result_sha256"):
        if key in tool:
            _sha256(tool[key], f"{path}.{key}")
    return tool


def _validate_memory(value: Any, path: str) -> None:
    memory = _mapping(value, path)
    _exact_keys(
        memory,
        path,
        required=frozenset({"store", "scope", "entry_id", "sha256"}),
        allowed=frozenset({"store", "scope", "entry_id", "sha256"}),
    )
    for key in ("store", "scope", "entry_id"):
        _string(memory[key], f"{path}.{key}")
    _sha256(memory["sha256"], f"{path}.sha256")


def validate_event_document(document: Mapping[str, Any]) -> None:
    """Validate one normalized cross-harness event."""

    root = _mapping(document, "$")
    _exact_keys(
        root,
        "$",
        required=_EVENT_REQUIRED,
        allowed=_EVENT_REQUIRED
        | {
            "session_id",
            "agent_id",
            "parent_agent_id",
            "tool",
            "artifact",
            "memory",
        },
    )
    if root["schema_name"] != "safety_bench_cross_harness_event":
        _fail("$.schema_name", "must equal safety_bench_cross_harness_event")
    if root["schema_version"] != 1:
        _fail("$.schema_version", "must equal 1")
    event_id = _string(root["event_id"], "$.event_id")
    if not _EVENT_ID_RE.fullmatch(event_id):
        _fail("$.event_id", "contains unsupported characters or is too long")
    event_type = _string(root["event_type"], "$.event_type")
    if event_type not in EVENT_TYPES:
        _fail("$.event_type", f"unknown event type {event_type!r}")
    _string(root["run_id"], "$.run_id")
    _string(root["case_id"], "$.case_id")
    _integer(root["sequence"], "$.sequence")
    _validate_timestamp(root["timestamp"], "$.timestamp")

    harness = _mapping(root["harness"], "$.harness")
    _exact_keys(
        harness,
        "$.harness",
        required=frozenset({"id", "version", "feature_flags"}),
        allowed=frozenset({"id", "version", "feature_flags"}),
    )
    if harness["id"] not in TARGET_HARNESSES:
        _fail("$.harness.id", f"unknown harness {harness['id']!r}")
    _string(harness["version"], "$.harness.version")
    flags = _mapping(harness["feature_flags"], "$.harness.feature_flags")
    for flag_name, flag_value in flags.items():
        _string(flag_name, "$.harness.feature_flags key")
        if (
            not isinstance(flag_value, (bool, str, int, float))
            or isinstance(flag_value, complex)
        ):
            _fail(f"$.harness.feature_flags.{flag_name}", "must be a JSON scalar")

    stage = _mapping(root["stage"], "$.stage")
    _exact_keys(
        stage,
        "$.stage",
        required=frozenset({"name", "index"}),
        allowed=frozenset({"name", "index"}),
    )
    _string(stage["name"], "$.stage.name")
    _integer(stage["index"], "$.stage.index")
    source = _mapping(root["source"], "$.source")
    _exact_keys(
        source,
        "$.source",
        required=frozenset({"trace_path", "line", "raw_event_type"}),
        allowed=frozenset({"trace_path", "line", "raw_event_type"}),
    )
    _string(source["trace_path"], "$.source.trace_path")
    _integer(source["line"], "$.source.line", minimum=1)
    _string(source["raw_event_type"], "$.source.raw_event_type")
    attributes = _mapping(root["attributes"], "$.attributes")

    for key in ("session_id", "agent_id", "parent_agent_id"):
        if key in root and root[key] is not None:
            _string(root[key], f"$.{key}")
    tool = _validate_tool(root["tool"], "$.tool") if "tool" in root else None
    if "artifact" in root:
        _validate_artifact(root["artifact"], "$.artifact")
    if "memory" in root:
        _validate_memory(root["memory"], "$.memory")

    if event_type == "instruction.loaded":
        _string(attributes.get("path"), "$.attributes.path")
        _sha256(attributes.get("sha256"), "$.attributes.sha256")
    if event_type in {"skill.discovered", "skill.activated"}:
        _string(attributes.get("skill_name"), "$.attributes.skill_name")
        _sha256(attributes.get("skill_sha256"), "$.attributes.skill_sha256")
    if event_type == "mcp.server_initialized":
        if tool is None or not tool.get("server"):
            _fail("$.tool.server", "is required for mcp.server_initialized")
        if attributes.get("status") not in {"connected", "failed"}:
            _fail("$.attributes.status", "must be connected or failed")
    if event_type in {"mcp.tool_requested", "mcp.tool_result"}:
        if tool is None:
            _fail("$.tool", f"is required for {event_type}")
        for key in ("server", "name", "call_id"):
            if not tool.get(key):
                _fail(f"$.tool.{key}", f"is required for {event_type}")
        if event_type == "mcp.tool_result" and tool.get("status") not in {
            "success",
            "error",
        }:
            _fail("$.tool.status", "must be success or error for mcp.tool_result")
    if event_type in {"file.read", "file.write", "artifact.handoff"}:
        if "artifact" not in root:
            _fail("$.artifact", f"is required for {event_type}")
    if event_type in {"memory.written", "memory.retrieved"} and "memory" not in root:
        _fail("$.memory", f"is required for {event_type}")
    if event_type.startswith("session.") and not root.get("session_id"):
        _fail("$.session_id", f"is required for {event_type}")
    if event_type == "session.compacted":
        pre_tokens = _integer(
            attributes.get("pre_tokens"), "$.attributes.pre_tokens", minimum=1
        )
        post_tokens = _integer(
            attributes.get("post_tokens"), "$.attributes.post_tokens", minimum=0
        )
        if pre_tokens <= post_tokens:
            _fail("$.attributes", "compaction must reduce token count")
        _sha256(attributes.get("summary_sha256"), "$.attributes.summary_sha256")
    if event_type.startswith("agent.") and not root.get("agent_id"):
        _fail("$.agent_id", f"is required for {event_type}")
    if event_type == "agent.spawned" and not root.get("parent_agent_id"):
        _fail("$.parent_agent_id", "is required for agent.spawned")


def _safe_repo_case_dir(value: Any, path: str) -> PurePosixPath:
    raw = _string(value, path)
    case_dir = PurePosixPath(raw)
    if case_dir.is_absolute() or ".." in case_dir.parts:
        _fail(path, "must be a safe repository-relative path")
    if len(case_dir.parts) < 3 or case_dir.parts[:2] != ("runs", "active"):
        _fail(path, "must be under runs/active")
    return case_dir


def validate_smoke_inventory(
    document: Mapping[str, Any],
    *,
    repo_root: Path | None = None,
) -> None:
    """Validate the frozen Codex conformance smoke inventory."""

    root = _mapping(document, "$")
    required = frozenset(
        {
            "schema_name",
            "schema_version",
            "inventory_id",
            "harness_id",
            "binding_contract_version",
            "event_ir_version",
            "target_case_count",
            "summary",
            "cases",
        }
    )
    _exact_keys(root, "$", required=required, allowed=required | {"notes"})
    if root["schema_name"] != "safety_bench_conformance_smoke_inventory":
        _fail("$.schema_name", "invalid smoke inventory schema_name")
    if root["schema_version"] != 1:
        _fail("$.schema_version", "must equal 1")
    _identifier(root["inventory_id"], "$.inventory_id")
    if root["harness_id"] != "codex":
        _fail("$.harness_id", "Contract v1 smoke inventory must target codex")
    if root["binding_contract_version"] != 1:
        _fail("$.binding_contract_version", "must equal 1")
    if root["event_ir_version"] != 1:
        _fail("$.event_ir_version", "must equal 1")
    target_count = _integer(root["target_case_count"], "$.target_case_count", minimum=1)
    cases = root["cases"]
    if not isinstance(cases, list):
        _fail("$.cases", "must be an array")
    if len(cases) != target_count:
        _fail("$.cases", f"must contain exactly {target_count} cases")
    if not 12 <= len(cases) <= 16:
        _fail("$.cases", "must contain 12-16 cases")

    seen_ids: set[str] = set()
    seen_dirs: set[str] = set()
    surface_counts: Counter[str] = Counter()
    selection_counts: Counter[str] = Counter()
    case_required = frozenset(
        {
            "case_id",
            "case_dir",
            "case_meta_sha256",
            "suite",
            "surface_class",
            "comparison_group",
            "expected_binding_class",
            "selection_status",
            "purpose",
            "required_capabilities",
            "required_event_types",
            "blocking_issues",
        }
    )
    for index, raw_case in enumerate(cases):
        path = f"$.cases[{index}]"
        case = _mapping(raw_case, path)
        _exact_keys(case, path, required=case_required, allowed=case_required)
        case_id = _string(case["case_id"], f"{path}.case_id")
        case_dir = _safe_repo_case_dir(case["case_dir"], f"{path}.case_dir")
        digest = _sha256(case["case_meta_sha256"], f"{path}.case_meta_sha256")
        _string(case["suite"], f"{path}.suite")
        if case["surface_class"] not in {"common", "native"}:
            _fail(f"{path}.surface_class", "must be common or native")
        _identifier(case["comparison_group"], f"{path}.comparison_group")
        if case["expected_binding_class"] not in {"D", "M", "N/A"}:
            _fail(f"{path}.expected_binding_class", "must be D, M, or N/A")
        if case["selection_status"] not in {
            "selected",
            "conditional",
            "blocked_contract",
        }:
            _fail(f"{path}.selection_status", "invalid selection status")
        _string(case["purpose"], f"{path}.purpose")
        _unique_strings(
            case["required_capabilities"],
            f"{path}.required_capabilities",
            allowed=CAPABILITIES,
        )
        _unique_strings(
            case["required_event_types"],
            f"{path}.required_event_types",
            allowed=EVENT_TYPES,
            allow_empty=True,
        )
        blocking_issues = _unique_strings(
            case["blocking_issues"],
            f"{path}.blocking_issues",
            allow_empty=True,
        )
        if case["selection_status"] == "blocked_contract" and not blocking_issues:
            _fail(f"{path}.blocking_issues", "must explain blocked_contract")
        if case["selection_status"] == "selected" and blocking_issues:
            _fail(f"{path}.blocking_issues", "selected cases cannot be blocked")
        if case_id in seen_ids or str(case_dir) in seen_dirs:
            _fail(path, "case_id and case_dir must be unique")
        seen_ids.add(case_id)
        seen_dirs.add(str(case_dir))
        surface_counts[case["surface_class"]] += 1
        selection_counts[case["selection_status"]] += 1

        if repo_root is not None:
            meta_path = repo_root / Path(*case_dir.parts) / "case_meta.json"
            if not meta_path.is_file():
                _fail(f"{path}.case_dir", f"missing {meta_path}")
            raw = meta_path.read_bytes()
            observed_digest = hashlib.sha256(raw).hexdigest()
            if observed_digest != digest:
                _fail(
                    f"{path}.case_meta_sha256",
                    f"stale digest: observed {observed_digest}",
                )
            meta = json.loads(raw)
            if meta.get("case_id") != case_id:
                _fail(
                    f"{path}.case_id",
                    f"does not match case_meta.json value {meta.get('case_id')!r}",
                )

    summary = _mapping(root["summary"], "$.summary")
    expected_summary = {
        "total": len(cases),
        "common": surface_counts["common"],
        "native": surface_counts["native"],
        "selected": selection_counts["selected"],
        "conditional": selection_counts["conditional"],
        "blocked_contract": selection_counts["blocked_contract"],
    }
    if dict(summary) != expected_summary:
        _fail("$.summary", f"must equal derived summary {expected_summary}")
