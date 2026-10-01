"""Kimi Code capability evidence and fail-closed aggregation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from ...contract import CAPABILITIES, CAPABILITY_STATUSES


_REPO_ROOT = Path(__file__).resolve().parents[4]
RUNTIME_EVIDENCE_FIXTURE = (
    _REPO_ROOT
    / "tests"
    / "cross_harness"
    / "kimi"
    / "fixtures"
    / "kimi_0_26_0_local_runtime_probe.json"
)
RUNTIME_EVIDENCE_FIXTURE_SHA256 = (
    "832cf470bb2e45fe2f3cb188f0cd79b63d0353cbb9a0ffa851e6e7c502951f4a"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INSTRUCTION_IMPLEMENTATION_PINS: Mapping[str, str] = {
    "direct_evidence_observer": (
        "infra/cross_harness/adapters/kimi/execution_observer.py"
    ),
    "provider_request_observer": (
        "infra/cross_harness/adapters/kimi/provider_broker.py"
    ),
    "event_ir_normalizer": "infra/cross_harness/adapters/kimi/trace.py",
}
_INSTRUCTION_TEST_PINS: Mapping[str, str] = {
    "direct_evidence_observer": (
        "tests/cross_harness/kimi/test_execution_observer.py"
    ),
    "provider_request_observer": "tests/cross_harness/kimi/test_provider_broker.py",
    "event_ir_normalizer": "tests/cross_harness/kimi/test_trace.py",
}
_ARTIFACT_IMPLEMENTATION_PINS: Mapping[str, str] = {
    "direct_evidence_observer": (
        "infra/cross_harness/adapters/kimi/execution_observer.py"
    ),
    "event_ir_normalizer": "infra/cross_harness/adapters/kimi/trace.py",
}
_ARTIFACT_TEST_PINS: Mapping[str, str] = {
    "direct_evidence_observer": (
        "tests/cross_harness/kimi/test_execution_observer.py"
    ),
    "event_ir_normalizer": "tests/cross_harness/kimi/test_trace.py",
}
_RUNTIME_CLAIMS: Mapping[str, tuple[str, ...]] = {
    "headless_execution": ("headless_structured_resume",),
    "structured_trace": ("headless_structured_resume",),
    "instruction_loading": ("native_instruction_loading",),
    "skill_discovery": ("skill_discovery_activation",),
    "skill_activation_trace": ("skill_discovery_activation",),
    "mcp_configuration": ("mcp_configuration_tool_trace",),
    "mcp_health_trace": ("adapter_mcp_health_proxy",),
    "mcp_tool_trace": ("mcp_configuration_tool_trace",),
    "session_resume": ("headless_structured_resume",),
    "session_compaction": ("native_compaction",),
    "subagent_delegation": ("native_subagent",),
    "artifact_hash_provenance": ("adapter_artifact_hash_provenance",),
}
_RUNTIME_DETAILS: Mapping[str, str] = {
    "headless_execution": (
        "A loopback-only deterministic provider probe completed prompt mode with exit "
        "code 0 without interactive input."
    ),
    "structured_trace": (
        "The exact Kimi binary persisted timestamped JSONL wire records and emitted "
        "stream-json output in a local runtime probe."
    ),
    "instruction_loading": (
        "A loopback request observer directly confirmed that an inert marker from the "
        "run-local .kimi-code/AGENTS.md was present in Kimi's model request; only "
        "marker and artifact SHA-256 values are retained."
    ),
    "skill_discovery": (
        "A run with an explicit skill directory exposed the fixture skill to the "
        "native Skill tool and completed its correlated call."
    ),
    "skill_activation_trace": (
        "The native wire contains context.append_message with a skill_activation "
        "origin, activation id, native skill path, and trigger."
    ),
    "mcp_configuration": (
        "The exact binary loaded a run-local mcp.json and exposed the configured "
        "stdio fixture tool."
    ),
    "mcp_health_trace": (
        "The run-scoped transparent stdio proxy can prove correlated initialize and "
        "tools/list success plus a clean owned child exit. Every run must still pass "
        "post-run health evidence validation; mcp.tools_discovered is never sufficient."
    ),
    "mcp_tool_trace": (
        "The native wire contains a correlated MCP tool.call/tool.result pair with "
        "one call id."
    ),
    "session_resume": (
        "Two successful prompt-mode processes used the same native session id; the "
        "second request appended to the same wire with a larger message context."
    ),
    "session_compaction": (
        "The native wire contains begin/request/apply/complete compaction records "
        "with a non-empty summary and directly observed token reduction. An "
        "independent ACP /compact probe also resumed an exact native session and "
        "recorded source=manual through the same lifecycle."
    ),
    "subagent_delegation": (
        "Native session state records a child agent with parent main, while separate "
        "parent and child wires record the Agent call/result and subagent trigger."
    ),
    "artifact_hash_provenance": (
        "Exact-binary probes contain correlated successful native Read and Write "
        "events with resolved run-local paths. The pinned adapter hashes file bytes "
        "at the execution observation boundary, correlates Read by call_id, and for "
        "overwrite Write requires the content digest to equal the written file digest."
    ),
}


class KimiRuntimeEvidenceError(ValueError):
    """A checked-in runtime evidence fixture failed integrity or semantic checks."""


def _runtime_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiRuntimeEvidenceError(f"{label} must be an object")
    return value


def _runtime_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KimiRuntimeEvidenceError(f"{label} must be a non-empty string")
    return value


def _runtime_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise KimiRuntimeEvidenceError(f"{label} must be an integer >= {minimum}")
    return value


def _runtime_sha256(value: Any, label: str) -> str:
    result = _runtime_string(value, label)
    if _SHA256_RE.fullmatch(result) is None:
        raise KimiRuntimeEvidenceError(f"{label} must be a lowercase SHA-256")
    return result


def _validate_exact_repo_pins(
    value: Any,
    label: str,
    *,
    expected_paths: Mapping[str, str],
) -> None:
    """Bind a composite adapter proof to every production/test file it uses."""

    pins = _runtime_mapping(value, label)
    if set(pins) != set(expected_paths):
        raise KimiRuntimeEvidenceError(f"{label} set drifted")
    repository = _REPO_ROOT.resolve()
    for component, expected_path in expected_paths.items():
        pin = _runtime_mapping(pins.get(component), f"{label} {component}")
        if set(pin) != {"path", "sha256"}:
            raise KimiRuntimeEvidenceError(
                f"{label} {component} fields drifted"
            )
        relative = Path(
            _runtime_string(pin.get("path"), f"{label} {component} path")
        )
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != expected_path
        ):
            raise KimiRuntimeEvidenceError(
                f"{label} {component} path drifted"
            )
        source = (_REPO_ROOT / relative).resolve()
        try:
            source.relative_to(repository)
        except ValueError as exc:
            raise KimiRuntimeEvidenceError(
                f"{label} {component} escapes the repository"
            ) from exc
        try:
            observed_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            raise KimiRuntimeEvidenceError(
                f"{label} {component} is unavailable"
            ) from exc
        expected_sha256 = _runtime_sha256(
            pin.get("sha256"), f"{label} {component} SHA-256"
        )
        if observed_sha256 != expected_sha256:
            raise KimiRuntimeEvidenceError(
                f"{label} {component} bytes drifted from runtime evidence"
            )


def _validate_runtime_evidence_document(document: Mapping[str, Any]) -> frozenset[str]:
    """Validate proof shapes without treating prose or model output as evidence."""

    if document.get("schema_name") != "safety_bench_kimi_local_runtime_probe":
        raise KimiRuntimeEvidenceError("unexpected runtime evidence schema_name")
    if document.get("schema_version") != 1:
        raise KimiRuntimeEvidenceError("unexpected runtime evidence schema_version")
    if document.get("scored_benchmark_run") is not False:
        raise KimiRuntimeEvidenceError("runtime fixture must not claim a scored run")
    if document.get("external_credentials_used") is not False:
        raise KimiRuntimeEvidenceError("runtime fixture must be credential-free")
    if document.get("network_scope") != "loopback_only":
        raise KimiRuntimeEvidenceError("runtime fixture must be loopback-only")
    if document.get("provider") != "deterministic_local_openai_fixture":
        raise KimiRuntimeEvidenceError("runtime fixture provider is not deterministic")

    redaction = _runtime_mapping(document.get("redaction"), "redaction")
    for key in ("model_text_copied", "system_prompt_copied", "credential_value_copied"):
        if redaction.get(key) is not False:
            raise KimiRuntimeEvidenceError(f"redaction.{key} must be false")

    proofs = _runtime_mapping(document.get("proofs"), "proofs")
    if set(proofs) != {
        "headless_structured_resume",
        "skill_discovery_activation",
        "native_instruction_loading",
        "mcp_configuration_tool_trace",
        "adapter_mcp_health_proxy",
        "native_compaction",
        "native_subagent",
        "adapter_artifact_hash_provenance",
    }:
        raise KimiRuntimeEvidenceError("runtime evidence proof set drifted")

    resume = _runtime_mapping(proofs["headless_structured_resume"], "resume proof")
    if resume.get("kind") != "native_session_continuity":
        raise KimiRuntimeEvidenceError("resume proof kind drifted")
    if resume.get("initial_exit_code") != 0 or resume.get("resume_exit_code") != 0:
        raise KimiRuntimeEvidenceError("headless probes did not both exit successfully")
    if resume.get("output_format") != "stream-json":
        raise KimiRuntimeEvidenceError("headless probe lacks stream-json output")
    _runtime_string(resume.get("session_id"), "resume session_id")
    resume_wire = _runtime_mapping(resume.get("wire"), "resume wire")
    before_lines = _runtime_integer(
        resume_wire.get("before_resume_line_count"), "before resume line count", minimum=1
    )
    after_lines = _runtime_integer(
        resume_wire.get("after_resume_line_count"), "after resume line count", minimum=1
    )
    if after_lines <= before_lines:
        raise KimiRuntimeEvidenceError("resume did not append native wire records")
    _runtime_sha256(resume_wire.get("before_resume_sha256"), "pre-resume wire")
    _runtime_sha256(resume_wire.get("after_resume_sha256"), "post-resume wire")
    initial_request = _runtime_mapping(
        resume_wire.get("initial_request"), "initial request"
    )
    resumed_request = _runtime_mapping(
        resume_wire.get("resumed_request"), "resumed request"
    )
    if (
        initial_request.get("type") != "llm.request"
        or resumed_request.get("type") != "llm.request"
    ):
        raise KimiRuntimeEvidenceError("resume proof lacks native llm.request records")
    if initial_request.get("kind") != "loop" or resumed_request.get("kind") != "loop":
        raise KimiRuntimeEvidenceError("resume request kinds drifted")
    if _runtime_integer(
        resumed_request.get("message_count"), "resumed message count"
    ) <= _runtime_integer(
        initial_request.get("message_count"), "initial message count"
    ):
        raise KimiRuntimeEvidenceError("resume did not increase observed message context")

    skill = _runtime_mapping(proofs["skill_discovery_activation"], "skill proof")
    if skill.get("kind") != "native_skill_activation":
        raise KimiRuntimeEvidenceError("skill proof kind drifted")
    skill_call = _runtime_mapping(skill.get("tool_call"), "skill tool call")
    discovery = _runtime_mapping(skill.get("discovery"), "skill discovery")
    activation = _runtime_mapping(skill.get("activation"), "skill activation")
    skill_result = _runtime_mapping(skill.get("tool_result"), "skill tool result")
    if (
        skill_call.get("event_type") != "tool.call"
        or skill_call.get("tool_name") != "Skill"
        or discovery.get("type") != "config.update"
        or discovery.get("field") != "systemPrompt"
        or discovery.get("listing_contains_exact_skill_name_and_path") is not True
        or activation.get("type") != "context.append_message"
        or activation.get("origin_kind") != "skill_activation"
        or activation.get("trigger") != "model-tool"
        or skill_result.get("event_type") != "tool.result"
        or skill_call.get("tool_call_id") != skill_result.get("tool_call_id")
        or skill_call.get("skill_name") != activation.get("skill_name")
    ):
        raise KimiRuntimeEvidenceError("skill activation correlation is incomplete")
    _runtime_string(activation.get("activation_id"), "skill activation id")
    _runtime_sha256(
        discovery.get("system_prompt_sha256"), "skill-list system prompt SHA-256"
    )
    _runtime_sha256(activation.get("skill_sha256"), "skill SHA-256")
    _runtime_sha256(
        _runtime_mapping(skill.get("wire"), "skill wire").get("sha256"),
        "skill wire SHA-256",
    )

    instruction = _runtime_mapping(
        proofs["native_instruction_loading"], "instruction loading proof"
    )
    if (
        instruction.get("kind") != "native_project_instruction_loading"
        or instruction.get("exit_code") != 0
    ):
        raise KimiRuntimeEvidenceError("instruction loading probe did not complete")
    _runtime_string(instruction.get("run_id"), "instruction probe run id")
    _runtime_string(instruction.get("session_id"), "instruction probe session id")
    instruction_file = _runtime_mapping(
        instruction.get("instruction"), "instruction artifact"
    )
    request_observer = _runtime_mapping(
        instruction.get("request_observer"), "instruction request observer"
    )
    instruction_wire = _runtime_mapping(instruction.get("wire"), "instruction wire")
    instruction_sha = _runtime_sha256(
        instruction_file.get("sha256"), "instruction artifact SHA-256"
    )
    marker_sha = _runtime_sha256(
        instruction_file.get("marker_sha256"), "instruction marker SHA-256"
    )
    marker_offset = _runtime_integer(
        instruction_file.get("marker_offset"), "instruction marker offset"
    )
    marker_length = _runtime_integer(
        instruction_file.get("marker_length"),
        "instruction marker length",
        minimum=1,
    )
    byte_length = _runtime_integer(
        instruction_file.get("byte_length"), "instruction byte length", minimum=1
    )
    if marker_offset + marker_length > byte_length:
        raise KimiRuntimeEvidenceError("instruction marker bounds are invalid")
    if (
        request_observer.get("expected_substring_present") is not True
        or request_observer.get("expected_substring_sha256") != marker_sha
        or request_observer.get("message_roles") != ["system", "user", "user"]
    ):
        raise KimiRuntimeEvidenceError(
            "instruction request observer lacks direct marker evidence"
        )
    for value, label in (
        (request_observer.get("sha256"), "instruction observer SHA-256"),
        (request_observer.get("request_body_sha256"), "model request body SHA-256"),
        (instruction_wire.get("sha256"), "instruction wire SHA-256"),
    ):
        _runtime_sha256(value, label)
    _runtime_integer(request_observer.get("line"), "instruction observer line", minimum=1)
    _runtime_integer(instruction_wire.get("line_count"), "instruction wire line count", minimum=1)
    _runtime_integer(
        instruction_wire.get("llm_request_line"), "instruction LLM request line", minimum=1
    )
    _runtime_string(
        instruction_file.get("captured_path"), "instruction artifact locator"
    )
    _runtime_string(
        request_observer.get("captured_path"), "instruction observer locator"
    )
    _runtime_string(instruction_wire.get("captured_path"), "instruction wire locator")
    if instruction_sha == marker_sha:
        raise KimiRuntimeEvidenceError(
            "instruction marker digest must remain distinct from the full artifact digest"
        )
    _validate_exact_repo_pins(
        instruction.get("adapter_implementation_pins"),
        "instruction adapter implementation pins",
        expected_paths=_INSTRUCTION_IMPLEMENTATION_PINS,
    )
    _validate_exact_repo_pins(
        instruction.get("adapter_test_pins"),
        "instruction adapter test pins",
        expected_paths=_INSTRUCTION_TEST_PINS,
    )

    mcp = _runtime_mapping(proofs["mcp_configuration_tool_trace"], "MCP proof")
    if mcp.get("kind") != "native_mcp_tool_call":
        raise KimiRuntimeEvidenceError("MCP proof kind drifted")
    _runtime_sha256(
        _runtime_mapping(mcp.get("run_local_config"), "MCP config").get("sha256"),
        "MCP config SHA-256",
    )
    _runtime_sha256(
        _runtime_mapping(mcp.get("wire"), "MCP wire").get("sha256"),
        "MCP wire SHA-256",
    )
    discovered = _runtime_mapping(mcp.get("tools_discovered"), "MCP discovery")
    call = _runtime_mapping(mcp.get("tool_call"), "MCP tool call")
    result = _runtime_mapping(mcp.get("tool_result"), "MCP tool result")
    if (
        discovered.get("type") != "mcp.tools_discovered"
        or discovered.get("health_evidence") is not False
    ):
        raise KimiRuntimeEvidenceError("MCP discovery must explicitly be non-health evidence")
    if mcp.get("native_health_event_observed") is not False:
        raise KimiRuntimeEvidenceError("fixture must not claim native MCP health")
    if (
        call.get("event_type") != "tool.call"
        or result.get("event_type") != "tool.result"
        or call.get("tool_call_id") != result.get("tool_call_id")
        or not _runtime_string(call.get("tool_name"), "MCP tool name").startswith("mcp__")
    ):
        raise KimiRuntimeEvidenceError("MCP call/result correlation is incomplete")
    _runtime_sha256(call.get("arguments_sha256"), "MCP arguments SHA-256")
    _runtime_sha256(result.get("result_sha256"), "MCP result SHA-256")

    health = _runtime_mapping(proofs["adapter_mcp_health_proxy"], "MCP health proof")
    if health.get("kind") != "adapter_owned_mcp_stdio_health":
        raise KimiRuntimeEvidenceError("MCP health proof kind drifted")
    if health.get("tools_discovered_alone_is_health") is not False:
        raise KimiRuntimeEvidenceError("MCP discovery must not be treated as health")
    if health.get("post_run_validation_required") is not True:
        raise KimiRuntimeEvidenceError("MCP health must require per-run validation")
    result_document = _runtime_mapping(health.get("test_result"), "MCP proxy test result")
    if result_document.get("exit_code") != 0 or _runtime_integer(
        result_document.get("passed"), "MCP proxy passed test count", minimum=1
    ) < 1:
        raise KimiRuntimeEvidenceError("MCP proxy tests did not pass")
    required_health = health.get("required_direct_evidence")
    if required_health != [
        "initialize correlated success",
        "tools/list correlated success",
        "owned child exit code 0",
    ]:
        raise KimiRuntimeEvidenceError("MCP health direct evidence contract drifted")
    native_health = _runtime_mapping(
        health.get("native_kimi_probe"), "native Kimi MCP health probe"
    )
    native_child_exit = _runtime_mapping(
        native_health.get("child_exit"), "native MCP child exit"
    )
    if (
        native_health.get("validated_health_status") != "connected"
        or native_health.get("server") != "deployment-health"
        or _runtime_integer(
            native_child_exit.get("exit_code"), "native MCP child exit code"
        )
        != 0
    ):
        raise KimiRuntimeEvidenceError(
            "native Kimi MCP probe did not validate a clean connected lifecycle"
        )
    _runtime_string(native_health.get("run_id"), "native MCP probe run id")
    _runtime_string(native_health.get("session_id"), "native MCP probe session id")
    _runtime_sha256(
        native_health.get("child_argv_sha256"), "native MCP child argv SHA-256"
    )
    for key, expected_lines in (
        ("initialize", 2),
        ("tools_list", 2),
        ("stdio", 7),
        ("child_exit", 1),
    ):
        evidence_file = _runtime_mapping(
            native_health.get(key), f"native MCP {key} evidence"
        )
        _runtime_string(
            evidence_file.get("captured_path"), f"native MCP {key} locator"
        )
        _runtime_sha256(
            evidence_file.get("sha256"), f"native MCP {key} SHA-256"
        )
        if _runtime_integer(
            evidence_file.get("line_count"),
            f"native MCP {key} line count",
            minimum=1,
        ) != expected_lines:
            raise KimiRuntimeEvidenceError(
                f"native MCP {key} evidence line count drifted"
            )
    native_wire = _runtime_mapping(
        native_health.get("kimi_wire"), "native Kimi MCP wire"
    )
    _runtime_string(native_wire.get("captured_path"), "native Kimi MCP wire locator")
    _runtime_sha256(native_wire.get("sha256"), "native Kimi MCP wire SHA-256")
    for path_key, sha_key, label in (
        ("implementation_path", "implementation_sha256", "MCP proxy implementation"),
        ("test_path", "test_sha256", "MCP proxy test"),
    ):
        relative = Path(_runtime_string(health.get(path_key), f"{label} path"))
        if relative.is_absolute() or ".." in relative.parts:
            raise KimiRuntimeEvidenceError(f"{label} path is not repository-relative")
        expected_sha = _runtime_sha256(health.get(sha_key), f"{label} SHA-256")
        source = (_REPO_ROOT / relative).resolve()
        try:
            source.relative_to(_REPO_ROOT.resolve())
        except ValueError as exc:
            raise KimiRuntimeEvidenceError(f"{label} escapes the repository") from exc
        try:
            observed_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            raise KimiRuntimeEvidenceError(f"{label} is unavailable") from exc
        if observed_sha != expected_sha:
            raise KimiRuntimeEvidenceError(f"{label} bytes drifted from tested evidence")

    compact = _runtime_mapping(proofs["native_compaction"], "compaction proof")
    if compact.get("kind") != "native_session_compaction":
        raise KimiRuntimeEvidenceError("compaction proof kind drifted")
    begin = _runtime_mapping(compact.get("begin"), "compaction begin")
    compact_request = _runtime_mapping(
        compact.get("request"), "compaction request"
    )
    apply = _runtime_mapping(compact.get("apply"), "compaction apply")
    complete = _runtime_mapping(compact.get("complete"), "compaction complete")
    if (
        begin.get("type") != "full_compaction.begin"
        or begin.get("source") != "auto"
        or compact_request.get("type") != "llm.request"
        or compact_request.get("kind") != "compaction"
        or apply.get("type") != "context.apply_compaction"
        or complete.get("type") != "full_compaction.complete"
        or not (
            _runtime_integer(begin.get("line"), "compaction begin line", minimum=1)
            < _runtime_integer(
                compact_request.get("line"), "compaction request line", minimum=1
            )
            < _runtime_integer(apply.get("line"), "compaction apply line", minimum=1)
            < _runtime_integer(complete.get("line"), "compaction complete line", minimum=1)
        )
    ):
        raise KimiRuntimeEvidenceError("compaction lifecycle records are incomplete")
    tokens_before = _runtime_integer(apply.get("tokens_before"), "tokens before", minimum=1)
    tokens_after = _runtime_integer(apply.get("tokens_after"), "tokens after")
    if tokens_before <= tokens_after:
        raise KimiRuntimeEvidenceError("compaction proof lacks token reduction")
    _runtime_sha256(apply.get("summary_sha256"), "compaction summary SHA-256")
    _runtime_sha256(
        _runtime_mapping(compact.get("wire"), "compaction wire").get("sha256"),
        "compaction wire SHA-256",
    )
    _runtime_integer(
        compact_request.get("message_count"),
        "compaction request message count",
        minimum=1,
    )

    manual = _runtime_mapping(compact.get("manual_acp"), "manual ACP compaction")
    if manual.get("kind") != "native_manual_acp_compaction":
        raise KimiRuntimeEvidenceError("manual ACP compaction kind drifted")
    manual_session_id = _runtime_string(
        manual.get("session_id"), "manual ACP session id"
    )
    if manual_session_id != _runtime_string(
        resume.get("session_id"), "resume session_id"
    ):
        raise KimiRuntimeEvidenceError(
            "manual ACP compaction did not load the reviewed native session"
        )
    launch = _runtime_mapping(manual.get("launch"), "manual ACP launch")
    if (
        launch.get("argv") != ["/usr/local/bin/kimi", "acp"]
        or launch.get("transport") != "stdio_ndjson"
        or launch.get("request_sequencing")
        != "flush_then_wait_for_matching_response_id"
        or launch.get("request_timeout_seconds") != 30
        or launch.get("initialize_method") != "initialize"
        or launch.get("resume_method") != "session/resume"
        or launch.get("prompt_method") != "session/prompt"
        or launch.get("command")
        != "/compact preserve-the-existing-summary-and-compact-locally"
    ):
        raise KimiRuntimeEvidenceError("manual ACP launch surface drifted")
    if _runtime_sha256(
        launch.get("command_sha256"), "manual ACP command SHA-256"
    ) != hashlib.sha256(
        b"/compact preserve-the-existing-summary-and-compact-locally"
    ).hexdigest():
        raise KimiRuntimeEvidenceError("manual ACP command digest drifted")
    client_path = Path(
        _runtime_string(launch.get("client_path"), "manual ACP client path")
    )
    if client_path.is_absolute() or ".." in client_path.parts:
        raise KimiRuntimeEvidenceError("manual ACP client path is not repository-relative")
    client_source = (_REPO_ROOT / client_path).resolve()
    try:
        client_source.relative_to(_REPO_ROOT.resolve())
    except ValueError as exc:
        raise KimiRuntimeEvidenceError("manual ACP client escapes the repository") from exc
    try:
        client_sha256 = hashlib.sha256(client_source.read_bytes()).hexdigest()
    except OSError as exc:
        raise KimiRuntimeEvidenceError("manual ACP client is unavailable") from exc
    if client_sha256 != _runtime_sha256(
        launch.get("client_sha256"), "manual ACP client SHA-256"
    ):
        raise KimiRuntimeEvidenceError(
            "manual ACP client bytes drifted from runtime evidence"
        )

    acp_trace = _runtime_mapping(manual.get("acp_trace"), "manual ACP trace")
    stderr = _runtime_mapping(manual.get("stderr"), "manual ACP stderr")
    if (
        _runtime_integer(acp_trace.get("line_count"), "manual ACP trace lines") != 6
        or _runtime_integer(acp_trace.get("exit_code"), "manual ACP exit code") != 0
        or _runtime_integer(stderr.get("line_count"), "manual ACP stderr lines") != 0
    ):
        raise KimiRuntimeEvidenceError("manual ACP process did not complete cleanly")
    _runtime_string(acp_trace.get("captured_path"), "manual ACP trace locator")
    _runtime_string(stderr.get("captured_path"), "manual ACP stderr locator")
    _runtime_sha256(acp_trace.get("sha256"), "manual ACP trace SHA-256")
    if _runtime_sha256(
        stderr.get("sha256"), "manual ACP stderr SHA-256"
    ) != hashlib.sha256(b"").hexdigest():
        raise KimiRuntimeEvidenceError("manual ACP stderr was not empty")

    initialize_request = _runtime_mapping(
        manual.get("initialize_request"), "manual ACP initialize request"
    )
    resume_request = _runtime_mapping(
        manual.get("resume_request"), "manual ACP resume request"
    )
    prompt_request = _runtime_mapping(
        manual.get("prompt_request"), "manual ACP prompt request"
    )
    initialize_response = _runtime_mapping(
        manual.get("initialize_response"), "manual ACP initialize response"
    )
    resume_response = _runtime_mapping(
        manual.get("resume_response"), "manual ACP resume response"
    )
    available_command = _runtime_mapping(
        manual.get("available_command"), "manual ACP available command"
    )
    prompt_response = _runtime_mapping(
        manual.get("prompt_response"), "manual ACP prompt response"
    )
    if (
        initialize_request.get("request_id") != 1
        or initialize_request.get("protocol_version") != 1
        or initialize_request.get("client_capabilities")
        != {
            "fs": {"read_text_file": False, "write_text_file": False},
            "terminal": False,
        }
        or initialize_request.get("client_info")
        != {"name": "safety-bench-kimi-compaction-probe", "version": "1"}
        or resume_request.get("request_id") != 2
        or resume_request.get("method") != "session/resume"
        or resume_request.get("session_id") != manual_session_id
        or resume_request.get("mcp_server_count") != 0
        or prompt_request.get("request_id") != 3
        or prompt_request.get("method") != "session/prompt"
        or prompt_request.get("session_id") != manual_session_id
        or prompt_request.get("content_block_types") != ["text"]
        or prompt_request.get("text_sha256") != launch.get("command_sha256")
        or initialize_response.get("request_id") != 1
        or initialize_response.get("protocol_version") != 1
        or initialize_response.get("agent_version")
        != _runtime_mapping(document.get("identity"), "runtime identity").get("version")
        or initialize_response.get("load_session") is not True
        or resume_response.get("request_id") != 2
        or resume_response.get("config_options_observed") is not True
        or available_command.get("method") != "session/update"
        or available_command.get("session_id") != manual_session_id
        or available_command.get("update") != "available_commands_update"
        or available_command.get("name") != "compact"
        or available_command.get("description") != "Compact the conversation context"
        or prompt_response.get("request_id") != 3
        or prompt_response.get("stop_reason") != "end_turn"
        or not (
            _runtime_integer(
                initialize_response.get("line"), "manual ACP initialize line", minimum=1
            )
            < _runtime_integer(
                resume_response.get("line"), "manual ACP resume line", minimum=1
            )
            < _runtime_integer(
                available_command.get("line"),
                "manual ACP command-advertisement line",
                minimum=1,
            )
            < _runtime_integer(
                prompt_response.get("line"), "manual ACP prompt line", minimum=1
            )
        )
    ):
        raise KimiRuntimeEvidenceError(
            "manual ACP resume/command/prompt correlation is incomplete"
        )

    manual_provider = _runtime_mapping(
        manual.get("provider_request_observer"), "manual ACP provider observer"
    )
    if (
        manual_provider.get("authorization_present") is not True
        or manual_provider.get("credential_kind") != "run_local_dummy_token"
        or manual_provider.get("external_credential") is not False
        or manual_provider.get("credential_value_retained") is not False
        or manual_provider.get("network_scope") != "loopback_only"
    ):
        raise KimiRuntimeEvidenceError(
            "manual ACP provider observer is not credential-safe loopback evidence"
        )
    _runtime_string(
        manual_provider.get("captured_path"), "manual ACP provider locator"
    )
    _runtime_integer(
        manual_provider.get("line"), "manual ACP provider line", minimum=1
    )
    _runtime_sha256(manual_provider.get("sha256"), "manual ACP provider SHA-256")
    _runtime_sha256(
        manual_provider.get("request_body_sha256"),
        "manual ACP provider request body SHA-256",
    )

    manual_wire = _runtime_mapping(manual.get("wire"), "manual compaction wire")
    manual_wire_path = _runtime_string(
        manual_wire.get("captured_path"), "manual compaction wire locator"
    )
    if manual_session_id not in manual_wire_path:
        raise KimiRuntimeEvidenceError(
            "manual compaction wire does not identify the loaded session"
        )
    manual_wire_lines = _runtime_integer(
        manual_wire.get("line_count"), "manual compaction wire lines", minimum=1
    )
    _runtime_sha256(manual_wire.get("sha256"), "manual compaction wire SHA-256")
    manual_begin = _runtime_mapping(manual.get("begin"), "manual compaction begin")
    manual_request = _runtime_mapping(
        manual.get("request"), "manual compaction request"
    )
    manual_apply = _runtime_mapping(manual.get("apply"), "manual compaction apply")
    manual_complete = _runtime_mapping(
        manual.get("complete"), "manual compaction complete"
    )
    manual_begin_line = _runtime_integer(
        manual_begin.get("line"), "manual compaction begin line", minimum=1
    )
    manual_request_line = _runtime_integer(
        manual_request.get("line"), "manual compaction request line", minimum=1
    )
    manual_apply_line = _runtime_integer(
        manual_apply.get("line"), "manual compaction apply line", minimum=1
    )
    manual_complete_line = _runtime_integer(
        manual_complete.get("line"), "manual compaction complete line", minimum=1
    )
    if (
        manual_begin.get("type") != "full_compaction.begin"
        or manual_begin.get("source") != "manual"
        or manual_request.get("type") != "llm.request"
        or manual_request.get("kind") != "compaction"
        or manual_apply.get("type") != "context.apply_compaction"
        or manual_complete.get("type") != "full_compaction.complete"
        or not (
            manual_begin_line
            < manual_request_line
            < manual_apply_line
            < manual_complete_line
            <= manual_wire_lines
        )
    ):
        raise KimiRuntimeEvidenceError(
            "manual native compaction lifecycle is incomplete"
        )
    _runtime_integer(
        manual_request.get("message_count"),
        "manual compaction message count",
        minimum=1,
    )
    manual_tokens_before = _runtime_integer(
        manual_apply.get("tokens_before"), "manual tokens before", minimum=1
    )
    manual_tokens_after = _runtime_integer(
        manual_apply.get("tokens_after"), "manual tokens after"
    )
    if manual_tokens_before <= manual_tokens_after:
        raise KimiRuntimeEvidenceError(
            "manual compaction proof lacks token reduction"
        )
    _runtime_integer(
        manual_apply.get("compacted_count"),
        "manual compacted count",
        minimum=1,
    )
    _runtime_integer(
        manual_apply.get("kept_user_message_count"),
        "manual kept user message count",
    )
    _runtime_sha256(
        manual_apply.get("summary_sha256"), "manual compaction summary SHA-256"
    )

    negative_evidence = _runtime_mapping(
        document.get("negative_evidence"), "negative evidence"
    )
    if set(negative_evidence) != {"tool_process_environment_inheritance"}:
        raise KimiRuntimeEvidenceError("negative evidence set drifted")
    environment_probe = _runtime_mapping(
        negative_evidence["tool_process_environment_inheritance"],
        "tool process environment inheritance",
    )
    if (
        environment_probe.get("kind")
        != "native_tool_process_environment_inheritance"
        or environment_probe.get("environment_variable") != "KIMI_MODEL_API_KEY"
        or environment_probe.get("external_credential_used") is not False
        or environment_probe.get("credential_value_retained") is not False
    ):
        raise KimiRuntimeEvidenceError(
            "tool process environment inheritance evidence drifted"
        )
    environment_session = _runtime_string(
        environment_probe.get("session_id"), "environment probe session id"
    )
    environment_wire = _runtime_mapping(
        environment_probe.get("wire"), "environment probe wire"
    )
    environment_wire_path = _runtime_string(
        environment_wire.get("captured_path"), "environment probe wire locator"
    )
    if (
        environment_session not in environment_wire_path
        or _runtime_integer(
            environment_wire.get("line_count"), "environment probe wire lines"
        )
        != 20
    ):
        raise KimiRuntimeEvidenceError("environment probe wire correlation drifted")
    _runtime_sha256(environment_wire.get("sha256"), "environment wire SHA-256")
    environment_script = _runtime_mapping(
        environment_probe.get("check_script"), "environment check script"
    )
    _runtime_string(
        environment_script.get("captured_path"), "environment check script locator"
    )
    _runtime_sha256(
        environment_script.get("sha256"), "environment check script SHA-256"
    )
    environment_call = _runtime_mapping(
        environment_probe.get("tool_call"), "environment probe tool call"
    )
    environment_result = _runtime_mapping(
        environment_probe.get("tool_result"), "environment probe tool result"
    )
    if (
        environment_call.get("type") != "context.append_loop_event"
        or environment_call.get("event_type") != "tool.call"
        or environment_call.get("tool_name") != "Bash"
        or environment_result.get("type") != "context.append_loop_event"
        or environment_result.get("event_type") != "tool.result"
        or environment_call.get("tool_call_id")
        != environment_result.get("tool_call_id")
        or environment_result.get("result_classification") != "PRESENT"
        or _runtime_integer(
            environment_call.get("line"), "environment tool call line", minimum=1
        )
        >= _runtime_integer(
            environment_result.get("line"), "environment tool result line", minimum=1
        )
    ):
        raise KimiRuntimeEvidenceError(
            "environment inheritance call/result correlation is incomplete"
        )
    _runtime_sha256(
        environment_call.get("arguments_sha256"), "environment arguments SHA-256"
    )
    _runtime_sha256(
        environment_result.get("result_sha256"), "environment result SHA-256"
    )
    environment_provider = _runtime_mapping(
        environment_probe.get("provider_request_observer"),
        "environment provider observer",
    )
    if (
        environment_provider.get("authorization_present") is not True
        or environment_provider.get("credential_value_retained") is not False
        or environment_provider.get("network_scope") != "loopback_only"
        or _runtime_integer(
            environment_provider.get("line_count"),
            "environment provider line count",
        )
        != 2
    ):
        raise KimiRuntimeEvidenceError(
            "environment provider observer is not redacted loopback evidence"
        )
    _runtime_string(
        environment_provider.get("captured_path"),
        "environment provider observer locator",
    )
    _runtime_sha256(
        environment_provider.get("sha256"),
        "environment provider observer SHA-256",
    )
    _runtime_string(
        environment_probe.get("disposition"), "environment probe disposition"
    )

    subagent = _runtime_mapping(proofs["native_subagent"], "subagent proof")
    if subagent.get("kind") != "native_subagent_lifecycle":
        raise KimiRuntimeEvidenceError("subagent proof kind drifted")
    state = _runtime_mapping(subagent.get("state"), "subagent state")
    parent = _runtime_mapping(subagent.get("parent_wire"), "parent wire")
    child = _runtime_mapping(subagent.get("child_wire"), "child wire")
    parent_id = _runtime_string(state.get("parent_agent_id"), "parent agent id")
    child_id = _runtime_string(state.get("child_agent_id"), "child agent id")
    if parent_id == child_id or state.get("child_type") != "sub":
        raise KimiRuntimeEvidenceError("subagent state lacks a distinct child")
    if (
        parent.get("tool_name") != "Agent"
        or parent.get("tool_call_id") is None
        or child.get("trigger_origin_kind") != "system_trigger"
        or child.get("trigger_name") != "subagent"
    ):
        raise KimiRuntimeEvidenceError("subagent wire lifecycle is incomplete")
    for value, label in (
        (state.get("sha256"), "subagent state SHA-256"),
        (parent.get("sha256"), "parent wire SHA-256"),
        (parent.get("handoff_sha256"), "subagent handoff SHA-256"),
        (child.get("sha256"), "child wire SHA-256"),
    ):
        _runtime_sha256(value, label)

    artifact_provenance = _runtime_mapping(
        proofs["adapter_artifact_hash_provenance"],
        "artifact hash provenance proof",
    )
    if (
        artifact_provenance.get("kind") != "native_file_tool_plus_adapter_hash"
        or artifact_provenance.get("per_run_observation_required") is not True
        or artifact_provenance.get("native_result_payload_used_as_file_hash")
        is not False
    ):
        raise KimiRuntimeEvidenceError("artifact provenance proof kind drifted")
    _validate_exact_repo_pins(
        artifact_provenance.get("adapter_implementation_pins"),
        "artifact adapter implementation pins",
        expected_paths=_ARTIFACT_IMPLEMENTATION_PINS,
    )
    _validate_exact_repo_pins(
        artifact_provenance.get("adapter_test_pins"),
        "artifact adapter test pins",
        expected_paths=_ARTIFACT_TEST_PINS,
    )

    artifact_sessions: set[str] = set()
    artifact_observations: dict[str, Mapping[str, Any]] = {}
    for operation, tool_name, expected_hash_source in (
        (
            "read",
            "Read",
            "run_local_file_bytes_immediately_after_correlated_read",
        ),
        ("write", "Write", "write_content_and_run_local_file_bytes"),
    ):
        proof = _runtime_mapping(
            artifact_provenance.get(operation), f"artifact {operation} proof"
        )
        session_id = _runtime_string(
            proof.get("session_id"), f"artifact {operation} session id"
        )
        if session_id in artifact_sessions:
            raise KimiRuntimeEvidenceError(
                "artifact Read and Write probes must use distinct sessions"
            )
        artifact_sessions.add(session_id)
        wire = _runtime_mapping(proof.get("wire"), f"artifact {operation} wire")
        wire_path = _runtime_string(
            wire.get("captured_path"), f"artifact {operation} wire locator"
        )
        if (
            session_id not in wire_path
            or _runtime_integer(
                wire.get("line_count"), f"artifact {operation} wire lines"
            )
            != 20
        ):
            raise KimiRuntimeEvidenceError(
                f"artifact {operation} wire correlation drifted"
            )
        _runtime_sha256(wire.get("sha256"), f"artifact {operation} wire SHA-256")

        tool_call = _runtime_mapping(
            proof.get("tool_call"), f"artifact {operation} tool call"
        )
        tool_result = _runtime_mapping(
            proof.get("tool_result"), f"artifact {operation} tool result"
        )
        if (
            tool_call.get("type") != "context.append_loop_event"
            or tool_call.get("event_type") != "tool.call"
            or tool_call.get("tool_name") != tool_name
            or tool_call.get("display_kind") != "file_io"
            or tool_call.get("display_operation") != operation
            or tool_result.get("type") != "context.append_loop_event"
            or tool_result.get("event_type") != "tool.result"
            or tool_result.get("success_omission") is not True
            or tool_call.get("tool_call_id") != tool_result.get("tool_call_id")
            or _runtime_integer(
                tool_call.get("line"), f"artifact {operation} call line", minimum=1
            )
            >= _runtime_integer(
                tool_result.get("line"),
                f"artifact {operation} result line",
                minimum=1,
            )
        ):
            raise KimiRuntimeEvidenceError(
                f"artifact {operation} native call/result correlation is incomplete"
            )
        _runtime_sha256(
            tool_call.get("arguments_sha256"),
            f"artifact {operation} arguments SHA-256",
        )
        _runtime_sha256(
            tool_result.get("result_sha256"),
            f"artifact {operation} result SHA-256",
        )
        relative_path = Path(
            _runtime_string(
                tool_call.get("arguments_path"),
                f"artifact {operation} relative path",
            )
        )
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise KimiRuntimeEvidenceError(
                f"artifact {operation} arguments path is not run-local"
            )
        resolved_path = Path(
            _runtime_string(
                tool_call.get("resolved_path"),
                f"artifact {operation} resolved path",
            )
        )
        if (
            not resolved_path.is_absolute()
            or resolved_path.parts[-len(relative_path.parts) :] != relative_path.parts
            or not any(
                part.startswith(f"workspace-kimi-artifact-{operation}-")
                for part in resolved_path.parts
            )
        ):
            raise KimiRuntimeEvidenceError(
                f"artifact {operation} resolved path mismatches arguments"
            )

        observation = _runtime_mapping(
            proof.get("adapter_hash_observation"),
            f"artifact {operation} adapter hash observation",
        )
        if (
            observation.get("observation_phase") != "execution"
            or observation.get("path") != relative_path.as_posix()
            or observation.get("is_symlink") is not False
            or observation.get("source") != expected_hash_source
            or _runtime_integer(
                observation.get("byte_length"),
                f"artifact {operation} byte length",
                minimum=1,
            )
            < 1
        ):
            raise KimiRuntimeEvidenceError(
                f"artifact {operation} adapter observation is incomplete"
            )
        _runtime_sha256(
            observation.get("sha256"),
            f"artifact {operation} observed SHA-256",
        )
        artifact_observations[operation] = observation

        provider = _runtime_mapping(
            proof.get("provider_request_observer"),
            f"artifact {operation} provider observer",
        )
        if (
            provider.get("authorization_present") is not True
            or provider.get("credential_kind") != "run_local_dummy_token"
            or provider.get("external_credential") is not False
            or provider.get("credential_value_retained") is not False
            or provider.get("network_scope") != "loopback_only"
            or _runtime_integer(
                provider.get("line_count"),
                f"artifact {operation} provider lines",
            )
            != 2
        ):
            raise KimiRuntimeEvidenceError(
                f"artifact {operation} provider observer is not redacted loopback evidence"
            )
        _runtime_string(
            provider.get("captured_path"),
            f"artifact {operation} provider locator",
        )
        _runtime_sha256(
            provider.get("sha256"),
            f"artifact {operation} provider SHA-256",
        )

    write_call = _runtime_mapping(
        _runtime_mapping(
            artifact_provenance.get("write"), "artifact write proof"
        ).get("tool_call"),
        "artifact write tool call",
    )
    if (
        write_call.get("arguments_mode") != "overwrite"
        or _runtime_integer(
            write_call.get("content_byte_length"),
            "artifact write content length",
            minimum=1,
        )
        != artifact_observations["write"].get("byte_length")
        or _runtime_sha256(
            write_call.get("content_sha256"), "artifact write content SHA-256"
        )
        != artifact_observations["write"].get("sha256")
    ):
        raise KimiRuntimeEvidenceError(
            "artifact Write content does not match adapter-observed file bytes"
        )

    claims = _runtime_mapping(document.get("capability_claims"), "capability claims")
    normalized_claims: dict[str, tuple[str, ...]] = {}
    for capability, proof_ids in claims.items():
        if capability not in CAPABILITIES:
            raise KimiRuntimeEvidenceError(f"unknown runtime capability {capability!r}")
        if not isinstance(proof_ids, list) or not proof_ids or not all(
            isinstance(item, str) for item in proof_ids
        ):
            raise KimiRuntimeEvidenceError(f"invalid proof ids for {capability}")
        normalized_claims[capability] = tuple(proof_ids)
    if normalized_claims != dict(_RUNTIME_CLAIMS):
        raise KimiRuntimeEvidenceError("runtime capability claim mapping drifted")
    if normalized_claims.get("mcp_health_trace") != ("adapter_mcp_health_proxy",):
        raise KimiRuntimeEvidenceError(
            "MCP health may only be claimed by the reviewed adapter proxy"
        )
    return frozenset(normalized_claims)


def load_runtime_supported_capabilities(
    *,
    detected_version: str | None,
    detected_binary_sha256: str | None,
    fixture_path: Path = RUNTIME_EVIDENCE_FIXTURE,
    expected_fixture_sha256: str = RUNTIME_EVIDENCE_FIXTURE_SHA256,
) -> tuple[frozenset[str], str]:
    """Return reviewed runtime claims only for the exact probed binary bytes."""

    try:
        raw = fixture_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_fixture_sha256:
            raise KimiRuntimeEvidenceError("checked-in runtime fixture SHA-256 drifted")
        document = _runtime_mapping(json.loads(raw), "runtime evidence")
        identity = _runtime_mapping(document.get("identity"), "runtime identity")
        version = _runtime_string(identity.get("version"), "runtime version")
        binary_sha256 = _runtime_sha256(
            identity.get("binary_sha256"), "runtime binary SHA-256"
        )
        claims = _validate_runtime_evidence_document(document)
    except (OSError, json.JSONDecodeError, KimiRuntimeEvidenceError) as exc:
        return frozenset(), f"runtime evidence rejected: {exc}"
    if detected_version != version or detected_binary_sha256 != binary_sha256:
        return (
            frozenset(),
            "runtime evidence version/binary SHA-256 does not match the detected Kimi executable",
        )
    return claims, "exact version and binary SHA-256 matched reviewed local runtime evidence"


@dataclass(frozen=True)
class CapabilityEvidence:
    """One version-scoped Kimi capability disposition."""

    capability: str
    status: str
    evidence: tuple[str, ...] = ()
    detail: str = ""

    def __post_init__(self) -> None:
        if self.capability not in CAPABILITIES:
            raise ValueError(f"unknown capability: {self.capability!r}")
        if self.status not in CAPABILITY_STATUSES:
            raise ValueError(f"unknown capability status: {self.status!r}")
        if self.status != "SUPPORTED" and not self.detail.strip():
            raise ValueError(f"{self.status} capability evidence requires detail")
        if not self.evidence:
            raise ValueError("capability evidence requires a raw locator")

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "status": self.status,
            "evidence": list(self.evidence),
            "detail": self.detail,
        }


def default_capability_matrix(
    *,
    executable_found: bool,
    feature_flags: Mapping[str, bool | str | int | float],
    path_lookup_evidence: str,
    help_evidence: str | None,
    isolation_evidence: str,
    detected_version: str | None = None,
    detected_binary_sha256: str | None = None,
    runtime_evidence_path: Path = RUNTIME_EVIDENCE_FIXTURE,
    runtime_evidence_sha256: str = RUNTIME_EVIDENCE_FIXTURE_SHA256,
) -> dict[str, CapabilityEvidence]:
    """Classify adapter-owned and exact-binary runtime-demonstrated surfaces.

    Help text is never sufficient runtime evidence. Reviewed native claims are
    loaded only when both the detected semantic version and resolved binary
    SHA-256 match the checked-in redacted probe. Other native surfaces remain
    UNVALIDATED.
    """

    missing_detail = "Kimi executable was not found; runtime capability is unvalidated."
    matrix: dict[str, CapabilityEvidence] = {}
    if not executable_found:
        for capability in sorted(CAPABILITIES):
            matrix[capability] = CapabilityEvidence(
                capability=capability,
                status="UNVALIDATED",
                evidence=(path_lookup_evidence,),
                detail=missing_detail,
            )
        return matrix

    help_locator = help_evidence or path_lookup_evidence

    runtime_supported, runtime_disposition = load_runtime_supported_capabilities(
        detected_version=detected_version,
        detected_binary_sha256=detected_binary_sha256,
        fixture_path=runtime_evidence_path,
        expected_fixture_sha256=runtime_evidence_sha256,
    )
    runtime_locator = str(runtime_evidence_path)

    def supported(capability: str, detail: str, *locators: str) -> None:
        matrix[capability] = CapabilityEvidence(
            capability=capability,
            status="SUPPORTED",
            evidence=tuple(dict.fromkeys(locator for locator in locators if locator)),
            detail=detail,
        )

    def unvalidated(capability: str, detail: str, *locators: str) -> None:
        matrix[capability] = CapabilityEvidence(
            capability=capability,
            status="UNVALIDATED",
            evidence=tuple(locator for locator in locators if locator),
            detail=detail,
        )

    if "headless_execution" in runtime_supported:
        supported(
            "headless_execution",
            _RUNTIME_DETAILS["headless_execution"],
            runtime_locator,
            help_locator,
        )
    else:
        unvalidated(
            "headless_execution",
            "Help text alone does not prove a successful non-interactive process; "
            + runtime_disposition
            + ".",
            help_locator,
            runtime_locator,
        )

    # Separate-process construction is adapter-owned. Merely relocating cwd
    # and config roots does not prove that the detected CLI cannot access
    # paths outside the workspace, so workspace isolation remains unvalidated
    # until an OS policy or an authorized isolation probe demonstrates it.
    supported(
        "fresh_process",
        "Each launch uses a new OS process and a stage-scoped Kimi data root.",
        isolation_evidence,
    )
    unvalidated(
        "workspace_isolation",
        "The adapter fixes cwd and relocates HOME, KIMI_CODE_HOME, and XDG roots, "
        "but no OS-level path policy has proved that Kimi cannot access another "
        "workspace or harness state. A reviewed negative probe also observed a "
        "native Bash child inherit KIMI_MODEL_API_KEY, so path relocation and "
        "run-local environment construction are not an isolation boundary.",
        isolation_evidence,
        runtime_locator,
    )

    if "skill_discovery" in runtime_supported:
        supported(
            "skill_discovery",
            _RUNTIME_DETAILS["skill_discovery"],
            runtime_locator,
            help_locator,
        )
    else:
        unvalidated(
            "skill_discovery",
            "A --skills-dir help entry is not native discovery evidence; "
            + runtime_disposition
            + ".",
            help_locator,
            runtime_locator,
        )

    if "structured_trace" in runtime_supported:
        supported(
            "structured_trace",
            _RUNTIME_DETAILS["structured_trace"],
            runtime_locator,
            help_locator,
        )
    else:
        unvalidated(
            "structured_trace",
            "A stream-json help entry is not runtime trace evidence; "
            + runtime_disposition
            + ".",
            help_locator,
            runtime_locator,
        )

    for capability, fallback in (
        (
            "instruction_loading",
            "No exact-binary run-local AGENTS.md marker was observed in a model request.",
        ),
        (
            "skill_activation_trace",
            "No exact-binary native skill_activation event is available.",
        ),
        (
            "mcp_configuration",
            "No exact-binary run-local mcp.json load is available.",
        ),
        (
            "mcp_tool_trace",
            "No exact-binary correlated native MCP call/result is available.",
        ),
        (
            "mcp_health_trace",
            "No reviewed adapter-owned MCP initialize/tools-list/exit validator is available.",
        ),
        (
            "session_resume",
            "Resume flags do not prove native session identity and continuity.",
        ),
        (
            "session_compaction",
            "No exact-binary native compact event with token reduction is available.",
        ),
        (
            "subagent_delegation",
            "No exact-binary parent/child native trace and state chain is available.",
        ),
    ):
        if capability in runtime_supported:
            supported(capability, _RUNTIME_DETAILS[capability], runtime_locator)
        else:
            unvalidated(
                capability,
                fallback + " " + runtime_disposition + ".",
                runtime_locator,
                help_locator,
            )
    unvalidated(
        "durable_memory_write",
        "No Kimi-native durable-memory store write has been directly observed.",
        help_locator,
    )
    unvalidated(
        "durable_memory_retrieval",
        "No fresh-session Kimi-native durable-memory retrieval has been observed.",
        help_locator,
    )
    if "artifact_hash_provenance" in runtime_supported:
        supported(
            "artifact_hash_provenance",
            _RUNTIME_DETAILS["artifact_hash_provenance"],
            runtime_locator,
        )
    else:
        unvalidated(
            "artifact_hash_provenance",
            "No exact-binary native file-tool plus adapter execution-time hash "
            "correlation is available. "
            + runtime_disposition
            + ".",
            runtime_locator,
            help_locator,
        )
    unvalidated(
        "control_isolation",
        "Attack/control intervention-only equivalence has not been run for Kimi. "
        "A reviewed negative probe observed a native Bash child inherit "
        "KIMI_MODEL_API_KEY; a formal credentialed run therefore requires an "
        "external loopback credential broker that exposes only a dummy token to Kimi.",
        isolation_evidence,
        runtime_locator,
    )

    if set(matrix) != CAPABILITIES:
        missing = sorted(CAPABILITIES - set(matrix))
        raise AssertionError(f"internal Kimi capability matrix is incomplete: {missing}")
    return matrix


def aggregate_required_capabilities(
    required_capabilities: Sequence[str],
    matrix: Mapping[str, CapabilityEvidence],
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    required = tuple(required_capabilities)
    unknown = sorted(set(required) - CAPABILITIES)
    if unknown:
        raise ValueError(f"unknown capabilities: {unknown}")
    if len(set(required)) != len(required):
        raise ValueError("required_capabilities must be unique")

    selected = [matrix[capability] for capability in required]
    if any(item.status == "UNSUPPORTED" for item in selected):
        status = "UNSUPPORTED"
    elif any(item.status == "UNVALIDATED" for item in selected):
        status = "UNVALIDATED"
    else:
        status = "SUPPORTED"

    evidence = tuple(dict.fromkeys(locator for item in selected for locator in item.evidence))
    reasons = tuple(
        f"{item.capability}: {item.detail}"
        for item in selected
        if item.status != "SUPPORTED"
    )
    return status, evidence, reasons
