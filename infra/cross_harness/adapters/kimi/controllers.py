"""Fail-closed native boundary controllers for Kimi Code 0.26.x.

The controllers in this module do not infer lifecycle events from assistant
prose.  They bind controller decisions to Kimi's persisted native session
files, correlated tool records, exact run-local artifacts, and self-hashed
adapter records.  The surrounding executor remains responsible for process
isolation and for writing the returned adapter observations to its assigned
trace.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from .executor import (
    ControlDirective,
    ControlFinalization,
    JsonRpcExchange,
    StageControlFinalizeRequest,
    StageControlRequest,
)
from .disposition import (
    MODEL_PROTOCOL_INCOMPLETE,
    KimiExecutionDispositionError,
    KimiExecutionInvalidError,
)
from .lifecycle import atomic_write_json
from .materializer import sha256_file


SESSION_RECORD_SCHEMA = "safety_bench_kimi_native_session_record"
COMPACTION_RECORD_SCHEMA = "safety_bench_kimi_native_compaction_record"
ARTIFACT_RECORD_SCHEMA = "safety_bench_kimi_subagent_artifact_checkpoint"
CONTROLLER_SCHEMA_VERSION = 1

_SELF_HASH_FIELD = "record_payload_sha256"
_SESSION_ID_RE = re.compile(r"^session_[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMPACT_TEXT = "/compact Retain the project context needed for the next task."
_COMPACT_INSTRUCTION = "Retain the project context needed for the next task."
_ACP_DUMMY_AUTH_DOCUMENT = {
    "access_token": "safety-bench-run-local-noncredential-acp-gate",
    "refresh_token": "",
    "expires_at": 0,
    "scope": "",
    "token_type": "Bearer",
    "expires_in": 0,
}
_RESUME_CONTROLLER_KIND = "kimi_exact_native_session_resume_v1"
_COMPACTION_CONTROLLER_KIND = "kimi_acp_exact_manual_compaction_resume_v1"
_SUBAGENT_PRODUCER_KIND = "kimi_agent_coder_exact_artifact_v1"
_SUBAGENT_CONSUMER_KIND = "kimi_fresh_main_exact_artifact_consumer_v1"


class KimiControllerError(KimiExecutionInvalidError):
    """A native Kimi boundary lacked exact, correlated evidence."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            failure_category="CONTROLLER_EVIDENCE_INVALID",
            retry_eligible=False,
        )


class KimiControllerModelProtocolIncompleteError(KimiControllerError):
    """Direct native evidence proves the model skipped a required protocol step."""

    outcome = MODEL_PROTOCOL_INCOMPLETE

    def __init__(self, message: str) -> None:
        KimiExecutionDispositionError.__init__(
            self,
            message,
            failure_category="MODEL_BOUNDARY_PROTOCOL_DEVIATION",
            retry_eligible=False,
        )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiControllerError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise KimiControllerError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise KimiControllerError(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise KimiControllerError(f"{label} must be an integer >= {minimum}")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise KimiControllerError(f"{label} SHA-256 is invalid")
    return value


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _record_payload_sha256(document: Mapping[str, Any]) -> str:
    return _canonical_sha256(
        {key: value for key, value in document.items() if key != _SELF_HASH_FIELD}
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _runtime(stage_document: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(stage_document.get("runtime_paths"), "stage runtime_paths")


def _run_root(stage_document: Mapping[str, Any], run_id: str) -> Path:
    trace = Path(_string(_runtime(stage_document).get("trace"), "runtime trace"))
    if not trace.is_absolute() or len(trace.parents) < 3:
        raise KimiControllerError("runtime trace cannot identify the Kimi run root")
    root = trace.parents[2].resolve(strict=True)
    lowered = root.as_posix().casefold()
    if run_id not in root.as_posix() or "kimi" not in lowered:
        raise KimiControllerError("derived run root lacks kimi/run_id ownership")
    return root


def _owned_path(
    raw: Any,
    *,
    run_root: Path,
    label: str,
    must_exist: bool = False,
    require_file: bool = False,
    require_dir: bool = False,
) -> Path:
    if isinstance(raw, Path):
        supplied = raw
    else:
        supplied = Path(_string(raw, f"{label} path"))
    if not supplied.is_absolute() or supplied.is_symlink():
        raise KimiControllerError(f"{label} must be an absolute non-symlink path")
    try:
        relative = supplied.relative_to(run_root)
    except ValueError as exc:
        raise KimiControllerError(f"{label} escapes the Kimi run") from exc
    cursor = run_root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiControllerError(f"{label} traverses a symlink")
    resolved = supplied.resolve(strict=must_exist)
    if not _is_relative_to(resolved, run_root):
        raise KimiControllerError(f"{label} resolves outside the Kimi run")
    if require_file and not resolved.is_file():
        raise KimiControllerError(f"{label} is not a regular file")
    if require_dir and not resolved.is_dir():
        raise KimiControllerError(f"{label} is not a directory")
    return resolved


def _workspace(request: StageControlRequest | StageControlFinalizeRequest, run_root: Path) -> Path:
    return _owned_path(
        _runtime(request.stage_document).get("workspace"),
        run_root=run_root,
        label="workspace",
        must_exist=True,
        require_dir=True,
    )


def _controller_document(
    request: StageControlRequest | StageControlFinalizeRequest,
    surface: str,
) -> Mapping[str, Any]:
    surfaces = _mapping(request.stage_document.get("surfaces"), "stage surfaces")
    surface_document = _mapping(surfaces.get(surface), f"{surface} surface")
    return _mapping(surface_document.get("controller"), f"{surface} controller")


def _session_controller(
    request: StageControlRequest | StageControlFinalizeRequest,
) -> Mapping[str, Any]:
    return _controller_document(request, "session")


def _subagent_controller(
    request: StageControlRequest | StageControlFinalizeRequest,
) -> Mapping[str, Any]:
    return _controller_document(request, "subagent")


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiControllerError(f"{label} is malformed JSON") from exc
    return _mapping(value, label)


def _read_jsonl(path: Path, label: str) -> list[tuple[int, Mapping[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise KimiControllerError(f"{label} is not UTF-8 JSONL") from exc
    if not lines:
        raise KimiControllerError(f"{label} is empty")
    records: list[tuple[int, Mapping[str, Any]]] = []
    for line_number, raw in enumerate(lines, 1):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KimiControllerError(
                f"{label} is malformed at line {line_number}"
            ) from exc
        records.append((line_number, _mapping(value, f"{label}:{line_number}")))
    return records


def _event_time(record: Mapping[str, Any], label: str) -> int | float | str:
    value = record.get("time")
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise KimiControllerError(f"{label} has no directly observed timestamp")
    if isinstance(value, str) and not value:
        raise KimiControllerError(f"{label} timestamp is empty")
    return value


def _write_record(
    path: Path,
    document: Mapping[str, Any],
    *,
    run_id: str,
    run_root: Path,
    label: str,
) -> tuple[Mapping[str, Any], str]:
    target = _owned_path(path, run_root=run_root, label=label)
    if target.exists() or target.is_symlink():
        raise KimiControllerError(f"{label} already exists")
    body = dict(document)
    if _SELF_HASH_FIELD in body:
        raise KimiControllerError(f"{label} supplied its own self-hash")
    body[_SELF_HASH_FIELD] = _record_payload_sha256(body)
    atomic_write_json(target, body, run_id=run_id)
    digest = sha256_file(target)
    loaded = _read_json(target, label)
    if loaded != body or not hmac.compare_digest(
        str(loaded.get(_SELF_HASH_FIELD)), _record_payload_sha256(loaded)
    ):
        raise KimiControllerError(f"{label} failed post-write verification")
    return loaded, digest


def _load_record(
    raw_path: Any,
    *,
    run_root: Path,
    schema_name: str,
    run_id: str,
    case_id: str,
    label: str,
) -> tuple[Path, Mapping[str, Any], str]:
    path = _owned_path(
        raw_path,
        run_root=run_root,
        label=label,
        must_exist=True,
        require_file=True,
    )
    document = _read_json(path, label)
    if (
        document.get("schema_name") != schema_name
        or document.get("schema_version") != CONTROLLER_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("run_id") != run_id
        or document.get("case_id") != case_id
    ):
        raise KimiControllerError(f"{label} identity mismatch")
    claimed = _sha256(document.get(_SELF_HASH_FIELD), f"{label} payload")
    if not hmac.compare_digest(claimed, _record_payload_sha256(document)):
        raise KimiControllerError(f"{label} self-hash mismatch")
    return path, document, sha256_file(path)


def _record_locator(kind: str, path: Path, digest: str) -> str:
    return f"kimi:{kind}:{path}#sha256={digest}"


def _prior_record_path(
    prior_stage_results: Sequence[Mapping[str, Any]],
    *,
    kind: str,
    run_root: Path,
) -> Path:
    prefix = f"kimi:{kind}:"
    candidates: list[Path] = []
    for stage in prior_stage_results:
        evidence = stage.get("control_evidence", [])
        if not isinstance(evidence, list):
            raise KimiControllerError("prior control_evidence must be an array")
        for locator in evidence:
            if not isinstance(locator, str) or not locator.startswith(prefix):
                continue
            raw_path, marker, claimed = locator[len(prefix) :].rpartition("#sha256=")
            if marker != "#sha256=":
                raise KimiControllerError(f"malformed prior {kind} locator")
            path = _owned_path(
                raw_path,
                run_root=run_root,
                label=f"prior {kind} record",
                must_exist=True,
                require_file=True,
            )
            if not hmac.compare_digest(
                sha256_file(path), _sha256(claimed, f"prior {kind} record")
            ):
                raise KimiControllerError(f"prior {kind} record hash mismatch")
            candidates.append(path)
    unique = tuple(dict.fromkeys(candidates))
    if len(unique) != 1:
        raise KimiControllerError(f"expected exactly one prior {kind} record")
    return unique[0]


def _require_stage_success(stage_result: Mapping[str, Any]) -> None:
    if stage_result.get("return_code") != 0 or stage_result.get("timed_out") is not False:
        raise KimiControllerError("native boundary stage did not complete successfully")


def _stdout_reference(
    stage_result: Mapping[str, Any], *, run_root: Path
) -> tuple[Path, str, list[tuple[int, Mapping[str, Any]]]]:
    reference = _mapping(stage_result.get("stdout"), "stage stdout reference")
    path = _owned_path(
        reference.get("path"),
        run_root=run_root,
        label="stage stdout",
        must_exist=True,
        require_file=True,
    )
    claimed = _sha256(reference.get("sha256"), "stage stdout")
    if not hmac.compare_digest(sha256_file(path), claimed):
        raise KimiControllerError("stage stdout SHA-256 mismatch")
    records = _read_jsonl(path, "stage stdout")
    if reference.get("line_count") != len(records):
        raise KimiControllerError("stage stdout line count mismatch")
    return path, claimed, records


def _capture_session_id(
    stage_result: Mapping[str, Any], *, run_root: Path
) -> tuple[str, Path, str, int]:
    path, digest, records = _stdout_reference(stage_result, run_root=run_root)
    hints = [
        (line, record)
        for line, record in records
        if record.get("role") == "meta"
        and record.get("type") == "session.resume_hint"
    ]
    if len(hints) != 1:
        raise KimiControllerError(
            "stream-json stdout must contain exactly one native session.resume_hint"
        )
    line_number, hint = hints[0]
    session_id = _string(hint.get("session_id"), "native session id")
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        raise KimiControllerError("native session id has an unsafe format")
    for _, record in records:
        if "session_id" in record and record is not hint:
            raise KimiControllerError(
                "stream-json stdout contains an ambiguous second session_id"
            )
    return session_id, path, digest, line_number


def _wire_capture(
    stage_result: Mapping[str, Any],
    *,
    run_root: Path,
    main: bool,
    expected_path: Path | None = None,
) -> tuple[Path, str, int]:
    wire = _mapping(stage_result.get("wire"), "stage wire reference")
    captures = _list(wire.get("captures"), "stage wire captures")
    matches: list[Mapping[str, Any]] = []
    for raw in captures:
        capture = _mapping(raw, "wire capture")
        if capture.get("is_main") is main:
            source = Path(_string(capture.get("source_path"), "wire source path"))
            if expected_path is None or source.resolve(strict=False) == expected_path.resolve(
                strict=False
            ):
                matches.append(capture)
    if len(matches) != 1:
        role = "main" if main else "child"
        raise KimiControllerError(f"expected exactly one {role} native wire capture")
    capture = matches[0]
    path = _owned_path(
        capture.get("source_path"),
        run_root=run_root,
        label="native wire",
        must_exist=True,
        require_file=True,
    )
    digest = _sha256(capture.get("sha256"), "native wire")
    if not hmac.compare_digest(sha256_file(path), digest):
        raise KimiControllerError("native wire capture SHA-256 mismatch")
    line_count = _integer(capture.get("line_count"), "native wire line count", minimum=1)
    if len(path.read_bytes().splitlines()) != line_count:
        raise KimiControllerError("native wire capture line count mismatch")
    if main:
        if wire.get("main_sha256") != digest:
            raise KimiControllerError("main wire hashes disagree")
    return path, digest, line_count


def _validate_native_session(
    *,
    session_id: str,
    main_wire: Path,
    workspace: Path,
    session_root: Path,
    run_root: Path,
) -> tuple[Path, str]:
    if (
        main_wire.name != "wire.jsonl"
        or main_wire.parent.name != "main"
        or main_wire.parent.parent.name != "agents"
    ):
        raise KimiControllerError("main wire is not a native Kimi main-agent wire")
    session_dir = main_wire.parent.parent.parent
    if session_dir.name != session_id or not _is_relative_to(session_dir, session_root):
        raise KimiControllerError("native wire does not belong to the captured session")
    state_path = _owned_path(
        session_dir / "state.json",
        run_root=run_root,
        label="native session state",
        must_exist=True,
        require_file=True,
    )
    state = _read_json(state_path, "native session state")
    if Path(_string(state.get("workDir"), "native session workDir")).resolve() != workspace:
        raise KimiControllerError("native session state belongs to another workspace")
    agents = _mapping(state.get("agents"), "native session agents")
    main = _mapping(agents.get("main"), "native main agent state")
    if main.get("type") != "main" or main.get("parentAgentId") is not None:
        raise KimiControllerError("native main agent state is invalid")
    if Path(_string(main.get("homedir"), "native main homedir")).resolve() != main_wire.parent:
        raise KimiControllerError("native main homedir does not match its wire")
    return state_path, sha256_file(state_path)


def _wire_records(path: Path) -> list[tuple[int, Mapping[str, Any]]]:
    return _read_jsonl(path, "native Kimi wire")


def _loop_requests(
    records: Iterable[tuple[int, Mapping[str, Any]]], *, after_line: int = 0
) -> list[tuple[int, Mapping[str, Any]]]:
    return [
        (line, record)
        for line, record in records
        if line > after_line
        and record.get("type") == "llm.request"
        and record.get("kind") == "loop"
    ]


def _wire_prefix_sha256(path: Path, line_count: int) -> str:
    lines = path.read_bytes().splitlines(keepends=True)
    if len(lines) < line_count:
        raise KimiControllerError("native wire is shorter than its recorded boundary")
    return hashlib.sha256(b"".join(lines[:line_count])).hexdigest()


def _session_record_path(
    request: StageControlRequest | StageControlFinalizeRequest,
    controller: Mapping[str, Any],
    run_root: Path,
) -> Path:
    operation = _string(controller.get("operation"), "session controller operation")
    if operation == "create_and_capture_exact_session":
        capture = _mapping(controller.get("session_id_capture"), "session id capture")
        if capture.get("json_pointer") != "/session_id":
            raise KimiControllerError("session capture is not bound to top-level /session_id")
        return _owned_path(
            capture.get("record_path"),
            run_root=run_root,
            label="session record",
        )
    return _owned_path(
        controller.get("session_id_record_path"),
        run_root=run_root,
        label="session record",
    )


def _load_session_record(
    request: StageControlRequest | StageControlFinalizeRequest,
    controller: Mapping[str, Any],
    run_root: Path,
) -> tuple[Path, Mapping[str, Any], str]:
    path, record, digest = _load_record(
        _session_record_path(request, controller, run_root),
        run_root=run_root,
        schema_name=SESSION_RECORD_SCHEMA,
        run_id=request.run_id,
        case_id=request.case_id,
        label="session record",
    )
    if record.get("session_key") != controller.get("session_key"):
        raise KimiControllerError("session record key mismatch")
    return path, record, digest


def _session_paths_from_record(
    record: Mapping[str, Any], *, run_root: Path, workspace: Path
) -> tuple[str, Path, Path, str, list[tuple[int, Mapping[str, Any]]]]:
    session_id = _string(record.get("session_id"), "recorded session id")
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        raise KimiControllerError("recorded session id has an unsafe format")
    if Path(_string(record.get("workspace"), "recorded workspace")).resolve() != workspace:
        raise KimiControllerError("session record workspace mismatch")
    session_root = _owned_path(
        record.get("session_root"),
        run_root=run_root,
        label="recorded session root",
        must_exist=True,
        require_dir=True,
    )
    wire_record = _mapping(record.get("wire"), "recorded native wire")
    wire = _owned_path(
        wire_record.get("path"),
        run_root=run_root,
        label="recorded native wire",
        must_exist=True,
        require_file=True,
    )
    state_path, state_sha = _validate_native_session(
        session_id=session_id,
        main_wire=wire,
        workspace=workspace,
        session_root=session_root,
        run_root=run_root,
    )
    if str(state_path) != record.get("state_path"):
        raise KimiControllerError("session record state path mismatch")
    return session_id, wire, state_path, state_sha, _wire_records(wire)


def _validate_seed_boundary(
    record: Mapping[str, Any], *, run_root: Path, workspace: Path
) -> tuple[str, Path, Path, str, list[tuple[int, Mapping[str, Any]]]]:
    session_id, wire, state_path, state_sha, records = _session_paths_from_record(
        record, run_root=run_root, workspace=workspace
    )
    wire_ref = _mapping(record.get("wire"), "recorded native wire")
    line_count = _integer(wire_ref.get("line_count"), "seed wire line count", minimum=1)
    expected = _sha256(wire_ref.get("sha256"), "seed wire")
    captured_state_sha = _sha256(
        record.get("state_sha256_at_capture"), "captured session state"
    )
    if (
        len(records) != line_count
        or not hmac.compare_digest(sha256_file(wire), expected)
        or not hmac.compare_digest(state_sha, captured_state_sha)
    ):
        raise KimiControllerError("native session changed before its controlled boundary")
    return session_id, wire, state_path, state_sha, records


def _create_session_record(
    request: StageControlFinalizeRequest,
    controller: Mapping[str, Any],
) -> ControlFinalization:
    if request.stage_index != 0:
        raise KimiControllerError("native session creation must be stage 0")
    capture_contract = _mapping(
        controller.get("session_id_capture"), "session id capture"
    )
    if (
        capture_contract.get("source") != "stream_json_meta_resume_hint"
        or capture_contract.get("sha256_required") is not True
    ):
        raise KimiControllerError("session capture contract is not exact or hash-bound")
    _require_stage_success(request.stage_result)
    run_root = _run_root(request.stage_document, request.run_id)
    workspace = _workspace(request, run_root)
    session_id, stdout_path, stdout_sha, stdout_line = _capture_session_id(
        request.stage_result, run_root=run_root
    )
    main_wire, wire_sha, wire_line_count = _wire_capture(
        request.stage_result, run_root=run_root, main=True
    )
    session_root = _owned_path(
        controller.get("session_root"),
        run_root=run_root,
        label="session root",
        must_exist=True,
        require_dir=True,
    )
    kimi_home = _owned_path(
        controller.get("kimi_code_home"),
        run_root=run_root,
        label="Kimi code home",
        must_exist=True,
        require_dir=True,
    )
    if session_root != kimi_home / "sessions":
        raise KimiControllerError("session root is not the run-local KIMI_CODE_HOME/sessions")
    state_path, state_sha = _validate_native_session(
        session_id=session_id,
        main_wire=main_wire,
        workspace=workspace,
        session_root=session_root,
        run_root=run_root,
    )
    loop_requests = _loop_requests(_wire_records(main_wire))
    if not loop_requests:
        raise KimiControllerError("seed session has no native loop request")
    # The Event IR contract's "initial request" is the first loop request in
    # the seed process.  Keeping that exact locator also remains meaningful
    # after compaction, where later seed-loop message counts may have been
    # deliberately reduced before the resumed turn.
    initial_line, initial_request = loop_requests[0]
    initial_messages = _integer(
        initial_request.get("messageCount"), "seed request messageCount", minimum=1
    )
    record_path = _session_record_path(request, controller, run_root)
    record, record_sha = _write_record(
        record_path,
        {
            "schema_name": SESSION_RECORD_SCHEMA,
            "schema_version": CONTROLLER_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": request.run_id,
            "case_id": request.case_id,
            "session_key": _string(controller.get("session_key"), "session key"),
            "session_id": session_id,
            "seed_stage": {"index": request.stage_index, "name": request.stage_name},
            "workspace": str(workspace),
            "kimi_code_home": str(kimi_home),
            "session_root": str(session_root),
            "session_dir": str(state_path.parent),
            "state_path": str(state_path),
            "state_sha256_at_capture": state_sha,
            "stdout_hint": {
                "path": str(stdout_path),
                "sha256": stdout_sha,
                "line": stdout_line,
            },
            "wire": {
                "path": str(main_wire),
                "sha256": wire_sha,
                "line_count": wire_line_count,
                "initial_request_line": initial_line,
                "initial_message_count": initial_messages,
            },
        },
        run_id=request.run_id,
        run_root=run_root,
        label="session record",
    )
    return ControlFinalization(
        evidence_locators=(
            f"{stdout_path}:{stdout_line}",
            f"{main_wire}:{initial_line}",
            _record_locator("session-record", record_path, record_sha),
        )
    )


def _resume_observation(
    request: StageControlFinalizeRequest,
    *,
    session_record: Mapping[str, Any],
    before_line_count: int,
    before_sha256: str,
) -> ControlFinalization:
    _require_stage_success(request.stage_result)
    run_root = _run_root(request.stage_document, request.run_id)
    workspace = _workspace(request, run_root)
    session_id, wire, state_path, state_sha, records = _session_paths_from_record(
        session_record, run_root=run_root, workspace=workspace
    )
    captured_wire, captured_sha, captured_count = _wire_capture(
        request.stage_result,
        run_root=run_root,
        main=True,
        expected_path=wire,
    )
    if captured_wire != wire or captured_count <= before_line_count:
        raise KimiControllerError("resume did not append to the exact captured session")
    if not hmac.compare_digest(_wire_prefix_sha256(wire, before_line_count), before_sha256):
        raise KimiControllerError("pre-resume native wire prefix changed")
    resumed = _loop_requests(records, after_line=before_line_count)
    if not resumed:
        raise KimiControllerError("resume appended no native loop request")
    resumed_line, resumed_request = resumed[0]
    initial_ref = _mapping(session_record.get("wire"), "session seed wire")
    initial_line = _integer(
        initial_ref.get("initial_request_line"), "initial request line", minimum=1
    )
    initial_messages = _integer(
        initial_ref.get("initial_message_count"), "initial messageCount", minimum=1
    )
    resumed_messages = _integer(
        resumed_request.get("messageCount"), "resumed messageCount", minimum=1
    )
    if resumed_messages <= initial_messages:
        raise KimiControllerError("native resume did not increase message context")
    observation = {
        "type": "adapter.session_resume_observed",
        "time": _event_time(resumed_request, "resumed loop request"),
        "session_id": session_id,
        "state": {"path": str(state_path), "sha256": state_sha},
        "wire": {
            "path": str(wire),
            "sha256": captured_sha,
            "before_line_count": before_line_count,
            "before_sha256": before_sha256,
            "initial_request_line": initial_line,
            "resumed_request_line": resumed_line,
        },
    }
    return ControlFinalization(
        evidence_locators=(f"{wire}:{resumed_line}",),
        observation_records=(observation,),
    )


class KimiExactSessionController:
    """Create and resume one exact run-local Kimi native session."""

    def prepare(self, request: StageControlRequest) -> ControlDirective:
        controller = _session_controller(request)
        operation = _string(controller.get("operation"), "session operation")
        if (
            controller.get("kind") != _RESUME_CONTROLLER_KIND
            or controller.get("required") is not True
        ):
            raise KimiControllerError("exact-session controller identity drifted")
        run_root = _run_root(request.stage_document, request.run_id)
        workspace = _workspace(request, run_root)
        if operation == "create_and_capture_exact_session":
            record_path = _session_record_path(request, controller, run_root)
            if record_path.exists() or record_path.is_symlink():
                raise KimiControllerError("session capture record already exists")
            return ControlDirective(evidence_locators=(str(record_path),))
        if operation != "resume_exact_captured_session":
            raise KimiControllerError(f"unsupported exact-session operation: {operation}")
        if request.stage_index != 1 or controller.get("require_same_session_id") is not True:
            raise KimiControllerError("exact session resume stage contract drifted")
        path, record, digest = _load_session_record(request, controller, run_root)
        session_id, _, _, _, _ = _validate_seed_boundary(
            record, run_root=run_root, workspace=workspace
        )
        return ControlDirective(
            argv_suffix=("--session", session_id),
            evidence_locators=(_record_locator("session-record", path, digest),),
        )

    def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization:
        controller = _session_controller(request)
        operation = _string(controller.get("operation"), "session operation")
        if (
            controller.get("kind") != _RESUME_CONTROLLER_KIND
            or controller.get("required") is not True
        ):
            raise KimiControllerError("exact-session controller identity drifted")
        if operation == "create_and_capture_exact_session":
            return _create_session_record(request, controller)
        if operation != "resume_exact_captured_session":
            raise KimiControllerError(f"unsupported exact-session operation: {operation}")
        run_root = _run_root(request.stage_document, request.run_id)
        _, record, _ = _load_session_record(request, controller, run_root)
        wire_ref = _mapping(record.get("wire"), "session seed wire")
        return _resume_observation(
            request,
            session_record=record,
            before_line_count=_integer(
                wire_ref.get("line_count"), "seed wire line count", minimum=1
            ),
            before_sha256=_sha256(wire_ref.get("sha256"), "seed wire"),
        )


def _acp_frames(
    controller: Mapping[str, Any], *, workspace: Path, session_id: str
) -> tuple[bytes, bytes, bytes]:
    protocol = _mapping(controller.get("acp_protocol"), "ACP protocol")
    sequence = _list(protocol.get("request_sequence"), "ACP request sequence")
    if len(sequence) != 3:
        raise KimiControllerError("ACP request sequence must contain exactly three requests")
    declared = [_mapping(item, "ACP request declaration") for item in sequence]
    if [item.get("id") for item in declared] != [1, 2, 3] or [
        item.get("method") for item in declared
    ] != ["initialize", "session/resume", "session/prompt"]:
        raise KimiControllerError("ACP request sequence drifted from the reviewed contract")
    initialize = _mapping(declared[0].get("params"), "ACP initialize params")
    expected_initialize = {
        "protocolVersion": 1,
        "clientCapabilities": {
            "fs": {"readTextFile": False, "writeTextFile": False},
            "terminal": False,
        },
        "clientInfo": {
            "name": "safety-bench-kimi-compaction-controller",
            "version": "1",
        },
    }
    prompt = _mapping(declared[2].get("params"), "ACP prompt declaration").get(
        "prompt"
    )
    if initialize != expected_initialize or prompt != [
        {"type": "text", "text": _COMPACT_TEXT}
    ]:
        raise KimiControllerError("ACP initialize or compact prompt is not exact")
    messages = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": initialize,
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/resume",
            "params": {
                "cwd": str(workspace),
                "mcpServers": [],
                "sessionId": session_id,
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/prompt",
            "params": {
                "sessionId": session_id,
                "prompt": prompt,
            },
        },
    )
    return tuple(
        (
            json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        for message in messages
    )  # type: ignore[return-value]


def _validate_acp_responses(
    path: Path, *, session_id: str
) -> list[tuple[int, Mapping[str, Any]]]:
    records = _read_jsonl(path, "ACP response trace")
    if any(record.get("jsonrpc") != "2.0" for _, record in records):
        raise KimiControllerError("ACP response trace contains non-JSON-RPC records")
    responses = [(line, record) for line, record in records if "id" in record]
    if [record.get("id") for _, record in responses] != [1, 2, 3]:
        raise KimiControllerError("ACP response ids are absent, duplicated, or out of order")
    if any("error" in record or not isinstance(record.get("result"), Mapping) for _, record in responses):
        raise KimiControllerError("ACP request did not receive three successful responses")
    initialize = _mapping(responses[0][1].get("result"), "ACP initialize result")
    capabilities = _mapping(
        initialize.get("agentCapabilities"), "ACP agent capabilities"
    )
    sessions = _mapping(
        capabilities.get("sessionCapabilities"), "ACP session capabilities"
    )
    if (
        initialize.get("protocolVersion") != 1
        or capabilities.get("loadSession") is not True
        or not isinstance(sessions.get("resume"), Mapping)
    ):
        raise KimiControllerError("ACP initialize did not prove native session resume")
    resume_result = _mapping(responses[1][1].get("result"), "ACP resume result")
    if not isinstance(resume_result.get("configOptions"), list):
        raise KimiControllerError("ACP session/resume response lacks configOptions")
    prompt_result = _mapping(responses[2][1].get("result"), "ACP prompt result")
    if prompt_result.get("stopReason") != "end_turn":
        raise KimiControllerError("ACP compact prompt did not stop with end_turn")
    notifications = [(line, record) for line, record in records if "method" in record]
    if any(record.get("method") != "session/update" for _, record in notifications):
        raise KimiControllerError("ACP trace contains an unexpected server notification")
    available: list[tuple[int, Mapping[str, Any]]] = []
    for line, notification in notifications:
        params = _mapping(notification.get("params"), "ACP session/update params")
        if params.get("sessionId") != session_id:
            raise KimiControllerError("ACP notification names another session")
        update = _mapping(params.get("update"), "ACP session update")
        if update.get("sessionUpdate") == "available_commands_update":
            available.append((line, update))
    if len(available) != 1:
        raise KimiControllerError("ACP trace lacks one available_commands_update")
    if not responses[1][0] < available[0][0] < responses[2][0]:
        raise KimiControllerError(
            "ACP compact command notification does not follow resume and precede prompt completion"
        )
    commands = _list(
        available[0][1].get("availableCommands"), "ACP available commands"
    )
    compact = [
        _mapping(command, "ACP command")
        for command in commands
        if isinstance(command, Mapping) and command.get("name") == "compact"
    ]
    if len(compact) != 1 or not isinstance(compact[0].get("description"), str):
        raise KimiControllerError("ACP available commands do not contain one compact command")
    return records


def _compaction_record_path_from_prior(
    request: StageControlRequest | StageControlFinalizeRequest,
    run_root: Path,
) -> Path:
    return _prior_record_path(
        request.prior_stage_results,
        kind="compaction-record",
        run_root=run_root,
    )


def _prepare_acp_dummy_auth(
    controller: Mapping[str, Any], *, run_root: Path, run_id: str
) -> Path:
    """Satisfy Kimi 0.26 ACP's OAuth-only gate without an external credential."""

    kimi_home = _owned_path(
        controller.get("kimi_code_home"),
        run_root=run_root,
        label="ACP Kimi home",
        must_exist=True,
        require_dir=True,
    )
    credentials = _owned_path(
        kimi_home / "credentials",
        run_root=run_root,
        label="ACP dummy credential directory",
    )
    if credentials.exists() and not credentials.is_dir():
        raise KimiControllerError("ACP dummy credential path is not a directory")
    credentials.mkdir(mode=0o700, exist_ok=True)
    credentials.chmod(0o700)
    token_path = _owned_path(
        credentials / "kimi-code.json",
        run_root=run_root,
        label="ACP dummy credential",
    )
    unexpected = [
        path
        for path in credentials.iterdir()
        if path != token_path
    ]
    if unexpected:
        raise KimiControllerError(
            "ACP Kimi home contains an unexpected credential entry"
        )
    if token_path.exists():
        if (
            token_path.is_symlink()
            or not token_path.is_file()
            or _read_json(token_path, "ACP dummy credential")
            != _ACP_DUMMY_AUTH_DOCUMENT
            or token_path.stat().st_mode & 0o777 != 0o600
        ):
            raise KimiControllerError(
                "ACP dummy credential differs from the fixed run-local marker"
            )
        return token_path
    atomic_write_json(token_path, _ACP_DUMMY_AUTH_DOCUMENT, run_id=run_id)
    token_path.chmod(0o600)
    if (
        _read_json(token_path, "ACP dummy credential")
        != _ACP_DUMMY_AUTH_DOCUMENT
        or token_path.stat().st_mode & 0o777 != 0o600
    ):
        raise KimiControllerError("ACP dummy credential failed post-write validation")
    return token_path


class KimiAcpCompactionController:
    """Capture, manually compact, and resume one exact Kimi session."""

    def prepare(self, request: StageControlRequest) -> ControlDirective:
        controller = _session_controller(request)
        operation = _string(controller.get("operation"), "compaction operation")
        if (
            controller.get("kind") != _COMPACTION_CONTROLLER_KIND
            or controller.get("required") is not True
        ):
            raise KimiControllerError("compaction controller identity drifted")
        run_root = _run_root(request.stage_document, request.run_id)
        workspace = _workspace(request, run_root)
        if operation == "create_and_capture_exact_session":
            record_path = _session_record_path(request, controller, run_root)
            if record_path.exists() or record_path.is_symlink():
                raise KimiControllerError("session capture record already exists")
            return ControlDirective(evidence_locators=(str(record_path),))
        session_path, session_record, session_sha = _load_session_record(
            request, controller, run_root
        )
        if operation == "compact_exact_captured_session_via_acp":
            if (
                request.stage_index != 1
                or controller.get("transport") != "acp_stdio"
                or controller.get("require_same_session_id") is not True
                or controller.get("prompt_mode_forbidden") is not True
            ):
                raise KimiControllerError("ACP compaction stage contract drifted")
            session_id, _, _, _, _ = _validate_seed_boundary(
                session_record, run_root=run_root, workspace=workspace
            )
            compaction_path = _owned_path(
                controller.get("compaction_evidence_record_path"),
                run_root=run_root,
                label="compaction record",
            )
            if compaction_path.exists() or compaction_path.is_symlink():
                raise KimiControllerError("compaction record already exists")
            _prepare_acp_dummy_auth(
                controller,
                run_root=run_root,
                run_id=request.run_id,
            )
            frames = _acp_frames(
                controller, workspace=workspace, session_id=session_id
            )
            return ControlDirective(
                argv_suffix=("acp",),
                evidence_locators=(
                    _record_locator("session-record", session_path, session_sha),
                    str(compaction_path),
                ),
                launch_mode="controller",
                jsonrpc_exchange=JsonRpcExchange(
                    request_frames=frames,
                    expected_response_ids=(1, 2, 3),
                ),
            )
        if operation != "resume_exact_compacted_session":
            raise KimiControllerError(f"unsupported compaction operation: {operation}")
        if (
            request.stage_index != 2
            or controller.get("require_same_session_id") is not True
            or controller.get("require_completed_compaction_from_stage") != 1
        ):
            raise KimiControllerError("post-compaction resume stage contract drifted")
        compaction_path = _compaction_record_path_from_prior(request, run_root)
        _, compaction, _ = _load_record(
            compaction_path,
            run_root=run_root,
            schema_name=COMPACTION_RECORD_SCHEMA,
            run_id=request.run_id,
            case_id=request.case_id,
            label="compaction record",
        )
        if compaction.get("session_record_sha256") != session_sha:
            raise KimiControllerError("compaction record is not bound to the session record")
        session_id, wire, _, _, _ = _session_paths_from_record(
            session_record, run_root=run_root, workspace=workspace
        )
        if compaction.get("session_id") != session_id:
            raise KimiControllerError("compaction record session id mismatch")
        compaction_state = _mapping(
            compaction.get("state"), "post-compaction session state"
        )
        current_state = _owned_path(
            compaction_state.get("path"),
            run_root=run_root,
            label="post-compaction session state",
            must_exist=True,
            require_file=True,
        )
        if not hmac.compare_digest(
            sha256_file(current_state),
            _sha256(compaction_state.get("sha256"), "post-compaction session state"),
        ):
            raise KimiControllerError("compacted session state changed before resume")
        after = _mapping(compaction.get("wire_after"), "post-compaction wire")
        after_count = _integer(after.get("line_count"), "post-compaction line count", minimum=1)
        after_sha = _sha256(after.get("sha256"), "post-compaction wire")
        if (
            str(wire) != after.get("path")
            or len(wire.read_bytes().splitlines()) != after_count
            or not hmac.compare_digest(sha256_file(wire), after_sha)
        ):
            raise KimiControllerError("compacted native session changed before resume")
        return ControlDirective(
            argv_suffix=("--session", session_id),
            evidence_locators=(
                _record_locator(
                    "compaction-record", compaction_path, sha256_file(compaction_path)
                ),
            ),
        )

    def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization:
        controller = _session_controller(request)
        operation = _string(controller.get("operation"), "compaction operation")
        if (
            controller.get("kind") != _COMPACTION_CONTROLLER_KIND
            or controller.get("required") is not True
        ):
            raise KimiControllerError("compaction controller identity drifted")
        if operation == "create_and_capture_exact_session":
            return _create_session_record(request, controller)
        run_root = _run_root(request.stage_document, request.run_id)
        workspace = _workspace(request, run_root)
        session_path, session_record, session_sha = _load_session_record(
            request, controller, run_root
        )
        if operation == "resume_exact_compacted_session":
            compaction_path = _compaction_record_path_from_prior(request, run_root)
            _, compaction, _ = _load_record(
                compaction_path,
                run_root=run_root,
                schema_name=COMPACTION_RECORD_SCHEMA,
                run_id=request.run_id,
                case_id=request.case_id,
                label="compaction record",
            )
            if compaction.get("session_record_sha256") != session_sha:
                raise KimiControllerError(
                    "compaction resume record is not bound to this session record"
                )
            after = _mapping(compaction.get("wire_after"), "post-compaction wire")
            return _resume_observation(
                request,
                session_record=session_record,
                before_line_count=_integer(
                    after.get("line_count"), "post-compaction line count", minimum=1
                ),
                before_sha256=_sha256(after.get("sha256"), "post-compaction wire"),
            )
        if operation != "compact_exact_captured_session_via_acp":
            raise KimiControllerError(f"unsupported compaction operation: {operation}")
        _require_stage_success(request.stage_result)
        session_id, wire, state_path, _, _ = _session_paths_from_record(
            session_record, run_root=run_root, workspace=workspace
        )
        seed_wire = _mapping(session_record.get("wire"), "session seed wire")
        before_count = _integer(
            seed_wire.get("line_count"), "pre-compaction line count", minimum=1
        )
        before_sha = _sha256(seed_wire.get("sha256"), "pre-compaction wire")
        captured_wire, after_sha, after_count = _wire_capture(
            request.stage_result,
            run_root=run_root,
            main=True,
            expected_path=wire,
        )
        if captured_wire != wire or after_count <= before_count:
            raise KimiControllerError("manual compaction did not append native wire records")
        if not hmac.compare_digest(_wire_prefix_sha256(wire, before_count), before_sha):
            raise KimiControllerError("pre-compaction wire prefix changed")
        controller_trace = _mapping(
            request.stage_result.get("controller_trace"), "ACP controller trace reference"
        )
        acp_path = _owned_path(
            controller_trace.get("path"),
            run_root=run_root,
            label="ACP controller trace",
            must_exist=True,
            require_file=True,
        )
        declared_acp_path = _owned_path(
            controller.get("acp_trace_path"),
            run_root=run_root,
            label="declared ACP trace",
            must_exist=True,
            require_file=True,
        )
        acp_sha = _sha256(controller_trace.get("sha256"), "ACP controller trace")
        if (
            acp_path != declared_acp_path
            or not hmac.compare_digest(sha256_file(acp_path), acp_sha)
        ):
            raise KimiControllerError("ACP controller trace path or hash mismatch")
        stdout_path, stdout_sha, _ = _stdout_reference(
            request.stage_result, run_root=run_root
        )
        if not hmac.compare_digest(stdout_sha, acp_sha) or stdout_path.read_bytes() != acp_path.read_bytes():
            raise KimiControllerError("ACP controller trace differs from process stdout")
        _validate_acp_responses(acp_path, session_id=session_id)
        expected_frames = _acp_frames(
            controller, workspace=workspace, session_id=session_id
        )
        expected_request_hashes = [hashlib.sha256(frame).hexdigest() for frame in expected_frames]
        if request.stage_result.get("controller_request_sha256") != expected_request_hashes:
            raise KimiControllerError("executed ACP request frames drifted from the binding")
        records = _wire_records(wire)
        appended = [(line, record) for line, record in records if line > before_count]
        begin = [(line, record) for line, record in appended if record.get("type") == "full_compaction.begin"]
        compact_request = [
            (line, record)
            for line, record in appended
            if record.get("type") == "llm.request" and record.get("kind") == "compaction"
        ]
        applied = [(line, record) for line, record in appended if record.get("type") == "context.apply_compaction"]
        complete = [(line, record) for line, record in appended if record.get("type") == "full_compaction.complete"]
        if not all(len(items) == 1 for items in (begin, compact_request, applied, complete)):
            raise KimiControllerError("native compaction sequence is absent or ambiguous")
        begin_line, begin_record = begin[0]
        request_line, request_record = compact_request[0]
        apply_line, apply_record = applied[0]
        complete_line, complete_record = complete[0]
        if not begin_line < request_line < apply_line < complete_line:
            raise KimiControllerError("native compaction records are out of order")
        if (
            begin_record.get("source") != "manual"
            or begin_record.get("instruction") != _COMPACT_INSTRUCTION
        ):
            raise KimiControllerError("native compaction is not the exact manual request")
        _integer(request_record.get("messageCount"), "compaction messageCount", minimum=1)
        summary = _string(apply_record.get("summary"), "compaction summary")
        tokens_before = _integer(
            apply_record.get("tokensBefore"), "compaction tokensBefore", minimum=1
        )
        tokens_after = _integer(
            apply_record.get("tokensAfter"), "compaction tokensAfter", minimum=0
        )
        compacted_count = _integer(
            apply_record.get("compactedCount"), "compaction compactedCount", minimum=1
        )
        kept_count = _integer(
            apply_record.get("keptUserMessageCount"),
            "compaction keptUserMessageCount",
            minimum=0,
        )
        if tokens_after >= tokens_before:
            raise KimiControllerError("native compaction did not reduce tokens")
        for record, label in (
            (begin_record, "compaction begin"),
            (request_record, "compaction request"),
            (apply_record, "compaction apply"),
            (complete_record, "compaction complete"),
        ):
            _event_time(record, label)
        state_path, state_sha = _validate_native_session(
            session_id=session_id,
            main_wire=wire,
            workspace=workspace,
            session_root=_owned_path(
                session_record.get("session_root"),
                run_root=run_root,
                label="session root",
                must_exist=True,
                require_dir=True,
            ),
            run_root=run_root,
        )
        compaction_path = _owned_path(
            controller.get("compaction_evidence_record_path"),
            run_root=run_root,
            label="compaction record",
        )
        record, record_sha = _write_record(
            compaction_path,
            {
                "schema_name": COMPACTION_RECORD_SCHEMA,
                "schema_version": CONTROLLER_SCHEMA_VERSION,
                "harness_id": "kimi",
                "run_id": request.run_id,
                "case_id": request.case_id,
                "session_id": session_id,
                "session_key": session_record.get("session_key"),
                "session_record_path": str(session_path),
                "session_record_sha256": session_sha,
                "workspace": str(workspace),
                "source": "manual",
                "compact_command_sha256": hashlib.sha256(
                    _COMPACT_TEXT.encode("utf-8")
                ).hexdigest(),
                "acp_trace": {"path": str(acp_path), "sha256": acp_sha},
                "wire_before": {
                    "path": str(wire),
                    "line_count": before_count,
                    "sha256": before_sha,
                },
                "wire_after": {
                    "path": str(wire),
                    "line_count": after_count,
                    "sha256": after_sha,
                },
                "wire_lines": {
                    "begin": begin_line,
                    "request": request_line,
                    "apply": apply_line,
                    "complete": complete_line,
                },
                "tokens": {"before": tokens_before, "after": tokens_after},
                "compacted_count": compacted_count,
                "kept_user_message_count": kept_count,
                "summary_sha256": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
                "state": {"path": str(state_path), "sha256": state_sha},
            },
            run_id=request.run_id,
            run_root=run_root,
            label="compaction record",
        )
        observation = {
            "type": "adapter.session_compaction_observed",
            "time": _event_time(apply_record, "compaction apply"),
            "session_id": session_id,
            "state": {"path": str(state_path), "sha256": state_sha},
            "wire": {
                "path": str(wire),
                "sha256": after_sha,
                "begin_line": begin_line,
                "request_line": request_line,
                "apply_line": apply_line,
                "complete_line": complete_line,
            },
        }
        return ControlFinalization(
            evidence_locators=(
                f"{acp_path}:1",
                f"{wire}:{begin_line}",
                f"{wire}:{apply_line}",
                _record_locator("compaction-record", compaction_path, record_sha),
            ),
            observation_records=(observation,),
        )


def _parse_tool_call(record: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any]] | None:
    if record.get("type") != "context.append_loop_event":
        return None
    event = _mapping(record.get("event"), "native loop event")
    if event.get("type") != "tool.call":
        return None
    call_id = _string(event.get("id", event.get("toolCallId")), "tool call id")
    function = event.get("function")
    if isinstance(function, Mapping):
        name = _string(function.get("name"), "tool call name")
        args: Any = function.get("arguments", {})
    else:
        name = _string(event.get("name"), "tool call name")
        args = event.get("args", event.get("arguments", {}))
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError as exc:
            raise KimiControllerError("tool call arguments are malformed JSON") from exc
    return call_id, name, _mapping(args, "tool call arguments")


def _parse_tool_result(record: Mapping[str, Any]) -> tuple[str, Any, bool] | None:
    if record.get("type") != "context.append_loop_event":
        return None
    event = _mapping(record.get("event"), "native loop event")
    if event.get("type") != "tool.result":
        return None
    call_id = _string(event.get("toolCallId"), "tool result id")
    result = _mapping(event.get("result"), "native tool result")
    raw_error = result.get("isError")
    if raw_error is not None and not isinstance(raw_error, bool):
        raise KimiControllerError("native tool result isError is malformed")
    return call_id, result.get("output"), raw_error is True


def _correlated_tools(
    records: Sequence[tuple[int, Mapping[str, Any]]], *, label: str
) -> list[Mapping[str, Any]]:
    calls: dict[str, dict[str, Any]] = {}
    results: dict[str, dict[str, Any]] = {}
    for line, record in records:
        call = _parse_tool_call(record)
        if call is not None:
            call_id, name, args = call
            if call_id in calls:
                raise KimiControllerError(f"{label} has a duplicate tool call id")
            calls[call_id] = {"call_id": call_id, "name": name, "args": args, "call_line": line}
        result = _parse_tool_result(record)
        if result is not None:
            call_id, output, is_error = result
            if call_id in results:
                raise KimiControllerError(f"{label} has a duplicate tool result id")
            results[call_id] = {
                "output": output,
                "is_error": is_error,
                "result_line": line,
                "record": record,
            }
    if set(calls) != set(results):
        raise KimiControllerError(f"{label} has uncorrelated native tool events")
    correlated: list[Mapping[str, Any]] = []
    for call_id, call in calls.items():
        result = results[call_id]
        if result["result_line"] <= call["call_line"]:
            raise KimiControllerError(f"{label} tool result precedes its call")
        correlated.append({**call, **result})
    return sorted(correlated, key=lambda item: int(item["call_line"]))


def _workspace_relative(raw: Any, *, workspace: Path, label: str) -> tuple[str, Path]:
    value = Path(_string(raw, f"{label} path"))
    supplied = value if value.is_absolute() else workspace / value
    if supplied.is_symlink():
        raise KimiControllerError(f"{label} path is a symlink")
    resolved = supplied.resolve(strict=False)
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as exc:
        raise KimiControllerError(f"{label} path escapes the workspace") from exc
    cursor = workspace
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiControllerError(f"{label} path traverses a symlink")
    return relative.as_posix(), resolved


def _state_agents(
    *,
    state_path: Path,
    session_dir: Path,
    workspace: Path,
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    state = _read_json(state_path, "subagent native session state")
    if Path(_string(state.get("workDir"), "native session workDir")).resolve() != workspace:
        raise KimiControllerError("subagent session belongs to another workspace")
    agents = _mapping(state.get("agents"), "native session agents")
    main = _mapping(agents.get("main"), "native main state")
    if (
        main.get("type") != "main"
        or main.get("parentAgentId") is not None
        or Path(_string(main.get("homedir"), "main homedir")).resolve()
        != session_dir / "agents" / "main"
    ):
        raise KimiControllerError("subagent parent state identity is invalid")
    return state, agents


def _consumer_checkpoint_path(
    controller: Mapping[str, Any], *, run_root: Path
) -> Path:
    prior = _mapping(controller.get("required_prior_artifact"), "prior artifact")
    return _owned_path(
        prior.get("checkpoint_record_path"),
        run_root=run_root,
        label="artifact checkpoint",
        must_exist=True,
        require_file=True,
    )


def _load_artifact_checkpoint(
    request: StageControlRequest | StageControlFinalizeRequest,
    controller: Mapping[str, Any],
    run_root: Path,
) -> tuple[Path, Mapping[str, Any], str, Path, str]:
    path, record, digest = _load_record(
        _consumer_checkpoint_path(controller, run_root=run_root),
        run_root=run_root,
        schema_name=ARTIFACT_RECORD_SCHEMA,
        run_id=request.run_id,
        case_id=request.case_id,
        label="artifact checkpoint",
    )
    workspace = _workspace(request, run_root)
    if Path(_string(record.get("workspace"), "checkpoint workspace")).resolve() != workspace:
        raise KimiControllerError("artifact checkpoint workspace mismatch")
    artifact = _mapping(record.get("artifact"), "checkpoint artifact")
    relative, artifact_path = _workspace_relative(
        artifact.get("path"), workspace=workspace, label="checkpoint artifact"
    )
    expected_path = _mapping(
        controller.get("required_prior_artifact"), "required prior artifact"
    ).get("path")
    if relative != expected_path:
        raise KimiControllerError("artifact checkpoint path mismatch")
    source = _mapping(record.get("source"), "checkpoint source")
    forbidden_sources = _list(
        controller.get("forbidden_source_paths"), "consumer forbidden source paths"
    )
    if forbidden_sources != [source.get("path")]:
        raise KimiControllerError("consumer forbidden source path drifted from checkpoint")
    if not artifact_path.is_file() or artifact_path.is_symlink():
        raise KimiControllerError("checkpoint artifact is absent or unsafe")
    artifact_sha = _sha256(artifact.get("sha256"), "checkpoint artifact")
    if not hmac.compare_digest(sha256_file(artifact_path), artifact_sha):
        raise KimiControllerError("checkpoint artifact bytes changed")
    return path, record, digest, artifact_path, artifact_sha


class KimiSubagentArtifactController:
    """Prove an Agent(coder) producer and a fresh exact-artifact consumer."""

    def prepare(self, request: StageControlRequest) -> ControlDirective:
        controller = _subagent_controller(request)
        operation = _string(controller.get("operation"), "subagent operation")
        run_root = _run_root(request.stage_document, request.run_id)
        workspace = _workspace(request, run_root)
        if Path(_string(controller.get("workspace"), "controller workspace")).resolve() != workspace:
            raise KimiControllerError("subagent controller workspace mismatch")
        if operation == "spawn_exactly_one_producer":
            if (
                request.stage_index != 0
                or controller.get("kind") != _SUBAGENT_PRODUCER_KIND
                or controller.get("required") is not True
            ):
                raise KimiControllerError("subagent producer controller identity drifted")
            checkpoint = _owned_path(
                controller.get("artifact_checkpoint_record_path"),
                run_root=run_root,
                label="artifact checkpoint",
            )
            artifact = _owned_path(
                controller.get("required_artifact_absolute_path"),
                run_root=run_root,
                label="required artifact",
            )
            if checkpoint.exists() or checkpoint.is_symlink():
                raise KimiControllerError("artifact checkpoint already exists")
            if artifact.exists() or artifact.is_symlink():
                raise KimiControllerError("producer artifact must not pre-exist")
            return ControlDirective(evidence_locators=(str(checkpoint),))
        if operation != "fresh_main_consumer":
            raise KimiControllerError(f"unsupported subagent operation: {operation}")
        if (
            request.stage_index != 1
            or controller.get("kind") != _SUBAGENT_CONSUMER_KIND
            or controller.get("required") is not True
            or controller.get("new_os_process") is not True
            or controller.get("forbid_subagent_reuse") is not True
        ):
            raise KimiControllerError("fresh consumer controller identity drifted")
        path, _, digest, artifact, artifact_sha = _load_artifact_checkpoint(
            request, controller, run_root
        )
        return ControlDirective(
            evidence_locators=(
                _record_locator("artifact-checkpoint", path, digest),
                f"{artifact}#sha256={artifact_sha}",
            )
        )

    def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization:
        _require_stage_success(request.stage_result)
        controller = _subagent_controller(request)
        operation = _string(controller.get("operation"), "subagent operation")
        expected_kind = (
            _SUBAGENT_PRODUCER_KIND
            if operation == "spawn_exactly_one_producer"
            else _SUBAGENT_CONSUMER_KIND
        )
        if controller.get("kind") != expected_kind or controller.get("required") is not True:
            raise KimiControllerError("subagent controller identity drifted")
        run_root = _run_root(request.stage_document, request.run_id)
        workspace = _workspace(request, run_root)
        session_id, _, _, _ = _capture_session_id(
            request.stage_result, run_root=run_root
        )
        main_wire, main_sha, _ = _wire_capture(
            request.stage_result, run_root=run_root, main=True
        )
        if main_wire.parent.parent.parent.name != session_id:
            raise KimiControllerError("subagent main wire session id mismatch")
        session_dir = main_wire.parent.parent.parent
        state_path = _owned_path(
            session_dir / "state.json",
            run_root=run_root,
            label="subagent session state",
            must_exist=True,
            require_file=True,
        )
        state, agents = _state_agents(
            state_path=state_path, session_dir=session_dir, workspace=workspace
        )
        parent_tools = _correlated_tools(
            _wire_records(main_wire), label="subagent parent wire"
        )
        if operation == "fresh_main_consumer":
            if set(agents) != {"main"}:
                raise KimiControllerModelProtocolIncompleteError(
                    "fresh consumer reused or spawned a subagent"
                )
            if any(tool["name"] == "Agent" for tool in parent_tools):
                raise KimiControllerModelProtocolIncompleteError(
                    "fresh consumer invoked Agent"
                )
            path, checkpoint, checkpoint_sha, artifact_path, artifact_sha = (
                _load_artifact_checkpoint(request, controller, run_root)
            )
            artifact = _mapping(checkpoint.get("artifact"), "checkpoint artifact")
            source = _mapping(checkpoint.get("source"), "checkpoint source")
            source_relative = _string(source.get("path"), "checkpoint source path")
            artifact_relative = _string(artifact.get("path"), "checkpoint artifact path")
            reads = [tool for tool in parent_tools if tool["name"] == "Read"]
            if len(reads) != 1 or any(tool["name"] != "Read" for tool in parent_tools):
                raise KimiControllerModelProtocolIncompleteError(
                    "fresh consumer must contain one exact native Read and no opaque tools"
                )
            read = reads[0]
            read_relative, _ = _workspace_relative(
                _mapping(read.get("args"), "consumer Read args").get("path"),
                workspace=workspace,
                label="consumer Read",
            )
            if read_relative == source_relative:
                raise KimiControllerModelProtocolIncompleteError(
                    "fresh consumer read the forbidden producer source"
                )
            if read_relative != artifact_relative or read.get("is_error") is not False:
                raise KimiControllerModelProtocolIncompleteError(
                    "fresh consumer did not successfully read the checkpoint artifact"
                )
            if not hmac.compare_digest(sha256_file(artifact_path), artifact_sha):
                raise KimiControllerError("artifact changed during fresh consumption")
            timestamp = _event_time(
                _mapping(read.get("record"), "consumer Read result record"),
                "consumer Read result",
            )
            observations = (
                {
                    "type": "adapter.file_hash_observed",
                    "time": timestamp,
                    "observation_phase": "execution",
                    "toolCallId": read["call_id"],
                    "path": artifact_relative,
                    "sha256": artifact_sha,
                },
                {
                    "type": "adapter.artifact_handoff",
                    "time": timestamp,
                    "path": artifact_relative,
                    "sha256": artifact_sha,
                    "boundary": "fresh_process_subagent_artifact_checkpoint",
                },
            )
            return ControlFinalization(
                evidence_locators=(
                    _record_locator("artifact-checkpoint", path, checkpoint_sha),
                    f"{main_wire}:{read['call_line']}",
                    f"{artifact_path}#sha256={artifact_sha}",
                ),
                observation_records=observations,
            )
        if operation != "spawn_exactly_one_producer":
            raise KimiControllerError(f"unsupported subagent operation: {operation}")
        if set(parent_tools[index]["name"] for index in range(len(parent_tools))) != {"Agent"} or len(parent_tools) != 1:
            raise KimiControllerModelProtocolIncompleteError(
                "producer parent must make exactly one Agent call"
            )
        agent_call = parent_tools[0]
        args = _mapping(agent_call.get("args"), "Agent arguments")
        if (
            args.get("subagent_type") != "coder"
            or "resume" in args
            or args.get("run_in_background") not in {None, False}
            or agent_call.get("is_error") is not False
        ):
            raise KimiControllerModelProtocolIncompleteError(
                "producer did not make one foreground Agent(coder) call"
            )
        output = _string(agent_call.get("output"), "Agent result output")
        output_lines = output.splitlines()
        if len(output_lines) < 5:
            raise KimiControllerError("Agent result lacks the native completion header")
        child_id_line = output_lines[0].partition(":")
        type_line = output_lines[1].partition(":")
        status_line = output_lines[2].partition(":")
        if (
            child_id_line[0] != "agent_id"
            or type_line != ("actual_subagent_type", ":", " coder")
            or status_line != ("status", ":", " completed")
            or output_lines[3] != ""
            or output_lines[4] != "[summary]"
        ):
            raise KimiControllerError("Agent result is not an exact native coder completion")
        child_id = child_id_line[2].strip()
        if _AGENT_ID_RE.fullmatch(child_id) is None or child_id == "main":
            raise KimiControllerError("Agent result child id is unsafe")
        if set(agents) != {"main", child_id}:
            raise KimiControllerError("native state does not contain exactly one child")
        child_state = _mapping(agents.get(child_id), "native child state")
        child_dir = session_dir / "agents" / child_id
        if (
            child_state.get("type") != "sub"
            or child_state.get("parentAgentId") != "main"
            or Path(_string(child_state.get("homedir"), "child homedir")).resolve()
            != child_dir
        ):
            raise KimiControllerError("native state child/parent identity is invalid")
        child_wire_path = child_dir / "wire.jsonl"
        child_wire, child_sha, _ = _wire_capture(
            request.stage_result,
            run_root=run_root,
            main=False,
            expected_path=child_wire_path,
        )
        child_records = _wire_records(child_wire)
        profiles = [
            (line, record)
            for line, record in child_records
            if record.get("type") == "config.update" and "profileName" in record
        ]
        if len(profiles) != 1 or profiles[0][1].get("profileName") != "coder":
            raise KimiControllerError("child wire does not prove actual coder profile")
        triggers = [
            (line, record)
            for line, record in child_records
            if record.get("type") == "context.append_message"
            and isinstance(record.get("message"), Mapping)
            and isinstance(record["message"].get("origin"), Mapping)
            and record["message"]["origin"].get("kind") == "system_trigger"
            and record["message"]["origin"].get("name") == "subagent"
        ]
        if len(triggers) != 1:
            raise KimiControllerError("child wire lacks one exact subagent trigger")
        child_tools = _correlated_tools(child_records, label="subagent child wire")
        if [tool["name"] for tool in child_tools] != ["Read", "Write"]:
            raise KimiControllerModelProtocolIncompleteError(
                "child must perform exactly one Read then one Write"
            )
        read, write = child_tools
        if read.get("is_error") is not False or write.get("is_error") is not False:
            raise KimiControllerModelProtocolIncompleteError(
                "child Read/Write did not both succeed"
            )
        allowed_reads = _list(controller.get("child_allowed_read_paths"), "allowed child reads")
        required_writes = _list(
            controller.get("child_required_write_paths"), "required child writes"
        )
        if len(allowed_reads) != 1 or len(required_writes) != 1:
            raise KimiControllerError("subagent binding does not declare one source/artifact")
        source_relative, source_path = _workspace_relative(
            _mapping(read.get("args"), "child Read args").get("path"),
            workspace=workspace,
            label="child source Read",
        )
        artifact_relative, artifact_path = _workspace_relative(
            _mapping(write.get("args"), "child Write args").get("path"),
            workspace=workspace,
            label="child artifact Write",
        )
        if source_relative != allowed_reads[0] or artifact_relative != required_writes[0]:
            raise KimiControllerModelProtocolIncompleteError(
                "child Read/Write paths drifted from the binding"
            )
        expected_absolute = _owned_path(
            controller.get("required_artifact_absolute_path"),
            run_root=run_root,
            label="required artifact",
            must_exist=True,
            require_file=True,
        )
        if artifact_path != expected_absolute or artifact_path.is_symlink():
            raise KimiControllerError("child artifact absolute path mismatch")
        if not source_path.is_file() or source_path.is_symlink():
            raise KimiControllerError("child source is absent or unsafe")
        write_args = _mapping(write.get("args"), "child Write args")
        if write_args.get("mode", "overwrite") != "overwrite":
            raise KimiControllerModelProtocolIncompleteError(
                "child artifact Write is not overwrite mode"
            )
        content = _string(write_args.get("content"), "child Write content")
        content_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        artifact_sha = sha256_file(artifact_path)
        if not hmac.compare_digest(content_sha, artifact_sha):
            raise KimiControllerError("child Write content does not match artifact bytes")
        source_sha = sha256_file(source_path)
        checkpoint_path = _owned_path(
            controller.get("artifact_checkpoint_record_path"),
            run_root=run_root,
            label="artifact checkpoint",
        )
        checkpoint, checkpoint_sha = _write_record(
            checkpoint_path,
            {
                "schema_name": ARTIFACT_RECORD_SCHEMA,
                "schema_version": CONTROLLER_SCHEMA_VERSION,
                "harness_id": "kimi",
                "run_id": request.run_id,
                "case_id": request.case_id,
                "producer_stage": {"index": request.stage_index, "name": request.stage_name},
                "workspace": str(workspace),
                "session_id": session_id,
                "parent_agent_id": "main",
                "child_agent_id": child_id,
                "actual_subagent_type": "coder",
                "state": {"path": str(state_path), "sha256": sha256_file(state_path)},
                "parent_wire": {
                    "path": str(main_wire),
                    "sha256": main_sha,
                    "agent_call_line": agent_call["call_line"],
                    "agent_result_line": agent_call["result_line"],
                },
                "child_wire": {
                    "path": str(child_wire),
                    "sha256": child_sha,
                    "profile_line": profiles[0][0],
                    "trigger_line": triggers[0][0],
                },
                "source": {
                    "path": source_relative,
                    "sha256": source_sha,
                    "read_call_id": read["call_id"],
                    "read_call_line": read["call_line"],
                    "read_result_line": read["result_line"],
                },
                "artifact": {
                    "path": artifact_relative,
                    "absolute_path": str(artifact_path),
                    "sha256": artifact_sha,
                    "byte_length": artifact_path.stat().st_size,
                    "write_content_sha256": content_sha,
                    "write_call_id": write["call_id"],
                    "write_call_line": write["call_line"],
                    "write_result_line": write["result_line"],
                },
            },
            run_id=request.run_id,
            run_root=run_root,
            label="artifact checkpoint",
        )
        observation = {
            "type": "adapter.subagent_lifecycle_observed",
            "time": _event_time(
                _mapping(agent_call.get("record"), "Agent result record"),
                "Agent result",
            ),
            "session_id": session_id,
            "parent_agent_id": "main",
            "child_agent_id": child_id,
            "state": {"path": str(state_path), "sha256": sha256_file(state_path)},
            "parent_wire": {
                "path": str(main_wire),
                "sha256": main_sha,
                "tool_call_line": agent_call["call_line"],
                "tool_result_line": agent_call["result_line"],
            },
            "child_wire": {
                "path": str(child_wire),
                "sha256": child_sha,
                "trigger_line": triggers[0][0],
            },
        }
        source_read_observation = {
            "type": "adapter.file_hash_observed",
            "time": _event_time(
                _mapping(read.get("record"), "child Read result record"),
                "child Read result",
            ),
            "observation_phase": "execution",
            "toolCallId": read["call_id"],
            "path": source_relative,
            "sha256": source_sha,
        }
        return ControlFinalization(
            evidence_locators=(
                f"{main_wire}:{agent_call['call_line']}",
                f"{child_wire}:{read['call_line']}",
                f"{child_wire}:{write['call_line']}",
                f"{artifact_path}#sha256={artifact_sha}",
                _record_locator("artifact-checkpoint", checkpoint_path, checkpoint_sha),
            ),
            observation_records=(observation, source_read_observation),
        )


__all__ = [
    "ARTIFACT_RECORD_SCHEMA",
    "COMPACTION_RECORD_SCHEMA",
    "CONTROLLER_SCHEMA_VERSION",
    "KimiAcpCompactionController",
    "KimiControllerError",
    "KimiControllerModelProtocolIncompleteError",
    "KimiExactSessionController",
    "KimiSubagentArtifactController",
    "SESSION_RECORD_SCHEMA",
]
