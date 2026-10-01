"""Direct, non-scoring execution evidence for Kimi Code stages.

The observer is deliberately shaped like ``NativeBoundaryController`` so the
executor can call it after stage surfaces have been activated and before the
Kimi process is spawned.  It does not launch a process and it does not infer
events from assistant text.  The only records it returns are backed by:

* a run-scoped provider-broker request observer;
* the executor's immutable copy of the native main-agent wire; or
* bytes hashed synchronously before or after a successful stage boundary.

Missing direct evidence is represented by an omitted observation.  The
existing required-Event-IR gate therefore fails closed without this module
inventing a score, verdict, or success disposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Protocol, Sequence

from .disposition import KimiExecutionInvalidError
from .executor import (
    ControlDirective,
    ControlFinalization,
    StageControlFinalizeRequest,
    StageControlRequest,
)
from .provider_broker import (
    InstructionRequestObservation,
    REQUEST_OBSERVATION_SCHEMA_NAME,
    REQUEST_OBSERVATION_SCHEMA_VERSION,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SESSION_ID_RE = re.compile(r"^session_[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_MARKER_BYTES = 8192
_EXPECTED_MESSAGE_ROLES = ("system", "user", "user")
_KNOWN_NON_MUTATING_TOOLS = frozenset({"Read", "Glob", "Grep", "Skill"})
_WRITE_TOOL = "Write"


class KimiDirectEvidenceError(KimiExecutionInvalidError):
    """Direct stage evidence was malformed or escaped its Kimi run."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            failure_category="DIRECT_EXECUTION_EVIDENCE_INVALID",
            retry_eligible=False,
        )


class InstructionObserverBroker(Protocol):
    """Narrow provider-broker surface consumed by this observer."""

    run_id: str
    case_id: str
    trial_id: str

    def configure_instruction_observer(
        self,
        *,
        run_id: str,
        stage_index: int,
        marker: bytes,
        expected_roles: Sequence[str] = _EXPECTED_MESSAGE_ROLES,
    ) -> Path: ...

    def finalize_instruction_observer(
        self, *, run_id: str, stage_index: int
    ) -> InstructionRequestObservation: ...


@dataclass(frozen=True)
class _InstructionMarker:
    path: Path
    file_sha256: str
    offset: int
    length: int
    sha256: str
    observer_path: Path


@dataclass(frozen=True)
class _ReadSnapshot:
    path: str
    sha256: str
    byte_length: int
    observed_at: str


@dataclass(frozen=True)
class _PreparedStage:
    run_id: str
    case_id: str
    stage_index: int
    stage_name: str
    control_kind: str
    run_root: Path
    workspace: Path
    stage_document_sha256: str
    prior_results_sha256: str
    expected_events: tuple[str, ...]
    expected_read_paths: tuple[str, ...]
    expected_read_snapshots: tuple[_ReadSnapshot, ...]
    produced_artifacts: tuple[Mapping[str, Any], ...]
    instruction: _InstructionMarker | None


@dataclass(frozen=True)
class _MainWire:
    source_path: Path
    captured_path: Path
    sha256: str
    line_count: int
    session_id: str
    records: tuple[tuple[int, Mapping[str, Any]], ...]
    prior_line_count: int


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiDirectEvidenceError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise KimiDirectEvidenceError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise KimiDirectEvidenceError(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise KimiDirectEvidenceError(f"{label} must be an integer >= {minimum}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise KimiDirectEvidenceError(f"{label} SHA-256 is invalid")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KimiDirectEvidenceError(
            "direct evidence request is not JSON-canonicalizable"
        ) from exc
    return _sha256_bytes(raw)


def _timestamp(value: Any, label: str) -> datetime:
    if isinstance(value, bool):
        raise KimiDirectEvidenceError(f"{label} timestamp is invalid")
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000 if value > 100_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OSError, OverflowError, ValueError) as exc:
            raise KimiDirectEvidenceError(f"{label} timestamp is invalid") from exc
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise KimiDirectEvidenceError(f"{label} timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise KimiDirectEvidenceError(f"{label} timestamp has no timezone")
        return parsed.astimezone(timezone.utc)
    raise KimiDirectEvidenceError(f"{label} timestamp is invalid")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _run_root(stage_document: Mapping[str, Any], run_id: str) -> Path:
    runtime = _mapping(stage_document.get("runtime_paths"), "stage runtime_paths")
    trace = Path(_string(runtime.get("trace"), "runtime trace path"))
    if not trace.is_absolute() or len(trace.parents) < 3:
        raise KimiDirectEvidenceError(
            "runtime trace cannot identify the exact Kimi run root"
        )
    supplied = trace.parents[2].absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise KimiDirectEvidenceError("derived Kimi run root is unsafe")
    root = supplied.resolve(strict=True)
    if (
        root != supplied
        or "kimi" not in root.as_posix().casefold()
        or run_id not in root.as_posix()
    ):
        raise KimiDirectEvidenceError("derived run root lacks Kimi/run ownership")
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
    supplied = raw if isinstance(raw, Path) else Path(_string(raw, f"{label} path"))
    supplied = supplied.absolute()
    if not supplied.is_absolute() or supplied.is_symlink():
        raise KimiDirectEvidenceError(
            f"{label} must be an absolute non-symlink path"
        )
    try:
        relative = supplied.relative_to(run_root)
    except ValueError as exc:
        raise KimiDirectEvidenceError(f"{label} escapes the Kimi run") from exc
    cursor = run_root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiDirectEvidenceError(f"{label} traverses a symlink")
    try:
        resolved = supplied.resolve(strict=must_exist)
    except OSError as exc:
        raise KimiDirectEvidenceError(f"{label} is unavailable") from exc
    if not _is_relative_to(resolved, run_root):
        raise KimiDirectEvidenceError(f"{label} resolves outside the Kimi run")
    if require_file and not resolved.is_file():
        raise KimiDirectEvidenceError(f"{label} is not a regular file")
    if require_dir and not resolved.is_dir():
        raise KimiDirectEvidenceError(f"{label} is not a directory")
    return resolved


def _workspace_path(
    raw: Any, *, workspace: Path, run_root: Path, label: str
) -> tuple[str, Path]:
    value = Path(_string(raw, f"{label} path"))
    supplied = value if value.is_absolute() else workspace / value
    path = _owned_path(supplied, run_root=run_root, label=label)
    try:
        relative = path.relative_to(workspace)
    except ValueError as exc:
        raise KimiDirectEvidenceError(f"{label} escapes the workspace") from exc
    if not relative.parts:
        raise KimiDirectEvidenceError(f"{label} cannot name the workspace root")
    return relative.as_posix(), path


def _workspace(
    request: StageControlRequest | StageControlFinalizeRequest, run_root: Path
) -> Path:
    runtime = _mapping(request.stage_document.get("runtime_paths"), "runtime paths")
    return _owned_path(
        runtime.get("workspace"),
        run_root=run_root,
        label="stage workspace",
        must_exist=True,
        require_dir=True,
    )


def _expected_events(stage_document: Mapping[str, Any]) -> tuple[str, ...]:
    values = _array(stage_document.get("expected_event_ir"), "expected_event_ir")
    if any(not isinstance(value, str) or not value for value in values):
        raise KimiDirectEvidenceError("expected_event_ir contains an invalid type")
    if len(set(values)) != len(values):
        raise KimiDirectEvidenceError("expected_event_ir contains duplicates")
    return tuple(values)


def _artifact_surface(stage_document: Mapping[str, Any]) -> Mapping[str, Any]:
    surfaces = _mapping(stage_document.get("surfaces"), "stage surfaces")
    return _mapping(surfaces.get("artifacts"), "stage artifact surface")


def _expected_read_paths(
    artifacts: Mapping[str, Any], *, workspace: Path, run_root: Path
) -> tuple[str, ...]:
    candidates: list[Any] = []
    consume = _array(artifacts.get("consume", []), "artifact consume paths")
    candidates.extend(consume)
    for key in ("entry_artifact", "consumes_carrier_artifact"):
        value = artifacts.get(key)
        if value is not None:
            candidates.append(value)
    normalized = [
        _workspace_path(
            value,
            workspace=workspace,
            run_root=run_root,
            label="expected Read artifact",
        )[0]
        for value in candidates
    ]
    return tuple(dict.fromkeys(normalized))


def _produced_artifacts(
    artifacts: Mapping[str, Any], *, workspace: Path, run_root: Path
) -> tuple[Mapping[str, Any], ...]:
    records: list[Mapping[str, Any]] = []
    for index, raw in enumerate(
        _array(artifacts.get("produce", []), "produced artifacts")
    ):
        record = _mapping(raw, f"produced artifact {index}")
        if set(record) != {"path", "change", "sha256_required_after_stage"}:
            raise KimiDirectEvidenceError(
                "produced artifact declaration keys drifted"
            )
        if record.get("sha256_required_after_stage") != "yes":
            raise KimiDirectEvidenceError(
                "produced artifact does not require a post-stage SHA-256"
            )
        relative, _ = _workspace_path(
            record.get("path"),
            workspace=workspace,
            run_root=run_root,
            label="produced artifact",
        )
        change = _string(record.get("change"), "produced artifact change")
        records.append({"path": relative, "change": change})
    paths = [str(record["path"]) for record in records]
    if len(set(paths)) != len(paths):
        raise KimiDirectEvidenceError("produced artifact path is duplicated")
    return tuple(records)


def _select_utf8_marker(content: bytes) -> tuple[int, bytes]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KimiDirectEvidenceError(
            "run-local Kimi instruction is not UTF-8"
        ) from exc
    if not text.strip() or "\0" in text:
        raise KimiDirectEvidenceError(
            "run-local Kimi instruction has no safe marker content"
        )
    if len(content) <= _MAX_MARKER_BYTES:
        return 0, content

    # Select one complete, non-empty UTF-8 line when possible.  Kimi may wrap
    # the project file with its own headings, but it preserves instruction
    # lines verbatim in the provider request.  Longest-first makes accidental
    # matches less likely while byte-offset ordering keeps the choice stable.
    candidates: list[tuple[int, int, bytes]] = []
    byte_offset = 0
    for line in text.splitlines(keepends=True):
        encoded = line.encode("utf-8")
        stripped = encoded.strip()
        if stripped and len(stripped) <= _MAX_MARKER_BYTES:
            inner = encoded.index(stripped)
            candidates.append((len(stripped), byte_offset + inner, stripped))
        byte_offset += len(encoded)
    if candidates:
        _, offset, marker = max(candidates, key=lambda item: (item[0], -item[1]))
        return offset, marker

    # A single line may itself exceed the broker limit.  Trim only on decoded
    # character boundaries and record the exact original byte offset.
    marker_chars: list[str] = []
    marker_size = 0
    for character in text:
        encoded = character.encode("utf-8")
        if marker_size + len(encoded) > _MAX_MARKER_BYTES:
            break
        marker_chars.append(character)
        marker_size += len(encoded)
    marker = "".join(marker_chars).encode("utf-8")
    if not marker.strip():
        raise KimiDirectEvidenceError(
            "run-local Kimi instruction has no bounded UTF-8 marker"
        )
    return 0, marker


def _read_jsonl(path: Path, label: str) -> tuple[tuple[int, Mapping[str, Any]], ...]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise KimiDirectEvidenceError(f"{label} is not UTF-8 JSONL") from exc
    lines = text.splitlines()
    if not lines:
        raise KimiDirectEvidenceError(f"{label} is empty")
    records: list[tuple[int, Mapping[str, Any]]] = []
    for line_number, line in enumerate(lines, 1):
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise KimiDirectEvidenceError(
                f"{label} is malformed at line {line_number}"
            ) from exc
        records.append((line_number, _mapping(decoded, f"{label}:{line_number}")))
    return tuple(records)


def _prior_wire_boundary(
    prior_results: Sequence[Mapping[str, Any]],
    *,
    source_path: Path,
    captured_bytes: bytes,
    run_root: Path,
) -> int:
    candidates: list[tuple[int, str]] = []
    for result_index, raw_result in enumerate(prior_results):
        result = _mapping(raw_result, f"prior stage result {result_index}")
        wire = _mapping(result.get("wire"), "prior stage wire")
        for raw_capture in _array(wire.get("captures"), "prior wire captures"):
            capture = _mapping(raw_capture, "prior wire capture")
            prior_source = _owned_path(
                capture.get("source_path"),
                run_root=run_root,
                label="prior native wire source",
                must_exist=True,
                require_file=True,
            )
            if prior_source != source_path:
                continue
            line_count = _integer(
                capture.get("line_count"), "prior wire line count", minimum=1
            )
            digest = _sha256(capture.get("sha256"), "prior wire")
            candidates.append((line_count, digest))
    if not candidates:
        return 0
    line_count, digest = max(candidates, key=lambda item: item[0])
    lines = captured_bytes.splitlines(keepends=True)
    if len(lines) <= line_count or not hmac.compare_digest(
        _sha256_bytes(b"".join(lines[:line_count])), digest
    ):
        raise KimiDirectEvidenceError(
            "current main wire is not an append-only extension of prior evidence"
        )
    return line_count


def _main_wire(
    request: StageControlFinalizeRequest, *, run_root: Path
) -> _MainWire:
    wire = _mapping(request.stage_result.get("wire"), "stage wire evidence")
    captures = [
        _mapping(raw, "stage wire capture")
        for raw in _array(wire.get("captures"), "stage wire captures")
    ]
    mains = [capture for capture in captures if capture.get("is_main") is True]
    if len(mains) != 1:
        raise KimiDirectEvidenceError(
            "stage evidence does not identify exactly one native main wire"
        )
    capture = mains[0]
    if set(capture) != {
        "source_path",
        "captured_path",
        "sha256",
        "line_count",
        "is_main",
    }:
        raise KimiDirectEvidenceError("native main wire capture keys drifted")
    source = _owned_path(
        capture.get("source_path"),
        run_root=run_root,
        label="native main wire",
        must_exist=True,
        require_file=True,
    )
    captured = _owned_path(
        capture.get("captured_path"),
        run_root=run_root,
        label="immutable captured main wire",
        must_exist=True,
        require_file=True,
    )
    if (
        source.name != "wire.jsonl"
        or source.parent.name != "main"
        or source.parent.parent.name != "agents"
    ):
        raise KimiDirectEvidenceError(
            "native main wire path does not have Kimi session layout"
        )
    session_id = source.parent.parent.parent.name
    if _SESSION_ID_RE.fullmatch(session_id) is None:
        raise KimiDirectEvidenceError("native main wire has an invalid session id")
    digest = _sha256(capture.get("sha256"), "captured main wire")
    line_count = _integer(
        capture.get("line_count"), "captured main wire line count", minimum=1
    )
    captured_bytes = captured.read_bytes()
    if (
        not hmac.compare_digest(_sha256_bytes(captured_bytes), digest)
        or len(captured_bytes.splitlines()) != line_count
    ):
        raise KimiDirectEvidenceError(
            "immutable captured main wire hash/line count drifted"
        )
    # At finalize this stage owns the just-created capture.  Requiring exact
    # source bytes prevents a concurrent append from being silently ignored.
    if source.read_bytes() != captured_bytes:
        raise KimiDirectEvidenceError(
            "native main wire changed after its immutable capture"
        )
    main_copy = _owned_path(
        wire.get("main_path"),
        run_root=run_root,
        label="stage main wire copy",
        must_exist=True,
        require_file=True,
    )
    if (
        wire.get("main_sha256") != digest
        or not hmac.compare_digest(_sha256_file(main_copy), digest)
        or main_copy.read_bytes() != captured_bytes
    ):
        raise KimiDirectEvidenceError("stage main wire copies do not agree")
    prior_line_count = _prior_wire_boundary(
        request.prior_stage_results,
        source_path=source,
        captured_bytes=captured_bytes,
        run_root=run_root,
    )
    return _MainWire(
        source_path=source,
        captured_path=captured,
        sha256=digest,
        line_count=line_count,
        session_id=session_id,
        records=_read_jsonl(captured, "immutable captured main wire"),
        prior_line_count=prior_line_count,
    )


def _parse_tool_call(
    record: Mapping[str, Any],
) -> tuple[str, str, Mapping[str, Any]] | None:
    if record.get("type") != "context.append_loop_event":
        return None
    event = _mapping(record.get("event"), "native loop event")
    if event.get("type") != "tool.call":
        return None
    call_id = _string(event.get("id", event.get("toolCallId")), "tool call id")
    function = event.get("function")
    if isinstance(function, Mapping):
        name = _string(function.get("name"), "tool call name")
        arguments: Any = function.get("arguments", {})
    else:
        name = _string(event.get("name"), "tool call name")
        arguments = event.get("args", event.get("arguments", {}))
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise KimiDirectEvidenceError(
                "native tool arguments are malformed JSON"
            ) from exc
    return call_id, name, _mapping(arguments, "native tool arguments")


def _parse_tool_result(
    record: Mapping[str, Any],
) -> tuple[str, bool] | None:
    if record.get("type") != "context.append_loop_event":
        return None
    event = _mapping(record.get("event"), "native loop event")
    if event.get("type") != "tool.result":
        return None
    call_id = _string(event.get("toolCallId"), "tool result id")
    result = _mapping(event.get("result"), "native tool result")
    is_error = result.get("isError")
    if is_error is not None and not isinstance(is_error, bool):
        raise KimiDirectEvidenceError("native tool result isError is malformed")
    return call_id, is_error is True


def _correlated_tools(wire: _MainWire) -> tuple[Mapping[str, Any], ...]:
    calls: dict[str, dict[str, Any]] = {}
    results: dict[str, dict[str, Any]] = {}
    for line_number, record in wire.records:
        if line_number <= wire.prior_line_count:
            continue
        call = _parse_tool_call(record)
        if call is not None:
            call_id, name, arguments = call
            if call_id in calls:
                raise KimiDirectEvidenceError(
                    "native main wire contains a duplicate tool call id"
                )
            calls[call_id] = {
                "call_id": call_id,
                "name": name,
                "args": arguments,
                "call_line": line_number,
            }
        result = _parse_tool_result(record)
        if result is not None:
            call_id, is_error = result
            if call_id in results:
                raise KimiDirectEvidenceError(
                    "native main wire contains a duplicate tool result id"
                )
            results[call_id] = {
                "is_error": is_error,
                "result_line": line_number,
                "result_time": record.get("time", record.get("timestamp")),
            }
    if set(calls) != set(results):
        raise KimiDirectEvidenceError(
            "native main wire contains uncorrelated stage tool events"
        )
    correlated: list[Mapping[str, Any]] = []
    for call_id, call in calls.items():
        result = results[call_id]
        if int(result["result_line"]) <= int(call["call_line"]):
            raise KimiDirectEvidenceError("native tool result precedes its call")
        correlated.append({**call, **result})
    return tuple(sorted(correlated, key=lambda item: int(item["call_line"])))


def _new_loop_request(wire: _MainWire) -> tuple[int, Mapping[str, Any]]:
    requests = [
        (line, record)
        for line, record in wire.records
        if line > wire.prior_line_count
        and record.get("type") == "llm.request"
        and record.get("kind") == "loop"
    ]
    if not requests:
        raise KimiDirectEvidenceError(
            "native main wire contains no new loop request for this stage"
        )
    return requests[0]


def _session_start_observation(
    *,
    request: StageControlFinalizeRequest,
    prepared: _PreparedStage,
    wire: _MainWire,
) -> tuple[Mapping[str, Any], tuple[str, ...]] | None:
    needs_start = (
        not prepared.expected_events
        or "session.started" in prepared.expected_events
    )
    if not needs_start:
        return None
    if wire.prior_line_count:
        if "session.started" in prepared.expected_events:
            raise KimiDirectEvidenceError(
                "session.started is required for an append-only resumed session"
            )
        return None
    stdout = _mapping(request.stage_result.get("stdout"), "stage stdout evidence")
    stdout_path = _owned_path(
        stdout.get("path"),
        run_root=prepared.run_root,
        label="immutable stream-json stdout",
        must_exist=True,
        require_file=True,
    )
    stdout_sha = _sha256(stdout.get("sha256"), "stream-json stdout")
    stdout_line_count = _integer(
        stdout.get("line_count"), "stream-json stdout line count", minimum=1
    )
    if (
        not hmac.compare_digest(_sha256_file(stdout_path), stdout_sha)
        or len(stdout_path.read_bytes().splitlines()) != stdout_line_count
    ):
        raise KimiDirectEvidenceError("stream-json stdout hash/line count drifted")
    hints = [
        (line, record)
        for line, record in _read_jsonl(stdout_path, "stream-json stdout")
        if record.get("role") == "meta"
        and record.get("type") == "session.resume_hint"
    ]
    if len(hints) != 1 or hints[0][1].get("session_id") != wire.session_id:
        raise KimiDirectEvidenceError(
            "fresh native session lacks one matching stream-json session hint"
        )
    request_line, native_request = _new_loop_request(wire)
    request_time = native_request.get("time", native_request.get("timestamp"))
    _timestamp(request_time, "fresh native session request")
    record = {
        "type": "adapter.session_start_observed",
        "time": request_time,
        "session_id": wire.session_id,
        "stdout": {
            "path": str(stdout_path),
            "sha256": stdout_sha,
            "line_count": stdout_line_count,
            "hint_line": hints[0][0],
        },
        "wire": {
            "path": str(wire.captured_path),
            "sha256": wire.sha256,
            "line_count": wire.line_count,
            "request_line": request_line,
            "prior_line_count": wire.prior_line_count,
        },
    }
    return record, (
        f"{stdout_path}:{hints[0][0]}",
        f"{wire.captured_path}:{request_line}",
    )


def _validate_observer_snapshot(
    observation: InstructionRequestObservation,
    *,
    configured_path: Path,
    run_root: Path,
    request: StageControlFinalizeRequest,
    marker_sha256: str,
    trial_id: str,
) -> Mapping[str, Any]:
    if not isinstance(observation, InstructionRequestObservation):
        raise KimiDirectEvidenceError(
            "provider broker returned an invalid instruction observation"
        )
    path = _owned_path(
        observation.path,
        run_root=run_root,
        label="instruction request observer",
        must_exist=True,
        require_file=True,
    )
    if path != configured_path or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise KimiDirectEvidenceError(
            "instruction request observer path/mode drifted"
        )
    raw = path.read_bytes()
    digest = _sha256(observation.sha256, "instruction request observer")
    if not hmac.compare_digest(_sha256_bytes(raw), digest):
        raise KimiDirectEvidenceError(
            "instruction request observer SHA-256 drifted"
        )
    line_count = _integer(
        observation.line_count, "instruction observer line count", minimum=1
    )
    line = _integer(observation.line, "instruction observer line", minimum=1)
    lines = raw.splitlines()
    if len(lines) != line_count or line > line_count:
        raise KimiDirectEvidenceError(
            "instruction request observer line locator drifted"
        )
    records: list[Mapping[str, Any]] = []
    for line_number, raw_line in enumerate(lines, 1):
        try:
            decoded = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise KimiDirectEvidenceError(
                f"instruction request observer is malformed at line {line_number}"
            ) from exc
        records.append(_mapping(decoded, "instruction request observer record"))
    selected = records[line - 1]
    required_keys = {
        "schema_name",
        "schema_version",
        "harness_id",
        "run_id",
        "case_id",
        "trial_id",
        "stage_index",
        "sequence",
        "time",
        "body_sha256",
        "body_bytes",
        "target_sha256",
        "message_roles",
        "expected_substring_present",
        "expected_substring_sha256",
    }
    if set(selected) != required_keys or (
        selected.get("schema_name") != REQUEST_OBSERVATION_SCHEMA_NAME
        or selected.get("schema_version") != REQUEST_OBSERVATION_SCHEMA_VERSION
        or selected.get("harness_id") != "kimi"
        or selected.get("run_id") != request.run_id
        or selected.get("case_id") != request.case_id
        or selected.get("trial_id") != trial_id
        or selected.get("stage_index") != request.stage_index
        or selected.get("sequence") != line
        or selected.get("expected_substring_present") is not True
        or selected.get("expected_substring_sha256") != marker_sha256
        or selected.get("message_roles") != list(_EXPECTED_MESSAGE_ROLES)
    ):
        raise KimiDirectEvidenceError(
            "instruction request observer identity/marker drifted"
        )
    body_sha = _sha256(selected.get("body_sha256"), "observed request body")
    _sha256(selected.get("target_sha256"), "observed request target")
    _integer(selected.get("body_bytes"), "observed request byte count", minimum=1)
    _timestamp(selected.get("time"), "observed provider request")
    if (
        observation.body_sha256 != body_sha
        or observation.marker_sha256 != marker_sha256
        or observation.message_roles != _EXPECTED_MESSAGE_ROLES
        or observation.observed_time != selected.get("time")
    ):
        raise KimiDirectEvidenceError(
            "provider broker observation object differs from immutable evidence"
        )
    return selected


def _instruction_observation(
    *,
    request: StageControlFinalizeRequest,
    prepared: _PreparedStage,
    broker: InstructionObserverBroker,
    marker: _InstructionMarker,
    wire: _MainWire,
) -> tuple[Mapping[str, Any], tuple[str, ...]]:
    if not marker.path.is_file() or marker.path.is_symlink() or not hmac.compare_digest(
        _sha256_file(marker.path), marker.file_sha256
    ):
        raise KimiDirectEvidenceError(
            "run-local instruction changed after observer configuration"
        )
    try:
        observation = broker.finalize_instruction_observer(
            run_id=request.run_id, stage_index=request.stage_index
        )
    except Exception as exc:
        raise KimiDirectEvidenceError(
            "provider broker could not finalize instruction evidence"
        ) from exc
    selected = _validate_observer_snapshot(
        observation,
        configured_path=marker.observer_path,
        run_root=prepared.run_root,
        request=request,
        marker_sha256=marker.sha256,
        trial_id=_string(getattr(broker, "trial_id", None), "broker trial id"),
    )
    request_line, native_request = _new_loop_request(wire)
    marker_bytes = marker.path.read_bytes()[
        marker.offset : marker.offset + marker.length
    ]
    marker_text = marker_bytes.decode("utf-8")
    prompt_candidates: list[tuple[int, str]] = []
    for line_number, record in wire.records:
        if not wire.prior_line_count < line_number < request_line:
            continue
        if record.get("type") != "config.update":
            continue
        system_prompt = record.get("systemPrompt")
        if isinstance(system_prompt, str) and marker_text in system_prompt:
            prompt_candidates.append(
                (line_number, _sha256_bytes(system_prompt.encode("utf-8")))
            )
    if len(prompt_candidates) != 1:
        raise KimiDirectEvidenceError(
            "instruction marker lacks one preceding native system prompt"
        )
    config_line, system_prompt_sha = prompt_candidates[0]
    if (
        native_request.get("systemPromptHash") != system_prompt_sha
        or native_request.get("messageCount") != len(_EXPECTED_MESSAGE_ROLES) - 1
        or observation.line != 1
    ):
        raise KimiDirectEvidenceError(
            "native loop request does not bind the observed instruction request"
        )
    native_time = _timestamp(
        native_request.get("time", native_request.get("timestamp")),
        "native loop request",
    )
    observed_time = _timestamp(selected.get("time"), "provider request observation")
    if native_time > observed_time:
        raise KimiDirectEvidenceError(
            "provider request observation precedes its native loop request"
        )
    record = {
        "type": "adapter.instruction_loading_observed",
        "time": selected["time"],
        "session_id": wire.session_id,
        "instruction": {
            "path": str(marker.path),
            "sha256": marker.file_sha256,
            "marker_offset": marker.offset,
            "marker_length": marker.length,
            "marker_sha256": marker.sha256,
        },
        "request_observer": {
            "path": str(marker.observer_path),
            "sha256": observation.sha256,
            "line": observation.line,
            "line_count": observation.line_count,
        },
        "wire": {
            "path": str(wire.captured_path),
            "sha256": wire.sha256,
            "line_count": wire.line_count,
            "prior_line_count": wire.prior_line_count,
            "llm_request_line": request_line,
            "llm_request_ordinal": 1,
            "message_count": native_request["messageCount"],
            "config_update_line": config_line,
            "system_prompt_sha256": system_prompt_sha,
            "native_source_path": str(wire.source_path),
        },
    }
    return record, (
        f"{marker.observer_path}:{observation.line}",
        f"{wire.captured_path}:{request_line}",
        f"{marker.path}#sha256={marker.file_sha256}",
    )


def _safe_post_read(
    *,
    selected: Mapping[str, Any],
    tools: Sequence[Mapping[str, Any]],
    selected_path: str,
    workspace: Path,
    run_root: Path,
) -> bool:
    result_line = int(selected["result_line"])
    for tool in tools:
        if int(tool["call_line"]) <= result_line:
            continue
        name = str(tool["name"])
        if name in _KNOWN_NON_MUTATING_TOOLS:
            continue
        if name != _WRITE_TOOL:
            # Agent, Shell, MCP and unknown tools may have modified the shared
            # workspace even when their final result reports an error.
            return False
        args = _mapping(tool.get("args"), "post-Read Write arguments")
        if args.get("mode", "overwrite") != "overwrite":
            return False
        try:
            write_path, _ = _workspace_path(
                args.get("path"),
                workspace=workspace,
                run_root=run_root,
                label="post-Read Write",
            )
        except KimiDirectEvidenceError:
            return False
        if tool.get("is_error") is False and write_path == selected_path:
            return False
    return True


def _safe_pre_read(
    *,
    selected: Mapping[str, Any],
    tools: Sequence[Mapping[str, Any]],
    selected_path: str,
    workspace: Path,
    run_root: Path,
) -> bool:
    """Prove that a runner snapshot still described bytes at native Read time."""

    call_line = int(selected["call_line"])
    for tool in tools:
        if int(tool["call_line"]) >= call_line:
            continue
        name = str(tool["name"])
        if name in _KNOWN_NON_MUTATING_TOOLS:
            continue
        if name not in {_WRITE_TOOL, "Edit"}:
            return False
        args = _mapping(tool.get("args"), "pre-Read mutation arguments")
        try:
            mutation_path, _ = _workspace_path(
                args.get("path"),
                workspace=workspace,
                run_root=run_root,
                label="pre-Read structured mutation",
            )
        except KimiDirectEvidenceError:
            return False
        if mutation_path == selected_path:
            return False
    return True


def _read_observations(
    *,
    prepared: _PreparedStage,
    wire: _MainWire,
    finalize_time: str,
    stage_completed_at: str,
) -> tuple[tuple[Mapping[str, Any], ...], tuple[str, ...]]:
    if "file.read" not in prepared.expected_events:
        return (), ()
    if not prepared.expected_read_paths:
        raise KimiDirectEvidenceError(
            "stage expects file.read without a declared artifact input"
        )
    tools = _correlated_tools(wire)
    successful_reads: dict[str, list[Mapping[str, Any]]] = {
        path: [] for path in prepared.expected_read_paths
    }
    for tool in tools:
        if tool.get("name") != "Read" or tool.get("is_error") is not False:
            continue
        relative, _ = _workspace_path(
            _mapping(tool.get("args"), "Read arguments").get("path"),
            workspace=prepared.workspace,
            run_root=prepared.run_root,
            label="successful Read",
        )
        if relative in successful_reads:
            successful_reads[relative].append(tool)

    selected_reads: list[tuple[str, Mapping[str, Any]]] = []
    for relative in prepared.expected_read_paths:
        candidates = successful_reads[relative]
        if not candidates:
            return (), ()
        selected = max(candidates, key=lambda item: int(item["result_line"]))
        selected_reads.append((relative, selected))

    records: list[Mapping[str, Any]] = []
    locators: list[str] = []
    snapshots = {
        snapshot.path: snapshot for snapshot in prepared.expected_read_snapshots
    }
    completed = _timestamp(stage_completed_at, "stage completion")
    finalized = _timestamp(finalize_time, "post-stage finalize")
    if finalized < completed:
        raise KimiDirectEvidenceError(
            "post-stage finalize time precedes stage completion"
        )
    for relative, selected in selected_reads:
        result_time_raw = selected.get("result_time")
        result_time = _timestamp(result_time_raw, "native Read result")
        if result_time > completed:
            raise KimiDirectEvidenceError(
                "native Read result timestamp follows stage completion"
            )
        if not _safe_post_read(
            selected=selected,
            tools=tools,
            selected_path=relative,
            workspace=prepared.workspace,
            run_root=prepared.run_root,
        ):
            snapshot = snapshots.get(relative)
            if snapshot is None or not _safe_pre_read(
                selected=selected,
                tools=tools,
                selected_path=relative,
                workspace=prepared.workspace,
                run_root=prepared.run_root,
            ):
                continue
            _timestamp(snapshot.observed_at, "pre-stage Read snapshot")
            records.append(
                {
                    "type": "adapter.file_hash_observed",
                    "time": result_time_raw,
                    "observation_phase": "pre_stage",
                    "pre_stage_observed_at": snapshot.observed_at,
                    "toolCallId": selected["call_id"],
                    "path": relative,
                    "sha256": snapshot.sha256,
                    "byte_length": snapshot.byte_length,
                    "native_call_line": selected["call_line"],
                    "native_result_line": selected["result_line"],
                    "captured_wire_path": str(wire.captured_path),
                    "captured_wire_sha256": wire.sha256,
                    "captured_wire_line_count": wire.line_count,
                }
            )
            locators.append(f"{wire.captured_path}:{selected['result_line']}")
            continue
        _, path = _workspace_path(
            relative,
            workspace=prepared.workspace,
            run_root=prepared.run_root,
            label="post-stage Read artifact",
        )
        if path.is_symlink() or not path.is_file():
            return (), ()
        digest = _sha256_file(path)
        records.append(
            {
                "type": "adapter.file_hash_observed",
                "time": finalize_time,
                "observation_phase": "post_stage",
                "stage_completed_at": stage_completed_at,
                "toolCallId": selected["call_id"],
                "path": relative,
                "sha256": digest,
                "native_call_line": selected["call_line"],
                "native_result_line": selected["result_line"],
                "captured_wire_path": str(wire.captured_path),
                "captured_wire_sha256": wire.sha256,
                "captured_wire_line_count": wire.line_count,
            }
        )
        locators.extend(
            (
                f"{wire.captured_path}:{selected['result_line']}",
                f"{path}#sha256={digest}",
            )
        )
    return tuple(records), tuple(locators)


def _handoff_observations(
    *,
    prepared: _PreparedStage,
    finalize_time: str,
    stage_completed_at: str,
) -> tuple[tuple[Mapping[str, Any], ...], tuple[str, ...]]:
    if "artifact.handoff" not in prepared.expected_events:
        return (), ()
    if not prepared.produced_artifacts:
        raise KimiDirectEvidenceError(
            "stage expects artifact.handoff without artifacts.produce"
        )
    if _timestamp(finalize_time, "post-stage finalize") < _timestamp(
        stage_completed_at, "stage completion"
    ):
        raise KimiDirectEvidenceError(
            "artifact handoff observation precedes stage completion"
        )
    records: list[Mapping[str, Any]] = []
    locators: list[str] = []
    for declaration in prepared.produced_artifacts:
        relative, path = _workspace_path(
            declaration.get("path"),
            workspace=prepared.workspace,
            run_root=prepared.run_root,
            label="produced handoff artifact",
        )
        if path.is_symlink() or not path.is_file():
            return (), ()
        digest = _sha256_file(path)
        records.append(
            {
                "type": "adapter.artifact_handoff",
                "time": finalize_time,
                "observation_phase": "post_stage",
                "stage_completed_at": stage_completed_at,
                "path": relative,
                "sha256": digest,
                "declared_change": declaration["change"],
                "boundary": "stage_completion_artifacts_produce",
            }
        )
        locators.append(f"{path}#sha256={digest}")
    return tuple(records), tuple(locators)


class KimiDirectEvidenceObserver:
    """Prepare/finalize observer compatible with ``NativeBoundaryController``."""

    def __init__(self, broker: InstructionObserverBroker | None = None) -> None:
        self.broker = broker
        self._prepared: dict[tuple[str, str, int], _PreparedStage] = {}

    @staticmethod
    def _key(
        request: StageControlRequest | StageControlFinalizeRequest,
    ) -> tuple[str, str, int]:
        if (
            not isinstance(request.run_id, str)
            or not request.run_id
            or not isinstance(request.case_id, str)
            or not request.case_id
            or not isinstance(request.stage_index, int)
            or isinstance(request.stage_index, bool)
            or request.stage_index < 0
            or not isinstance(request.stage_name, str)
            or not request.stage_name
            or not isinstance(request.control_kind, str)
            or not request.control_kind
        ):
            raise KimiDirectEvidenceError(
                "direct evidence request identity is invalid"
            )
        return request.run_id, request.case_id, request.stage_index

    def prepare(self, request: StageControlRequest) -> ControlDirective:
        key = self._key(request)
        if key in self._prepared:
            raise KimiDirectEvidenceError(
                "direct evidence observer is already prepared for this stage"
            )
        run_root = _run_root(request.stage_document, request.run_id)
        workspace = _workspace(request, run_root)
        expected = _expected_events(request.stage_document)
        artifacts = _artifact_surface(request.stage_document)
        expected_reads = _expected_read_paths(
            artifacts, workspace=workspace, run_root=run_root
        )
        read_snapshots: list[_ReadSnapshot] = []
        for relative in expected_reads:
            _, path = _workspace_path(
                relative,
                workspace=workspace,
                run_root=run_root,
                label="pre-stage Read snapshot",
            )
            if path.is_symlink() or not path.is_file():
                continue
            content = path.read_bytes()
            read_snapshots.append(
                _ReadSnapshot(
                    path=relative,
                    sha256=_sha256_bytes(content),
                    byte_length=len(content),
                    observed_at=datetime.now(timezone.utc).isoformat(),
                )
            )
        produced = _produced_artifacts(
            artifacts, workspace=workspace, run_root=run_root
        )
        if "file.read" in expected and not expected_reads:
            raise KimiDirectEvidenceError(
                "file.read is expected without a declared artifact input"
            )
        if "artifact.handoff" in expected and not produced:
            raise KimiDirectEvidenceError(
                "artifact.handoff is expected without artifacts.produce"
            )

        instruction_marker: _InstructionMarker | None = None
        evidence: list[str] = []
        if "instruction.loaded" in expected:
            surfaces = _mapping(request.stage_document.get("surfaces"), "stage surfaces")
            instruction_surface = _mapping(
                surfaces.get("instruction"), "stage instruction surface"
            )
            if instruction_surface.get("kind") not in {
                "project_instruction",
                "dynamic_project_instruction",
            } or instruction_surface.get("target") != "workspace/.kimi-code/AGENTS.md":
                raise KimiDirectEvidenceError(
                    "instruction.loaded is not bound to the Kimi project surface"
                )
            instruction = _owned_path(
                workspace / ".kimi-code" / "AGENTS.md",
                run_root=run_root,
                label="run-local Kimi instruction",
                must_exist=True,
                require_file=True,
            )
            if instruction.parent != workspace / ".kimi-code":
                raise KimiDirectEvidenceError(
                    "instruction path is not .kimi-code/AGENTS.md"
                )
            content = instruction.read_bytes()
            offset, marker = _select_utf8_marker(content)
            marker_sha = _sha256_bytes(marker)
            broker = self.broker
            if broker is None or (
                getattr(broker, "run_id", None) != request.run_id
                or getattr(broker, "case_id", None) != request.case_id
                or not isinstance(getattr(broker, "trial_id", None), str)
                or not getattr(broker, "trial_id", None)
            ):
                raise KimiDirectEvidenceError(
                    "instruction evidence lacks the exact run/case provider broker"
                )
            try:
                observer_path = broker.configure_instruction_observer(
                    run_id=request.run_id,
                    stage_index=request.stage_index,
                    marker=marker,
                    expected_roles=_EXPECTED_MESSAGE_ROLES,
                )
            except Exception as exc:
                raise KimiDirectEvidenceError(
                    "provider broker could not configure instruction observation"
                ) from exc
            observer_path = _owned_path(
                observer_path,
                run_root=run_root,
                label="instruction request observer",
                must_exist=True,
                require_file=True,
            )
            if (
                stat.S_IMODE(observer_path.stat().st_mode) != 0o600
                or observer_path.read_bytes()
            ):
                raise KimiDirectEvidenceError(
                    "instruction request observer is not a private empty file"
                )
            instruction_marker = _InstructionMarker(
                path=instruction,
                file_sha256=_sha256_bytes(content),
                offset=offset,
                length=len(marker),
                sha256=marker_sha,
                observer_path=observer_path,
            )
            evidence.extend(
                (
                    str(observer_path),
                    (
                        f"kimi:instruction-marker:{instruction}"
                        f"#offset={offset}&length={len(marker)}&sha256={marker_sha}"
                    ),
                )
            )

        prepared = _PreparedStage(
            run_id=request.run_id,
            case_id=request.case_id,
            stage_index=request.stage_index,
            stage_name=request.stage_name,
            control_kind=request.control_kind,
            run_root=run_root,
            workspace=workspace,
            stage_document_sha256=_canonical_sha256(request.stage_document),
            prior_results_sha256=_canonical_sha256(request.prior_stage_results),
            expected_events=expected,
            expected_read_paths=expected_reads,
            expected_read_snapshots=tuple(read_snapshots),
            produced_artifacts=produced,
            instruction=instruction_marker,
        )
        self._prepared[key] = prepared
        return ControlDirective(evidence_locators=tuple(evidence))

    def finalize(
        self, request: StageControlFinalizeRequest
    ) -> ControlFinalization:
        key = self._key(request)
        prepared = self._prepared.pop(key, None)
        if prepared is None:
            raise KimiDirectEvidenceError(
                "direct evidence observer was not prepared for this stage"
            )
        if (
            request.stage_name != prepared.stage_name
            or request.control_kind != prepared.control_kind
            or not hmac.compare_digest(
                _canonical_sha256(request.stage_document),
                prepared.stage_document_sha256,
            )
            or not hmac.compare_digest(
                _canonical_sha256(request.prior_stage_results),
                prepared.prior_results_sha256,
            )
        ):
            raise KimiDirectEvidenceError(
                "direct evidence finalize request drifted from prepare"
            )
        stage_result = _mapping(request.stage_result, "stage result")
        stage_identity = _mapping(stage_result.get("stage"), "stage result identity")
        if (
            stage_result.get("schema_name") != "safety_bench_kimi_stage_execution"
            or stage_result.get("schema_version") != 1
            or stage_result.get("harness_id") != "kimi"
            or stage_result.get("run_id") != request.run_id
            or stage_result.get("case_id") != request.case_id
            or stage_identity
            != {"index": request.stage_index, "name": request.stage_name}
            or stage_result.get("return_code") != 0
            or stage_result.get("timed_out") is not False
            or Path(_string(stage_result.get("cwd"), "stage cwd")).resolve()
            != prepared.workspace
        ):
            raise KimiDirectEvidenceError(
                "direct evidence requires one successful exact Kimi stage"
            )
        stage_completed_at = _string(
            stage_result.get("completed_at"), "stage completed_at"
        )
        completed = _timestamp(stage_completed_at, "stage completion")
        finalize_clock = datetime.now(timezone.utc)
        if finalize_clock < completed:
            raise KimiDirectEvidenceError(
                "local finalize clock precedes the recorded stage completion"
            )
        finalize_time = finalize_clock.isoformat()

        needs_wire = (
            prepared.instruction is not None
            or "file.read" in prepared.expected_events
            or not prepared.expected_events
            or "session.started" in prepared.expected_events
        )
        wire = _main_wire(request, run_root=prepared.run_root) if needs_wire else None
        observations: list[Mapping[str, Any]] = []
        evidence: list[str] = []
        if wire is not None:
            start = _session_start_observation(
                request=request,
                prepared=prepared,
                wire=wire,
            )
            if start is not None:
                record, locators = start
                observations.append(record)
                evidence.extend(locators)
        if prepared.instruction is not None:
            assert wire is not None
            broker = self.broker
            if broker is None:
                raise KimiDirectEvidenceError(
                    "instruction observer lost its provider broker"
                )
            record, locators = _instruction_observation(
                request=request,
                prepared=prepared,
                broker=broker,
                marker=prepared.instruction,
                wire=wire,
            )
            observations.append(record)
            evidence.extend(locators)
        if "file.read" in prepared.expected_events:
            assert wire is not None
            records, locators = _read_observations(
                prepared=prepared,
                wire=wire,
                finalize_time=finalize_time,
                stage_completed_at=stage_completed_at,
            )
            observations.extend(records)
            evidence.extend(locators)
        records, locators = _handoff_observations(
            prepared=prepared,
            finalize_time=finalize_time,
            stage_completed_at=stage_completed_at,
        )
        observations.extend(records)
        evidence.extend(locators)
        return ControlFinalization(
            evidence_locators=tuple(dict.fromkeys(evidence)),
            observation_records=tuple(observations),
        )


__all__ = [
    "InstructionObserverBroker",
    "KimiDirectEvidenceError",
    "KimiDirectEvidenceObserver",
]
