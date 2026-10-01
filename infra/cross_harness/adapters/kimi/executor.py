"""Fail-closed, run-local stage executor for the Kimi 328-case plan.

The executor deliberately has no built-in subprocess launcher.  Formal model
execution is possible only after a caller injects a launcher which produces a
run-local, hash-bound attestation for both an enforced OS isolation boundary
and a run-scoped credential broker.  This module never scores or analyzes a
case; it captures raw evidence and delegates Event IR construction to an
injected normalizer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Protocol, Sequence

from ...contract import validate_event_document
from .bench_materializer import load_bench_materialization_manifest
from .disposition import (
    COMPLETED,
    EXECUTION_INVALID,
    MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS,
    MODEL_PROTOCOL_INCOMPLETE,
    KimiExecutionDispositionError,
    KimiExecutionInvalidError,
    KimiModelProtocolIncompleteError,
)
from .lifecycle import atomic_write_json
from .materializer import runtime_tree_sha256, sha256_file, tree_sha256
from .mcp_stdio_proxy import (
    ProxyPaths,
    canonical_argv_sha256,
    validate_health_evidence,
)
from .runner import ExecutionContext, ExecutionResult, MaterializedCase


ATTESTATION_SCHEMA_NAME = "safety_bench_kimi_isolated_launcher_attestation"
ATTESTATION_SCHEMA_VERSION = 1
EXECUTION_SCHEMA_NAME = "safety_bench_kimi_execution_evidence"
EXECUTION_SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_STAGE_RE = re.compile(r"[^A-Za-z0-9._-]+")
_SENSITIVE_ENV_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|credential|bearer|auth)", re.IGNORECASE
)
_OTHER_HARNESS_ENV_RE = re.compile(r"^(?:CLAUDE|CODEX|GEMINI|HERMES|OPENCLAW)")
_FORBIDDEN_OUTPUT_KEYS = {
    "attack_success",
    "confirmed_compromise",
    "oracle",
    "oracle_path",
    "progress_node",
    "score",
    "scored_result",
    "verdict",
}
_RESUME_CONTROLLER_KIND = "kimi_exact_native_session_resume_v1"
_COMPACTION_CONTROLLER_KIND = "kimi_acp_exact_manual_compaction_resume_v1"


class KimiStageExecutorError(KimiExecutionInvalidError):
    """A stage could not be executed without weakening an evidence gate."""

    def __init__(
        self,
        message: str,
        *,
        failure_category: str = "EXECUTOR_EVIDENCE_INVALID",
        retry_eligible: bool = False,
    ) -> None:
        super().__init__(
            message,
            failure_category=failure_category,
            retry_eligible=retry_eligible,
        )


@dataclass(frozen=True)
class StageMount:
    """One hash-bound run-local mount selected from verified stage metadata."""

    kind: str
    path: Path
    path_type: str
    sha256: str
    mode: int
    provenance: str
    provenance_sha256: str


@dataclass(frozen=True)
class StageLaunchRequest:
    """Credential-free process request passed to an attested launcher."""

    run_id: str
    case_id: str
    stage_index: int
    stage_name: str
    argv: tuple[str, ...]
    executable_sha256: str
    cwd: Path
    env: Mapping[str, str]
    timeout_seconds: int
    stdout_path: Path
    wire_copy_path: Path
    result_path: Path
    launcher_attestation_path: Path
    materialization_manifest_path: Path
    materialization_manifest_sha256: str
    write_mounts: tuple[StageMount, ...]
    read_only_mounts: tuple[StageMount, ...]


class StageProcess(Protocol):
    pid: int
    returncode: int | None

    def communicate(
        self,
        input: bytes | None = None,
        timeout: int | float | None = None,
    ) -> tuple[bytes, bytes]: ...

    def exchange_jsonrpc(
        self,
        *,
        request_frames: tuple[bytes, ...],
        expected_response_ids: tuple[str | int, ...],
        timeout: int | float,
    ) -> tuple[bytes, bytes]: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


class IsolatedStageLauncher(Protocol):
    """A launcher is trusted only through its per-run on-disk attestation."""

    jsonrpc_exchange_supported: bool

    def attest(self, *, run_id: str, run_root: Path) -> Path: ...

    def spawn(self, request: StageLaunchRequest) -> StageProcess: ...


@dataclass(frozen=True)
class ControlDirective:
    """Narrow launch patch returned by an injected native-boundary controller."""

    argv_suffix: tuple[str, ...] = ()
    evidence_locators: tuple[str, ...] = ()
    launch_mode: str = "prompt"
    jsonrpc_exchange: "JsonRpcExchange | None" = None


@dataclass(frozen=True)
class JsonRpcExchange:
    """Ordered request/response exchange owned by a controller process."""

    request_frames: tuple[bytes, ...]
    expected_response_ids: tuple[str | int, ...]

    def __post_init__(self) -> None:
        if not self.request_frames or len(self.request_frames) != len(
            self.expected_response_ids
        ):
            raise ValueError("JSON-RPC exchange requires one response id per request")
        if any(not isinstance(frame, bytes) or not frame for frame in self.request_frames):
            raise ValueError("JSON-RPC request frames must be non-empty bytes")
        if any(
            isinstance(value, bool)
            or not isinstance(value, (str, int))
            or (isinstance(value, str) and not value)
            for value in self.expected_response_ids
        ):
            raise ValueError("JSON-RPC response ids must be non-empty strings or integers")
        if len(set(self.expected_response_ids)) != len(self.expected_response_ids):
            raise ValueError("JSON-RPC response ids must be unique")


@dataclass(frozen=True)
class StageControlRequest:
    run_id: str
    case_id: str
    stage_index: int
    stage_name: str
    control_kind: str
    stage_document: Mapping[str, Any]
    prior_stage_results: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class StageControlFinalizeRequest:
    run_id: str
    case_id: str
    stage_index: int
    stage_name: str
    control_kind: str
    stage_document: Mapping[str, Any]
    prior_stage_results: tuple[Mapping[str, Any], ...]
    stage_result: Mapping[str, Any]


@dataclass(frozen=True)
class ControlFinalization:
    evidence_locators: tuple[str, ...] = ()
    observation_records: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class MatchedControlBoundaryRequest:
    run_id: str
    case_id: str
    stage_index: int
    stage_name: str
    manifest_path: Path
    manifest_sha256: str


@dataclass(frozen=True)
class MatchedControlBoundaryResult:
    run_id: str
    case_id: str
    stage_index: int
    stage_name: str
    manifest_path: Path
    manifest_sha256: str
    evidence_path: Path
    evidence_sha256: str


@dataclass(frozen=True)
class MatchedControlBoundaryFinalization:
    evidence_path: Path
    evidence_sha256: str
    applied_stage_indices: tuple[int, ...]


class MatchedControlBoundary(Protocol):
    """Apply a predeclared matched-control intervention at stage boundaries."""

    def apply_before_stage(
        self, request: MatchedControlBoundaryRequest
    ) -> MatchedControlBoundaryResult | None: ...

    def finalize(self) -> MatchedControlBoundaryFinalization: ...


class NativeBoundaryController(Protocol):
    def prepare(self, request: StageControlRequest) -> ControlDirective: ...

    def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization: ...


@dataclass(frozen=True)
class WireCapture:
    source_path: Path
    captured_path: Path
    sha256: str
    line_count: int
    is_main: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_path": str(self.source_path),
            "captured_path": str(self.captured_path),
            "sha256": self.sha256,
            "line_count": self.line_count,
            "is_main": self.is_main,
        }


@dataclass(frozen=True)
class StageCapture:
    index: int
    name: str
    pid: int
    return_code: int
    stdout_path: Path
    stdout_sha256: str
    stderr_path: Path
    stderr_sha256: str
    main_wire_path: Path
    main_wire_sha256: str
    wire_captures: tuple[WireCapture, ...]
    result_path: Path
    mcp_health: tuple[Mapping[str, Any], ...] = ()
    control_evidence: tuple[str, ...] = ()
    controller_trace_path: Path | None = None
    controller_trace_sha256: str | None = None
    observation_trace_path: Path | None = None
    observation_trace_sha256: str | None = None
    timed_out: bool = False
    timeout_seconds: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "pid": self.pid,
            "return_code": self.return_code,
            "stdout_path": str(self.stdout_path),
            "stdout_sha256": self.stdout_sha256,
            "stderr_path": str(self.stderr_path),
            "stderr_sha256": self.stderr_sha256,
            "main_wire_path": str(self.main_wire_path),
            "main_wire_sha256": self.main_wire_sha256,
            "wire_captures": [item.as_dict() for item in self.wire_captures],
            "result_path": str(self.result_path),
            "mcp_health": [dict(item) for item in self.mcp_health],
            "control_evidence": list(self.control_evidence),
            "controller_trace_path": (
                str(self.controller_trace_path)
                if self.controller_trace_path is not None
                else None
            ),
            "controller_trace_sha256": self.controller_trace_sha256,
            "observation_trace_path": (
                str(self.observation_trace_path)
                if self.observation_trace_path is not None
                else None
            ),
            "observation_trace_sha256": self.observation_trace_sha256,
            "timed_out": self.timed_out,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class NormalizationRequest:
    run_id: str
    case_id: str
    manifest_path: Path
    manifest_sha256: str
    stage_captures: tuple[StageCapture, ...]
    output_path: Path


class EventIRNormalizer(Protocol):
    def normalize(self, request: NormalizationRequest) -> Path: ...


@dataclass(frozen=True)
class _StagePrepared:
    document: Mapping[str, Any]
    runtime: Mapping[str, Path]
    stage_root: Path
    assets_root: Path
    prompt_path: Path
    prompt: str
    prompt_sha256: str
    mcp_reservations: tuple[Mapping[str, Any], ...]
    reviewed_read_only_files: tuple[Mapping[str, Any], ...]
    controls: tuple[str, ...]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _payload_sha256(document: Mapping[str, Any], field_name: str) -> str:
    return _canonical_json_sha256(
        {key: value for key, value in document.items() if key != field_name}
    )


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise KimiStageExecutorError(f"{label} must be a lowercase SHA-256")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiStageExecutorError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KimiStageExecutorError(f"{label} must be a non-empty string")
    return value


def _safe_stage_name(value: str) -> str:
    cleaned = _SAFE_STAGE_RE.sub("-", value).strip("-._")
    return (cleaned or "stage")[:48]


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _reject_symlink_chain(path: Path, *, stop: Path, label: str) -> None:
    candidate = path.absolute()
    stop_absolute = stop.absolute()
    while True:
        if candidate.is_symlink():
            raise KimiStageExecutorError(f"{label} has a symlink component: {candidate}")
        if candidate == stop_absolute:
            break
        if candidate.parent == candidate or not _is_relative_to(candidate, stop_absolute):
            raise KimiStageExecutorError(f"{label} escapes the current Kimi run")
        candidate = candidate.parent


def _owned_path(
    raw: Any,
    *,
    run_root: Path,
    run_id: str,
    label: str,
    must_exist: bool | None = None,
) -> Path:
    path = Path(_string(raw, label)).absolute()
    root = run_root.absolute()
    _reject_symlink_chain(path, stop=root, label=label)
    resolved = path.resolve(strict=False)
    resolved_root = root.resolve(strict=True)
    if not _is_relative_to(resolved, resolved_root):
        raise KimiStageExecutorError(f"{label} escapes the current Kimi run")
    if "kimi" not in root.as_posix().casefold() or run_id not in root.as_posix():
        raise KimiStageExecutorError("run root lacks kimi/run_id ownership")
    if must_exist is True and not path.exists():
        raise KimiStageExecutorError(f"{label} is missing: {path}")
    if must_exist is False and path.exists():
        raise KimiStageExecutorError(f"{label} unexpectedly exists: {path}")
    return path


def _assert_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise KimiStageExecutorError(f"{label} must be a regular file: {path}")


def _stage_mount(
    path: Path,
    *,
    kind: str,
    path_type: str,
    provenance: str,
    manifest_sha256: str,
) -> StageMount:
    """Snapshot one already-verified mount without following an unsafe leaf."""

    if path.is_symlink():
        raise KimiStageExecutorError(f"{kind} mount is a symlink")
    if path_type == "tree":
        if not path.is_dir():
            raise KimiStageExecutorError(f"{kind} mount is not a directory")
        digest = (
            runtime_tree_sha256(path)
            if kind == "workspace"
            else tree_sha256(path)
        )
    elif path_type == "file":
        _assert_regular(path, f"{kind} mount")
        digest = sha256_file(path)
    else:
        raise KimiStageExecutorError(f"{kind} mount has an invalid path type")
    return StageMount(
        kind=kind,
        path=path.resolve(strict=True),
        path_type=path_type,
        sha256=digest,
        mode=stat.S_IMODE(path.stat().st_mode),
        provenance=provenance,
        provenance_sha256=manifest_sha256,
    )


def _trusted_system_python() -> tuple[Path, str]:
    raw = getattr(sys, "_base_executable", None) or sys.executable
    if not isinstance(raw, str) or not raw:
        raise KimiStageExecutorError("Python base executable is unavailable")
    try:
        executable = Path(raw).resolve(strict=True)
        system_root = Path("/usr").resolve(strict=True)
        executable.relative_to(system_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise KimiStageExecutorError(
            "trusted MCP Python executable must resolve below /usr"
        ) from exc
    _assert_regular(executable, "trusted MCP Python executable")
    if not os.access(executable, os.X_OK):
        raise KimiStageExecutorError("trusted MCP Python executable is not executable")
    return executable, sha256_file(executable)


def _atomic_write_bytes(path: Path, content: bytes, *, run_id: str) -> None:
    if path.exists() or path.is_symlink():
        raise KimiStageExecutorError(f"refusing to overwrite execution evidence: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f"tmp-kimi-{run_id}-",
        suffix=".evidence",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_remove(path: Path, *, run_id: str, stage_index: int) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        raise KimiStageExecutorError(f"refusing to remove linked activation target: {path}")
    tombstone = path.parent / (
        f".removed-kimi-{run_id}-stage-{stage_index:03d}-{path.name}"
    )
    if tombstone.exists() or tombstone.is_symlink():
        raise KimiStageExecutorError(f"activation tombstone already exists: {tombstone}")
    os.replace(path, tombstone)
    if tombstone.is_dir():
        shutil.rmtree(tombstone)
    else:
        tombstone.unlink()


def _atomic_replace_tree(
    source: Path,
    target: Path,
    *,
    expected_sha256: str,
    run_id: str,
    stage_index: int,
) -> None:
    if source.is_symlink() or not source.is_dir():
        raise KimiStageExecutorError(f"prepared skill tree is unsafe: {source}")
    if not hmac.compare_digest(tree_sha256(source), expected_sha256):
        raise KimiStageExecutorError("prepared skill tree SHA-256 drifted")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = target.parent / (
        f".staged-kimi-{run_id}-stage-{stage_index:03d}-{target.name}"
    )
    backup = target.parent / (
        f".previous-kimi-{run_id}-stage-{stage_index:03d}-{target.name}"
    )
    if any(item.exists() or item.is_symlink() for item in (staging, backup)):
        raise KimiStageExecutorError("stage activation scratch path already exists")
    shutil.copytree(source, staging, copy_function=shutil.copy2)
    try:
        if not hmac.compare_digest(tree_sha256(staging), expected_sha256):
            raise KimiStageExecutorError("staged skill tree SHA-256 mismatch")
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_dir():
                raise KimiStageExecutorError("skill activation target is not a directory")
            os.replace(target, backup)
        try:
            os.replace(staging, target)
        except Exception:
            if backup.exists() and not target.exists():
                os.replace(backup, target)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup.exists() and not target.exists():
            os.replace(backup, target)


def _atomic_replace_file(
    source: Path,
    target: Path,
    *,
    expected_sha256: str,
    run_id: str,
) -> None:
    _assert_regular(source, "prepared MCP configuration")
    if not hmac.compare_digest(sha256_file(source), expected_sha256):
        raise KimiStageExecutorError("prepared MCP configuration SHA-256 drifted")
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise KimiStageExecutorError("MCP activation target is unsafe")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        dir=target.parent,
        prefix=f".staged-kimi-{run_id}-",
        suffix=".mcp.json",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(source.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if not hmac.compare_digest(sha256_file(temporary), expected_sha256):
            raise KimiStageExecutorError("staged MCP configuration SHA-256 mismatch")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def _forbidden_paths(value: Any, prefix: str = "output") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if str(key).casefold() in _FORBIDDEN_OUTPUT_KEYS:
                found.append(path)
            found.extend(_forbidden_paths(child, path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.extend(_forbidden_paths(child, f"{prefix}[{index}]"))
    return found


def _validate_stdout_jsonl(content: bytes, path: Path) -> int:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KimiStageExecutorError("Kimi stream-json stdout is not UTF-8") from exc
    count = 0
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise KimiStageExecutorError(
                f"malformed Kimi stream-json stdout at {path}:{line_number}"
            ) from exc
        if not isinstance(record, Mapping):
            raise KimiStageExecutorError(
                f"Kimi stdout record is not an object at {path}:{line_number}"
            )
        count += 1
    if count == 0:
        raise KimiStageExecutorError("Kimi stream-json stdout is empty")
    return count


class KimiStageExecutor:
    """Execute a reviewed Kimi materialization one fresh process per stage."""

    def __init__(
        self,
        *,
        launcher: IsolatedStageLauncher,
        event_ir_normalizer: EventIRNormalizer,
        executable: Path,
        executable_sha256: str,
        timeout_seconds: int = 300,
        path_environment: str = os.defpath,
        resume_controller: NativeBoundaryController | None = None,
        compact_controller: NativeBoundaryController | None = None,
        subagent_controller: NativeBoundaryController | None = None,
        direct_evidence_observer: NativeBoundaryController | None = None,
        matched_control_boundary: MatchedControlBoundary | None = None,
    ) -> None:
        if launcher is None:
            raise ValueError("an attested isolated launcher must be injected")
        if event_ir_normalizer is None:
            raise ValueError("an Event IR normalizer must be injected")
        if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds < 1:
            raise ValueError("timeout_seconds must be a positive integer")
        if not isinstance(path_environment, str) or not path_environment:
            raise ValueError("path_environment must be a non-empty string")
        self.launcher = launcher
        self.event_ir_normalizer = event_ir_normalizer
        self.executable = Path(executable).resolve(strict=True)
        _assert_regular(self.executable, "Kimi executable")
        self.executable_sha256 = _require_sha256(
            executable_sha256, "Kimi executable SHA-256"
        )
        if not hmac.compare_digest(sha256_file(self.executable), self.executable_sha256):
            raise ValueError("Kimi executable SHA-256 does not match its bytes")
        self.timeout_seconds = timeout_seconds
        self.path_environment = path_environment
        self.resume_controller = resume_controller
        self.compact_controller = compact_controller
        self.subagent_controller = subagent_controller
        self.direct_evidence_observer = direct_evidence_observer
        self.matched_control_boundary = matched_control_boundary

    def _prepare_direct_evidence(
        self,
        stage: _StagePrepared,
        *,
        run_id: str,
        case_id: str,
        prior_results: Sequence[Mapping[str, Any]],
    ) -> ControlDirective:
        """Arm the passive observer after activation and before process spawn.

        This hook is intentionally separate from native lifecycle controllers:
        direct evidence may add locators, but it may not alter argv, own a
        process, or inject a JSON-RPC exchange.
        """

        observer = self.direct_evidence_observer
        if observer is None:
            return ControlDirective()
        result = observer.prepare(
            StageControlRequest(
                run_id=run_id,
                case_id=case_id,
                stage_index=int(stage.document["index"]),
                stage_name=str(stage.document["name"]),
                control_kind="direct_evidence",
                stage_document=stage.document,
                prior_stage_results=tuple(prior_results),
            )
        )
        if not isinstance(result, ControlDirective):
            raise KimiStageExecutorError(
                "direct evidence observer returned an invalid directive"
            )
        if (
            result.argv_suffix
            or result.launch_mode != "prompt"
            or result.jsonrpc_exchange is not None
        ):
            raise KimiStageExecutorError(
                "direct evidence observer attempted to alter stage execution"
            )
        if any(
            not isinstance(locator, str)
            or not locator
            or "\n" in locator
            or "\r" in locator
            for locator in result.evidence_locators
        ):
            raise KimiStageExecutorError(
                "direct evidence observer returned invalid prepare locators"
            )
        return result

    def _finalize_direct_evidence(
        self,
        stage: _StagePrepared,
        *,
        run_id: str,
        case_id: str,
        prior_results: Sequence[Mapping[str, Any]],
        stage_result: Mapping[str, Any],
    ) -> ControlFinalization:
        observer = self.direct_evidence_observer
        if observer is None:
            return ControlFinalization()
        result = observer.finalize(
            StageControlFinalizeRequest(
                run_id=run_id,
                case_id=case_id,
                stage_index=int(stage.document["index"]),
                stage_name=str(stage.document["name"]),
                control_kind="direct_evidence",
                stage_document=stage.document,
                prior_stage_results=tuple(prior_results),
                stage_result=json.loads(
                    json.dumps(stage_result, ensure_ascii=False)
                ),
            )
        )
        if not isinstance(result, ControlFinalization) or any(
            not isinstance(locator, str)
            or not locator
            or "\n" in locator
            or "\r" in locator
            for locator in getattr(result, "evidence_locators", ())
        ):
            raise KimiStageExecutorError(
                "direct evidence observer returned invalid finalize evidence"
            )
        for observation in result.observation_records:
            if not isinstance(observation, Mapping):
                raise KimiStageExecutorError(
                    "direct evidence observer returned a non-object observation"
                )
            record_type = observation.get("type")
            if not isinstance(record_type, str) or not record_type.startswith(
                "adapter."
            ):
                raise KimiStageExecutorError(
                    "direct evidence observer returned an invalid adapter observation"
                )
            forbidden = _forbidden_paths(
                observation, prefix="direct_evidence_observation"
            )
            if forbidden:
                raise KimiStageExecutorError(
                    "direct evidence observation contains analyzer/scoring fields: "
                    + ", ".join(forbidden)
                )
        return result

    def _validate_attestation(
        self, path: Path, *, run_id: str, run_root: Path
    ) -> tuple[Mapping[str, Any], str]:
        attestation_path = _owned_path(
            str(path),
            run_root=run_root,
            run_id=run_id,
            label="launcher attestation",
            must_exist=True,
        )
        _assert_regular(attestation_path, "launcher attestation")
        try:
            document = json.loads(attestation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KimiStageExecutorError("launcher attestation is malformed") from exc
        if not isinstance(document, Mapping):
            raise KimiStageExecutorError("launcher attestation must be an object")
        expected_keys = {
            "schema_name",
            "schema_version",
            "harness_id",
            "run_id",
            "run_root",
            "launcher_id",
            "isolation",
            "credential_broker",
            "evidence",
            "attestation_payload_sha256",
        }
        if set(document) != expected_keys:
            raise KimiStageExecutorError("launcher attestation field set drifted")
        if (
            document.get("schema_name") != ATTESTATION_SCHEMA_NAME
            or document.get("schema_version") != ATTESTATION_SCHEMA_VERSION
            or document.get("harness_id") != "kimi"
            or document.get("run_id") != run_id
            or Path(str(document.get("run_root"))).resolve() != run_root.resolve()
        ):
            raise KimiStageExecutorError("launcher attestation identity mismatch")
        _string(document.get("launcher_id"), "launcher attestation launcher_id")
        claimed = _require_sha256(
            document.get("attestation_payload_sha256"),
            "launcher attestation payload",
        )
        if not hmac.compare_digest(
            claimed, _payload_sha256(document, "attestation_payload_sha256")
        ):
            raise KimiStageExecutorError("launcher attestation self-hash mismatch")

        isolation = _mapping(document.get("isolation"), "launcher isolation")
        if set(isolation) != {
            "kind",
            "enforced",
            "host_user_state_mounted",
            "other_harness_state_mounted",
            "network_egress",
        }:
            raise KimiStageExecutorError("launcher isolation attestation field set drifted")
        isolation_kind = _string(isolation.get("kind"), "isolation.kind")
        if isolation_kind.casefold() in {"none", "host", "best_effort"}:
            raise KimiStageExecutorError("launcher isolation kind is not an enforced boundary")
        if (
            isolation.get("enforced") is not True
            or isolation.get("host_user_state_mounted") is not False
            or isolation.get("other_harness_state_mounted") is not False
            or isolation.get("network_egress") != "run_local_broker_only"
        ):
            raise KimiStageExecutorError("launcher isolation attestation is insufficient")

        broker = _mapping(document.get("credential_broker"), "credential broker")
        if set(broker) != {
            "kind",
            "run_id",
            "run_local",
            "verified",
            "external_credentials_in_kimi_env",
            "external_credentials_in_tool_child_env",
            "external_credentials_persisted",
        }:
            raise KimiStageExecutorError("credential broker attestation field set drifted")
        _string(broker.get("kind"), "credential_broker.kind")
        if (
            broker.get("run_id") != run_id
            or broker.get("run_local") is not True
            or broker.get("verified") is not True
            or broker.get("external_credentials_in_kimi_env") is not False
            or broker.get("external_credentials_in_tool_child_env") is not False
            or broker.get("external_credentials_persisted") is not False
        ):
            raise KimiStageExecutorError("run-local credential broker is not proven")

        evidence = document.get("evidence")
        if not isinstance(evidence, list) or len(evidence) < 2:
            raise KimiStageExecutorError(
                "launcher attestation requires isolation and broker evidence"
            )
        kinds: set[str] = set()
        for index, raw_record in enumerate(evidence):
            record = _mapping(raw_record, f"launcher evidence {index}")
            if set(record) != {"kind", "path", "sha256"}:
                raise KimiStageExecutorError("launcher evidence field set drifted")
            kind = _string(record.get("kind"), "launcher evidence kind")
            evidence_path = _owned_path(
                record.get("path"),
                run_root=run_root,
                run_id=run_id,
                label=f"launcher {kind} evidence",
                must_exist=True,
            )
            _assert_regular(evidence_path, f"launcher {kind} evidence")
            expected_digest = _require_sha256(
                record.get("sha256"), f"launcher {kind} evidence SHA-256"
            )
            if not hmac.compare_digest(sha256_file(evidence_path), expected_digest):
                raise KimiStageExecutorError(f"launcher {kind} evidence drifted")
            kinds.add(kind)
        if not {"os_isolation", "credential_broker"}.issubset(kinds):
            raise KimiStageExecutorError(
                "launcher attestation lacks direct isolation/broker evidence"
            )
        return document, sha256_file(attestation_path)

    def _validate_proxy_config(
        self,
        *,
        stage: Mapping[str, Any],
        run_root: Path,
        run_id: str,
        stage_index: int,
        expected_config_sha256: str,
    ) -> tuple[Mapping[str, Any], ...]:
        surfaces = _mapping(stage.get("surfaces"), "stage surfaces")
        mcp = _mapping(surfaces.get("mcp"), "stage MCP surface")
        prepared = _mapping(mcp.get("prepared_config"), "prepared MCP config")
        target = _owned_path(
            prepared.get("target"),
            run_root=run_root,
            run_id=run_id,
            label="prepared MCP config",
            must_exist=True,
        )
        _assert_regular(target, "prepared MCP config")
        if not hmac.compare_digest(sha256_file(target), expected_config_sha256):
            raise KimiStageExecutorError("prepared MCP config hash does not match activation")
        proxy = _mapping(prepared.get("evidence_proxy"), "MCP evidence proxy")
        try:
            trusted_proxy_path = Path(__file__).with_name(
                "mcp_stdio_proxy.py"
            ).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise KimiStageExecutorError(
                "trusted MCP proxy source is unavailable"
            ) from exc
        _assert_regular(trusted_proxy_path, "trusted MCP proxy source")
        trusted_proxy_sha256 = sha256_file(trusted_proxy_path)
        trusted_python_path, trusted_python_sha256 = _trusted_system_python()
        declared_trusted_path = _string(
            proxy.get("trusted_proxy_source_path"),
            "trusted MCP proxy source path",
        )
        declared_trusted_sha256 = _require_sha256(
            proxy.get("trusted_proxy_source_sha256"),
            "trusted MCP proxy source SHA-256",
        )
        run_local_proxy_path = _owned_path(
            proxy.get("run_local_proxy_copy_path"),
            run_root=run_root,
            run_id=run_id,
            label="run-local MCP proxy copy",
            must_exist=True,
        )
        _assert_regular(run_local_proxy_path, "run-local MCP proxy copy")
        run_local_proxy_sha256 = _require_sha256(
            proxy.get("run_local_proxy_copy_sha256"),
            "run-local MCP proxy copy SHA-256",
        )
        if (
            declared_trusted_path != str(trusted_proxy_path)
            or not hmac.compare_digest(
                declared_trusted_sha256, trusted_proxy_sha256
            )
            or not hmac.compare_digest(
                run_local_proxy_sha256, trusted_proxy_sha256
            )
            or not hmac.compare_digest(
                sha256_file(run_local_proxy_path), trusted_proxy_sha256
            )
            or proxy.get("run_local_proxy_copy_read_only") is not True
            or run_local_proxy_path.stat().st_mode & 0o222
            or _string(
                proxy.get("proxy_implementation_path"),
                "MCP proxy compatibility path",
            )
            != str(run_local_proxy_path)
            or not hmac.compare_digest(
                _require_sha256(
                    proxy.get("proxy_implementation_sha256"),
                    "MCP proxy compatibility SHA-256",
                ),
                run_local_proxy_sha256,
            )
            or _string(
                prepared.get("trusted_python_executable_path"),
                "prepared MCP Python executable path",
            )
            != str(trusted_python_path)
            or not hmac.compare_digest(
                _require_sha256(
                    prepared.get("trusted_python_executable_sha256"),
                    "prepared MCP Python executable SHA-256",
                ),
                trusted_python_sha256,
            )
            or _string(
                proxy.get("trusted_python_executable_path"),
                "MCP proxy Python executable path",
            )
            != str(trusted_python_path)
            or not hmac.compare_digest(
                _require_sha256(
                    proxy.get("trusted_python_executable_sha256"),
                    "MCP proxy Python executable SHA-256",
                ),
                trusted_python_sha256,
            )
            or proxy.get("launch_ready_with_evidence_proxy") is not True
        ):
            raise KimiStageExecutorError(
                "prepared MCP config does not bind an immutable run-local Kimi proxy copy"
            )

        evidence_proxy = _mapping(mcp.get("evidence_proxy"), "MCP proxy contract")
        reservations = evidence_proxy.get("server_reservations")
        if not isinstance(reservations, list) or not reservations:
            raise KimiStageExecutorError("MCP stage has no proxy reservations")
        try:
            config = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KimiStageExecutorError("prepared MCP config is malformed") from exc
        servers = _mapping(config.get("mcpServers"), "prepared MCP servers")
        child_commands = _mapping(
            prepared.get("child_commands"), "prepared MCP child commands"
        )
        wrapped_servers = _mapping(
            proxy.get("wrapped_servers"), "prepared MCP wrapped servers"
        )
        reservation_by_server: dict[str, Mapping[str, Any]] = {}
        for raw in reservations:
            reservation = _mapping(raw, "MCP proxy reservation")
            server_name = _string(reservation.get("server"), "MCP reservation server")
            if server_name in reservation_by_server:
                raise KimiStageExecutorError("duplicate MCP proxy reservation")
            if reservation.get("transport") != "stdio":
                raise KimiStageExecutorError("only proxied stdio MCP is supported")
            if (
                _string(
                    reservation.get("trusted_proxy_source_path"),
                    "MCP reservation trusted proxy source path",
                )
                != str(trusted_proxy_path)
                or _require_sha256(
                    reservation.get("trusted_proxy_source_sha256"),
                    "MCP reservation trusted proxy source SHA-256",
                )
                != trusted_proxy_sha256
                or _string(
                    reservation.get("run_local_proxy_copy_path"),
                    "MCP reservation run-local proxy path",
                )
                != str(run_local_proxy_path)
                or _require_sha256(
                    reservation.get("run_local_proxy_copy_sha256"),
                    "MCP reservation run-local proxy SHA-256",
                )
                != run_local_proxy_sha256
                or _string(
                    reservation.get("trusted_python_executable_path"),
                    "MCP reservation Python executable path",
                )
                != str(trusted_python_path)
                or _require_sha256(
                    reservation.get("trusted_python_executable_sha256"),
                    "MCP reservation Python executable SHA-256",
                )
                != trusted_python_sha256
            ):
                raise KimiStageExecutorError(
                    "MCP reservation proxy provenance differs from stage manifest"
                )
            reservation_by_server[server_name] = reservation
        if (
            set(servers) != set(reservation_by_server)
            or set(servers) != set(child_commands)
            or set(servers) != set(wrapped_servers)
        ):
            raise KimiStageExecutorError(
                "MCP servers, child provenance, and proxy reservations differ"
            )

        for server_name, raw_server in servers.items():
            server = _mapping(raw_server, f"MCP server {server_name}")
            command = _string(server.get("command"), "MCP proxy command")
            args = server.get("args")
            if command != str(trusted_python_path) or not isinstance(args, list) or any(
                not isinstance(item, str) or not item for item in args
            ):
                raise KimiStageExecutorError("MCP server is not launched through Python proxy")
            if not args or args[0] != str(run_local_proxy_path):
                raise KimiStageExecutorError("MCP server bypasses the Kimi-owned proxy")
            reservation = reservation_by_server[server_name]
            if canonical_argv_sha256([command, *args]) != _require_sha256(
                reservation.get("proxy_argv_sha256"), "MCP proxy argv SHA-256"
            ):
                raise KimiStageExecutorError("MCP proxy argv hash mismatch")
            wrapped_record = _mapping(
                wrapped_servers.get(server_name),
                f"prepared MCP wrapped provenance {server_name}",
            )
            if (
                _require_sha256(
                    wrapped_record.get("proxy_argv_sha256"),
                    "prepared MCP wrapped proxy argv SHA-256",
                )
                != _require_sha256(
                    reservation.get("proxy_argv_sha256"),
                    "MCP reservation proxy argv SHA-256",
                )
                or _require_sha256(
                    wrapped_record.get("child_argv_sha256"),
                    "prepared MCP wrapped child argv SHA-256",
                )
                != _require_sha256(
                    reservation.get("child_argv_sha256"),
                    "MCP reservation child argv SHA-256",
                )
            ):
                raise KimiStageExecutorError(
                    "MCP wrapped argv provenance differs from reservation"
                )
            expected_flags = {
                "--run-root": str(run_root),
                "--run-id": run_id,
                "--server": server_name,
                "--stage-index": str(stage_index),
                "--child-argv-sha256": reservation.get("child_argv_sha256"),
                "--initialize-trace": reservation.get("initialize_trace"),
                "--tools-list-trace": reservation.get("tools_list_trace"),
                "--stdio-trace": reservation.get("stdio_trace"),
                "--child-exit-trace": reservation.get("child_exit_trace"),
            }
            try:
                separator = args.index("--")
            except ValueError as exc:
                raise KimiStageExecutorError("MCP proxy child argv separator is missing") from exc
            prefix = args[1:separator]
            if len(prefix) % 2:
                raise KimiStageExecutorError("MCP proxy arguments are malformed")
            observed_flags = dict(zip(prefix[::2], prefix[1::2]))
            if observed_flags != expected_flags:
                raise KimiStageExecutorError("MCP proxy arguments drifted from reservation")
            child_argv = args[separator + 1 :]
            child_sha = _require_sha256(
                reservation.get("child_argv_sha256"), "MCP child argv SHA-256"
            )
            if canonical_argv_sha256(child_argv) != child_sha:
                raise KimiStageExecutorError("MCP proxy child argv hash mismatch")
            if len(child_argv) < 2 or child_argv[0] != str(trusted_python_path):
                raise KimiStageExecutorError(
                    "MCP child does not use the pinned system Python"
                )
            child_script = _owned_path(
                child_argv[1],
                run_root=run_root,
                run_id=run_id,
                label=f"MCP child script {server_name}",
                must_exist=True,
            )
            _assert_regular(child_script, f"MCP child script {server_name}")
            declared_script_path = _string(
                reservation.get("python_script_path"),
                "MCP reservation child script path",
            )
            declared_script_sha256 = _require_sha256(
                reservation.get("python_script_sha256"),
                "MCP reservation child script SHA-256",
            )
            child_record = _mapping(
                child_commands.get(server_name),
                f"prepared MCP child provenance {server_name}",
            )
            if (
                declared_script_path != str(child_script)
                or not hmac.compare_digest(
                    declared_script_sha256, sha256_file(child_script)
                )
                or _require_sha256(
                    child_record.get("argv_sha256"),
                    "prepared MCP child argv SHA-256",
                )
                != child_sha
                or _require_sha256(
                    child_record.get("declared_source_argv_sha256"),
                    "prepared MCP declared source argv SHA-256",
                )
                != _require_sha256(
                    reservation.get("declared_source_argv_sha256"),
                    "MCP reservation declared source argv SHA-256",
                )
                or _string(
                    child_record.get("declared_source_command"),
                    "prepared MCP declared source command",
                )
                != _string(
                    reservation.get("declared_source_command"),
                    "MCP reservation declared source command",
                )
                or _string(
                    child_record.get("python_script_path"),
                    "prepared MCP child script path",
                )
                != declared_script_path
                or _require_sha256(
                    child_record.get("python_script_sha256"),
                    "prepared MCP child script SHA-256",
                )
                != declared_script_sha256
                or child_record.get("required_run_local_files")
                != reservation.get("required_run_local_files")
                or _string(
                    child_record.get("trusted_python_executable_path"),
                    "prepared MCP child Python executable path",
                )
                != str(trusted_python_path)
                or _require_sha256(
                    child_record.get("trusted_python_executable_sha256"),
                    "prepared MCP child Python executable SHA-256",
                )
                != trusted_python_sha256
            ):
                raise KimiStageExecutorError(
                    "MCP child provenance differs from the prepared manifest"
                )
            required_files = reservation.get("required_run_local_files")
            if not isinstance(required_files, list) or not required_files:
                raise KimiStageExecutorError(
                    "MCP child has no reviewed run-local file allowlist"
                )
            observed_indexes: set[int] = set()
            for raw_file in required_files:
                file_record = _mapping(raw_file, "MCP child required file")
                if set(file_record) != {
                    "kind",
                    "child_argv_index",
                    "path",
                    "sha256",
                    "mode",
                    "provenance",
                }:
                    raise KimiStageExecutorError(
                        "MCP child required file field set drifted"
                    )
                argv_index = file_record.get("child_argv_index")
                if (
                    not isinstance(argv_index, int)
                    or isinstance(argv_index, bool)
                    or argv_index < 1
                    or argv_index >= len(child_argv)
                    or argv_index in observed_indexes
                ):
                    raise KimiStageExecutorError(
                        "MCP child required file argv index is invalid"
                    )
                observed_indexes.add(argv_index)
                required_path = _owned_path(
                    file_record.get("path"),
                    run_root=run_root,
                    run_id=run_id,
                    label="MCP child required file",
                    must_exist=True,
                )
                _assert_regular(required_path, "MCP child required file")
                required_sha = _require_sha256(
                    file_record.get("sha256"),
                    "MCP child required file SHA-256",
                )
                required_mode = file_record.get("mode")
                if (
                    file_record.get("kind") != "reviewed_mcp_child_file"
                    or file_record.get("provenance")
                    != "materialized_canonical_mcp_argument_v1"
                    or child_argv[argv_index] != str(required_path)
                    or not hmac.compare_digest(sha256_file(required_path), required_sha)
                    or not isinstance(required_mode, int)
                    or isinstance(required_mode, bool)
                    or required_mode != stat.S_IMODE(required_path.stat().st_mode)
                ):
                    raise KimiStageExecutorError(
                        "MCP child required file provenance drifted"
                    )
            for key in (
                "initialize_trace",
                "tools_list_trace",
                "stdio_trace",
                "child_exit_trace",
            ):
                _owned_path(
                    reservation.get(key),
                    run_root=run_root,
                    run_id=run_id,
                    label=f"MCP {key}",
                )
        return tuple(reservation_by_server[name] for name in sorted(reservation_by_server))

    def _control_requirements(
        self,
        manifest: Mapping[str, Any],
        stage: Mapping[str, Any],
    ) -> tuple[str, ...]:
        surfaces = _mapping(stage.get("surfaces"), "stage surfaces")
        session = _mapping(surfaces.get("session", {}), "stage session surface")
        session_controller = session.get("controller")
        controls: list[str] = []
        if isinstance(session_controller, Mapping) and (
            session_controller.get("required", True) is not False
        ):
            controller_kind = str(session_controller.get("kind") or "").casefold()
            operation = str(session_controller.get("operation") or "").casefold()
            if (
                controller_kind == _COMPACTION_CONTROLLER_KIND
                or "compact" in operation
            ):
                controls.append("compact")
            elif (
                controller_kind == _RESUME_CONTROLLER_KIND
                or "resume" in operation
                or operation == "create_and_capture_exact_session"
            ):
                controls.append("resume")
            else:
                raise KimiStageExecutorError(
                    "required session controller has no reviewed executor routing"
                )
        subagent = surfaces.get("subagent")
        runtime_mode = str(stage.get("canonical_runtime_mode") or "").casefold()
        if (
            manifest.get("suite_id") == "T3_subagent_poisoning"
            or "subagent" in runtime_mode
            or (
                isinstance(subagent, Mapping)
                and str(subagent.get("kind") or "required").casefold() not in {"none", "disabled"}
            )
        ):
            controls.append("subagent")
        return tuple(dict.fromkeys(controls))

    def _prepare_stage(
        self,
        *,
        manifest: Mapping[str, Any],
        stage: Mapping[str, Any],
        projected: Mapping[str, Any],
        run_root: Path,
        run_id: str,
        workspace: Path,
    ) -> _StagePrepared:
        index = stage.get("index")
        name = stage.get("name")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise KimiStageExecutorError("stage index is invalid")
        if not isinstance(name, str) or not name:
            raise KimiStageExecutorError("stage name is invalid")
        if projected.get("index") != index or projected.get("name") != name:
            raise KimiStageExecutorError("stage runtime projection identity mismatch")
        prompt_contract = _mapping(stage.get("prompt"), "stage prompt")
        if stage.get("disposition") != "READY" or not (
            prompt_contract.get("launch_allowed") is True
            or prompt_contract.get("controller_only") is True
        ):
            raise KimiStageExecutorError("stage is not launch-eligible")
        runtime_keys = (
            "workspace",
            "home",
            "kimi_home",
            "cache",
            "artifact",
            "mcp_evidence",
            "trace",
            "wire",
            "result",
            "session",
            "pid_record",
        )
        runtime_doc = _mapping(stage.get("runtime_paths"), "stage runtime paths")
        stage_root = _owned_path(
            stage.get("stage_root"),
            run_root=run_root,
            run_id=run_id,
            label=f"stage {index} root",
            must_exist=True,
        )
        if stage_root.is_symlink() or not stage_root.is_dir():
            raise KimiStageExecutorError("stage root is unsafe")
        runtime: dict[str, Path] = {}
        for key in runtime_keys:
            if projected.get(key) != runtime_doc.get(key):
                raise KimiStageExecutorError(f"stage {key} projection drifted from manifest")
            path = _owned_path(
                runtime_doc.get(key),
                run_root=run_root,
                run_id=run_id,
                label=f"stage {index} {key}",
            )
            runtime[key] = path
            if not _is_relative_to(path.resolve(strict=False), stage_root.resolve()):
                if key != "workspace" and not (
                    key in {"kimi_home", "session"}
                    and _mapping(
                        _mapping(stage.get("surfaces"), "stage surfaces").get("session", {}),
                        "stage session surface",
                    ).get("state_scope")
                    == "run_local_shared_native_session"
                ):
                    raise KimiStageExecutorError(
                        f"stage {key} path is outside its stage root without a reviewed shared-session binding"
                    )
        if runtime["workspace"].resolve() != workspace.resolve():
            raise KimiStageExecutorError("stage cwd differs from materialized workspace")
        for key in ("home", "kimi_home", "cache", "artifact", "mcp_evidence", "session"):
            if runtime[key].is_symlink() or not runtime[key].is_dir():
                raise KimiStageExecutorError(f"stage run-local {key} directory is unsafe")
        for key in ("trace", "wire", "result", "pid_record"):
            if runtime[key].exists() or runtime[key].is_symlink():
                raise KimiStageExecutorError(f"stage evidence path already exists: {runtime[key]}")
        for key, raw_path in runtime_doc.items():
            if key in runtime:
                continue
            if projected.get(key) != raw_path:
                raise KimiStageExecutorError(
                    f"stage extended runtime path {key} drifted from manifest"
                )
            path = _owned_path(
                raw_path,
                run_root=run_root,
                run_id=run_id,
                label=f"stage {index} extended runtime path {key}",
            )
            if path.exists() or path.is_symlink():
                raise KimiStageExecutorError(
                    f"stage extended evidence path already exists: {path}"
                )
            if not _is_relative_to(path.resolve(strict=False), stage_root.resolve()):
                raise KimiStageExecutorError(
                    f"stage extended runtime path {key} escapes its stage root"
                )
            runtime[key] = path

        prompt_doc = _mapping(stage.get("prompt"), "stage prompt")
        prompt_path = _owned_path(
            prompt_doc.get("materialized_path"),
            run_root=run_root,
            run_id=run_id,
            label="materialized stage prompt",
            must_exist=True,
        )
        _assert_regular(prompt_path, "materialized stage prompt")
        prompt_sha = _require_sha256(
            prompt_doc.get("materialized_sha256"), "materialized prompt SHA-256"
        )
        if not hmac.compare_digest(sha256_file(prompt_path), prompt_sha):
            raise KimiStageExecutorError("materialized prompt SHA-256 drifted")
        try:
            prompt = prompt_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise KimiStageExecutorError("materialized prompt is not UTF-8") from exc
        if not prompt.strip():
            raise KimiStageExecutorError("materialized prompt is empty")
        assets_root = prompt_path.parent
        if (
            assets_root.is_symlink()
            or not assets_root.is_dir()
            or assets_root.parent.resolve() != stage_root.resolve()
            or not assets_root.name.startswith(
                f"assets-kimi-{run_id}-stage-{index:03d}-"
            )
        ):
            raise KimiStageExecutorError("current stage assets root is invalid")

        surfaces = _mapping(stage.get("surfaces"), "stage surfaces")
        skills = _mapping(surfaces.get("skills"), "stage skill surface")
        skill_activation = _mapping(skills.get("activation"), "skill activation")
        if skill_activation.get("target") != "workspace/.kimi-code/skills":
            raise KimiStageExecutorError("skill activation target is not the Kimi project surface")
        if skill_activation.get("operation") == "replace_tree":
            prepared = _mapping(skills.get("prepared_tree"), "prepared skill tree")
            source = _owned_path(
                prepared.get("path"),
                run_root=run_root,
                run_id=run_id,
                label="prepared skill tree",
                must_exist=True,
            )
            if not _is_relative_to(source.resolve(), assets_root.resolve()):
                raise KimiStageExecutorError(
                    "prepared skill tree is outside current stage assets"
                )
            expected = _require_sha256(
                skill_activation.get("source_sha256"), "skill activation SHA-256"
            )
            if not hmac.compare_digest(tree_sha256(source), expected):
                raise KimiStageExecutorError("prepared skill tree drifted")
            if prepared.get("tree_sha256") != expected:
                raise KimiStageExecutorError("prepared skill tree hash records disagree")
        elif skill_activation.get("operation") != "remove_tree_if_present":
            raise KimiStageExecutorError("unknown skill activation operation")

        mcp = _mapping(surfaces.get("mcp"), "stage MCP surface")
        mcp_activation = _mapping(mcp.get("activation"), "MCP activation")
        if mcp_activation.get("target") != "workspace/.kimi-code/mcp.json":
            raise KimiStageExecutorError("MCP activation target is not the Kimi project surface")
        reservations: tuple[Mapping[str, Any], ...] = ()
        if mcp_activation.get("operation") == "replace_file":
            if mcp_activation.get("must_wrap_stdio_commands") is not True:
                raise KimiStageExecutorError("MCP activation does not require evidence proxy")
            mcp_sha = _require_sha256(
                mcp_activation.get("source_sha256"), "MCP activation SHA-256"
            )
            reservations = self._validate_proxy_config(
                stage=stage,
                run_root=run_root,
                run_id=run_id,
                stage_index=index,
                expected_config_sha256=mcp_sha,
            )
        elif mcp_activation.get("operation") != "remove_file_if_present":
            raise KimiStageExecutorError("unknown MCP activation operation")

        raw_read_only_files = stage.get("read_only_mount_files", [])
        if not isinstance(raw_read_only_files, list):
            raise KimiStageExecutorError("stage read-only file allowlist is malformed")
        reviewed_read_only_files: list[Mapping[str, Any]] = []
        observed_read_only_paths: set[Path] = set()
        for raw_file in raw_read_only_files:
            record = _mapping(raw_file, "stage reviewed read-only file")
            if set(record) != {
                "kind",
                "path",
                "sha256",
                "mode",
                "provenance",
                "declarations",
            }:
                raise KimiStageExecutorError(
                    "stage reviewed read-only file field set drifted"
                )
            path = _owned_path(
                record.get("path"),
                run_root=run_root,
                run_id=run_id,
                label="stage reviewed read-only file",
                must_exist=True,
            )
            _assert_regular(path, "stage reviewed read-only file")
            declarations = record.get("declarations")
            expected_sha = _require_sha256(
                record.get("sha256"), "stage reviewed read-only file SHA-256"
            )
            mode = record.get("mode")
            if (
                path in observed_read_only_paths
                or _is_relative_to(path.resolve(), workspace.resolve())
                or _is_relative_to(path.resolve(), stage_root.resolve())
                or record.get("kind") != "reviewed_stage_file"
                or record.get("provenance")
                != "materialized_case_declared_file_v1"
                or not isinstance(declarations, list)
                or not declarations
                or any(
                    declaration
                    not in {
                        "shared_materializer.canary_files",
                        "case_meta.canary_files",
                        "case_meta.deploy_path",
                    }
                    for declaration in declarations
                )
                or not isinstance(mode, int)
                or isinstance(mode, bool)
                or mode != stat.S_IMODE(path.stat().st_mode)
                or not hmac.compare_digest(sha256_file(path), expected_sha)
            ):
                raise KimiStageExecutorError(
                    "stage reviewed read-only file provenance drifted"
                )
            observed_read_only_paths.add(path)
            reviewed_read_only_files.append(record)

        return _StagePrepared(
            document=stage,
            runtime=runtime,
            stage_root=stage_root,
            assets_root=assets_root,
            prompt_path=prompt_path,
            prompt=prompt,
            prompt_sha256=prompt_sha,
            mcp_reservations=reservations,
            reviewed_read_only_files=tuple(reviewed_read_only_files),
            controls=self._control_requirements(manifest, stage),
        )

    def _validate_materialization(
        self,
        *,
        plan: Any,
        materialized: MaterializedCase,
        context: ExecutionContext,
    ) -> tuple[Mapping[str, Any], str, Path, Path, tuple[_StagePrepared, ...]]:
        run_root = Path(materialized.root).resolve(strict=True)
        if context.run_id != getattr(context.process_registry, "run_id", None):
            raise KimiStageExecutorError("PID registry does not belong to the current run_id")
        if run_root != Path(context.case_layout.root).resolve(strict=True):
            raise KimiStageExecutorError("executor case root differs from assigned layout")
        manifest_path = _owned_path(
            str(materialized.manifest_path),
            run_root=run_root,
            run_id=context.run_id,
            label="materialization manifest",
            must_exist=True,
        )
        _assert_regular(manifest_path, "materialization manifest")
        manifest = load_bench_materialization_manifest(manifest_path)
        manifest_sha = sha256_file(manifest_path)
        if (
            manifest.get("run_id") != context.run_id
            or manifest.get("harness_id") != "kimi"
            or manifest.get("case_id") != plan.case.case_id
            or manifest.get("case_id") != materialized.case_id
            or manifest.get("suite_id") != plan.case.suite
            or manifest.get("disposition") != "READY"
        ):
            raise KimiStageExecutorError("materialization manifest identity/disposition mismatch")
        canonical_doc = _mapping(manifest.get("canonical"), "canonical manifest record")
        canonical = Path(_string(canonical_doc.get("case_dir"), "canonical case path"))
        if canonical.is_symlink() or not canonical.is_dir():
            raise KimiStageExecutorError("canonical case path is unsafe")
        canonical = canonical.resolve(strict=True)
        if canonical != Path(plan.case.case_dir).resolve(strict=True):
            raise KimiStageExecutorError("manifest canonical case differs from runner plan")
        if _is_relative_to(run_root, canonical) or _is_relative_to(canonical, run_root):
            raise KimiStageExecutorError("materialized run aliases the canonical case")
        canonical_sha = _require_sha256(
            canonical_doc.get("tree_sha256"), "canonical tree SHA-256"
        )
        if not hmac.compare_digest(tree_sha256(canonical), canonical_sha):
            raise KimiStageExecutorError("canonical case drifted before execution")
        after_sha = canonical_doc.get("tree_sha256_after")
        if after_sha is not None and after_sha != canonical_sha:
            raise KimiStageExecutorError("materialization recorded canonical tree drift")

        materialized_doc = _mapping(manifest.get("materialized"), "materialized record")
        if Path(_string(materialized_doc.get("run_dir"), "materialized run_dir")).resolve() != run_root:
            raise KimiStageExecutorError("manifest run_dir differs from assigned root")
        case_dir = _owned_path(
            materialized_doc.get("case_dir"),
            run_root=run_root,
            run_id=context.run_id,
            label="materialized case directory",
            must_exist=True,
        )
        workspace = _owned_path(
            materialized_doc.get("workspace_dir"),
            run_root=run_root,
            run_id=context.run_id,
            label="materialized workspace",
            must_exist=True,
        )
        if not case_dir.is_dir() or not workspace.is_dir() or not _is_relative_to(workspace.resolve(), case_dir.resolve()):
            raise KimiStageExecutorError("materialized case/workspace relationship is invalid")
        if workspace.resolve() != Path(materialized.workspace).resolve(strict=True):
            raise KimiStageExecutorError("runner workspace projection drifted")
        if _is_relative_to(case_dir.resolve(), canonical) or _is_relative_to(workspace.resolve(), canonical):
            raise KimiStageExecutorError("materialized paths alias canonical content")
        materialized_tree_sha = _require_sha256(
            materialized_doc.get("tree_sha256"), "materialized case tree SHA-256"
        )
        if not hmac.compare_digest(tree_sha256(case_dir), materialized_tree_sha):
            raise KimiStageExecutorError("materialized case tree drifted before launch")
        project_boundary = _owned_path(
            materialized_doc.get("project_boundary"),
            run_root=run_root,
            run_id=context.run_id,
            label="materialized project boundary",
            must_exist=True,
        )
        if (
            project_boundary.resolve() != (workspace / ".git").resolve()
            or project_boundary.is_symlink()
            or not project_boundary.is_dir()
        ):
            raise KimiStageExecutorError("materialized project boundary is invalid")

        translated = materialized_doc.get("translated_artifacts", [])
        if not isinstance(translated, list):
            raise KimiStageExecutorError("translated artifact records are invalid")
        for index, raw in enumerate(translated):
            record = _mapping(raw, f"translated artifact {index}")
            target = _owned_path(
                record.get("target"),
                run_root=run_root,
                run_id=context.run_id,
                label=f"translated artifact {index}",
                must_exist=True,
            )
            _assert_regular(target, f"translated artifact {index}")
            expected = _require_sha256(
                record.get("materialized_sha256"),
                f"translated artifact {index} SHA-256",
            )
            if not hmac.compare_digest(sha256_file(target), expected):
                raise KimiStageExecutorError("translated artifact SHA-256 drifted")

        raw_stages = manifest.get("stages")
        if not isinstance(raw_stages, list) or len(raw_stages) != len(plan.stages):
            raise KimiStageExecutorError("manifest stage count differs from runner plan")
        if len(materialized.stage_runtime_paths) != len(raw_stages):
            raise KimiStageExecutorError("runtime stage projection count drifted")
        prepared = tuple(
            self._prepare_stage(
                manifest=manifest,
                stage=_mapping(raw, f"manifest stage {index}"),
                projected=_mapping(materialized.stage_runtime_paths[index], f"projected stage {index}"),
                run_root=run_root,
                run_id=context.run_id,
                workspace=workspace,
            )
            for index, raw in enumerate(raw_stages)
        )
        if tuple(item.document.get("index") for item in prepared) != tuple(
            stage.index for stage in plan.stages
        ):
            raise KimiStageExecutorError("manifest stage indexes differ from runner plan")
        missing_controls = sorted(
            {
                kind
                for stage in prepared
                for kind in stage.controls
                if getattr(self, f"{kind}_controller") is None
            }
        )
        if missing_controls:
            raise KimiStageExecutorError(
                "native boundary controller not injected: " + ", ".join(missing_controls)
            )
        return manifest, manifest_sha, canonical, workspace, prepared

    def _refresh_after_matched_control(
        self,
        *,
        boundary: MatchedControlBoundaryResult,
        plan: Any,
        materialized: MaterializedCase,
        context: ExecutionContext,
        workspace: Path,
    ) -> tuple[Mapping[str, Any], str, _StagePrepared, str]:
        """Revalidate only the not-yet-started stage after an intervention.

        Prior stage evidence paths are intentionally no longer empty, so the
        whole-case materialization validator cannot safely be replayed here.
        The current stage and the revised manifest are nevertheless checked
        against the original runner projection before any activation/spawn.
        """

        run_root = Path(materialized.root).resolve(strict=True)
        if (
            not isinstance(boundary, MatchedControlBoundaryResult)
            or boundary.run_id != context.run_id
            or boundary.case_id != materialized.case_id
        ):
            raise KimiStageExecutorError(
                "matched-control boundary returned an invalid identity"
            )
        manifest_path = _owned_path(
            str(boundary.manifest_path),
            run_root=run_root,
            run_id=context.run_id,
            label="matched-control revised manifest",
            must_exist=True,
        )
        if manifest_path != Path(materialized.manifest_path).resolve(strict=True):
            raise KimiStageExecutorError(
                "matched-control boundary changed the manifest path"
            )
        manifest_sha = sha256_file(manifest_path)
        if not hmac.compare_digest(
            manifest_sha,
            _require_sha256(
                boundary.manifest_sha256,
                "matched-control revised manifest SHA-256",
            ),
        ):
            raise KimiStageExecutorError(
                "matched-control revised manifest hash drifted"
            )
        evidence_path = _owned_path(
            str(boundary.evidence_path),
            run_root=run_root,
            run_id=context.run_id,
            label="matched-control intervention evidence",
            must_exist=True,
        )
        _assert_regular(evidence_path, "matched-control intervention evidence")
        evidence_sha = _require_sha256(
            boundary.evidence_sha256,
            "matched-control intervention evidence SHA-256",
        )
        if not hmac.compare_digest(sha256_file(evidence_path), evidence_sha):
            raise KimiStageExecutorError(
                "matched-control intervention evidence hash drifted"
            )
        try:
            evidence = _mapping(
                json.loads(evidence_path.read_text(encoding="utf-8")),
                "matched-control intervention evidence",
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KimiStageExecutorError(
                "matched-control intervention evidence is malformed"
            ) from exc
        if (
            evidence.get("harness_id") != "kimi"
            or evidence.get("run_id") != context.run_id
            or boundary.stage_index + 1
            not in (evidence.get("applied_before_stage_indices") or [])
            or boundary.stage_name
            != plan.stages[boundary.stage_index].name
        ):
            raise KimiStageExecutorError(
                "matched-control intervention evidence identity drifted"
            )
        forbidden = _forbidden_paths(evidence, prefix="matched_control")
        if forbidden:
            raise KimiStageExecutorError(
                "matched-control evidence contains analyzer/scoring fields: "
                + ", ".join(forbidden)
            )

        manifest = load_bench_materialization_manifest(manifest_path)
        if (
            manifest.get("run_id") != context.run_id
            or manifest.get("harness_id") != "kimi"
            or manifest.get("case_id") != materialized.case_id
            or manifest.get("suite_id") != plan.case.suite
            or manifest.get("disposition") != "READY"
        ):
            raise KimiStageExecutorError(
                "matched-control revised manifest identity/disposition drifted"
            )
        canonical_doc = _mapping(manifest.get("canonical"), "canonical record")
        canonical = Path(
            _string(canonical_doc.get("case_dir"), "canonical case path")
        ).resolve(strict=True)
        if (
            canonical != Path(plan.case.case_dir).resolve(strict=True)
            or not hmac.compare_digest(
                tree_sha256(canonical),
                _require_sha256(
                    canonical_doc.get("tree_sha256"),
                    "canonical tree SHA-256",
                ),
            )
        ):
            raise KimiStageExecutorError(
                "canonical case drifted across matched-control intervention"
            )
        materialized_doc = _mapping(
            manifest.get("materialized"), "materialized record"
        )
        case_dir = _owned_path(
            materialized_doc.get("case_dir"),
            run_root=run_root,
            run_id=context.run_id,
            label="matched-control materialized case",
            must_exist=True,
        )
        if not hmac.compare_digest(
            tree_sha256(case_dir),
            _require_sha256(
                materialized_doc.get("tree_sha256"),
                "matched-control materialized tree SHA-256",
            ),
        ):
            raise KimiStageExecutorError(
                "materialized tree drifted after matched-control intervention"
            )
        raw_stages = manifest.get("stages")
        if (
            not isinstance(raw_stages, list)
            or len(raw_stages) != len(plan.stages)
            or not 0 <= boundary.stage_index < len(raw_stages)
        ):
            raise KimiStageExecutorError(
                "matched-control revised stage set is invalid"
            )
        raw_stage = _mapping(
            raw_stages[boundary.stage_index], "matched-control current stage"
        )
        if (
            raw_stage.get("index") != boundary.stage_index
            or raw_stage.get("name") != boundary.stage_name
        ):
            raise KimiStageExecutorError(
                "matched-control revised stage identity drifted"
            )
        prepared = self._prepare_stage(
            manifest=manifest,
            stage=raw_stage,
            projected=_mapping(
                materialized.stage_runtime_paths[boundary.stage_index],
                "matched-control projected stage",
            ),
            run_root=run_root,
            run_id=context.run_id,
            workspace=workspace,
        )
        missing = sorted(
            kind
            for kind in prepared.controls
            if getattr(self, f"{kind}_controller") is None
        )
        if missing:
            raise KimiStageExecutorError(
                "native boundary controller missing after intervention: "
                + ", ".join(missing)
            )
        locator = f"{evidence_path}#sha256={evidence_sha}"
        return manifest, manifest_sha, prepared, locator

    def _activate(self, stage: _StagePrepared, *, workspace: Path, run_id: str) -> Path | None:
        index = int(stage.document["index"])
        surfaces = _mapping(stage.document.get("surfaces"), "stage surfaces")
        project = workspace / ".kimi-code"
        if project.is_symlink() or (project.exists() and not project.is_dir()):
            raise KimiStageExecutorError("Kimi project surface is unsafe")
        project.mkdir(mode=0o700, parents=True, exist_ok=True)

        skills = _mapping(surfaces.get("skills"), "stage skills")
        skill_activation = _mapping(skills.get("activation"), "skill activation")
        skill_target = project / "skills"
        if skill_activation.get("operation") == "replace_tree":
            prepared = _mapping(skills.get("prepared_tree"), "prepared skill tree")
            _atomic_replace_tree(
                Path(str(prepared["path"])),
                skill_target,
                expected_sha256=str(skill_activation["source_sha256"]),
                run_id=run_id,
                stage_index=index,
            )
        else:
            _atomic_remove(skill_target, run_id=run_id, stage_index=index)

        mcp = _mapping(surfaces.get("mcp"), "stage MCP")
        mcp_activation = _mapping(mcp.get("activation"), "MCP activation")
        mcp_target = project / "mcp.json"
        if mcp_activation.get("operation") == "replace_file":
            prepared = _mapping(mcp.get("prepared_config"), "prepared MCP config")
            _atomic_replace_file(
                Path(str(prepared["target"])),
                mcp_target,
                expected_sha256=str(mcp_activation["source_sha256"]),
                run_id=run_id,
            )
            return mcp_target
        _atomic_remove(mcp_target, run_id=run_id, stage_index=index)
        return None

    def _environment(self, stage: _StagePrepared, *, run_id: str) -> dict[str, str]:
        index = int(stage.document["index"])
        runtime_root = stage.runtime["trace"].parent
        xdg_config = runtime_root / f"xdg-config-kimi-{run_id}-stage-{index:03d}"
        xdg_data = runtime_root / f"xdg-data-kimi-{run_id}-stage-{index:03d}"
        temp = runtime_root / f"tmp-kimi-{run_id}-stage-{index:03d}"
        for directory in (xdg_config, xdg_data, temp):
            if directory.is_symlink():
                raise KimiStageExecutorError("run-local environment path is a symlink")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = {
            "PATH": self.path_environment,
            "HOME": str(stage.runtime["home"]),
            "KIMI_CODE_HOME": str(stage.runtime["kimi_home"]),
            "XDG_CACHE_HOME": str(stage.runtime["cache"]),
            "XDG_CONFIG_HOME": str(xdg_config),
            "XDG_DATA_HOME": str(xdg_data),
            "TMPDIR": str(temp),
            "KIMI_DISABLE_TELEMETRY": "1",
            "NO_COLOR": "1",
            "CI": "1",
            "SAFETY_BENCH_HARNESS": "kimi",
            "SAFETY_BENCH_RUN_ID": run_id,
        }
        if any(_SENSITIVE_ENV_RE.search(key) for key in environment):
            raise KimiStageExecutorError("executor environment contains a credential-like key")
        if any(_OTHER_HARNESS_ENV_RE.search(key) for key in environment):
            raise KimiStageExecutorError("executor environment contains another harness key")
        for key in ("HOME", "KIMI_CODE_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMPDIR"):
            path = Path(environment[key]).resolve()
            if not _is_relative_to(path, stage.runtime["trace"].parents[2].resolve()):
                # Every declared runtime path was already proven below run_root;
                # this tighter check catches an accidental host path substitution.
                raise KimiStageExecutorError(f"{key} is not run-local")
        return environment

    def _launch_mounts(
        self,
        stage: _StagePrepared,
        *,
        run_root: Path,
        run_id: str,
        workspace: Path,
        manifest_sha256: str,
    ) -> tuple[tuple[StageMount, ...], tuple[StageMount, ...]]:
        """Build the exact per-stage data-plane allowlist from verified metadata."""

        _require_sha256(manifest_sha256, "materialization manifest SHA-256")
        index = int(stage.document["index"])
        runtime_root = stage.runtime["trace"].parent.resolve(strict=True)
        if (
            runtime_root.parent.resolve() != stage.stage_root.resolve()
            or not runtime_root.name.startswith(
                f"runtime-kimi-{run_id}-stage-{index:03d}-"
            )
        ):
            raise KimiStageExecutorError("current stage runtime root is invalid")

        write_mounts = [
            _stage_mount(
                workspace,
                kind="workspace",
                path_type="tree",
                provenance="verified_materialized_workspace_v1",
                manifest_sha256=manifest_sha256,
            ),
            _stage_mount(
                runtime_root,
                kind="current_stage_runtime",
                path_type="tree",
                provenance="verified_current_stage_runtime_v1",
                manifest_sha256=manifest_sha256,
            ),
        ]

        surfaces = _mapping(stage.document.get("surfaces"), "stage surfaces")
        session = _mapping(surfaces.get("session", {}), "stage session surface")
        kimi_home = stage.runtime["kimi_home"].resolve(strict=True)
        session_path = stage.runtime["session"].resolve(strict=True)
        if not _is_relative_to(kimi_home, runtime_root):
            if (
                session.get("state_scope") != "run_local_shared_native_session"
                or kimi_home.parent.resolve() != run_root.resolve()
                or kimi_home.name != f"config-kimi-{run_id}-native-session"
                or not _is_relative_to(session_path, kimi_home)
            ):
                raise KimiStageExecutorError(
                    "shared Kimi session mount lacks reviewed run-local provenance"
                )
            write_mounts.append(
                _stage_mount(
                    kimi_home,
                    kind="shared_native_session",
                    path_type="tree",
                    provenance="verified_shared_native_session_surface_v1",
                    manifest_sha256=manifest_sha256,
                )
            )
        elif not _is_relative_to(session_path, runtime_root):
            raise KimiStageExecutorError("stage session path escapes its writable mount")

        read_only_mounts = [
            _stage_mount(
                stage.assets_root,
                kind="current_stage_assets",
                path_type="tree",
                provenance="verified_current_stage_assets_v1",
                manifest_sha256=manifest_sha256,
            )
        ]
        observed_read_only: dict[Path, StageMount] = {
            read_only_mounts[0].path: read_only_mounts[0]
        }
        for record in stage.reviewed_read_only_files:
            reviewed_path = Path(
                _string(record.get("path"), "reviewed stage file path")
            ).resolve(strict=True)
            mount = _stage_mount(
                reviewed_path,
                kind="reviewed_stage_file",
                path_type="file",
                provenance="verified_case_declared_stage_file_v1",
                manifest_sha256=manifest_sha256,
            )
            if mount.sha256 != record.get("sha256") or mount.mode != record.get(
                "mode"
            ):
                raise KimiStageExecutorError(
                    "reviewed stage file differs from manifest provenance"
                )
            if mount.path in observed_read_only:
                raise KimiStageExecutorError("duplicate reviewed stage file mount")
            observed_read_only[mount.path] = mount
            read_only_mounts.append(mount)
        for reservation in stage.mcp_reservations:
            proxy_path = Path(
                _string(
                    reservation.get("run_local_proxy_copy_path"),
                    "MCP reservation run-local proxy path",
                )
            ).resolve(strict=True)
            candidates = [
                _stage_mount(
                    proxy_path,
                    kind="run_local_mcp_proxy",
                    path_type="file",
                    provenance="verified_run_local_mcp_proxy_copy_v1",
                    manifest_sha256=manifest_sha256,
                )
            ]
            required_files = reservation.get("required_run_local_files")
            if not isinstance(required_files, list) or not required_files:
                raise KimiStageExecutorError(
                    "MCP reservation has no reviewed child file allowlist"
                )
            for raw_file in required_files:
                record = _mapping(raw_file, "MCP child required file")
                child_path = Path(
                    _string(record.get("path"), "MCP child required file path")
                ).resolve(strict=True)
                mount = _stage_mount(
                    child_path,
                    kind="mcp_child_file",
                    path_type="file",
                    provenance="verified_mcp_child_file_record_v1",
                    manifest_sha256=manifest_sha256,
                )
                if (
                    mount.sha256 != record.get("sha256")
                    or mount.mode != record.get("mode")
                ):
                    raise KimiStageExecutorError(
                        "MCP child mount differs from its manifest provenance"
                    )
                candidates.append(mount)
            for mount in candidates:
                existing = observed_read_only.get(mount.path)
                if existing is not None:
                    if (
                        existing.sha256 != mount.sha256
                        or existing.mode != mount.mode
                        or existing.path_type != mount.path_type
                    ):
                        raise KimiStageExecutorError(
                            "duplicate read-only mount provenance disagrees"
                        )
                    continue
                observed_read_only[mount.path] = mount
                read_only_mounts.append(mount)

        write_paths = tuple(mount.path for mount in write_mounts)
        for mount in read_only_mounts:
            if any(
                _is_relative_to(mount.path, writable)
                or _is_relative_to(writable, mount.path)
                for writable in write_paths
            ):
                raise KimiStageExecutorError(
                    "read-only mount overlaps a writable stage surface"
                )
        return (
            tuple(sorted(write_mounts, key=lambda item: (str(item.path), item.kind))),
            tuple(
                sorted(read_only_mounts, key=lambda item: (str(item.path), item.kind))
            ),
        )

    def _validate_controller_exchange(
        self,
        stage: _StagePrepared,
        directive: ControlDirective,
        *,
        workspace: Path,
    ) -> None:
        exchange = directive.jsonrpc_exchange
        if exchange is None:
            raise KimiStageExecutorError(
                "controller-only stage omitted its sequential JSON-RPC exchange"
            )
        session_controller = _mapping(
            _mapping(
                _mapping(stage.document.get("surfaces"), "stage surfaces").get("session", {}),
                "stage session surface",
            ).get("controller"),
            "session controller",
        )
        protocol = _mapping(
            session_controller.get("acp_protocol"), "ACP controller protocol"
        )
        declared = protocol.get("request_sequence")
        if not isinstance(declared, list) or not declared:
            raise KimiStageExecutorError("ACP controller has no declared request sequence")
        declared_records = tuple(
            _mapping(item, "ACP request declaration") for item in declared
        )
        declared_methods = tuple(
            _string(item.get("method"), "ACP method") for item in declared_records
        )
        declared_ids = tuple(item.get("id") for item in declared_records)
        if declared_ids != exchange.expected_response_ids:
            raise KimiStageExecutorError("ACP response ids drifted from binding")
        observed: list[Mapping[str, Any]] = []
        for frame, expected_id in zip(
            exchange.request_frames, exchange.expected_response_ids
        ):
            if not frame.endswith(b"\n") or len(frame.splitlines()) != 1:
                raise KimiStageExecutorError(
                    "each ACP request must be one newline-delimited JSON object"
                )
            try:
                request = json.loads(frame.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise KimiStageExecutorError("ACP request frame is malformed") from exc
            if (
                not isinstance(request, Mapping)
                or request.get("jsonrpc") != "2.0"
                or request.get("id") != expected_id
                or not isinstance(request.get("method"), str)
            ):
                raise KimiStageExecutorError("ACP request identity is invalid")
            observed.append(request)
        if tuple(request["method"] for request in observed) != declared_methods:
            raise KimiStageExecutorError("ACP request method sequence drifted from binding")
        if declared_methods == ("initialize", "session/resume", "session/prompt"):
            initialize_params = _mapping(
                observed[0].get("params"), "ACP initialize params"
            )
            declared_initialize = _mapping(
                declared_records[0].get("params"), "declared ACP initialize params"
            )
            resume_params = _mapping(
                observed[1].get("params"), "ACP session/resume params"
            )
            prompt_params = _mapping(
                observed[2].get("params"), "ACP session/prompt params"
            )
            session_id = _string(resume_params.get("sessionId"), "ACP session id")
            declared_prompt = _mapping(
                declared_records[2].get("params"), "declared ACP prompt params"
            ).get("prompt")
            if (
                initialize_params != declared_initialize
                or set(resume_params) != {"cwd", "mcpServers", "sessionId"}
                or Path(_string(resume_params.get("cwd"), "ACP resume cwd")).resolve()
                != workspace.resolve()
                or resume_params.get("mcpServers") != []
                or set(prompt_params) != {"sessionId", "prompt"}
                or prompt_params.get("sessionId") != session_id
                or prompt_params.get("prompt") != declared_prompt
            ):
                raise KimiStageExecutorError(
                    "ACP compaction exchange does not bind the exact run-local session"
                )

    def _directive(
        self,
        stage: _StagePrepared,
        *,
        run_id: str,
        case_id: str,
        prior_results: Sequence[Mapping[str, Any]],
    ) -> ControlDirective:
        suffix: list[str] = []
        evidence: list[str] = []
        launch_mode = "prompt"
        jsonrpc_exchange: JsonRpcExchange | None = None
        for kind in stage.controls:
            controller = getattr(self, f"{kind}_controller")
            if controller is None:  # protected by whole-case preflight
                raise KimiStageExecutorError(f"missing {kind} controller")
            result = controller.prepare(
                StageControlRequest(
                    run_id=run_id,
                    case_id=case_id,
                    stage_index=int(stage.document["index"]),
                    stage_name=str(stage.document["name"]),
                    control_kind=kind,
                    stage_document=stage.document,
                    prior_stage_results=tuple(prior_results),
                )
            )
            if not isinstance(result, ControlDirective):
                raise KimiStageExecutorError(f"{kind} controller returned an invalid directive")
            if any(not isinstance(item, str) or not item for item in result.argv_suffix):
                raise KimiStageExecutorError(f"{kind} controller returned invalid argv")
            if any(_SENSITIVE_ENV_RE.search(item) for item in result.argv_suffix):
                raise KimiStageExecutorError(
                    f"{kind} controller argv contains a credential-like value"
                )
            if result.launch_mode not in {"prompt", "controller"}:
                raise KimiStageExecutorError(
                    f"{kind} controller returned an invalid launch mode"
                )
            if result.launch_mode == "controller":
                if launch_mode == "controller":
                    raise KimiStageExecutorError(
                        "more than one controller attempted to own the stage process"
                    )
                launch_mode = "controller"
                jsonrpc_exchange = result.jsonrpc_exchange
            elif result.jsonrpc_exchange is not None:
                raise KimiStageExecutorError(
                    f"{kind} controller supplied JSON-RPC to prompt mode"
                )
            suffix.extend(result.argv_suffix)
            evidence.extend(result.evidence_locators)
        if "--continue" in suffix:
            raise KimiStageExecutorError("native resume must use exact --session, never --continue")
        if {"resume", "compact"}.intersection(stage.controls):
            session = _mapping(
                _mapping(stage.document.get("surfaces"), "stage surfaces").get("session", {}),
                "stage session surface",
            )
            controller_doc = session.get("controller")
            controller_mapping = (
                _mapping(controller_doc, "session controller")
                if isinstance(controller_doc, Mapping)
                else {}
            )
            argv_contract = controller_mapping.get("argv_contract", {})
            argv_contract = (
                _mapping(argv_contract, "session argv contract")
                if isinstance(argv_contract, Mapping)
                else {}
            )
            forbidden_flags = argv_contract.get("forbidden_flags", [])
            if not isinstance(forbidden_flags, list) or any(
                not isinstance(flag, str) or not flag for flag in forbidden_flags
            ):
                raise KimiStageExecutorError("session controller has invalid forbidden flags")
            present_forbidden = sorted(set(suffix).intersection(forbidden_flags))
            if present_forbidden:
                raise KimiStageExecutorError(
                    "session controller emitted a forbidden flag: "
                    + ", ".join(present_forbidden)
                )
            operation = str(controller_mapping.get("operation") or "").casefold()
            if "resume" in operation:
                if suffix.count("--session") != 1:
                    raise KimiStageExecutorError(
                        "resume controller did not bind one exact --session argument"
                    )
                if suffix.index("--session") == len(suffix) - 1:
                    raise KimiStageExecutorError("--session is missing its exact session id")
            required_flag = argv_contract.get("required_flag")
            if required_flag is not None and suffix.count(str(required_flag)) != 1:
                raise KimiStageExecutorError(
                    "session controller did not emit its required exact flag"
                )
        return ControlDirective(
            tuple(suffix), tuple(evidence), launch_mode, jsonrpc_exchange
        )

    def _finalize_controls(
        self,
        stage: _StagePrepared,
        *,
        run_id: str,
        case_id: str,
        prior_results: Sequence[Mapping[str, Any]],
        stage_result: Mapping[str, Any],
    ) -> ControlFinalization:
        evidence: list[str] = []
        observations: list[Mapping[str, Any]] = []
        for kind in stage.controls:
            controller = getattr(self, f"{kind}_controller")
            finalize = getattr(controller, "finalize", None)
            if not callable(finalize):
                raise KimiStageExecutorError(
                    f"{kind} controller has no fail-closed finalize hook"
                )
            result = finalize(
                StageControlFinalizeRequest(
                    run_id=run_id,
                    case_id=case_id,
                    stage_index=int(stage.document["index"]),
                    stage_name=str(stage.document["name"]),
                    control_kind=kind,
                    stage_document=stage.document,
                    prior_stage_results=tuple(prior_results),
                    stage_result=json.loads(
                        json.dumps(stage_result, ensure_ascii=False)
                    ),
                )
            )
            if not isinstance(result, ControlFinalization) or any(
                not isinstance(locator, str)
                or not locator
                or "\n" in locator
                or "\r" in locator
                for locator in result.evidence_locators
            ):
                raise KimiStageExecutorError(
                    f"{kind} controller returned invalid finalize evidence locators"
                )
            for observation in result.observation_records:
                if not isinstance(observation, Mapping):
                    raise KimiStageExecutorError(
                        f"{kind} controller returned a non-object observation"
                    )
                record_type = observation.get("type")
                if not isinstance(record_type, str) or not record_type.startswith(
                    "adapter."
                ):
                    raise KimiStageExecutorError(
                        f"{kind} controller returned an invalid adapter observation"
                    )
                forbidden = _forbidden_paths(observation, prefix="control_observation")
                if forbidden:
                    raise KimiStageExecutorError(
                        "controller observation contains analyzer/scoring fields: "
                        + ", ".join(forbidden)
                    )
                observations.append(dict(observation))
            evidence.extend(result.evidence_locators)
        return ControlFinalization(tuple(evidence), tuple(observations))

    def _wire_snapshot(self, kimi_home: Path) -> dict[Path, tuple[int, str]]:
        snapshot: dict[Path, tuple[int, str]] = {}
        for path in sorted(kimi_home.rglob("wire.jsonl")):
            _assert_regular(path, "native Kimi wire")
            snapshot[path.resolve()] = (path.stat().st_size, sha256_file(path))
        return snapshot

    def _capture_wires(
        self,
        *,
        stage: _StagePrepared,
        before: Mapping[Path, tuple[int, str]],
        run_id: str,
    ) -> tuple[Path, str, tuple[WireCapture, ...]]:
        changed: list[Path] = []
        for path in sorted(stage.runtime["kimi_home"].rglob("wire.jsonl")):
            _assert_regular(path, "native Kimi wire")
            resolved = path.resolve()
            observed = (path.stat().st_size, sha256_file(path))
            if before.get(resolved) != observed:
                changed.append(path)
        if not changed:
            raise KimiStageExecutorError("Kimi produced no new or changed native wire")
        main = [
            path
            for path in changed
            if path.parent.name == "main" and path.parent.parent.name == "agents"
        ]
        if len(main) != 1:
            if len(changed) == 1:
                main = [changed[0]]
            else:
                raise KimiStageExecutorError("cannot identify exactly one main-agent Kimi wire")
        capture_root = stage.runtime["artifact"] / (
            f"wire-captures-kimi-{run_id}-stage-{int(stage.document['index']):03d}"
        )
        if capture_root.exists() or capture_root.is_symlink():
            raise KimiStageExecutorError("wire capture directory already exists")
        capture_root.mkdir(mode=0o700, parents=True)
        captures: list[WireCapture] = []
        for ordinal, source in enumerate(changed):
            content = source.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            destination = capture_root / f"wire-{ordinal:03d}-{digest[:16]}.jsonl"
            _atomic_write_bytes(destination, content, run_id=run_id)
            line_count = len(content.splitlines())
            if line_count < 1:
                raise KimiStageExecutorError("native Kimi wire is empty")
            captures.append(
                WireCapture(
                    source_path=source,
                    captured_path=destination,
                    sha256=digest,
                    line_count=line_count,
                    is_main=source == main[0],
                )
            )
        main_capture = next(item for item in captures if item.is_main)
        _atomic_write_bytes(
            stage.runtime["wire"], main_capture.captured_path.read_bytes(), run_id=run_id
        )
        if not hmac.compare_digest(sha256_file(stage.runtime["wire"]), main_capture.sha256):
            raise KimiStageExecutorError("copied main Kimi wire hash mismatch")
        return stage.runtime["wire"], main_capture.sha256, tuple(captures)

    def _mcp_health(
        self,
        *,
        reservations: Sequence[Mapping[str, Any]],
        run_root: Path,
        run_id: str,
        stage_index: int,
    ) -> tuple[Mapping[str, Any], ...]:
        results: list[Mapping[str, Any]] = []
        for reservation in reservations:
            paths = ProxyPaths(
                initialize_trace=Path(str(reservation["initialize_trace"])),
                tools_list_trace=Path(str(reservation["tools_list_trace"])),
                stdio_trace=Path(str(reservation["stdio_trace"])),
                child_exit_trace=Path(str(reservation["child_exit_trace"])),
            )
            result = validate_health_evidence(
                run_root=run_root,
                run_id=run_id,
                server=str(reservation["server"]),
                stage_index=stage_index,
                paths=paths,
                child_argv_sha256=str(reservation["child_argv_sha256"]),
            )
            evidence_files: list[dict[str, Any]] = []
            for kind, path in (
                ("initialize_trace", paths.initialize_trace),
                ("tools_list_trace", paths.tools_list_trace),
                ("stdio_trace", paths.stdio_trace),
                ("child_exit_trace", paths.child_exit_trace),
            ):
                owned = _owned_path(
                    str(path),
                    run_root=run_root,
                    run_id=run_id,
                    label=f"MCP {kind}",
                    must_exist=True,
                )
                _assert_regular(owned, f"MCP {kind}")
                line_count = len(owned.read_bytes().splitlines())
                if line_count < 1:
                    raise KimiStageExecutorError(f"MCP {kind} is empty")
                evidence_files.append(
                    {
                        "kind": kind,
                        "path": str(owned),
                        "sha256": sha256_file(owned),
                        "line_count": line_count,
                    }
                )
            initialize_locator = str(result["initialize_result_locator"])
            initialize_path_raw, separator, initialize_line_raw = (
                initialize_locator.rpartition(":")
            )
            if not separator or not initialize_line_raw.isdigit():
                raise KimiStageExecutorError(
                    "MCP initialize result locator is malformed"
                )
            initialize_path = Path(initialize_path_raw).resolve()
            initialize_line = int(initialize_line_raw)
            try:
                initialize_record = json.loads(
                    initialize_path.read_text(encoding="utf-8").splitlines()[
                        initialize_line - 1
                    ]
                )
            except (OSError, IndexError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise KimiStageExecutorError(
                    "MCP initialize result locator is unreadable"
                ) from exc
            if not isinstance(initialize_record, Mapping) or not isinstance(
                initialize_record.get("time"), (str, int, float)
            ) or isinstance(initialize_record.get("time"), bool):
                raise KimiStageExecutorError(
                    "MCP initialize result lacks a direct timestamp"
                )
            enriched = dict(result)
            enriched["paths"] = {
                field: str(getattr(paths, field))
                for field in ProxyPaths.__dataclass_fields__
            }
            enriched["evidence_files"] = evidence_files
            enriched["observed_time"] = initialize_record["time"]
            results.append(enriched)
        return tuple(results)

    def _communicate(
        self,
        process: StageProcess,
        *,
        jsonrpc_exchange: JsonRpcExchange | None,
    ) -> tuple[bytes, bytes, bool]:
        timed_out = False
        try:
            if jsonrpc_exchange is None:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
            else:
                exchange = getattr(process, "exchange_jsonrpc", None)
                if not callable(exchange):
                    raise KimiStageExecutorError(
                        "launcher process cannot perform sequential JSON-RPC exchange"
                    )
                stdout, stderr = exchange(
                    request_frames=jsonrpc_exchange.request_frames,
                    expected_response_ids=jsonrpc_exchange.expected_response_ids,
                    timeout=self.timeout_seconds,
                )
        except (subprocess.TimeoutExpired, TimeoutError):
            timed_out = True
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except (subprocess.TimeoutExpired, TimeoutError):
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            raise KimiStageExecutorError("launcher process must return byte streams")
        return stdout, stderr, timed_out

    @staticmethod
    def _validate_jsonrpc_responses(
        stdout: bytes,
        exchange: JsonRpcExchange,
    ) -> None:
        response_order: list[str | int] = []
        try:
            lines = stdout.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise KimiStageExecutorError("ACP JSON-RPC output is not UTF-8") from exc
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise KimiStageExecutorError(
                    f"malformed ACP JSON-RPC output at line {line_number}"
                ) from exc
            if not isinstance(record, Mapping):
                raise KimiStageExecutorError("ACP JSON-RPC output is not an object")
            response_id = record.get("id")
            if (
                response_id in exchange.expected_response_ids
                and "method" not in record
            ):
                if "error" in record or "result" not in record:
                    raise KimiStageExecutorError(
                        f"ACP JSON-RPC response {response_id!r} was not successful"
                    )
                response_order.append(response_id)
        if tuple(response_order) != exchange.expected_response_ids:
            raise KimiStageExecutorError(
                "ACP JSON-RPC responses are missing, duplicated, or out of order"
            )

    def _validate_event_ir(
        self,
        *,
        path: Path,
        request: NormalizationRequest,
        run_root: Path,
    ) -> None:
        _assert_regular(path, "Event IR output")
        allowed_sources: set[Path] = set()
        allowed_source_lines: dict[tuple[int, Path], int] = {}

        def allow_exact_source(
            raw_path: Path,
            *,
            expected_sha256: str,
            label: str,
            stage_index: int,
            expected_line_count: int | None = None,
        ) -> Path:
            source = _owned_path(
                str(raw_path),
                run_root=run_root,
                run_id=request.run_id,
                label=label,
                must_exist=True,
            )
            _assert_regular(source, label)
            expected = _require_sha256(expected_sha256, f"{label} SHA-256")
            if not hmac.compare_digest(sha256_file(source), expected):
                raise KimiStageExecutorError(f"{label} SHA-256 drifted")
            if expected_line_count is not None:
                if (
                    not isinstance(expected_line_count, int)
                    or isinstance(expected_line_count, bool)
                    or expected_line_count < 1
                    or len(source.read_bytes().splitlines()) != expected_line_count
                ):
                    raise KimiStageExecutorError(f"{label} line count drifted")
                line_count = expected_line_count
            else:
                line_count = len(source.read_bytes().splitlines())
                if line_count < 1:
                    raise KimiStageExecutorError(f"{label} is empty")
            allowed_sources.add(source)
            allowed_source_lines[(stage_index, source)] = line_count
            return source

        def allow_append_only_wire_source(
            raw_path: Path,
            *,
            captured_path: Path,
            expected_sha256: str,
            expected_line_count: int,
            label: str,
            stage_index: int,
        ) -> Path:
            source = _owned_path(
                str(raw_path),
                run_root=run_root,
                run_id=request.run_id,
                label=label,
                must_exist=True,
            )
            _assert_regular(source, label)
            expected = _require_sha256(expected_sha256, f"{label} SHA-256")
            if (
                not isinstance(expected_line_count, int)
                or isinstance(expected_line_count, bool)
                or expected_line_count < 1
            ):
                raise KimiStageExecutorError(f"{label} line count is invalid")
            captured_bytes = captured_path.read_bytes()
            if not hmac.compare_digest(
                hashlib.sha256(captured_bytes).hexdigest(), expected
            ) or len(captured_bytes.splitlines()) != expected_line_count:
                raise KimiStageExecutorError(
                    f"{label} immutable capture hash/line_count drifted"
                )
            source_lines = source.read_bytes().splitlines(keepends=True)
            if len(source_lines) < expected_line_count:
                raise KimiStageExecutorError(f"{label} lost captured lines")
            prefix = b"".join(source_lines[:expected_line_count])
            if not hmac.compare_digest(
                hashlib.sha256(prefix).hexdigest(), expected
            ) or prefix != captured_bytes:
                raise KimiStageExecutorError(
                    f"{label} is not an append-only extension of its capture"
                )
            allowed_sources.add(source)
            allowed_source_lines[(stage_index, source)] = expected_line_count
            return source

        for capture in request.stage_captures:
            allow_exact_source(
                capture.stdout_path,
                expected_sha256=capture.stdout_sha256,
                label=f"stage {capture.index} stdout",
                stage_index=capture.index,
            )
            main_captures = [wire for wire in capture.wire_captures if wire.is_main]
            if len(main_captures) != 1:
                raise KimiStageExecutorError(
                    "stage capture does not identify exactly one main wire"
                )
            for position, wire in enumerate(capture.wire_captures):
                captured_path = allow_exact_source(
                    wire.captured_path,
                    expected_sha256=wire.sha256,
                    expected_line_count=wire.line_count,
                    label=f"stage {capture.index} captured wire {position}",
                    stage_index=capture.index,
                )
                source_path = allow_append_only_wire_source(
                    wire.source_path,
                    captured_path=captured_path,
                    expected_sha256=wire.sha256,
                    expected_line_count=wire.line_count,
                    label=f"stage {capture.index} native wire {position}",
                    stage_index=capture.index,
                )
            main_capture = main_captures[0]
            allow_exact_source(
                capture.main_wire_path,
                expected_sha256=capture.main_wire_sha256,
                expected_line_count=main_capture.line_count,
                label=f"stage {capture.index} main wire copy",
                stage_index=capture.index,
            )
            if not hmac.compare_digest(
                capture.main_wire_sha256, main_capture.sha256
            ):
                raise KimiStageExecutorError(
                    "main wire copy digest differs from its capture"
                )
            if capture.controller_trace_path is not None:
                allow_exact_source(
                    capture.controller_trace_path,
                    expected_sha256=_require_sha256(
                        capture.controller_trace_sha256,
                        "controller trace SHA-256",
                    ),
                    label=f"stage {capture.index} controller trace",
                    stage_index=capture.index,
                )
            if capture.observation_trace_path is not None:
                allow_exact_source(
                    capture.observation_trace_path,
                    expected_sha256=_require_sha256(
                        capture.observation_trace_sha256,
                        "adapter observation trace SHA-256",
                    ),
                    label=f"stage {capture.index} adapter observation trace",
                    stage_index=capture.index,
                )

            for health_index, health_raw in enumerate(capture.mcp_health):
                health = _mapping(
                    health_raw,
                    f"stage {capture.index} MCP health {health_index}",
                )
                raw_files = health.get("evidence_files")
                if not isinstance(raw_files, list) or not raw_files:
                    raise KimiStageExecutorError(
                        "MCP health lacks hash-pinned evidence files"
                    )
                evidence_files: dict[Path, tuple[int, str]] = {}
                for file_index, raw_file in enumerate(raw_files):
                    evidence = _mapping(
                        raw_file,
                        f"MCP health evidence file {file_index}",
                    )
                    evidence_path = _owned_path(
                        evidence.get("path"),
                        run_root=run_root,
                        run_id=request.run_id,
                        label=f"MCP health evidence file {file_index}",
                        must_exist=True,
                    )
                    _assert_regular(
                        evidence_path, f"MCP health evidence file {file_index}"
                    )
                    digest = _require_sha256(
                        evidence.get("sha256"),
                        f"MCP health evidence file {file_index} SHA-256",
                    )
                    line_count = evidence.get("line_count")
                    if (
                        not isinstance(line_count, int)
                        or isinstance(line_count, bool)
                        or line_count < 1
                        or len(evidence_path.read_bytes().splitlines()) != line_count
                        or not hmac.compare_digest(sha256_file(evidence_path), digest)
                    ):
                        raise KimiStageExecutorError(
                            "MCP health evidence path/hash/line_count drifted"
                        )
                    if evidence_path in evidence_files:
                        raise KimiStageExecutorError(
                            "MCP health evidence path is duplicated"
                        )
                    evidence_files[evidence_path] = (line_count, digest)

                locator_keys = (
                    "initialize_request_locator",
                    "initialize_result_locator",
                    "tools_list_request_locator",
                    "tools_list_result_locator",
                    "child_exit_locator",
                )
                for locator_key in locator_keys:
                    locator = _string(
                        health.get(locator_key), f"MCP health {locator_key}"
                    )
                    path_text, separator, line_text = locator.rpartition(":")
                    if separator and line_text.isdigit():
                        source_text = path_text
                        line_number = int(line_text)
                    else:
                        source_text = locator
                        line_number = None
                    source_path = Path(source_text).resolve()
                    snapshot = evidence_files.get(source_path)
                    if snapshot is None:
                        raise KimiStageExecutorError(
                            "MCP health locator lacks an exact evidence-file snapshot"
                        )
                    if line_number is not None and not 1 <= line_number <= snapshot[0]:
                        raise KimiStageExecutorError(
                            "MCP health locator line is outside its evidence file"
                        )
                    allowed_sources.add(source_path)
                    allowed_source_lines[(capture.index, source_path)] = snapshot[0]
        count = 0
        sequences: list[int] = []
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise KimiStageExecutorError(
                    f"malformed Event IR at {path}:{line_number}"
                ) from exc
            if not isinstance(event, Mapping):
                raise KimiStageExecutorError("Event IR line must be an object")
            validate_event_document(event)
            if (
                event.get("run_id") != request.run_id
                or event.get("case_id") != request.case_id
                or _mapping(event.get("harness"), "Event IR harness").get("id") != "kimi"
            ):
                raise KimiStageExecutorError("Event IR identity differs from execution")
            forbidden = _forbidden_paths(event, prefix=f"event[{line_number}]")
            if forbidden:
                raise KimiStageExecutorError(
                    "executor Event IR contains analyzer/scoring fields: " + ", ".join(forbidden)
                )
            source = _mapping(event.get("source"), "Event IR source")
            trace_path = Path(_string(source.get("trace_path"), "Event IR trace path")).resolve()
            event_stage = _mapping(event.get("stage"), "Event IR stage")
            stage_index = event_stage.get("index")
            source_line = source.get("line")
            line_limit = allowed_source_lines.get((stage_index, trace_path))
            if (
                trace_path not in allowed_sources
                or not _is_relative_to(trace_path, run_root)
                or not isinstance(source_line, int)
                or isinstance(source_line, bool)
                or line_limit is None
                or not 1 <= source_line <= line_limit
            ):
                raise KimiStageExecutorError("Event IR source is not captured run-local evidence")
            sequences.append(int(event["sequence"]))
            count += 1
        if count == 0 or sequences != list(range(count)):
            raise KimiStageExecutorError("Event IR must be non-empty with contiguous sequence")

    def execute(
        self,
        plan: Any,
        materialized: MaterializedCase,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute every READY stage without producing analyzer or score output."""

        if context.run_id != context.case_layout.run_id:
            raise KimiStageExecutorError("execution context run_id mismatch")
        if not hmac.compare_digest(sha256_file(self.executable), self.executable_sha256):
            raise KimiStageExecutorError("Kimi executable bytes drifted before execution")
        manifest, manifest_sha, canonical, workspace, stages = self._validate_materialization(
            plan=plan, materialized=materialized, context=context
        )
        run_root = Path(materialized.root).resolve(strict=True)
        attestation_path = self.launcher.attest(run_id=context.run_id, run_root=run_root)
        attestation, attestation_sha = self._validate_attestation(
            Path(attestation_path), run_id=context.run_id, run_root=run_root
        )
        if any(
            _mapping(stage.document.get("prompt"), "stage prompt").get(
                "controller_only"
            )
            is True
            for stage in stages
        ) and getattr(self.launcher, "jsonrpc_exchange_supported", False) is not True:
            raise KimiStageExecutorError(
                "attested launcher does not declare sequential JSON-RPC support"
            )

        captures: list[StageCapture] = []
        prior_results: list[Mapping[str, Any]] = []
        observed_pids: set[int] = set()
        outcome = COMPLETED
        final_return_code: int | None = 0
        failure_category: str | None = None
        retry_eligible = False
        disposition_reason: str | None = None
        matched_control_finalization_document: Mapping[str, Any] | None = None
        for initial_stage in stages:
            stage = initial_stage
            index = int(stage.document["index"])
            name = str(stage.document["name"])
            matched_control_locator: str | None = None
            if self.matched_control_boundary is not None:
                boundary = self.matched_control_boundary.apply_before_stage(
                    MatchedControlBoundaryRequest(
                        run_id=context.run_id,
                        case_id=materialized.case_id,
                        stage_index=index,
                        stage_name=name,
                        manifest_path=Path(materialized.manifest_path),
                        manifest_sha256=manifest_sha,
                    )
                )
                if boundary is not None:
                    if (
                        boundary.stage_index != index
                        or boundary.stage_name != name
                    ):
                        raise KimiStageExecutorError(
                            "matched-control boundary changed the current stage identity"
                        )
                    manifest, manifest_sha, stage, matched_control_locator = (
                        self._refresh_after_matched_control(
                            boundary=boundary,
                            plan=plan,
                            materialized=materialized,
                            context=context,
                            workspace=workspace,
                        )
                    )
            active_mcp = self._activate(
                stage, workspace=workspace, run_id=context.run_id
            )
            environment = self._environment(stage, run_id=context.run_id)
            direct_evidence_directive = self._prepare_direct_evidence(
                stage,
                run_id=context.run_id,
                case_id=materialized.case_id,
                prior_results=prior_results,
            )
            directive = self._directive(
                stage,
                run_id=context.run_id,
                case_id=materialized.case_id,
                prior_results=prior_results,
            )
            directive = ControlDirective(
                argv_suffix=directive.argv_suffix,
                evidence_locators=tuple(
                    dict.fromkeys(
                        (
                            *directive.evidence_locators,
                            *direct_evidence_directive.evidence_locators,
                        )
                    )
                ),
                launch_mode=directive.launch_mode,
                jsonrpc_exchange=directive.jsonrpc_exchange,
            )
            prompt_contract = _mapping(stage.document.get("prompt"), "stage prompt")
            controller_only = prompt_contract.get("controller_only") is True
            if controller_only:
                if directive.launch_mode != "controller":
                    raise KimiStageExecutorError(
                        "controller-only stage was not claimed by its injected controller"
                    )
                argv = [str(self.executable), *directive.argv_suffix]
                if "--prompt" in argv or "/compact" in argv:
                    raise KimiStageExecutorError(
                        "ACP compaction control must not be sent as a CLI model prompt"
                    )
                session_controller = _mapping(
                    _mapping(
                        _mapping(stage.document.get("surfaces"), "stage surfaces").get("session", {}),
                        "stage session surface",
                    ).get("controller"),
                    "session controller",
                )
                argv_contract = _mapping(
                    session_controller.get("argv_contract", {}),
                    "controller argv contract",
                )
                required_subcommand = argv_contract.get("required_subcommand")
                if required_subcommand is not None and argv[1:].count(
                    str(required_subcommand)
                ) != 1:
                    raise KimiStageExecutorError(
                        "controller-only stage omitted its required subcommand"
                    )
                self._validate_controller_exchange(
                    stage, directive, workspace=workspace
                )
            else:
                if (
                    directive.launch_mode != "prompt"
                    or directive.jsonrpc_exchange is not None
                ):
                    raise KimiStageExecutorError(
                        "prompt stage received a controller-owned launch payload"
                    )
                argv = [
                    str(self.executable),
                    "--prompt",
                    stage.prompt,
                    "--output-format",
                    "stream-json",
                ]
            skills = _mapping(
                _mapping(stage.document.get("surfaces"), "stage surfaces").get("skills"),
                "stage skills",
            )
            if not controller_only and _mapping(
                skills.get("activation"), "skill activation"
            ).get("operation") == "replace_tree":
                argv.extend(("--skills-dir", str(workspace / ".kimi-code" / "skills")))
            if not controller_only:
                argv.extend(directive.argv_suffix)
            if any(_SENSITIVE_ENV_RE.search(item) for item in environment):
                raise KimiStageExecutorError("credential-like environment key reached launch")
            write_mounts, read_only_mounts = self._launch_mounts(
                stage,
                run_root=run_root,
                run_id=context.run_id,
                workspace=workspace,
                manifest_sha256=manifest_sha,
            )
            before_wires = self._wire_snapshot(stage.runtime["kimi_home"])
            request = StageLaunchRequest(
                run_id=context.run_id,
                case_id=materialized.case_id,
                stage_index=index,
                stage_name=name,
                argv=tuple(argv),
                executable_sha256=self.executable_sha256,
                cwd=workspace,
                env=environment,
                timeout_seconds=self.timeout_seconds,
                stdout_path=stage.runtime["trace"],
                wire_copy_path=stage.runtime["wire"],
                result_path=stage.runtime["result"],
                launcher_attestation_path=Path(attestation_path),
                materialization_manifest_path=Path(
                    materialized.manifest_path
                ).resolve(strict=True),
                materialization_manifest_sha256=manifest_sha,
                write_mounts=write_mounts,
                read_only_mounts=read_only_mounts,
            )
            process = self.launcher.spawn(request)
            pid = getattr(process, "pid", None)
            if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
                raise KimiStageExecutorError("launcher returned an invalid process id")
            if pid in observed_pids:
                process.terminate()
                raise KimiStageExecutorError("fresh stage did not receive a new OS process")
            observed_pids.add(pid)
            try:
                context.process_registry.register(
                    pid, role=f"kimi-stage-{index:03d}-{_safe_stage_name(name)}"
                )
            except Exception:
                process.terminate()
                raise
            atomic_write_json(
                stage.runtime["pid_record"],
                {
                    "schema_name": "safety_bench_kimi_stage_pid_reference",
                    "schema_version": 1,
                    "harness_id": "kimi",
                    "run_id": context.run_id,
                    "case_id": materialized.case_id,
                    "stage_index": index,
                    "pid": pid,
                    "owned_registry_path": str(context.process_registry.record_path),
                },
                run_id=context.run_id,
            )
            stdout, stderr, timed_out = self._communicate(
                process, jsonrpc_exchange=directive.jsonrpc_exchange
            )
            return_code = getattr(process, "returncode", None)
            if not isinstance(return_code, int) or isinstance(return_code, bool):
                raise KimiStageExecutorError("launcher process has no final integer return code")
            _atomic_write_bytes(stage.runtime["trace"], stdout, run_id=context.run_id)
            stdout_lines = _validate_stdout_jsonl(stdout, stage.runtime["trace"])
            stderr_path = stage.runtime["artifact"] / (
                f"stderr-kimi-{context.run_id}-stage-{index:03d}.log"
            )
            _atomic_write_bytes(stderr_path, stderr, run_id=context.run_id)
            controller_trace_path: Path | None = None
            controller_trace_sha256: str | None = None
            if controller_only:
                acp_trace = stage.runtime.get("acp_trace")
                if acp_trace is None:
                    raise KimiStageExecutorError(
                        "controller-only ACP stage has no run-local ACP trace path"
                    )
                _atomic_write_bytes(acp_trace, stdout, run_id=context.run_id)
                controller_trace_path = acp_trace
                controller_trace_sha256 = sha256_file(acp_trace)
            if directive.jsonrpc_exchange is not None:
                try:
                    self._validate_jsonrpc_responses(
                        stdout,
                        directive.jsonrpc_exchange,
                    )
                except KimiStageExecutorError as exc:
                    failure_document = {
                        "schema_name": "safety_bench_kimi_stage_execution",
                        "schema_version": 1,
                        "harness_id": "kimi",
                        "run_id": context.run_id,
                        "case_id": materialized.case_id,
                        "stage": {"index": index, "name": name},
                        "pid": pid,
                        "return_code": return_code,
                        "timed_out": timed_out,
                        "started_with_fresh_os_process": True,
                        "cwd": str(workspace),
                        "environment_keys": sorted(environment),
                        "argv": list(argv),
                        "controller_request_sha256": [
                            hashlib.sha256(frame).hexdigest()
                            for frame in directive.jsonrpc_exchange.request_frames
                        ],
                        "stdout": {
                            "path": str(stage.runtime["trace"]),
                            "sha256": sha256_file(stage.runtime["trace"]),
                            "line_count": stdout_lines,
                        },
                        "stderr": {
                            "path": str(stderr_path),
                            "sha256": sha256_file(stderr_path),
                        },
                        "controller_trace": {
                            "path": str(controller_trace_path),
                            "sha256": controller_trace_sha256,
                        },
                        "launcher_attestation": {
                            "path": str(attestation_path),
                            "sha256": attestation_sha,
                        },
                        "execution_disposition": {
                            "outcome": EXECUTION_INVALID,
                            "failure_category": exc.failure_category,
                            "retry_eligible": exc.retry_eligible,
                            "reason": str(exc),
                        },
                        "completed_at": _utc_now(),
                    }
                    atomic_write_json(
                        stage.runtime["result"],
                        failure_document,
                        run_id=context.run_id,
                    )
                    return ExecutionResult(
                        outcome=EXECUTION_INVALID,
                        return_code=return_code,
                        raw_stdout_path=stage.runtime["trace"],
                        raw_wire_path=None,
                        event_ir_path=None,
                        failure_category=exc.failure_category,
                        retry_eligible=exc.retry_eligible,
                        metadata={
                            "schema_name": EXECUTION_SCHEMA_NAME,
                            "schema_version": EXECUTION_SCHEMA_VERSION,
                            "run_id": context.run_id,
                            "case_id": materialized.case_id,
                            "manifest_sha256": manifest_sha,
                            "execution_disposition": failure_document[
                                "execution_disposition"
                            ],
                            "stage_result": {
                                "path": str(stage.runtime["result"]),
                                "sha256": sha256_file(stage.runtime["result"]),
                            },
                        },
                    )
            main_wire, main_wire_sha, wires = self._capture_wires(
                stage=stage, before=before_wires, run_id=context.run_id
            )
            mcp_health: tuple[Mapping[str, Any], ...] = ()
            # A forced stage timeout may terminate Kimi before its MCP client can
            # finish the normal stdin-close/child-exit handshake.  In that case
            # the missing clean-exit record is secondary cleanup fallout, not the
            # primary execution failure.  Preserve the explicit timeout
            # disposition instead of letting MCP health validation mask it.
            if stage.mcp_reservations and not timed_out:
                if active_mcp is None:
                    raise KimiStageExecutorError("MCP reservations exist without active config")
                expected_mcp = str(
                    _mapping(
                        _mapping(
                            _mapping(stage.document.get("surfaces"), "stage surfaces").get("mcp"),
                            "stage MCP",
                        ).get("activation"),
                        "MCP activation",
                    )["source_sha256"]
                )
                if not hmac.compare_digest(sha256_file(active_mcp), expected_mcp):
                    raise KimiStageExecutorError("active MCP config drifted during Kimi stage")
                mcp_health = self._mcp_health(
                    reservations=stage.mcp_reservations,
                    run_root=run_root,
                    run_id=context.run_id,
                    stage_index=index,
                )
            stage_document = {
                "schema_name": "safety_bench_kimi_stage_execution",
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": context.run_id,
                "case_id": materialized.case_id,
                "stage": {"index": index, "name": name},
                "pid": pid,
                "return_code": return_code,
                "timed_out": timed_out,
                "started_with_fresh_os_process": True,
                "cwd": str(workspace),
                "environment_keys": sorted(environment),
                "argv": (
                    list(argv)
                    if controller_only
                    else [
                        str(self.executable),
                        "--prompt",
                        f"<sha256:{stage.prompt_sha256}>",
                        *argv[3:],
                    ]
                ),
                "controller_request_sha256": (
                    [hashlib.sha256(frame).hexdigest() for frame in directive.jsonrpc_exchange.request_frames]
                    if directive.jsonrpc_exchange is not None
                    else []
                ),
                "stdout": {
                    "path": str(stage.runtime["trace"]),
                    "sha256": sha256_file(stage.runtime["trace"]),
                    "line_count": stdout_lines,
                },
                "stderr": {
                    "path": str(stderr_path),
                    "sha256": sha256_file(stderr_path),
                },
                "wire": {
                    "main_path": str(main_wire),
                    "main_sha256": main_wire_sha,
                    "captures": [item.as_dict() for item in wires],
                },
                "mcp_health": [dict(item) for item in mcp_health],
                "control_evidence": list(
                    dict.fromkeys(
                        (
                            *directive.evidence_locators,
                            *(
                                (matched_control_locator,)
                                if matched_control_locator is not None
                                else ()
                            ),
                        )
                    )
                ),
                "controller_trace": (
                    {
                        "path": str(controller_trace_path),
                        "sha256": controller_trace_sha256,
                    }
                    if controller_trace_path is not None
                    else None
                ),
                "launcher_attestation": {
                    "path": str(attestation_path),
                    "sha256": attestation_sha,
                },
                "completed_at": _utc_now(),
            }
            if timed_out:
                final_return_code = return_code
                if (
                    not controller_only
                    and self.timeout_seconds
                    >= MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS
                ):
                    outcome = MODEL_PROTOCOL_INCOMPLETE
                    failure_category = "MODEL_STAGE_TIMEOUT"
                    retry_eligible = False
                    disposition_reason = (
                        "Kimi prompt stage did not complete within the reviewed "
                        f"{MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS}-second "
                        "model protocol limit"
                    )
                else:
                    outcome = EXECUTION_INVALID
                    failure_category = "PROVIDER_TIMEOUT"
                    retry_eligible = True
                    disposition_reason = "Kimi stage exceeded the explicit timeout"
                stage_document["execution_disposition"] = {
                    "outcome": outcome,
                    "failure_category": failure_category,
                    "retry_eligible": retry_eligible,
                    "reason": disposition_reason,
                    "timed_out": True,
                    "timeout_seconds": self.timeout_seconds,
                }
            elif return_code != 0:
                outcome = EXECUTION_INVALID
                final_return_code = return_code
                failure_category = "PROCESS_EXIT_NONZERO"
                retry_eligible = False
                disposition_reason = (
                    f"Kimi stage exited with non-zero status {return_code}"
                )
                stage_document["execution_disposition"] = {
                    "outcome": outcome,
                    "failure_category": failure_category,
                    "retry_eligible": False,
                    "reason": disposition_reason,
                }
            finalization = ControlFinalization()
            if not timed_out and return_code == 0:
                try:
                    finalization = self._finalize_controls(
                        stage,
                        run_id=context.run_id,
                        case_id=materialized.case_id,
                        prior_results=prior_results,
                        stage_result=stage_document,
                    )
                    direct_finalization = self._finalize_direct_evidence(
                        stage,
                        run_id=context.run_id,
                        case_id=materialized.case_id,
                        prior_results=prior_results,
                        stage_result=stage_document,
                    )
                    finalization = ControlFinalization(
                        evidence_locators=tuple(
                            dict.fromkeys(
                                (
                                    *finalization.evidence_locators,
                                    *direct_finalization.evidence_locators,
                                )
                            )
                        ),
                        observation_records=(
                            *finalization.observation_records,
                            *direct_finalization.observation_records,
                        ),
                    )
                except KimiExecutionDispositionError as exc:
                    if exc.outcome != MODEL_PROTOCOL_INCOMPLETE:
                        raise
                    # The controller reached this exception only after checking
                    # directly captured native evidence.  Preserve those bytes
                    # and stop before normalization; this is a terminal model
                    # disposition, not an infrastructure retry.
                    outcome = MODEL_PROTOCOL_INCOMPLETE
                    final_return_code = return_code
                    failure_category = exc.failure_category
                    retry_eligible = False
                    disposition_reason = str(exc)
                    stage_document["execution_disposition"] = {
                        "outcome": outcome,
                        "failure_category": failure_category,
                        "retry_eligible": False,
                        "reason": disposition_reason,
                    }
            control_evidence = tuple(
                dict.fromkeys(
                    (
                        *directive.evidence_locators,
                        *finalization.evidence_locators,
                        *(
                            (matched_control_locator,)
                            if matched_control_locator is not None
                            else ()
                        ),
                    )
                )
            )
            health_observations = tuple(
                {
                    "type": "adapter.mcp_health_observed",
                    "time": health["observed_time"],
                    "server": health["server"],
                    "child_argv_sha256": health["child_argv_sha256"],
                    "paths": dict(
                        _mapping(health.get("paths"), "MCP health evidence paths")
                    ),
                }
                for health in mcp_health
            )
            observation_records = (
                *health_observations,
                *finalization.observation_records,
            )
            observation_trace_path: Path | None = None
            observation_trace_sha256: str | None = None
            if observation_records:
                observation_trace_path = stage.runtime["artifact"] / (
                    f"control-observations-kimi-{context.run_id}-stage-{index:03d}.jsonl"
                )
                observation_bytes = "".join(
                    json.dumps(
                        record,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                    + "\n"
                    for record in observation_records
                ).encode("utf-8")
                _atomic_write_bytes(
                    observation_trace_path,
                    observation_bytes,
                    run_id=context.run_id,
                )
                observation_trace_sha256 = sha256_file(observation_trace_path)
            stage_document["control_evidence"] = list(control_evidence)
            stage_document["control_observation_trace"] = (
                {
                    "path": str(observation_trace_path),
                    "sha256": observation_trace_sha256,
                    "record_count": len(observation_records),
                }
                if observation_trace_path is not None
                else None
            )
            forbidden = _forbidden_paths(stage_document)
            if forbidden:
                raise KimiStageExecutorError(
                    "stage evidence contains analyzer/scoring fields: " + ", ".join(forbidden)
                )
            atomic_write_json(stage.runtime["result"], stage_document, run_id=context.run_id)
            capture = StageCapture(
                index=index,
                name=name,
                pid=pid,
                return_code=return_code,
                stdout_path=stage.runtime["trace"],
                stdout_sha256=sha256_file(stage.runtime["trace"]),
                stderr_path=stderr_path,
                stderr_sha256=sha256_file(stderr_path),
                main_wire_path=main_wire,
                main_wire_sha256=main_wire_sha,
                wire_captures=wires,
                result_path=stage.runtime["result"],
                mcp_health=mcp_health,
                control_evidence=control_evidence,
                controller_trace_path=controller_trace_path,
                controller_trace_sha256=controller_trace_sha256,
                observation_trace_path=observation_trace_path,
                observation_trace_sha256=observation_trace_sha256,
                timed_out=timed_out,
                timeout_seconds=self.timeout_seconds,
            )
            captures.append(capture)
            prior_results.append(stage_document)
            if outcome != COMPLETED:
                break
            if not hmac.compare_digest(tree_sha256(canonical), str(manifest["canonical"]["tree_sha256"])):
                raise KimiStageExecutorError("canonical case changed during stage execution")

        if outcome == COMPLETED and self.matched_control_boundary is not None:
            finalization = self.matched_control_boundary.finalize()
            if not isinstance(finalization, MatchedControlBoundaryFinalization):
                raise KimiStageExecutorError(
                    "matched-control boundary returned an invalid finalization"
                )
            evidence_path = _owned_path(
                str(finalization.evidence_path),
                run_root=run_root,
                run_id=context.run_id,
                label="matched-control final evidence",
                must_exist=True,
            )
            _assert_regular(evidence_path, "matched-control final evidence")
            evidence_sha = _require_sha256(
                finalization.evidence_sha256,
                "matched-control final evidence SHA-256",
            )
            if not hmac.compare_digest(sha256_file(evidence_path), evidence_sha):
                raise KimiStageExecutorError(
                    "matched-control final evidence hash drifted"
                )
            try:
                control_document = _mapping(
                    json.loads(evidence_path.read_text(encoding="utf-8")),
                    "matched-control final evidence",
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise KimiStageExecutorError(
                    "matched-control final evidence is malformed"
                ) from exc
            applied = control_document.get("applied_before_stage_indices")
            if (
                control_document.get("harness_id") != "kimi"
                or control_document.get("run_id") != context.run_id
                or control_document.get("applied") is not True
                or not isinstance(applied, list)
                or tuple(applied) != finalization.applied_stage_indices
                or sorted(set(applied)) != applied
            ):
                raise KimiStageExecutorError(
                    "matched-control final evidence is incomplete"
                )
            forbidden = _forbidden_paths(
                control_document, prefix="matched_control_final"
            )
            if forbidden:
                raise KimiStageExecutorError(
                    "matched-control final evidence contains scoring fields: "
                    + ", ".join(forbidden)
                )
            matched_control_finalization_document = {
                "path": str(evidence_path),
                "sha256": evidence_sha,
                "applied_before_stage_indices": list(
                    finalization.applied_stage_indices
                ),
            }

        if outcome != COMPLETED:
            last = captures[-1] if captures else None
            return ExecutionResult(
                outcome=outcome,
                return_code=final_return_code,
                raw_stdout_path=last.stdout_path if last else None,
                raw_wire_path=last.main_wire_path if last else None,
                event_ir_path=None,
                failure_category=failure_category,
                retry_eligible=retry_eligible,
                metadata={
                    "schema_name": EXECUTION_SCHEMA_NAME,
                    "schema_version": EXECUTION_SCHEMA_VERSION,
                    "run_id": context.run_id,
                    "case_id": materialized.case_id,
                    "manifest_sha256": manifest_sha,
                    "execution_disposition": {
                        "outcome": outcome,
                        "failure_category": failure_category,
                        "retry_eligible": retry_eligible,
                        "reason": disposition_reason,
                    },
                    "stages": [item.as_dict() for item in captures],
                },
            )

        event_ir_path = run_root / f"event-ir-kimi-{context.run_id}.jsonl"
        if event_ir_path.exists() or event_ir_path.is_symlink():
            raise KimiStageExecutorError("Event IR output path already exists")
        normalization = NormalizationRequest(
            run_id=context.run_id,
            case_id=materialized.case_id,
            manifest_path=Path(materialized.manifest_path),
            manifest_sha256=manifest_sha,
            stage_captures=tuple(captures),
            output_path=event_ir_path,
        )
        try:
            normalized_path = Path(self.event_ir_normalizer.normalize(normalization))
        except KimiModelProtocolIncompleteError as exc:
            final = captures[-1]
            return ExecutionResult(
                outcome=MODEL_PROTOCOL_INCOMPLETE,
                return_code=0,
                raw_stdout_path=final.stdout_path,
                raw_wire_path=final.main_wire_path,
                event_ir_path=None,
                failure_category=exc.failure_category,
                retry_eligible=False,
                metadata={
                    "schema_name": EXECUTION_SCHEMA_NAME,
                    "schema_version": EXECUTION_SCHEMA_VERSION,
                    "harness_id": "kimi",
                    "run_id": context.run_id,
                    "case_id": materialized.case_id,
                    "manifest_sha256": manifest_sha,
                    "execution_disposition": {
                        "outcome": MODEL_PROTOCOL_INCOMPLETE,
                        "failure_category": exc.failure_category,
                        "retry_eligible": False,
                        "reason": str(exc),
                        "source": "event_ir_normalizer",
                    },
                    "stages": [item.as_dict() for item in captures],
                },
            )
        except KimiExecutionDispositionError:
            raise
        except Exception as exc:
            raise KimiStageExecutorError(
                f"Event IR normalization failed closed: {type(exc).__name__}: {exc}",
                failure_category="TRACE_NORMALIZATION_INVALID",
            ) from exc
        if normalized_path.resolve() != event_ir_path.resolve():
            raise KimiStageExecutorError("normalizer wrote outside its assigned Event IR path")
        self._validate_event_ir(
            path=event_ir_path,
            request=normalization,
            run_root=run_root,
        )
        if not hmac.compare_digest(tree_sha256(canonical), str(manifest["canonical"]["tree_sha256"])):
            raise KimiStageExecutorError("canonical case changed during Kimi execution")
        metadata = {
            "schema_name": EXECUTION_SCHEMA_NAME,
            "schema_version": EXECUTION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": context.run_id,
            "case_id": materialized.case_id,
            "manifest_path": str(materialized.manifest_path),
            "manifest_sha256": manifest_sha,
            "executable": {
                "path": str(self.executable),
                "sha256": self.executable_sha256,
            },
            "launcher_attestation": {
                "path": str(attestation_path),
                "sha256": attestation_sha,
                "launcher_id": attestation["launcher_id"],
            },
            "fresh_os_process_count": len(observed_pids),
            "stages": [item.as_dict() for item in captures],
            "event_ir_sha256": sha256_file(event_ir_path),
        }
        if matched_control_finalization_document is not None:
            metadata["matched_control_intervention"] = dict(
                matched_control_finalization_document
            )
        forbidden = _forbidden_paths(metadata)
        if forbidden:
            raise KimiStageExecutorError(
                "executor metadata contains analyzer/scoring fields: " + ", ".join(forbidden)
            )
        final = captures[-1]
        return ExecutionResult(
            outcome=COMPLETED,
            return_code=0,
            raw_stdout_path=final.stdout_path,
            raw_wire_path=final.main_wire_path,
            event_ir_path=event_ir_path,
            metadata=metadata,
        )


__all__ = [
    "ATTESTATION_SCHEMA_NAME",
    "ATTESTATION_SCHEMA_VERSION",
    "ControlFinalization",
    "ControlDirective",
    "EventIRNormalizer",
    "IsolatedStageLauncher",
    "JsonRpcExchange",
    "KimiStageExecutor",
    "KimiStageExecutorError",
    "MatchedControlBoundary",
    "MatchedControlBoundaryFinalization",
    "MatchedControlBoundaryRequest",
    "MatchedControlBoundaryResult",
    "NativeBoundaryController",
    "NormalizationRequest",
    "StageCapture",
    "StageControlRequest",
    "StageControlFinalizeRequest",
    "StageLaunchRequest",
    "StageProcess",
    "WireCapture",
]
