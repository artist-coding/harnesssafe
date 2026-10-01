"""Completed Kimi execution to unchanged shared-analyzer pipeline.

This module is deliberately Kimi-owned.  It does not interpret oracle output
and it never creates a score or verdict.  Its only jobs are to revalidate one
terminal Kimi 0.26.0 execution, construct the already-reviewed analyzer
compatibility projection, publish an exact completed-trial evidence document,
and invoke the repository's unchanged analyzer through :mod:`analysis_invoker`.

Every source is re-read from a private run root and hash/line pinned.  Existing
outputs are never replaced.  A failure rolls back only output paths created by
this invocation; captured execution evidence is never modified.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Any, Callable, Mapping, Protocol, Sequence

from .analysis_invoker import (
    COMPLETED_TRIAL_SCHEMA_NAME,
    COMPLETED_TRIAL_SCHEMA_VERSION,
    KimiAnalysisInvocationRequest,
    KimiAnalysisInvocationResult,
    PinnedAnalysisInput,
    invoke_kimi_shared_analyzer,
)
from .analyzer_projection import (
    SEMANTIC_TRANSLATION,
    KimiAnalyzerProjectionRequest,
    KimiAnalyzerProjectionResult,
    KimiCallbackCollectorEvidence,
    KimiProjectionStage,
    PinnedProjectionInput,
    project_kimi_analyzer_compatibility,
)
from .bench_materializer import load_bench_materialization_manifest
from .runner import (
    COMPLETED,
    CaseExecutor,
    CasePlan,
    ExecutionContext,
    ExecutionResult,
    MaterializedCase,
)


KIMI_ANALYSIS_PIPELINE_VERSION = 1
EXPECTED_KIMI_VERSION = "0.26.0"
EXPECTED_KIMI_EXECUTABLE = Path(
    "/usr/local/lib/node_modules/@moonshot-ai/kimi-code/dist/main.mjs"
)
EXPECTED_KIMI_EXECUTABLE_SHA256 = (
    "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
)

_EXECUTION_SCHEMA_NAME = "safety_bench_kimi_execution_evidence"
_EXECUTION_SCHEMA_VERSION = 1
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset(
    {
        "attack_success",
        "confirmed_compromise",
        "oracle",
        "oracle_path",
        "progress_node",
        "risk_score",
        "score",
        "scored_result",
        "verdict",
    }
)


class KimiAnalysisPipelineError(RuntimeError):
    """A completed execution could not cross an exact analysis boundary."""


@dataclass(frozen=True)
class KimiCallbackEvidencePaths:
    """The inseparable manifest/evidence pair from one callback collector."""

    manifest_path: Path
    evidence_path: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifest_path", Path(self.manifest_path).absolute())
        object.__setattr__(self, "evidence_path", Path(self.evidence_path).absolute())
        if self.manifest_path == self.evidence_path:
            raise ValueError("callback manifest and evidence paths must differ")


@dataclass(frozen=True)
class KimiCompletedAnalysisRequest:
    """One terminal execution and the exact materialization which produced it."""

    run_id: str
    case_id: str
    trial_id: str
    run_root: Path
    materialization_manifest_path: Path
    execution_result: ExecutionResult
    callback: KimiCallbackEvidencePaths | None = None
    timeout_seconds: int = 120


@dataclass(frozen=True)
class KimiCompletedAnalysisResult:
    projection: KimiAnalyzerProjectionResult
    completed_trial_path: Path
    completed_trial_sha256: str
    invocation: KimiAnalysisInvocationResult


class KimiCompletedAnalysisCallable(Protocol):
    def __call__(
        self, request: KimiCompletedAnalysisRequest
    ) -> KimiCompletedAnalysisResult: ...


class KimiCallbackEvidenceProvider(Protocol):
    def __call__(
        self,
        plan: CasePlan,
        materialized: MaterializedCase,
        context: ExecutionContext,
        result: ExecutionResult,
    ) -> KimiCallbackEvidencePaths | None: ...


Projector = Callable[[KimiAnalyzerProjectionRequest], KimiAnalyzerProjectionResult]
Invoker = Callable[[KimiAnalysisInvocationRequest], KimiAnalysisInvocationResult]


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    try:
        content = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KimiAnalysisPipelineError(
            "execution metadata is not canonical JSON"
        ) from exc
    return _sha256_bytes(content)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiAnalysisPipelineError(f"{label} must be an object")
    return value


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise KimiAnalysisPipelineError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise KimiAnalysisPipelineError(f"{label} must be a non-empty string")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise KimiAnalysisPipelineError(f"{label} is not a lowercase SHA-256")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise KimiAnalysisPipelineError(f"{label} must be an integer >= {minimum}")
    return value


def _reject_forbidden(value: Any, *, prefix: str = "evidence") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{prefix}.{key}"
            if str(key).casefold() in _FORBIDDEN_KEYS:
                raise KimiAnalysisPipelineError(
                    f"analysis boundary contains forbidden scoring key: {child_path}"
                )
            _reject_forbidden(child, prefix=child_path)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for index, child in enumerate(value):
            _reject_forbidden(child, prefix=f"{prefix}[{index}]")


def _validate_identity(request: KimiCompletedAnalysisRequest) -> None:
    for value, label in (
        (request.run_id, "run_id"),
        (request.case_id, "case_id"),
        (request.trial_id, "trial_id"),
    ):
        if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
            raise KimiAnalysisPipelineError(f"{label} has an unsafe identity")
    if (
        not isinstance(request.timeout_seconds, int)
        or isinstance(request.timeout_seconds, bool)
        or not 1 <= request.timeout_seconds <= 900
    ):
        raise KimiAnalysisPipelineError("analysis timeout must be 1-900 seconds")
    if not isinstance(request.execution_result, ExecutionResult):
        raise KimiAnalysisPipelineError(
            "analysis pipeline requires runner.ExecutionResult"
        )


def _strict_run_root(request: KimiCompletedAnalysisRequest) -> Path:
    supplied = Path(request.run_root).absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise KimiAnalysisPipelineError("run_root must be a real directory")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise KimiAnalysisPipelineError("run_root is unavailable") from exc
    if resolved != supplied:
        raise KimiAnalysisPipelineError("run_root must not use a symlink alias")
    if (
        "kimi" not in resolved.as_posix().casefold()
        or request.run_id not in resolved.as_posix()
        or resolved.stat().st_mode & 0o077
    ):
        raise KimiAnalysisPipelineError(
            "run_root lacks private, exact Kimi/run ownership"
        )
    return resolved


def _run_path(
    raw: Path | str,
    *,
    run_root: Path,
    label: str,
    must_exist: bool = True,
) -> Path:
    supplied = Path(raw).absolute()
    if supplied.is_symlink():
        raise KimiAnalysisPipelineError(f"{label} must not be a symlink")
    try:
        relative = supplied.relative_to(run_root)
    except ValueError as exc:
        raise KimiAnalysisPipelineError(f"{label} escapes the exact run root") from exc
    cursor = run_root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiAnalysisPipelineError(f"{label} traverses a symlink")
    try:
        resolved = supplied.resolve(strict=must_exist)
    except OSError as exc:
        raise KimiAnalysisPipelineError(f"{label} is unavailable") from exc
    try:
        resolved.relative_to(run_root)
    except ValueError as exc:
        raise KimiAnalysisPipelineError(f"{label} resolves outside run_root") from exc
    return resolved


def _regular_file(raw: Path | str, *, run_root: Path, label: str) -> Path:
    path = _run_path(raw, run_root=run_root, label=label)
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise KimiAnalysisPipelineError(f"{label} is not a regular file")
    return path


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiAnalysisPipelineError(f"{label} is malformed JSON") from exc
    return _mapping(decoded, label)


def _read_jsonl(
    path: Path, *, label: str, allow_empty: bool = False
) -> tuple[Mapping[str, Any], ...]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise KimiAnalysisPipelineError(f"{label} is not UTF-8") from exc
    records: list[Mapping[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise KimiAnalysisPipelineError(
                f"{label}:{line_number} is an empty JSONL record"
            )
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise KimiAnalysisPipelineError(
                f"{label}:{line_number} is malformed JSON"
            ) from exc
        records.append(_mapping(decoded, f"{label}:{line_number}"))
    if not records and not allow_empty:
        raise KimiAnalysisPipelineError(f"{label} is empty")
    return tuple(records)


def _pinned_json(
    raw: Path | str,
    *,
    expected_sha256: str,
    run_root: Path,
    label: str,
    kind: str,
) -> tuple[PinnedProjectionInput, Mapping[str, Any]]:
    path = _regular_file(raw, run_root=run_root, label=label)
    content = path.read_bytes()
    expected = _sha256(expected_sha256, f"{label} SHA-256")
    if not hmac.compare_digest(_sha256_bytes(content), expected):
        raise KimiAnalysisPipelineError(f"{label} SHA-256 drifted")
    document = _read_json(path, label)
    return (
        PinnedProjectionInput(
            path=path,
            sha256=expected,
            line_count=len(content.splitlines()),
            kind=kind,
        ),
        document,
    )


def _pinned_jsonl(
    raw: Path | str,
    *,
    expected_sha256: str,
    expected_line_count: int | None,
    run_root: Path,
    label: str,
    kind: str,
    allow_empty: bool = False,
) -> tuple[PinnedProjectionInput, tuple[Mapping[str, Any], ...]]:
    path = _regular_file(raw, run_root=run_root, label=label)
    content = path.read_bytes()
    expected = _sha256(expected_sha256, f"{label} SHA-256")
    if not hmac.compare_digest(_sha256_bytes(content), expected):
        raise KimiAnalysisPipelineError(f"{label} SHA-256 drifted")
    records = _read_jsonl(path, label=label, allow_empty=allow_empty)
    observed_lines = len(content.splitlines())
    if len(records) != observed_lines:
        raise KimiAnalysisPipelineError(f"{label} contains uncounted lines")
    if expected_line_count is not None and _integer(
        expected_line_count, f"{label} line count"
    ) != observed_lines:
        raise KimiAnalysisPipelineError(f"{label} line count drifted")
    return (
        PinnedProjectionInput(
            path=path,
            sha256=expected,
            line_count=observed_lines,
            kind=kind,
        ),
        records,
    )


def _register_path(path: Path, seen: set[Path], *, label: str) -> None:
    if path in seen:
        raise KimiAnalysisPipelineError(f"duplicate analysis input path: {label}")
    seen.add(path)


def _validate_executable(metadata: Mapping[str, Any]) -> Path:
    executable = _mapping(metadata.get("executable"), "execution executable")
    if set(executable) != {"path", "sha256"}:
        raise KimiAnalysisPipelineError("execution executable keys drifted")
    raw_path = Path(_string(executable.get("path"), "execution executable path"))
    if not raw_path.is_absolute() or raw_path.is_symlink():
        raise KimiAnalysisPipelineError(
            "execution executable must be its resolved absolute path"
        )
    try:
        path = raw_path.resolve(strict=True)
        expected_path = EXPECTED_KIMI_EXECUTABLE.resolve(strict=True)
    except OSError as exc:
        raise KimiAnalysisPipelineError("reviewed Kimi executable is unavailable") from exc
    digest = _sha256(executable.get("sha256"), "execution executable")
    if (
        path != raw_path
        or path != expected_path
        or not path.is_file()
        or not os.access(path, os.X_OK)
        or not hmac.compare_digest(digest, EXPECTED_KIMI_EXECUTABLE_SHA256)
        or not hmac.compare_digest(_sha256_file(path), digest)
    ):
        raise KimiAnalysisPipelineError(
            "execution is not pinned to reviewed Kimi 0.26.0 entrypoint bytes"
        )
    return path


@dataclass(frozen=True)
class _ValidatedInputs:
    manifest_path: Path
    manifest_sha256: str
    executable_path: Path
    metadata_sha256: str
    projection_request: KimiAnalyzerProjectionRequest


def _analysis_documents(
    *,
    manifest: Mapping[str, Any],
    stages: Sequence[Mapping[str, Any]],
    run_root: Path,
    seen_paths: set[Path],
) -> tuple[PinnedProjectionInput, tuple[PinnedProjectionInput, ...]]:
    projection = _mapping(
        manifest.get("analysis_projection_inputs"), "analysis_projection_inputs"
    )
    if set(projection) != {
        "schema_version",
        "semantic_translation",
        "root",
        "case_document",
        "stages",
    } or (
        projection.get("schema_version") != 1
        or projection.get("semantic_translation") != SEMANTIC_TRANSLATION
    ):
        raise KimiAnalysisPipelineError(
            "materialization analysis projection contract drifted"
        )
    analysis_root = _run_path(
        _string(projection.get("root"), "analysis projection root"),
        run_root=run_root,
        label="analysis projection root",
    )
    if (
        not analysis_root.is_dir()
        or analysis_root.parent != run_root
        or "kimi" not in analysis_root.name.casefold()
        or manifest.get("run_id") not in analysis_root.name
    ):
        raise KimiAnalysisPipelineError(
            "analysis projection root is not the exact materialized child"
        )
    case_ref = _mapping(projection.get("case_document"), "analysis case document")
    if set(case_ref) != {"path", "sha256"}:
        raise KimiAnalysisPipelineError("analysis case document keys drifted")
    case_input, _ = _pinned_json(
        _string(case_ref.get("path"), "analysis case document path"),
        expected_sha256=_sha256(
            case_ref.get("sha256"), "analysis case document"
        ),
        run_root=run_root,
        label="analysis case document",
        kind="case_source",
    )
    if case_input.path.parent != analysis_root:
        raise KimiAnalysisPipelineError("analysis case document escaped its root")
    _register_path(case_input.path, seen_paths, label="analysis case document")

    raw_stage_refs = _sequence(projection.get("stages"), "analysis stage documents")
    if len(raw_stage_refs) != len(stages):
        raise KimiAnalysisPipelineError("analysis stage document count drifted")
    stage_inputs: list[PinnedProjectionInput] = []
    for position, (raw_ref, stage) in enumerate(zip(raw_stage_refs, stages)):
        ref = _mapping(raw_ref, f"analysis stage document {position}")
        if set(ref) != {"index", "name", "case_document"} or (
            ref.get("index") != stage.get("index")
            or ref.get("name") != stage.get("name")
        ):
            raise KimiAnalysisPipelineError(
                "analysis stage document identity drifted"
            )
        case_document = _mapping(
            ref.get("case_document"), f"analysis stage {position} case document"
        )
        if set(case_document) != {"path", "sha256"}:
            raise KimiAnalysisPipelineError(
                "analysis stage case document keys drifted"
            )
        pinned, _ = _pinned_json(
            _string(case_document.get("path"), "stage case document path"),
            expected_sha256=_sha256(
                case_document.get("sha256"), "stage case document"
            ),
            run_root=run_root,
            label=f"stage {position} analysis case document",
            kind="stage_case_source",
        )
        if pinned.path.parent != analysis_root:
            raise KimiAnalysisPipelineError(
                "analysis stage case document escaped its root"
            )
        _register_path(pinned.path, seen_paths, label=f"stage {position} case")
        stage_inputs.append(pinned)
    return case_input, tuple(stage_inputs)


def _wire_inputs(
    *,
    stage_index: int,
    metadata: Mapping[str, Any],
    result: Mapping[str, Any],
    run_root: Path,
    seen_paths: set[Path],
) -> tuple[tuple[PinnedProjectionInput, ...], tuple[PinnedProjectionInput, ...]]:
    result_wire = _mapping(result.get("wire"), f"stage {stage_index} result wire")
    result_captures = _sequence(
        result_wire.get("captures"), f"stage {stage_index} result wire captures"
    )
    metadata_captures = _sequence(
        metadata.get("wire_captures"), f"stage {stage_index} metadata wire captures"
    )
    if list(result_captures) != list(metadata_captures) or not result_captures:
        raise KimiAnalysisPipelineError(
            f"stage {stage_index} wire capture records drifted"
        )
    native: list[PinnedProjectionInput] = []
    main_capture: PinnedProjectionInput | None = None
    for position, raw_capture in enumerate(result_captures):
        capture = _mapping(raw_capture, f"stage {stage_index} wire {position}")
        if set(capture) != {
            "source_path",
            "captured_path",
            "sha256",
            "line_count",
            "is_main",
        } or not isinstance(capture.get("is_main"), bool):
            raise KimiAnalysisPipelineError(
                f"stage {stage_index} wire capture keys drifted"
            )
        pinned, _ = _pinned_jsonl(
            _string(capture.get("captured_path"), "captured wire path"),
            expected_sha256=_sha256(capture.get("sha256"), "captured wire"),
            expected_line_count=_integer(
                capture.get("line_count"), "captured wire line count", minimum=1
            ),
            run_root=run_root,
            label=f"stage {stage_index} captured native wire {position}",
            kind="native_wire",
        )
        _register_path(
            pinned.path,
            seen_paths,
            label=f"stage {stage_index} captured wire {position}",
        )
        source = _regular_file(
            _string(capture.get("source_path"), "native wire source path"),
            run_root=run_root,
            label=f"stage {stage_index} native wire source {position}",
        )
        source_lines = source.read_bytes().splitlines(keepends=True)
        if len(source_lines) < pinned.line_count or b"".join(
            source_lines[: pinned.line_count]
        ) != pinned.path.read_bytes():
            raise KimiAnalysisPipelineError(
                f"stage {stage_index} native wire source lost its captured prefix"
            )
        native.append(pinned)
        if capture["is_main"]:
            if main_capture is not None:
                raise KimiAnalysisPipelineError(
                    f"stage {stage_index} has multiple main native wires"
                )
            main_capture = pinned
    if main_capture is None:
        raise KimiAnalysisPipelineError(
            f"stage {stage_index} lacks a main native wire"
        )

    main_path = _string(metadata.get("main_wire_path"), "metadata main wire path")
    main_sha = _sha256(metadata.get("main_wire_sha256"), "metadata main wire")
    if (
        result_wire.get("main_path") != main_path
        or result_wire.get("main_sha256") != main_sha
        or not hmac.compare_digest(main_sha, main_capture.sha256)
    ):
        raise KimiAnalysisPipelineError(
            f"stage {stage_index} main wire reference drifted"
        )
    main_copy, _ = _pinned_jsonl(
        main_path,
        expected_sha256=main_sha,
        expected_line_count=main_capture.line_count,
        run_root=run_root,
        label=f"stage {stage_index} main wire copy",
        kind="main_wire_copy",
    )
    _register_path(main_copy.path, seen_paths, label=f"stage {stage_index} main copy")
    return tuple(native), (main_copy,)


def _optional_auxiliary_inputs(
    *,
    stage_index: int,
    metadata: Mapping[str, Any],
    result: Mapping[str, Any],
    run_root: Path,
    seen_paths: set[Path],
) -> tuple[PinnedProjectionInput, ...]:
    auxiliary: list[PinnedProjectionInput] = []

    def add(item: PinnedProjectionInput, label: str) -> None:
        _register_path(item.path, seen_paths, label=label)
        auxiliary.append(item)

    controller_path = metadata.get("controller_trace_path")
    controller_sha = metadata.get("controller_trace_sha256")
    controller_ref = result.get("controller_trace")
    if (controller_path is None) != (controller_sha is None) or (
        controller_path is None
    ) != (controller_ref is None):
        raise KimiAnalysisPipelineError(
            f"stage {stage_index} controller trace pair is incomplete"
        )
    if controller_path is not None:
        ref = _mapping(controller_ref, f"stage {stage_index} controller trace")
        if set(ref) != {"path", "sha256"} or (
            ref.get("path") != controller_path or ref.get("sha256") != controller_sha
        ):
            raise KimiAnalysisPipelineError(
                f"stage {stage_index} controller trace reference drifted"
            )
        pinned, _ = _pinned_jsonl(
            _string(controller_path, "controller trace path"),
            expected_sha256=_sha256(controller_sha, "controller trace"),
            expected_line_count=None,
            run_root=run_root,
            label=f"stage {stage_index} controller trace",
            kind="controller_trace",
        )
        add(pinned, f"stage {stage_index} controller trace")

    observation_path = metadata.get("observation_trace_path")
    observation_sha = metadata.get("observation_trace_sha256")
    observation_ref = result.get("control_observation_trace")
    if (observation_path is None) != (observation_sha is None) or (
        observation_path is None
    ) != (observation_ref is None):
        raise KimiAnalysisPipelineError(
            f"stage {stage_index} observation trace pair is incomplete"
        )
    if observation_path is not None:
        ref = _mapping(observation_ref, f"stage {stage_index} observation trace")
        if set(ref) != {"path", "sha256", "record_count"} or (
            ref.get("path") != observation_path or ref.get("sha256") != observation_sha
        ):
            raise KimiAnalysisPipelineError(
                f"stage {stage_index} observation trace reference drifted"
            )
        pinned, records = _pinned_jsonl(
            _string(observation_path, "observation trace path"),
            expected_sha256=_sha256(observation_sha, "observation trace"),
            expected_line_count=_integer(
                ref.get("record_count"), "observation record count", minimum=1
            ),
            run_root=run_root,
            label=f"stage {stage_index} adapter observation trace",
            kind="adapter_observation",
        )
        add(pinned, f"stage {stage_index} observation trace")
        for line, record in enumerate(records, 1):
            observer_ref = record.get("request_observer")
            if observer_ref is None:
                continue
            observer = _mapping(
                observer_ref,
                f"stage {stage_index} observation {line} request observer",
            )
            if set(observer) != {"path", "sha256", "line", "line_count"}:
                raise KimiAnalysisPipelineError(
                    "instruction request observer reference keys drifted"
                )
            observer_input, observer_records = _pinned_jsonl(
                _string(observer.get("path"), "instruction observer path"),
                expected_sha256=_sha256(
                    observer.get("sha256"), "instruction observer"
                ),
                expected_line_count=_integer(
                    observer.get("line_count"),
                    "instruction observer line count",
                    minimum=1,
                ),
                run_root=run_root,
                label=f"stage {stage_index} instruction request observer",
                kind="provider_request_observation",
            )
            selected = _integer(
                observer.get("line"), "instruction observer selected line", minimum=1
            )
            if selected > len(observer_records):
                raise KimiAnalysisPipelineError(
                    "instruction observer selected line is outside evidence"
                )
            add(observer_input, f"stage {stage_index} instruction observer")

    result_health = _sequence(result.get("mcp_health", []), "stage MCP health")
    metadata_health = _sequence(metadata.get("mcp_health", []), "metadata MCP health")
    if list(result_health) != list(metadata_health):
        raise KimiAnalysisPipelineError(
            f"stage {stage_index} MCP health records drifted"
        )
    for health_index, raw_health in enumerate(result_health):
        health = _mapping(raw_health, f"stage {stage_index} MCP health {health_index}")
        evidence_files = _sequence(
            health.get("evidence_files"), "MCP health evidence files"
        )
        if not evidence_files:
            raise KimiAnalysisPipelineError("MCP health has no auxiliary evidence")
        for file_index, raw_file in enumerate(evidence_files):
            evidence = _mapping(raw_file, "MCP auxiliary evidence")
            if set(evidence) != {"kind", "path", "sha256", "line_count"}:
                raise KimiAnalysisPipelineError(
                    "MCP auxiliary evidence keys drifted"
                )
            kind = _string(evidence.get("kind"), "MCP evidence kind")
            pinned, _ = _pinned_jsonl(
                _string(evidence.get("path"), "MCP evidence path"),
                expected_sha256=_sha256(evidence.get("sha256"), "MCP evidence"),
                expected_line_count=_integer(
                    evidence.get("line_count"), "MCP evidence line count", minimum=1
                ),
                run_root=run_root,
                label=(
                    f"stage {stage_index} MCP health {health_index} file {file_index}"
                ),
                kind=f"mcp_{kind}",
            )
            add(pinned, f"stage {stage_index} MCP {health_index}/{file_index}")
    return tuple(auxiliary)


def _validate_inputs(request: KimiCompletedAnalysisRequest) -> _ValidatedInputs:
    _validate_identity(request)
    run_root = _strict_run_root(request)
    execution = request.execution_result
    if (
        execution.outcome != COMPLETED
        or execution.return_code != 0
        or execution.failure_category is not None
        or execution.retry_eligible is not False
        or execution.event_ir_path is None
        or execution.raw_stdout_path is None
        or execution.raw_wire_path is None
    ):
        raise KimiAnalysisPipelineError(
            "analysis requires exact terminal COMPLETED execution evidence"
        )
    metadata = _mapping(execution.metadata, "execution metadata")
    _reject_forbidden(metadata, prefix="execution.metadata")
    metadata_sha = _canonical_sha256(metadata)
    if (
        metadata.get("schema_name") != _EXECUTION_SCHEMA_NAME
        or metadata.get("schema_version") != _EXECUTION_SCHEMA_VERSION
        or metadata.get("harness_id") != "kimi"
        or metadata.get("run_id") != request.run_id
        or metadata.get("case_id") != request.case_id
    ):
        raise KimiAnalysisPipelineError("execution metadata identity drifted")
    executable_path = _validate_executable(metadata)

    manifest_path = _regular_file(
        request.materialization_manifest_path,
        run_root=run_root,
        label="materialization manifest",
    )
    manifest_sha = _sha256_file(manifest_path)
    if (
        metadata.get("manifest_path") != str(manifest_path)
        or metadata.get("manifest_sha256") != manifest_sha
    ):
        raise KimiAnalysisPipelineError(
            "execution metadata does not pin the exact materialization manifest"
        )
    try:
        manifest = load_bench_materialization_manifest(manifest_path)
    except Exception as exc:
        raise KimiAnalysisPipelineError(
            "materialization manifest failed its Kimi self-check"
        ) from exc
    if (
        manifest.get("run_id") != request.run_id
        or manifest.get("case_id") != request.case_id
        or manifest.get("harness_id") != "kimi"
        or manifest.get("disposition") != "READY"
    ):
        raise KimiAnalysisPipelineError(
            "materialization manifest identity/disposition drifted"
        )
    raw_manifest_stages = _sequence(manifest.get("stages"), "manifest stages")
    metadata_stages = _sequence(metadata.get("stages"), "execution stages")
    if not raw_manifest_stages or len(raw_manifest_stages) != len(metadata_stages):
        raise KimiAnalysisPipelineError("execution stage count drifted")
    if metadata.get("fresh_os_process_count") != len(metadata_stages):
        raise KimiAnalysisPipelineError("fresh process count does not cover every stage")

    manifest_stages: list[Mapping[str, Any]] = []
    for index, raw_stage in enumerate(raw_manifest_stages):
        stage = _mapping(raw_stage, f"manifest stage {index}")
        if stage.get("index") != index or not isinstance(stage.get("name"), str):
            raise KimiAnalysisPipelineError("manifest stage identities are not contiguous")
        manifest_stages.append(stage)

    seen_paths: set[Path] = {manifest_path}
    case_document, stage_case_documents = _analysis_documents(
        manifest=manifest,
        stages=manifest_stages,
        run_root=run_root,
        seen_paths=seen_paths,
    )

    projection_stages: list[KimiProjectionStage] = []
    final_stdout: Path | None = None
    final_main_wire: Path | None = None
    for index, (manifest_stage, raw_metadata_stage) in enumerate(
        zip(manifest_stages, metadata_stages)
    ):
        stage_metadata = _mapping(raw_metadata_stage, f"execution stage {index}")
        name = _string(manifest_stage.get("name"), f"stage {index} name")
        if (
            stage_metadata.get("index") != index
            or stage_metadata.get("name") != name
            or stage_metadata.get("return_code") != 0
        ):
            raise KimiAnalysisPipelineError(
                f"execution stage {index} identity/return code drifted"
            )
        result_path = _regular_file(
            _string(stage_metadata.get("result_path"), "stage result path"),
            run_root=run_root,
            label=f"stage {index} result",
        )
        _register_path(result_path, seen_paths, label=f"stage {index} result")
        result_bytes = result_path.read_bytes()
        stage_result = _read_json(result_path, f"stage {index} result")
        result_identity = _mapping(stage_result.get("stage"), "stage result identity")
        if (
            stage_result.get("schema_name") != "safety_bench_kimi_stage_execution"
            or stage_result.get("schema_version") != 1
            or stage_result.get("harness_id") != "kimi"
            or stage_result.get("run_id") != request.run_id
            or stage_result.get("case_id") != request.case_id
            or result_identity != {"index": index, "name": name}
            or stage_result.get("return_code") != 0
            or stage_result.get("timed_out") is not False
        ):
            raise KimiAnalysisPipelineError(f"stage {index} result identity drifted")
        _reject_forbidden(stage_result, prefix=f"stage[{index}].result")

        stdout_ref = _mapping(stage_result.get("stdout"), "stage result stdout")
        stdout, _ = _pinned_jsonl(
            _string(stage_metadata.get("stdout_path"), "stage stdout path"),
            expected_sha256=_sha256(
                stage_metadata.get("stdout_sha256"), "stage stdout"
            ),
            expected_line_count=_integer(
                stdout_ref.get("line_count"), "stage stdout line count", minimum=1
            ),
            run_root=run_root,
            label=f"stage {index} Kimi stdout",
            kind="kimi_stdout",
        )
        if (
            stdout_ref.get("path") != str(stdout.path)
            or stdout_ref.get("sha256") != stdout.sha256
        ):
            raise KimiAnalysisPipelineError(
                f"stage {index} stdout references drifted"
            )
        _register_path(stdout.path, seen_paths, label=f"stage {index} stdout")
        native_wires, main_aux = _wire_inputs(
            stage_index=index,
            metadata=stage_metadata,
            result=stage_result,
            run_root=run_root,
            seen_paths=seen_paths,
        )
        auxiliary = (
            *main_aux,
            *_optional_auxiliary_inputs(
                stage_index=index,
                metadata=stage_metadata,
                result=stage_result,
                run_root=run_root,
                seen_paths=seen_paths,
            ),
        )
        result_input = PinnedProjectionInput(
            path=result_path,
            sha256=_sha256_bytes(result_bytes),
            line_count=len(result_bytes.splitlines()),
            kind="stage_result",
        )
        projection_stages.append(
            KimiProjectionStage(
                index=index,
                name=name,
                case_document=stage_case_documents[index],
                stdout=stdout,
                native_wires=native_wires,
                auxiliary_sources=tuple(auxiliary),
                result=result_input,
            )
        )
        final_stdout = stdout.path
        final_main_wire = main_aux[0].path

    if (
        Path(execution.raw_stdout_path).absolute() != final_stdout
        or Path(execution.raw_wire_path).absolute() != final_main_wire
    ):
        raise KimiAnalysisPipelineError(
            "ExecutionResult raw evidence does not identify the final stage"
        )

    event_ir_path = _regular_file(
        execution.event_ir_path, run_root=run_root, label="Event IR"
    )
    event_ir_sha = _sha256(metadata.get("event_ir_sha256"), "Event IR")
    event_ir, _ = _pinned_jsonl(
        event_ir_path,
        expected_sha256=event_ir_sha,
        expected_line_count=None,
        run_root=run_root,
        label="Cross-Harness Event IR",
        kind="event_ir_v1",
    )
    _register_path(event_ir.path, seen_paths, label="Event IR")

    callback: KimiCallbackCollectorEvidence | None = None
    if request.callback is not None:
        callback_manifest_path = _regular_file(
            request.callback.manifest_path,
            run_root=run_root,
            label="callback manifest",
        )
        callback_evidence_path = _regular_file(
            request.callback.evidence_path,
            run_root=run_root,
            label="callback evidence",
        )
        manifest_content = callback_manifest_path.read_bytes()
        callback_manifest = PinnedProjectionInput(
            path=callback_manifest_path,
            sha256=_sha256_bytes(manifest_content),
            line_count=len(manifest_content.splitlines()),
            kind="callback_manifest",
        )
        _read_json(callback_manifest_path, "callback manifest")
        evidence_content = callback_evidence_path.read_bytes()
        callback_records = _read_jsonl(
            callback_evidence_path,
            label="callback evidence",
            allow_empty=True,
        )
        if len(callback_records) != len(evidence_content.splitlines()):
            raise KimiAnalysisPipelineError(
                "callback evidence contains uncounted lines"
            )
        callback_observations = PinnedProjectionInput(
            path=callback_evidence_path,
            sha256=_sha256_bytes(evidence_content),
            line_count=len(callback_records),
            kind="callback_observations",
        )
        _register_path(callback_manifest_path, seen_paths, label="callback manifest")
        _register_path(callback_evidence_path, seen_paths, label="callback evidence")
        callback = KimiCallbackCollectorEvidence(
            manifest=callback_manifest,
            observations=callback_observations,
        )

    output_dir = run_root / (
        f"analyzer-projection-kimi-{request.run_id}-{request.trial_id}"
    )
    projection_request = KimiAnalyzerProjectionRequest(
        run_id=request.run_id,
        case_id=request.case_id,
        trial_id=request.trial_id,
        run_root=run_root,
        output_dir=output_dir,
        harness_version=EXPECTED_KIMI_VERSION,
        binary_sha256=EXPECTED_KIMI_EXECUTABLE_SHA256,
        case_document=case_document,
        event_ir=event_ir,
        stages=tuple(projection_stages),
        callback=callback,
    )
    return _ValidatedInputs(
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha,
        executable_path=executable_path,
        metadata_sha256=metadata_sha,
        projection_request=projection_request,
    )


def _atomic_write_json(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise KimiAnalysisPipelineError(f"refusing to replace analysis output: {path}")
    content = json.dumps(
        document, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise KimiAnalysisPipelineError(
                f"refusing to replace analysis output: {path}"
            ) from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def _completed_trial_document(
    *,
    request: KimiCompletedAnalysisRequest,
    validated: _ValidatedInputs,
    projection_manifest_path: Path,
    projection_manifest_sha256: str,
) -> dict[str, Any]:
    event_ir = validated.projection_request.event_ir
    document: dict[str, Any] = {
        "schema_name": COMPLETED_TRIAL_SCHEMA_NAME,
        "schema_version": COMPLETED_TRIAL_SCHEMA_VERSION,
        "harness_id": "kimi",
        "harness_version": EXPECTED_KIMI_VERSION,
        "run_id": request.run_id,
        "case_id": request.case_id,
        "trial_id": request.trial_id,
        "outcome": COMPLETED,
        "return_code": 0,
        "failure_category": None,
        "retry_eligible": False,
        "executable": {
            "path": str(validated.executable_path),
            "sha256": EXPECTED_KIMI_EXECUTABLE_SHA256,
        },
        "event_ir": {"path": str(event_ir.path), "sha256": event_ir.sha256},
        "projection_manifest": {
            "path": str(projection_manifest_path),
            "sha256": projection_manifest_sha256,
        },
    }
    document["manifest_payload_sha256"] = _canonical_sha256(document)
    return document


def _remove_created_output(path: Path, *, run_root: Path) -> None:
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except OSError:
        return
    if resolved_parent != run_root or not path.name.startswith(
        ("analyzer-projection-kimi-", "analysis-kimi-", "completed-trial-kimi-")
    ):
        return
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def run_kimi_completed_analysis(
    request: KimiCompletedAnalysisRequest,
    *,
    projector: Projector = project_kimi_analyzer_compatibility,
    invoker: Invoker = invoke_kimi_shared_analyzer,
) -> KimiCompletedAnalysisResult:
    """Project and analyze one exact COMPLETED trial, without interpreting it."""

    validated = _validate_inputs(request)
    run_root = validated.projection_request.run_root
    projection_dir = validated.projection_request.output_dir
    completed_trial_path = run_root / (
        f"completed-trial-kimi-{request.run_id}-{request.trial_id}.json"
    )
    analysis_dir = run_root / f"analysis-kimi-{request.run_id}-{request.trial_id}"
    output_paths = (projection_dir, completed_trial_path, analysis_dir)
    if any(path.exists() or path.is_symlink() for path in output_paths):
        raise KimiAnalysisPipelineError(
            "analysis output already exists; no output may be overwritten"
        )
    created: list[Path] = []
    try:
        created.append(projection_dir)
        projection = projector(validated.projection_request)
        if (
            not isinstance(projection, KimiAnalyzerProjectionResult)
            or Path(projection.root).resolve() != projection_dir.resolve(strict=True)
        ):
            raise KimiAnalysisPipelineError(
                "projector returned an unexpected output root"
            )
        projection_manifest_path = _regular_file(
            projection.manifest_path,
            run_root=run_root,
            label="projection manifest",
        )
        if projection_manifest_path.parent != projection_dir:
            raise KimiAnalysisPipelineError(
                "projection manifest escaped its exact output root"
            )
        projection_manifest_content = projection_manifest_path.read_bytes()
        projection_manifest_sha = _sha256_bytes(projection_manifest_content)
        projection_manifest_lines = len(projection_manifest_content.splitlines())
        if projection_manifest_lines < 1:
            raise KimiAnalysisPipelineError("projection manifest is empty")

        completed_trial = _completed_trial_document(
            request=request,
            validated=validated,
            projection_manifest_path=projection_manifest_path,
            projection_manifest_sha256=projection_manifest_sha,
        )
        _reject_forbidden(completed_trial, prefix="completed_trial")
        created.append(completed_trial_path)
        _atomic_write_json(completed_trial_path, completed_trial)
        completed_sha = _sha256_file(completed_trial_path)
        completed_lines = len(completed_trial_path.read_bytes().splitlines())

        invocation_request = KimiAnalysisInvocationRequest(
            run_id=request.run_id,
            case_id=request.case_id,
            trial_id=request.trial_id,
            run_root=run_root,
            analysis_dir=analysis_dir,
            completed_trial=PinnedAnalysisInput(
                completed_trial_path, completed_sha, completed_lines
            ),
            projection_manifest=PinnedAnalysisInput(
                projection_manifest_path,
                projection_manifest_sha,
                projection_manifest_lines,
            ),
            timeout_seconds=request.timeout_seconds,
        )
        created.append(analysis_dir)
        invocation = invoker(invocation_request)
        if (
            not isinstance(invocation, KimiAnalysisInvocationResult)
            or Path(invocation.analysis_dir).resolve() != analysis_dir.resolve(strict=True)
        ):
            raise KimiAnalysisPipelineError(
                "analysis invoker returned an unexpected output root"
            )
        provenance = _regular_file(
            invocation.provenance_manifest_path,
            run_root=run_root,
            label="analysis provenance",
        )
        try:
            provenance.relative_to(analysis_dir)
        except ValueError as exc:
            raise KimiAnalysisPipelineError(
                "analysis provenance escaped its output root"
            ) from exc

        # Revalidate mutable boundary objects and source pins after the shared
        # analyzer returns.  The invoker separately revalidates every source
        # listed by the projection manifest.
        if (
            not hmac.compare_digest(
                _sha256_file(validated.manifest_path), validated.manifest_sha256
            )
            or not hmac.compare_digest(
                _sha256_file(validated.executable_path),
                EXPECTED_KIMI_EXECUTABLE_SHA256,
            )
            or not hmac.compare_digest(
                _canonical_sha256(request.execution_result.metadata),
                validated.metadata_sha256,
            )
            or not hmac.compare_digest(
                _sha256_file(projection_manifest_path), projection_manifest_sha
            )
            or not hmac.compare_digest(
                _sha256_file(completed_trial_path), completed_sha
            )
        ):
            raise KimiAnalysisPipelineError(
                "analysis inputs changed while the analyzer was running"
            )
        return KimiCompletedAnalysisResult(
            projection=projection,
            completed_trial_path=completed_trial_path,
            completed_trial_sha256=completed_sha,
            invocation=invocation,
        )
    except BaseException:
        for path in reversed(created):
            _remove_created_output(path, run_root=run_root)
        raise


class KimiAnalyzingExecutor:
    """CaseExecutor decorator which analyzes only exact COMPLETED executions."""

    def __init__(
        self,
        *,
        delegate: CaseExecutor,
        trial_id: str,
        callback_evidence_provider: KimiCallbackEvidenceProvider | None = None,
        pipeline: KimiCompletedAnalysisCallable = run_kimi_completed_analysis,
    ) -> None:
        if delegate is None or not callable(getattr(delegate, "execute", None)):
            raise ValueError("delegate must implement CaseExecutor")
        if not isinstance(trial_id, str) or _SAFE_ID_RE.fullmatch(trial_id) is None:
            raise ValueError("trial_id has an unsafe identity")
        if callback_evidence_provider is not None and not callable(
            callback_evidence_provider
        ):
            raise ValueError("callback_evidence_provider must be callable")
        if not callable(pipeline):
            raise ValueError("pipeline must be callable")
        self.delegate = delegate
        self.trial_id = trial_id
        self.callback_evidence_provider = callback_evidence_provider
        self.pipeline = pipeline

    def execute(
        self,
        plan: CasePlan,
        materialized: MaterializedCase,
        context: ExecutionContext,
    ) -> ExecutionResult:
        result = self.delegate.execute(plan, materialized, context)
        if not isinstance(result, ExecutionResult):
            raise KimiAnalysisPipelineError(
                "delegate did not return runner.ExecutionResult"
            )
        if result.outcome != COMPLETED:
            return result
        callback = (
            self.callback_evidence_provider(plan, materialized, context, result)
            if self.callback_evidence_provider is not None
            else None
        )
        if callback is not None and not isinstance(
            callback, KimiCallbackEvidencePaths
        ):
            raise KimiAnalysisPipelineError(
                "callback evidence provider returned an invalid pair"
            )
        analyzed = self.pipeline(
            KimiCompletedAnalysisRequest(
                run_id=context.run_id,
                case_id=materialized.case_id,
                trial_id=self.trial_id,
                run_root=materialized.root,
                materialization_manifest_path=materialized.manifest_path,
                execution_result=result,
                callback=callback,
            )
        )
        if not isinstance(analyzed, KimiCompletedAnalysisResult):
            raise KimiAnalysisPipelineError("analysis pipeline returned an invalid result")
        run_root = Path(materialized.root).resolve(strict=True)
        projection_manifest = _regular_file(
            analyzed.projection.manifest_path,
            run_root=run_root,
            label="decorated projection manifest",
        )
        completed_trial = _regular_file(
            analyzed.completed_trial_path,
            run_root=run_root,
            label="decorated completed trial",
        )
        provenance = _regular_file(
            analyzed.invocation.provenance_manifest_path,
            run_root=run_root,
            label="decorated analysis provenance",
        )
        completed_sha = _sha256_file(completed_trial)
        if not hmac.compare_digest(
            completed_sha,
            _sha256(
                analyzed.completed_trial_sha256,
                "analysis result completed trial",
            ),
        ):
            raise KimiAnalysisPipelineError(
                "analysis result completed-trial SHA-256 drifted"
            )
        records = {
            "projection_manifest": {
                "path": str(projection_manifest),
                "sha256": _sha256_file(projection_manifest),
            },
            "completed_trial": {
                "path": str(completed_trial),
                "sha256": completed_sha,
            },
            "analysis_provenance": {
                "path": str(provenance),
                "sha256": _sha256_file(provenance),
            },
            "semantic_translation": SEMANTIC_TRANSLATION,
            "pipeline_version": KIMI_ANALYSIS_PIPELINE_VERSION,
        }
        _reject_forbidden(records, prefix="analysis_pipeline")
        metadata = dict(result.metadata)
        if "analysis_pipeline" in metadata:
            raise KimiAnalysisPipelineError(
                "delegate metadata already contains analysis_pipeline"
            )
        metadata["analysis_pipeline"] = records
        return ExecutionResult(
            outcome=result.outcome,
            return_code=result.return_code,
            raw_stdout_path=result.raw_stdout_path,
            raw_wire_path=result.raw_wire_path,
            event_ir_path=result.event_ir_path,
            metadata=metadata,
            failure_category=result.failure_category,
            retry_eligible=result.retry_eligible,
        )


def build_kimi_analyzing_executor(
    *,
    delegate: CaseExecutor,
    run_id: str,
    case_id: str,
    trial_id: str,
    run_root: Path,
    callback_collector: Any,
    pipeline: KimiCompletedAnalysisCallable = run_kimi_completed_analysis,
) -> KimiAnalyzingExecutor:
    """Bind a live trial collector to the production executor decorator.

    The production runtime creates one collector and one raw executor per
    trial.  This factory deliberately consumes only that narrow identity
    surface, so runtime construction does not need to expose analyzer internals.
    """

    for value, label in ((run_id, "run_id"), (case_id, "case_id"), (trial_id, "trial_id")):
        if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{label} has an unsafe identity")
    root = Path(run_root).absolute()
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise ValueError("run_root must be an existing non-symlink directory")
    if "kimi" not in root.as_posix().casefold() or run_id not in root.as_posix():
        raise ValueError("run_root lacks Kimi/run ownership")
    if (
        getattr(callback_collector, "run_id", None) != run_id
        or getattr(callback_collector, "case_id", None) != case_id
        or getattr(callback_collector, "trial_id", None) != trial_id
    ):
        raise ValueError("callback collector identity differs from the trial")
    manifest_path = Path(
        getattr(callback_collector, "evidence_manifest_path", Path("/"))
    ).absolute()
    evidence_path = Path(
        getattr(callback_collector, "evidence_path", Path("/"))
    ).absolute()
    for path, label in (
        (manifest_path, "callback manifest"),
        (evidence_path, "callback evidence"),
    ):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"{label} escapes the exact run root") from exc

    def callback_provider(
        plan: CasePlan,
        materialized: MaterializedCase,
        context: ExecutionContext,
        result: ExecutionResult,
    ) -> KimiCallbackEvidencePaths:
        del plan, result
        if (
            context.run_id != run_id
            or materialized.case_id != case_id
            or Path(materialized.root).resolve(strict=True) != root
            or getattr(callback_collector, "run_id", None) != run_id
            or getattr(callback_collector, "case_id", None) != case_id
            or getattr(callback_collector, "trial_id", None) != trial_id
        ):
            raise KimiAnalysisPipelineError(
                "callback collector/runtime identity drifted before analysis"
            )
        return KimiCallbackEvidencePaths(
            manifest_path=manifest_path,
            evidence_path=evidence_path,
        )

    return KimiAnalyzingExecutor(
        delegate=delegate,
        trial_id=trial_id,
        callback_evidence_provider=callback_provider,
        pipeline=pipeline,
    )


__all__ = [
    "EXPECTED_KIMI_EXECUTABLE",
    "EXPECTED_KIMI_EXECUTABLE_SHA256",
    "EXPECTED_KIMI_VERSION",
    "KIMI_ANALYSIS_PIPELINE_VERSION",
    "KimiAnalysisPipelineError",
    "KimiAnalyzingExecutor",
    "KimiCallbackEvidencePaths",
    "KimiCallbackEvidenceProvider",
    "KimiCompletedAnalysisCallable",
    "KimiCompletedAnalysisRequest",
    "KimiCompletedAnalysisResult",
    "build_kimi_analyzing_executor",
    "run_kimi_completed_analysis",
]
