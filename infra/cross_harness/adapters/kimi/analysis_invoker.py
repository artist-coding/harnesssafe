"""Fail-closed invocation of the shared analyzer for Kimi projections.

The invoker does not interpret analyzer output and never creates a score or a
verdict.  It revalidates a completed Kimi trial and its analyzer-compatibility
projection, runs the repository's existing analyzer in a sanitized subprocess,
and atomically publishes only provenance and hashes for that invocation.
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
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

from .analyzer_projection import (
    PROJECTION_SCHEMA_NAME,
    PROJECTION_SCHEMA_VERSION,
    SEMANTIC_TRANSLATION,
)


ANALYSIS_PROVENANCE_SCHEMA_NAME = "safety_bench_kimi_analysis_provenance"
ANALYSIS_PROVENANCE_SCHEMA_VERSION = 1
COMPLETED_TRIAL_SCHEMA_NAME = "safety_bench_kimi_completed_trial_evidence"
COMPLETED_TRIAL_SCHEMA_VERSION = 1

_KIMI_VERSION = "0.26.0"
_KIMI_BINARY_SHA256 = (
    "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_PROVENANCE_KEYS = {
    "attack_success",
    "confirmed_compromise",
    "progress_node",
    "risk_score",
    "score",
    "scored_result",
    "verdict",
}


class KimiAnalysisInvocationError(RuntimeError):
    """The analyzer could not be invoked with complete, unchanged evidence."""


@dataclass(frozen=True)
class PinnedAnalysisInput:
    path: Path
    sha256: str
    line_count: int


@dataclass(frozen=True)
class KimiAnalysisInvocationRequest:
    run_id: str
    case_id: str
    trial_id: str
    run_root: Path
    analysis_dir: Path
    completed_trial: PinnedAnalysisInput
    projection_manifest: PinnedAnalysisInput
    timeout_seconds: int = 120


@dataclass(frozen=True)
class KimiAnalysisInvocationResult:
    analysis_dir: Path
    analyzer_results_dir: Path
    provenance_manifest_path: Path
    stdout_path: Path
    stderr_path: Path


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    return _sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiAnalysisInvocationError(f"{label} must be an object")
    return value


def _valid_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise KimiAnalysisInvocationError(f"{label} SHA-256 is invalid")
    return value


def _exact_keys(
    document: Mapping[str, Any], *, required: set[str], label: str
) -> None:
    if set(document) != required:
        missing = sorted(required - set(document))
        extra = sorted(set(document) - required)
        raise KimiAnalysisInvocationError(
            f"{label} keys drifted; missing={missing}; extra={extra}"
        )


def _reject_forbidden_keys(value: Any, *, path: str = "provenance") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _FORBIDDEN_PROVENANCE_KEYS:
                raise KimiAnalysisInvocationError(
                    f"analysis provenance contains forbidden scoring key: {path}.{key}"
                )
            _reject_forbidden_keys(child, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, path=f"{path}[{index}]")


def _strict_run_root(request: KimiAnalysisInvocationRequest) -> Path:
    supplied = Path(request.run_root).absolute()
    if supplied.is_symlink() or not supplied.is_dir():
        raise KimiAnalysisInvocationError("run_root must be a real directory")
    resolved = supplied.resolve(strict=True)
    if resolved != supplied:
        raise KimiAnalysisInvocationError("run_root must not use a symlink alias")
    if "kimi" not in resolved.as_posix().casefold() or request.run_id not in resolved.as_posix():
        raise KimiAnalysisInvocationError("run_root lacks exact Kimi/run ownership")
    return resolved


def _run_path(path: Path, *, run_root: Path, label: str) -> Path:
    supplied = Path(path).absolute()
    if supplied.is_symlink():
        raise KimiAnalysisInvocationError(f"{label} must not be a symlink")
    try:
        relative = supplied.relative_to(run_root)
    except ValueError as exc:
        raise KimiAnalysisInvocationError(f"{label} escapes the exact run root") from exc
    cursor = run_root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise KimiAnalysisInvocationError(f"{label} traverses a symlink")
    resolved = supplied.resolve()
    try:
        resolved.relative_to(run_root)
    except ValueError as exc:
        raise KimiAnalysisInvocationError(f"{label} resolves outside the run root") from exc
    return resolved


def _read_pinned(
    item: PinnedAnalysisInput, *, run_root: Path, label: str
) -> tuple[Path, bytes]:
    path = _run_path(item.path, run_root=run_root, label=label)
    if not path.is_file():
        raise KimiAnalysisInvocationError(f"{label} is not a regular file")
    expected = _valid_sha256(item.sha256, label)
    content = path.read_bytes()
    if not hmac.compare_digest(_sha256_bytes(content), expected):
        raise KimiAnalysisInvocationError(f"{label} SHA-256 drifted")
    if (
        not isinstance(item.line_count, int)
        or isinstance(item.line_count, bool)
        or item.line_count < 1
        or len(content.splitlines()) != item.line_count
    ):
        raise KimiAnalysisInvocationError(f"{label} line count drifted")
    return path, content


def _decode_json(content: bytes, label: str) -> Mapping[str, Any]:
    try:
        decoded = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiAnalysisInvocationError(f"{label} is malformed JSON") from exc
    return _mapping(decoded, label)


def _validate_self_hash(document: Mapping[str, Any], *, label: str) -> None:
    claimed = document.get("manifest_payload_sha256")
    expected = _canonical_sha256(
        {key: value for key, value in document.items() if key != "manifest_payload_sha256"}
    )
    if not isinstance(claimed, str) or not hmac.compare_digest(claimed, expected):
        raise KimiAnalysisInvocationError(f"{label} self-hash drifted")


def _file_record(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "path": str(path),
        "sha256": _sha256_bytes(content),
        "bytes": len(content),
        "line_count": len(content.splitlines()),
    }


def _validate_manifest_file_record(
    record: Mapping[str, Any], *, root: Path, label: str
) -> Path:
    raw_path = record.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise KimiAnalysisInvocationError(f"{label} path is missing")
    path = _run_path(Path(raw_path), run_root=root, label=label)
    if not path.is_file():
        raise KimiAnalysisInvocationError(f"{label} is not a regular file")
    content = path.read_bytes()
    if (
        not hmac.compare_digest(
            _sha256_bytes(content), _valid_sha256(record.get("sha256"), label)
        )
        or record.get("line_count") != len(content.splitlines())
    ):
        raise KimiAnalysisInvocationError(f"{label} hash or line count drifted")
    if "bytes" in record and record.get("bytes") != len(content):
        raise KimiAnalysisInvocationError(f"{label} byte count drifted")
    return path


def _validate_completed_trial(
    *,
    document: Mapping[str, Any],
    request: KimiAnalysisInvocationRequest,
    projection_path: Path,
    projection_sha256: str,
    run_root: Path,
) -> tuple[Path, str]:
    _exact_keys(
        document,
        required={
            "schema_name",
            "schema_version",
            "manifest_payload_sha256",
            "harness_id",
            "harness_version",
            "run_id",
            "case_id",
            "trial_id",
            "outcome",
            "return_code",
            "failure_category",
            "retry_eligible",
            "executable",
            "event_ir",
            "projection_manifest",
        },
        label="completed trial",
    )
    _validate_self_hash(document, label="completed trial")
    if (
        document.get("schema_name") != COMPLETED_TRIAL_SCHEMA_NAME
        or document.get("schema_version") != COMPLETED_TRIAL_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("harness_version") != _KIMI_VERSION
        or document.get("run_id") != request.run_id
        or document.get("case_id") != request.case_id
        or document.get("trial_id") != request.trial_id
        or document.get("outcome") != "COMPLETED"
        or document.get("return_code") != 0
        or document.get("failure_category") is not None
        or document.get("retry_eligible") is not False
    ):
        raise KimiAnalysisInvocationError(
            "analysis requires an exact, terminal COMPLETED Kimi trial"
        )
    executable = _mapping(document.get("executable"), "completed trial executable")
    _exact_keys(executable, required={"path", "sha256"}, label="trial executable")
    executable_path = Path(str(executable.get("path") or "")).absolute()
    if executable_path.is_symlink():
        raise KimiAnalysisInvocationError(
            "completed trial executable must identify its resolved file"
        )
    try:
        executable_path = executable_path.resolve(strict=True)
    except OSError as exc:
        raise KimiAnalysisInvocationError("Kimi executable is unavailable") from exc
    executable_sha = _valid_sha256(executable.get("sha256"), "trial executable")
    if (
        not executable_path.is_file()
        or not hmac.compare_digest(executable_sha, _KIMI_BINARY_SHA256)
        or not hmac.compare_digest(_sha256_file(executable_path), executable_sha)
    ):
        raise KimiAnalysisInvocationError("Kimi executable/version pin drifted")

    projection = _mapping(
        document.get("projection_manifest"), "trial projection manifest reference"
    )
    _exact_keys(projection, required={"path", "sha256"}, label="trial projection reference")
    if (
        Path(str(projection.get("path") or "")).absolute() != projection_path
        or not hmac.compare_digest(
            str(projection.get("sha256") or ""), projection_sha256
        )
    ):
        raise KimiAnalysisInvocationError("completed trial projection reference drifted")

    event_ir = _mapping(document.get("event_ir"), "completed trial Event IR reference")
    _exact_keys(event_ir, required={"path", "sha256"}, label="trial Event IR reference")
    event_ir_path = _run_path(
        Path(str(event_ir.get("path") or "")), run_root=run_root, label="trial Event IR"
    )
    event_ir_sha = _valid_sha256(event_ir.get("sha256"), "trial Event IR")
    if not event_ir_path.is_file() or not hmac.compare_digest(
        _sha256_file(event_ir_path), event_ir_sha
    ):
        raise KimiAnalysisInvocationError("completed trial Event IR drifted")
    return event_ir_path, event_ir_sha


def _validate_projection(
    *,
    document: Mapping[str, Any],
    request: KimiAnalysisInvocationRequest,
    projection_path: Path,
    run_root: Path,
    event_ir_path: Path,
    event_ir_sha256: str,
) -> tuple[Path, list[Path], list[Path], list[dict[str, Any]]]:
    _validate_self_hash(document, label="projection manifest")
    if (
        document.get("schema_name") != PROJECTION_SCHEMA_NAME
        or document.get("schema_version") != PROJECTION_SCHEMA_VERSION
        or document.get("semantic_translation") != SEMANTIC_TRANSLATION
        or document.get("harness_id") != "kimi"
        or document.get("harness_version") != _KIMI_VERSION
        or document.get("binary_sha256") != _KIMI_BINARY_SHA256
        or document.get("run_id") != request.run_id
        or document.get("case_id") != request.case_id
        or document.get("trial_id") != request.trial_id
    ):
        raise KimiAnalysisInvocationError("projection manifest identity drifted")
    claims = _mapping(document.get("claims"), "projection claims")
    if claims != {
        "native_trace": False,
        "analyzer_compatibility_only": True,
        "raw_evidence_modified": False,
    }:
        raise KimiAnalysisInvocationError("projection semantic claims drifted")
    projection_root = _run_path(
        Path(str(document.get("projection_root") or "")),
        run_root=run_root,
        label="projection root",
    )
    if projection_root != projection_path.parent or not projection_root.is_dir():
        raise KimiAnalysisInvocationError("projection root identity drifted")
    declared_run_root = _run_path(
        Path(str(document.get("run_root") or "")),
        run_root=run_root,
        label="projection declared run root",
    )
    try:
        projection_root.relative_to(declared_run_root)
    except ValueError as exc:
        raise KimiAnalysisInvocationError(
            "projection root escapes its declared Kimi trial root"
        ) from exc

    inputs_raw = document.get("inputs")
    outputs_raw = document.get("outputs")
    if not isinstance(inputs_raw, list) or not inputs_raw:
        raise KimiAnalysisInvocationError("projection source inputs are absent")
    if not isinstance(outputs_raw, list) or not outputs_raw:
        raise KimiAnalysisInvocationError("projection outputs are absent")
    input_paths: list[Path] = []
    input_records: list[dict[str, Any]] = []
    for index, raw in enumerate(inputs_raw):
        record = _mapping(raw, f"projection input {index}")
        if set(record) != {"kind", "path", "sha256", "line_count"}:
            raise KimiAnalysisInvocationError("projection input record keys drifted")
        if not isinstance(record.get("kind"), str) or not record.get("kind"):
            raise KimiAnalysisInvocationError("projection input kind is missing")
        path = _validate_manifest_file_record(
            record, root=run_root, label=f"projection input {index}"
        )
        if path in input_paths:
            raise KimiAnalysisInvocationError("projection input path is duplicated")
        input_paths.append(path)
        input_records.append(dict(record))

    output_paths: list[Path] = []
    for index, raw in enumerate(outputs_raw):
        record = _mapping(raw, f"projection output {index}")
        if set(record) != {"path", "sha256", "bytes", "line_count"}:
            raise KimiAnalysisInvocationError("projection output record keys drifted")
        path = _validate_manifest_file_record(
            record, root=run_root, label=f"projection output {index}"
        )
        try:
            path.relative_to(projection_root)
        except ValueError as exc:
            raise KimiAnalysisInvocationError("projection output escapes projection root") from exc
        if path in output_paths:
            raise KimiAnalysisInvocationError("projection output path is duplicated")
        output_paths.append(path)

    required_root = {
        projection_root / "case.json",
        projection_root / "trace.jsonl",
        projection_root / "honeypot.jsonl",
    }
    if not required_root.issubset(output_paths):
        raise KimiAnalysisInvocationError("projection lacks root analyzer inputs")
    stage_roots = sorted(
        {
            path.parent
            for path in output_paths
            if path.parent.parent == projection_root / "stages"
        },
        key=str,
    )
    if not stage_roots:
        raise KimiAnalysisInvocationError("projection lacks stage analyzer inputs")
    for stage_root in stage_roots:
        required = {
            stage_root / "case.json",
            stage_root / "trace.jsonl",
            stage_root / "honeypot.jsonl",
        }
        if not required.issubset(output_paths):
            raise KimiAnalysisInvocationError(
                f"projection stage is incomplete: {stage_root.name}"
            )

    existing = {
        path.resolve()
        for path in projection_root.rglob("*")
        if path.is_file() and not path.is_symlink() and path.resolve() != projection_path
    }
    if existing != set(output_paths):
        raise KimiAnalysisInvocationError(
            "projection tree contains undeclared or missing analyzer files"
        )
    if (
        document.get("event_ir_sha256") != event_ir_sha256
        or event_ir_path not in input_paths
    ):
        raise KimiAnalysisInvocationError("projection Event IR provenance drifted")
    matching_event_ir = [
        record
        for record, path in zip(input_records, input_paths)
        if path == event_ir_path
    ]
    if len(matching_event_ir) != 1 or matching_event_ir[0]["sha256"] != event_ir_sha256:
        raise KimiAnalysisInvocationError("projection Event IR input pin drifted")
    return projection_root, input_paths, output_paths, input_records


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_json(path: Path, document: Mapping[str, Any]) -> None:
    _atomic_bytes(
        path,
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        + b"\n",
    )


def _copy_projection_inputs(
    *, projection_root: Path, output_paths: Sequence[Path], target: Path
) -> None:
    for source in output_paths:
        relative = source.relative_to(projection_root)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = source.read_bytes()
        _atomic_bytes(destination, content)
        if not hmac.compare_digest(_sha256_bytes(content), _sha256_file(destination)):
            raise KimiAnalysisInvocationError("analyzer input copy hash drifted")


def invoke_kimi_shared_analyzer(
    request: KimiAnalysisInvocationRequest,
) -> KimiAnalysisInvocationResult:
    """Run the unchanged shared analyzer after all Kimi evidence gates pass."""

    if (
        not request.run_id
        or not request.case_id
        or not request.trial_id
        or not isinstance(request.timeout_seconds, int)
        or isinstance(request.timeout_seconds, bool)
        or request.timeout_seconds < 1
        or request.timeout_seconds > 900
    ):
        raise KimiAnalysisInvocationError("analysis request identity or timeout is invalid")
    run_root = _strict_run_root(request)
    analysis_dir = _run_path(
        request.analysis_dir, run_root=run_root, label="analysis directory"
    )
    if analysis_dir.exists() or analysis_dir.is_symlink():
        raise KimiAnalysisInvocationError("analysis directory already exists")
    if not analysis_dir.parent.is_dir() or analysis_dir.parent.is_symlink():
        raise KimiAnalysisInvocationError("analysis directory parent is unsafe")
    if (
        "kimi" not in analysis_dir.as_posix().casefold()
        or request.run_id not in analysis_dir.as_posix()
        or request.trial_id not in analysis_dir.as_posix()
    ):
        raise KimiAnalysisInvocationError(
            "analysis directory lacks exact Kimi/run/trial ownership"
        )

    projection_path, projection_bytes = _read_pinned(
        request.projection_manifest,
        run_root=run_root,
        label="projection manifest",
    )
    projection_document = _decode_json(projection_bytes, "projection manifest")
    trial_path, trial_bytes = _read_pinned(
        request.completed_trial, run_root=run_root, label="completed trial"
    )
    trial_document = _decode_json(trial_bytes, "completed trial")
    event_ir_path, event_ir_sha = _validate_completed_trial(
        document=trial_document,
        request=request,
        projection_path=projection_path,
        projection_sha256=request.projection_manifest.sha256,
        run_root=run_root,
    )
    projection_root, source_paths, projected_paths, _ = _validate_projection(
        document=projection_document,
        request=request,
        projection_path=projection_path,
        run_root=run_root,
        event_ir_path=event_ir_path,
        event_ir_sha256=event_ir_sha,
    )

    repo_root = Path(__file__).resolve().parents[4]
    analyzer_path = repo_root / "infra" / "analyze_trace.py"
    if analyzer_path.is_symlink() or not analyzer_path.is_file():
        raise KimiAnalysisInvocationError("shared analyzer source is unavailable")
    analyzer_path = analyzer_path.resolve(strict=True)
    analyzer_sha_before = _sha256_file(analyzer_path)
    python_path = Path(getattr(sys, "_base_executable", sys.executable)).resolve(
        strict=True
    )
    if python_path.is_symlink() or not python_path.is_file():
        raise KimiAnalysisInvocationError("trusted Python executable is unavailable")
    python_sha = _sha256_file(python_path)

    analysis_dir.mkdir(mode=0o700)
    results_dir = analysis_dir / f"results-kimi-{request.run_id}-{request.trial_id}"
    results_dir.mkdir(mode=0o700)
    stdout_path = analysis_dir / f"analyzer-stdout-kimi-{request.run_id}-{request.trial_id}.log"
    stderr_path = analysis_dir / f"analyzer-stderr-kimi-{request.run_id}-{request.trial_id}.log"
    provenance_path = (
        analysis_dir
        / f"analysis-provenance-kimi-{request.run_id}-{request.trial_id}.json"
    )
    try:
        _copy_projection_inputs(
            projection_root=projection_root,
            output_paths=projected_paths,
            target=results_dir,
        )
        command = (
            str(python_path),
            str(analyzer_path),
            "--results",
            str(results_dir),
        )
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=repo_root,
                env=environment,
                timeout=request.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise KimiAnalysisInvocationError("shared analyzer timed out") from exc
        _atomic_bytes(stdout_path, completed.stdout)
        _atomic_bytes(stderr_path, completed.stderr)
        if completed.returncode != 0:
            raise KimiAnalysisInvocationError(
                f"shared analyzer failed with exit code {completed.returncode}"
            )

        if not hmac.compare_digest(_sha256_file(analyzer_path), analyzer_sha_before):
            raise KimiAnalysisInvocationError("shared analyzer source changed during invocation")
        if not hmac.compare_digest(_sha256_file(trial_path), request.completed_trial.sha256):
            raise KimiAnalysisInvocationError("completed trial changed during analysis")
        if not hmac.compare_digest(
            _sha256_file(projection_path), request.projection_manifest.sha256
        ):
            raise KimiAnalysisInvocationError("projection manifest changed during analysis")
        for path in source_paths:
            expected = next(
                str(record["sha256"])
                for record in projection_document["inputs"]
                if Path(str(record["path"])).absolute().resolve() == path
            )
            if not hmac.compare_digest(_sha256_file(path), expected):
                raise KimiAnalysisInvocationError(
                    "projection source changed during analysis"
                )
        for path in projected_paths:
            expected = next(
                str(record["sha256"])
                for record in projection_document["outputs"]
                if Path(str(record["path"])).absolute().resolve() == path
            )
            if not hmac.compare_digest(_sha256_file(path), expected):
                raise KimiAnalysisInvocationError(
                    "projection output changed during analysis"
                )

        copied_inputs = [results_dir / path.relative_to(projection_root) for path in projected_paths]
        for source, copied in zip(projected_paths, copied_inputs):
            if not hmac.compare_digest(_sha256_file(source), _sha256_file(copied)):
                raise KimiAnalysisInvocationError(
                    "shared analyzer modified its copied compatibility input"
                )
        stage_dirs = sorted(
            path for path in (results_dir / "stages").iterdir() if path.is_dir()
        )
        expected_outputs = {
            results_dir / "oracle.json",
            results_dir / "oracle.md",
            *(
                output
                for stage_dir in stage_dirs
                for output in (stage_dir / "oracle.json", stage_dir / "oracle.md")
            ),
        }
        if any(path.is_symlink() or not path.is_file() for path in expected_outputs):
            raise KimiAnalysisInvocationError(
                "shared analyzer did not produce every required oracle artifact"
            )
        observed_oracles = {
            path.resolve()
            for path in results_dir.rglob("oracle.*")
            if path.is_file() and not path.is_symlink()
        }
        if observed_oracles != {path.resolve() for path in expected_outputs}:
            raise KimiAnalysisInvocationError(
                "shared analyzer produced an unexpected oracle artifact set"
            )
        analyzer_outputs = [_file_record(path) for path in sorted(expected_outputs, key=str)]
        provenance: dict[str, Any] = {
            "schema_name": ANALYSIS_PROVENANCE_SCHEMA_NAME,
            "schema_version": ANALYSIS_PROVENANCE_SCHEMA_VERSION,
            "harness_id": "kimi",
            "harness_version": _KIMI_VERSION,
            "binary_sha256": _KIMI_BINARY_SHA256,
            "run_id": request.run_id,
            "case_id": request.case_id,
            "trial_id": request.trial_id,
            "trial_disposition": "COMPLETED",
            "inputs": {
                "completed_trial": {
                    "path": str(trial_path),
                    "sha256": request.completed_trial.sha256,
                },
                "projection_manifest": {
                    "path": str(projection_path),
                    "sha256": request.projection_manifest.sha256,
                },
                "projection_source_count": len(source_paths),
                "projection_output_count": len(projected_paths),
            },
            "analyzer": {
                "source_path": str(analyzer_path),
                "source_sha256": analyzer_sha_before,
                "entry": "infra.analyze_trace.main",
                "invocation_mode": "sanitized_subprocess",
                "python_path": str(python_path),
                "python_sha256": python_sha,
            },
            "process": {
                "argv": list(command),
                "cwd": str(repo_root),
                "timeout_seconds": request.timeout_seconds,
                "exit_code": completed.returncode,
                "stdout": _file_record(stdout_path),
                "stderr": _file_record(stderr_path),
            },
            "analyzer_outputs": analyzer_outputs,
            "evidence_revalidation": {
                "projection_and_sources_unchanged": True,
                "shared_analyzer_source_unchanged": True,
            },
        }
        _reject_forbidden_keys(provenance)
        provenance["manifest_payload_sha256"] = _canonical_sha256(provenance)
        _atomic_json(provenance_path, provenance)
        return KimiAnalysisInvocationResult(
            analysis_dir=analysis_dir,
            analyzer_results_dir=results_dir,
            provenance_manifest_path=provenance_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
    except BaseException:
        shutil.rmtree(analysis_dir, ignore_errors=True)
        raise


__all__ = [
    "ANALYSIS_PROVENANCE_SCHEMA_NAME",
    "ANALYSIS_PROVENANCE_SCHEMA_VERSION",
    "COMPLETED_TRIAL_SCHEMA_NAME",
    "COMPLETED_TRIAL_SCHEMA_VERSION",
    "KimiAnalysisInvocationError",
    "KimiAnalysisInvocationRequest",
    "KimiAnalysisInvocationResult",
    "PinnedAnalysisInput",
    "invoke_kimi_shared_analyzer",
]
