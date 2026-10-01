"""Gemini CLI Contract v1 adapter orchestration."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Iterable, Mapping, Sequence

from ...adapter import (
    CapabilityProbe,
    HarnessAdapter,
    HarnessIdentity,
    LaunchSpec,
    MaterializedBinding,
)
from .capabilities import aggregate_required_capabilities, capability_matrix
from .launcher import GeminiLaunchError, build_gemini_launch_spec
from .materializer import (
    GeminiMaterializationError,
    binding_document_sha256,
    load_materialization_manifest,
    materialize_gemini_binding,
    sha256_file,
    validate_run_id,
)


class GeminiExecutableNotFound(FileNotFoundError):
    """No Gemini CLI executable was found on the configured path."""


class GeminiProbeError(RuntimeError):
    """A read-only Gemini CLI version/help probe failed."""


class GeminiPreflightError(GeminiLaunchError):
    """A Gemini trial was blocked before model execution."""


_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)")


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _output_sha256(stdout: str, stderr: str) -> str:
    return hashlib.sha256((stdout + "\0" + stderr).encode("utf-8")).hexdigest()


def _parse_version(stdout: str, stderr: str) -> str:
    match = _VERSION_RE.search("\n".join((stdout, stderr)))
    if match is None:
        raise GeminiProbeError("gemini --version did not contain a semantic version")
    return match.group(1)


class GeminiHarnessAdapter(HarnessAdapter):
    """Fail-closed Gemini CLI implementation of Cross-Harness Contract v1."""

    harness_id = "gemini"

    def __init__(
        self,
        *,
        run_id: str,
        run_dir: Path,
        stage_index: int = 0,
        executable: str = "gemini",
        conformance_evidence_path: Path | None = None,
        model: str | None = None,
        callback_url: str = "http://127.0.0.1:18765",
        canary_token: str | None = None,
        control_type: str | None = None,
        base_environment: Mapping[str, str] | None = None,
    ) -> None:
        validate_run_id(run_id)
        if not isinstance(stage_index, int) or isinstance(stage_index, bool) or stage_index < 0:
            raise ValueError("stage_index must be a non-negative integer")
        if not isinstance(executable, str) or not executable.strip():
            raise ValueError("executable must be non-empty")
        if not isinstance(callback_url, str) or not callback_url.startswith(
            ("http://127.0.0.1:", "http://localhost:")
        ):
            raise ValueError("Gemini adapter permits loopback callback URLs only")
        self.run_id = run_id
        self.run_dir = Path(run_dir).resolve()
        self.stage_index = stage_index
        self.executable = executable
        self.conformance_evidence_path = (
            Path(conformance_evidence_path).resolve()
            if conformance_evidence_path is not None
            else None
        )
        if model is not None and (not isinstance(model, str) or not model.strip()):
            raise ValueError("model must be a non-empty string when supplied")
        if control_type not in {
            None,
            "clean_control",
            "no_persist_control",
            "no_trigger_control",
            "cleanup_control",
        }:
            raise ValueError("control_type is not a reviewed matched control")
        self.model = model
        self.callback_url = callback_url
        self.canary_token = canary_token
        self.control_type = control_type
        self.base_environment = dict(base_environment or os.environ)
        self.evidence_dir = self.run_dir / "evidence"
        self._identity: HarnessIdentity | None = None
        self._trusted_bindings: dict[Path, dict[str, Any]] = {}
        self._trusted_manifests: dict[Path, dict[str, Any]] = {}
        self.last_capability_matrix: Mapping[str, Any] | None = None

    def _resolve_executable(self) -> Path:
        candidate = Path(self.executable)
        if candidate.is_absolute() or candidate.parent != Path("."):
            resolved = candidate.expanduser().resolve()
        else:
            located = shutil.which(
                self.executable, path=self.base_environment.get("PATH", os.defpath)
            )
            if located is None:
                raise GeminiExecutableNotFound(
                    f"Gemini CLI executable {self.executable!r} was not found"
                )
            resolved = Path(located).resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise GeminiExecutableNotFound(
                f"Gemini CLI executable is not an executable file: {resolved}"
            )
        return resolved

    def _read_only_probe(self, executable: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": self.base_environment.get("PATH", os.defpath),
            "NO_COLOR": "1",
            "CI": "1",
        }
        for key in ("LANG", "LC_ALL"):
            if self.base_environment.get(key):
                environment[key] = self.base_environment[key]
        try:
            result = subprocess.run(
                [str(executable), *arguments],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GeminiProbeError(
                f"Gemini read-only probe {' '.join(arguments)} failed: {exc}"
            ) from exc
        if result.returncode != 0:
            raise GeminiProbeError(
                f"Gemini read-only probe {' '.join(arguments)} exited {result.returncode}"
            )
        return result

    def detect_identity(self) -> HarnessIdentity:
        if self._identity is not None:
            return self._identity
        executable = self._resolve_executable()
        version_result = self._read_only_probe(executable, "--version")
        help_result = self._read_only_probe(executable, "--help")
        help_text = help_result.stdout + "\n" + help_result.stderr
        flags = {
            "binary_sha256": sha256_file(executable),
            "resolved_executable": str(executable),
            "version_output_sha256": _output_sha256(
                version_result.stdout, version_result.stderr
            ),
            "help_output_sha256": _output_sha256(help_result.stdout, help_result.stderr),
            "headless_prompt": "--prompt" in help_text,
            "stream_json": "--output-format" in help_text and "stream-json" in help_text,
            "resume": "--resume" in help_text,
            "session_id": "--session-id" in help_text,
            "session_file": "--session-file" in help_text,
            "skip_trust": "--skip-trust" in help_text,
            "policy": "--policy" in help_text,
            "approval_mode": "--approval-mode" in help_text or "--yolo" in help_text,
            "mcp_filter": "--allowed-mcp-server-names" in help_text,
        }
        self._identity = HarnessIdentity(
            harness_id="gemini",
            version=_parse_version(version_result.stdout, version_result.stderr),
            executable=str(executable),
            feature_flags=flags,
        )
        _write_json(
            self.evidence_dir / f"identity-gemini-{self.run_id}.json",
            {
                "schema_name": "safety_bench_gemini_identity",
                "schema_version": 1,
                "run_id": self.run_id,
                "identity": {
                    "harness_id": "gemini",
                    "version": self._identity.version,
                    "executable": self._identity.executable,
                    "feature_flags": flags,
                },
                "probe_commands": ["gemini --version", "gemini --help"],
                "note": "Read-only interface evidence; not model/runtime conformance.",
            },
        )
        return self._identity

    def _identity_is_current(self, identity: HarnessIdentity) -> bool:
        if self._identity is None or identity != self._identity:
            return False
        try:
            executable = Path(identity.executable).resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        return (
            executable.is_file()
            and os.access(executable, os.X_OK)
            and sha256_file(executable) == identity.feature_flags.get("binary_sha256")
        )

    def probe_capabilities(
        self, required_capabilities: Sequence[str]
    ) -> CapabilityProbe:
        required = tuple(required_capabilities)
        if not required:
            raise ValueError("required_capabilities must not be empty")
        try:
            identity: HarnessIdentity | None = self.detect_identity()
        except (GeminiExecutableNotFound, GeminiProbeError):
            identity = None
        matrix = capability_matrix(
            identity=identity, conformance_path=self.conformance_evidence_path
        )
        self.last_capability_matrix = matrix
        status, evidence, reasons = aggregate_required_capabilities(required, matrix)
        matrix_path = self.evidence_dir / f"capabilities-gemini-{self.run_id}.json"
        _write_json(
            matrix_path,
            {
                "schema_name": "safety_bench_gemini_capability_probe",
                "schema_version": 1,
                "run_id": self.run_id,
                "required_capabilities": list(required),
                "aggregate_status": status,
                "capabilities": {
                    key: value.as_dict() for key, value in sorted(matrix.items())
                },
                "scoring_prohibited": status != "SUPPORTED",
            },
        )
        return CapabilityProbe(
            status=status,
            required_capabilities=required,
            evidence=tuple(dict.fromkeys((*evidence, str(matrix_path)))),
            reasons=reasons,
        )

    def materialize_binding(
        self,
        *,
        case_dir: Path,
        binding_document: Mapping[str, Any],
        run_dir: Path,
    ) -> MaterializedBinding:
        if Path(run_dir).resolve() != self.run_dir:
            raise GeminiMaterializationError(
                f"run_dir must equal adapter-owned path {self.run_dir}"
            )
        materialized = materialize_gemini_binding(
            run_id=self.run_id,
            case_dir=case_dir,
            binding_document=binding_document,
            run_dir=self.run_dir,
            callback_url=self.callback_url,
            canary_token=self.canary_token,
            requested_model=self.model,
            control_type=self.control_type,
        )
        manifest = load_materialization_manifest(materialized)
        self._trusted_bindings[materialized.manifest_path.resolve()] = json.loads(
            json.dumps(binding_document, ensure_ascii=False)
        )
        self._trusted_manifests[materialized.manifest_path.resolve()] = json.loads(
            json.dumps(manifest, ensure_ascii=False)
        )
        return materialized

    def _trusted_materialization(
        self, materialized: MaterializedBinding
    ) -> tuple[dict[str, Any], Mapping[str, Any]]:
        key = materialized.manifest_path.resolve()
        manifest = load_materialization_manifest(materialized)
        snapshot = self._trusted_manifests.get(key)
        binding = self._trusted_bindings.get(key)
        if snapshot is None or binding is None:
            raise GeminiMaterializationError(
                "formal Gemini lifecycle cannot resume from run-local state alone"
            )
        if manifest != snapshot:
            raise GeminiMaterializationError(
                "Gemini materialization manifest drifted from the adapter snapshot"
            )
        if manifest["binding_sha256"] != binding_document_sha256(binding):
            raise GeminiMaterializationError("Gemini binding/manifest digest mismatch")
        return manifest, binding

    def build_launch_spec(
        self,
        *,
        materialized: MaterializedBinding,
        prompt: str,
        timeout_seconds: int,
    ) -> LaunchSpec:
        manifest, binding = self._trusted_materialization(materialized)
        binding_status = binding["supported_harnesses"]["gemini"]["status"]
        if binding_status not in {"supported", "conditional"}:
            raise GeminiPreflightError(
                "Gemini binding disposition is UNVALIDATED; outcome=NOT_RUN"
            )
        probe = self.probe_capabilities(manifest["required_capabilities"])
        if probe.status != "SUPPORTED":
            raise GeminiPreflightError(
                f"Gemini trial blocked ({probe.status}); outcome=NOT_RUN; "
                + "; ".join(probe.reasons)
            )
        if self.canary_token is None:
            raise GeminiPreflightError(
                "Gemini scored launch requires a run-specific canary; outcome=NOT_RUN"
            )
        if self.model is None:
            raise GeminiPreflightError(
                "Gemini scored launch requires an explicit model pin; outcome=NOT_RUN"
            )
        identity = self.detect_identity()
        if not self._identity_is_current(identity):
            raise GeminiPreflightError(
                "Gemini executable identity drifted after capability preflight"
            )
        return build_gemini_launch_spec(
            identity=identity,
            materialized=materialized,
            manifest=manifest,
            stage_index=self.stage_index,
            prompt=prompt,
            timeout_seconds=timeout_seconds,
            base_environment=self.base_environment,
            model=self.model,
        )

    def normalize_trace(
        self,
        *,
        identity: HarnessIdentity,
        materialized: MaterializedBinding,
        raw_trace_path: Path,
    ) -> Iterable[Mapping[str, Any]]:
        from .trace import GeminiTraceNormalizationError, normalize_gemini_trace

        manifest, binding = self._trusted_materialization(materialized)
        detected = self.detect_identity()
        if identity != detected or not self._identity_is_current(detected):
            raise GeminiTraceNormalizationError(
                "raw trace identity does not match the current Gemini executable"
            )
        return normalize_gemini_trace(
            identity=detected,
            materialized=materialized,
            manifest=manifest,
            binding_document=binding,
            raw_trace_path=Path(raw_trace_path),
            stage_index=self.stage_index,
        )

    def cleanup(self, *, materialized: MaterializedBinding) -> None:
        manifest, _ = self._trusted_materialization(materialized)
        if materialized.run_dir.resolve() != self.run_dir:
            raise GeminiMaterializationError("cleanup target is not adapter-owned")
        _write_json(
            self.evidence_dir / f"cleanup-gemini-{self.run_id}.json",
            {
                "schema_name": "safety_bench_gemini_cleanup",
                "schema_version": 1,
                "run_id": self.run_id,
                "case_id": materialized.case_id,
                "owned_processes_terminated": [],
                "removed_paths": [],
                "preserved": [
                    manifest["materialized_case_dir"],
                    str(materialized.manifest_path),
                    *[stage["trace_path"] for stage in manifest["stages"]],
                ],
                "note": "The Contract v1 adapter builds launch specs but owns no executor process.",
            },
        )


__all__ = [
    "GeminiExecutableNotFound",
    "GeminiHarnessAdapter",
    "GeminiPreflightError",
    "GeminiProbeError",
]
