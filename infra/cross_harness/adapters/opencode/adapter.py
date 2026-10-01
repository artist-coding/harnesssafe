"""OpenCode orchestration for Cross-Harness Contract v1."""

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
from .launcher import OpenCodeLaunchError, build_opencode_launch_spec
from .materializer import (
    OpenCodeMaterializationError,
    binding_document_sha256,
    load_materialization_manifest,
    materialize_opencode_binding,
    sha256_file,
    validate_run_id,
)
from .trace import OpenCodeTraceError, normalize_opencode_trace


class OpenCodeExecutableNotFound(FileNotFoundError):
    """No OpenCode executable was found on the configured path."""


class OpenCodeProbeError(RuntimeError):
    """A read-only OpenCode version/help probe failed."""


class OpenCodePreflightError(OpenCodeLaunchError):
    """A trial was blocked before model execution."""


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
        raise OpenCodeProbeError(
            "opencode --version did not contain a semantic version"
        )
    return match.group(1)


class OpenCodeHarnessAdapter(HarnessAdapter):
    """Fail-closed OpenCode implementation of Contract v1."""

    harness_id = "opencode"

    def __init__(
        self,
        *,
        run_id: str,
        run_dir: Path,
        model: str,
        executable: str = "opencode",
        stage_index: int = 0,
        session_id: str | None = None,
        conformance_evidence_path: Path | None = None,
        provider_config: Mapping[str, Any] | None = None,
        permissions: Mapping[str, Any] | None = None,
        credential_environment_names: Sequence[str] = (),
        base_environment: Mapping[str, str] | None = None,
    ) -> None:
        validate_run_id(run_id)
        if (
            not isinstance(stage_index, int)
            or isinstance(stage_index, bool)
            or stage_index < 0
        ):
            raise ValueError("stage_index must be a non-negative integer")
        if not isinstance(executable, str) or not executable.strip():
            raise ValueError("executable must be non-empty")
        if not isinstance(model, str) or "/" not in model:
            raise ValueError("model must use provider/model form")
        if session_id is not None and (
            not isinstance(session_id, str) or not session_id.strip()
        ):
            raise ValueError("session_id must be non-empty when supplied")
        credential_names = tuple(credential_environment_names)
        if len(set(credential_names)) != len(credential_names):
            raise ValueError("credential_environment_names must be unique")
        self.run_id = run_id
        self.run_dir = Path(run_dir).resolve()
        self.model = model
        self.executable = executable
        self.stage_index = stage_index
        self.session_id = session_id
        self.conformance_evidence_path = (
            Path(conformance_evidence_path).resolve()
            if conformance_evidence_path is not None
            else None
        )
        self.provider_config = dict(provider_config or {})
        self.permissions = dict(permissions or {})
        self.credential_environment_names = credential_names
        self.base_environment = dict(base_environment or os.environ)
        self.evidence_dir = self.run_dir / "evidence"
        self._identity: HarnessIdentity | None = None
        self._trusted_materializations: set[Path] = set()
        self._last_probe: CapabilityProbe | None = None
        self.last_capability_matrix: Mapping[str, Any] | None = None

    def _resolve_executable(self) -> Path:
        candidate = Path(self.executable)
        if candidate.is_absolute() or candidate.parent != Path("."):
            resolved = candidate.expanduser().resolve()
        else:
            located = shutil.which(
                self.executable,
                path=self.base_environment.get("PATH", os.defpath),
            )
            if located is None:
                raise OpenCodeExecutableNotFound(
                    f"OpenCode executable {self.executable!r} was not found"
                )
            resolved = Path(located).resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise OpenCodeExecutableNotFound(
                f"OpenCode executable is not executable: {resolved}"
            )
        return resolved

    def _read_only_probe(
        self, executable: Path, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": self.base_environment.get("PATH", os.defpath),
            "HOME": str(self.run_dir / "identity-home"),
            "XDG_CONFIG_HOME": str(self.run_dir / "identity-xdg-config"),
            "XDG_DATA_HOME": str(self.run_dir / "identity-xdg-data"),
            "XDG_CACHE_HOME": str(self.run_dir / "identity-xdg-cache"),
            "CI": "1",
            "NO_COLOR": "1",
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
        }
        for name in ("LANG", "LC_ALL"):
            value = self.base_environment.get(name)
            if value:
                environment[name] = value
        for name in (
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
        ):
            Path(environment[name]).mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [str(executable), *arguments],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OpenCodeProbeError(
                f"OpenCode probe {' '.join(arguments)} failed: {exc}"
            ) from exc
        if result.returncode != 0:
            raise OpenCodeProbeError(
                f"OpenCode probe {' '.join(arguments)} exited {result.returncode}"
            )
        return result

    def detect_identity(self) -> HarnessIdentity:
        if self._identity is not None:
            return self._identity
        executable = self._resolve_executable()
        version_result = self._read_only_probe(executable, "--version")
        top_help = self._read_only_probe(executable, "--help")
        run_help = self._read_only_probe(executable, "run", "--help")
        top_text = top_help.stdout + "\n" + top_help.stderr
        run_text = run_help.stdout + "\n" + run_help.stderr
        flags = {
            "binary_sha256": sha256_file(executable),
            "resolved_executable": str(executable),
            "version_output_sha256": _output_sha256(
                version_result.stdout, version_result.stderr
            ),
            "top_help_output_sha256": _output_sha256(
                top_help.stdout, top_help.stderr
            ),
            "run_help_output_sha256": _output_sha256(
                run_help.stdout, run_help.stderr
            ),
            "headless_run": "run [message" in run_text,
            "json_trace": "--format" in run_text and "json" in run_text,
            "session_resume": "--session" in run_text,
            "session_fork": "--fork" in run_text,
            "model_selection": "--model" in run_text,
            "agent_selection": "--agent" in run_text,
            "auto_permissions": "--auto" in run_text,
            "pure_mode": "--pure" in top_text,
        }
        self._identity = HarnessIdentity(
            harness_id="opencode",
            version=_parse_version(version_result.stdout, version_result.stderr),
            executable=str(executable),
            feature_flags=flags,
        )
        _write_json(
            self.evidence_dir / f"identity-opencode-{self.run_id}.json",
            {
                "schema_name": "safety_bench_opencode_identity",
                "schema_version": 1,
                "run_id": self.run_id,
                "identity": {
                    "harness_id": "opencode",
                    "version": self._identity.version,
                    "executable": self._identity.executable,
                    "feature_flags": flags,
                },
                "probe_commands": [
                    "opencode --version",
                    "opencode --help",
                    "opencode run --help",
                ],
                "note": "Read-only interface evidence; not runtime conformance.",
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
            and sha256_file(executable)
            == identity.feature_flags.get("binary_sha256")
        )

    def probe_capabilities(
        self, required_capabilities: Sequence[str]
    ) -> CapabilityProbe:
        required = tuple(required_capabilities)
        if not required:
            raise ValueError("required_capabilities must not be empty")
        try:
            identity: HarnessIdentity | None = self.detect_identity()
        except (OpenCodeExecutableNotFound, OpenCodeProbeError):
            identity = None
        matrix = capability_matrix(
            identity=identity,
            conformance_path=self.conformance_evidence_path,
        )
        self.last_capability_matrix = matrix
        status, evidence, reasons = aggregate_required_capabilities(
            required, matrix
        )
        result = CapabilityProbe(
            status=status,
            required_capabilities=required,
            evidence=evidence,
            reasons=reasons,
        )
        self._last_probe = result
        matrix_path = (
            self.evidence_dir / f"capabilities-opencode-{self.run_id}.json"
        )
        _write_json(
            matrix_path,
            {
                "schema_name": "safety_bench_opencode_capability_probe",
                "schema_version": 1,
                "run_id": self.run_id,
                "required_capabilities": list(required),
                "aggregate_status": status,
                "capabilities": {
                    key: value.as_dict()
                    for key, value in sorted(matrix.items())
                },
                "scoring_prohibited": status != "SUPPORTED",
            },
        )
        return result

    def materialize_binding(
        self,
        *,
        case_dir: Path,
        binding_document: Mapping[str, Any],
        run_dir: Path,
    ) -> MaterializedBinding:
        materialized = materialize_opencode_binding(
            run_id=self.run_id,
            case_dir=case_dir,
            binding_document=binding_document,
            run_dir=run_dir,
            model=self.model,
            provider_config=self.provider_config,
            permissions=self.permissions,
        )
        manifest = load_materialization_manifest(materialized)
        if manifest["binding_sha256"] != binding_document_sha256(binding_document):
            raise OpenCodeMaterializationError(
                "materialized binding digest does not match the input binding"
            )
        self._trusted_materializations.add(materialized.manifest_path.resolve())
        return materialized

    def build_launch_spec(
        self,
        *,
        materialized: MaterializedBinding,
        prompt: str,
        timeout_seconds: int,
    ) -> LaunchSpec:
        if materialized.manifest_path.resolve() not in self._trusted_materializations:
            raise OpenCodePreflightError(
                "materialization was not produced by this adapter instance"
            )
        if self._last_probe is None or self._last_probe.status != "SUPPORTED":
            raise OpenCodePreflightError(
                "OpenCode capability preflight has not passed for this trial"
            )
        identity = self.detect_identity()
        if not self._identity_is_current(identity):
            raise OpenCodePreflightError(
                "OpenCode executable identity changed after capability preflight"
            )
        manifest = load_materialization_manifest(materialized)
        stage = next(
            (
                value
                for value in manifest["stages"]
                if value["index"] == self.stage_index
            ),
            None,
        )
        if stage is None:
            raise OpenCodePreflightError(
                f"materialization has no stage {self.stage_index}"
            )
        frozen_prompt = Path(stage["prompt_path"]).read_text(
            encoding="utf-8"
        ).rstrip("\n")
        if prompt.rstrip("\n") != frozen_prompt:
            raise OpenCodePreflightError(
                "launch prompt differs from the materialized stage prompt"
            )
        return build_opencode_launch_spec(
            materialized=materialized,
            executable=identity.executable,
            prompt=frozen_prompt,
            timeout_seconds=timeout_seconds,
            stage_index=self.stage_index,
            session_id=self.session_id,
            base_environment=self.base_environment,
            credential_environment_names=self.credential_environment_names,
        )

    def normalize_trace(
        self,
        *,
        identity: HarnessIdentity,
        materialized: MaterializedBinding,
        raw_trace_path: Path,
        artifact_snapshot_before: Mapping[str, str | None] | None = None,
    ) -> Iterable[Mapping[str, Any]]:
        if materialized.manifest_path.resolve() not in self._trusted_materializations:
            raise OpenCodeTraceError(
                "materialization was not produced by this adapter instance"
            )
        if not self._identity_is_current(identity):
            raise OpenCodeTraceError(
                "trace identity does not match the current OpenCode binary"
            )
        return normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=raw_trace_path,
            stage_index=self.stage_index,
            run_id=self.run_id,
            artifact_snapshot_before=artifact_snapshot_before,
        )

    def cleanup(self, *, materialized: MaterializedBinding) -> None:
        # OpenCode `run` is process-scoped.  The adapter does not delete evidence
        # or canonical state; process cleanup is owned by the runner that spawned
        # the LaunchSpec.
        if materialized.manifest_path.resolve() not in self._trusted_materializations:
            raise OpenCodeMaterializationError(
                "refusing cleanup for an untrusted materialization"
            )


__all__ = [
    "OpenCodeExecutableNotFound",
    "OpenCodeHarnessAdapter",
    "OpenCodePreflightError",
    "OpenCodeProbeError",
]
