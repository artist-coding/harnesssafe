"""Kimi Code HarnessAdapter vertical slice for Cross-Harness Contract v1."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
from typing import Any, Callable, Iterable, Mapping, Sequence

from ...adapter import (
    CapabilityProbe,
    HarnessAdapter,
    HarnessIdentity,
    LaunchSpec,
    MaterializedBinding,
)
from .capabilities import (
    CapabilityEvidence,
    aggregate_required_capabilities,
    default_capability_matrix,
)
from .materializer import (
    KimiMaterializationError,
    binding_document_sha256,
    load_materialization_manifest,
    materialize_kimi_binding,
    sha256_file,
    validate_manifest_against_binding,
    validate_prelaunch_artifacts,
    validate_run_id,
)
from .trace import KimiTraceNormalizationError, normalize_kimi_trace


_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)")
_SENSITIVE_ENV_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|credential|authorization)", re.IGNORECASE
)
_REPO_ROOT = Path(__file__).resolve().parents[4]


class KimiExecutableNotFound(FileNotFoundError):
    """No verified Kimi executable was found on the configured PATH."""


class KimiProbeError(RuntimeError):
    """A read-only identity/help probe failed."""


class KimiPreflightError(RuntimeError):
    """A scored Kimi launch was blocked before model execution."""

    execution_outcome = "NOT_RUN"


ProcessInspector = Callable[[int], Mapping[str, Any] | None]
ProcessTerminator = Callable[[int], None]


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _parse_version(stdout: str, stderr: str) -> str:
    combined = "\n".join(value for value in (stdout, stderr) if value.strip())
    match = _VERSION_RE.search(combined)
    if match is None:
        raise KimiProbeError("Kimi --version output did not contain a semantic version")
    return match.group(1)


def _reviewed_case_dir(case_id: object) -> Path:
    """Resolve the sole canonical case path frozen by the source inventory."""

    if not isinstance(case_id, str) or not case_id:
        raise KimiMaterializationError("reviewed Kimi case_id must be non-empty")
    inventory_path = _REPO_ROOT / "docs" / "codex_conformance_smoke_v1.json"
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        matches = [
            entry
            for entry in inventory["cases"]
            if entry.get("surface_class") == "common"
            and entry.get("case_id") == case_id
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise KimiMaterializationError(
            "cannot resolve reviewed canonical case_dir from the source inventory"
        ) from exc
    if len(matches) != 1:
        raise KimiMaterializationError(
            "reviewed canonical case_dir must have exactly one inventory entry"
        )
    relative = Path(str(matches[0].get("case_dir", "")))
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        raise KimiMaterializationError(
            "reviewed canonical case_dir is not a safe repository-relative path"
        )
    try:
        repo_root = _REPO_ROOT.resolve(strict=True)
        expected = (repo_root / relative).resolve(strict=True)
        expected.relative_to(repo_root)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        raise KimiMaterializationError(
            "reviewed canonical case_dir is unavailable or escapes the repository"
        ) from exc
    if not expected.is_dir():
        raise KimiMaterializationError("reviewed canonical case_dir is not a directory")
    return expected


def _safe_process_snapshot(pid: int) -> Mapping[str, Any] | None:
    """Read Linux process ownership fields; fail closed on any uncertainty."""

    proc = Path("/proc") / str(pid)
    try:
        stat_fields = (proc / "stat").read_text(encoding="utf-8").split()
        environ_raw = (proc / "environ").read_bytes()
        cmdline_raw = (proc / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        return None
    if len(stat_fields) < 22:
        return None
    environ: dict[str, str] = {}
    for item in environ_raw.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        environ[key.decode("utf-8", errors="replace")] = value.decode(
            "utf-8", errors="replace"
        )
    argv = [
        value.decode("utf-8", errors="replace")
        for value in cmdline_raw.split(b"\0")
        if value
    ]
    return {
        "start_time": stat_fields[21],
        "environ": environ,
        "argv": argv,
    }


class KimiHarnessAdapter(HarnessAdapter):
    """Fail-closed adapter for the detected Kimi Code CLI version."""

    harness_id = "kimi"
    executable_candidates = ("kimi", "kimi-code", "kimi-cli")

    def __init__(
        self,
        *,
        run_id: str,
        state_root: Path,
        stage_index: int = 0,
        executable: Path | str | None = None,
        search_path: str | None = None,
        base_environment: Mapping[str, str] | None = None,
        process_inspector: ProcessInspector | None = None,
        process_terminator: ProcessTerminator | None = None,
    ) -> None:
        validate_run_id(run_id)
        if not isinstance(stage_index, int) or isinstance(stage_index, bool) or stage_index < 0:
            raise ValueError("stage_index must be a non-negative integer")
        self.run_id = run_id
        self.stage_index = stage_index
        self.state_root = Path(state_root).resolve()
        if any(
            part.lower() in {".claude", ".codex", ".kimi-code"}
            for part in self.state_root.parts
        ):
            raise ValueError("state_root must not be user-level harness state")
        self.run_dir = self.state_root / f"run-kimi-{run_id}"
        self.evidence_dir = self.run_dir / f"evidence-kimi-{run_id}"
        self._explicit_executable = Path(executable) if executable is not None else None
        self._search_path = search_path
        self._base_environment = dict(
            os.environ if base_environment is None else base_environment
        )
        self._process_inspector = process_inspector or _safe_process_snapshot
        self._process_terminator = process_terminator or (
            lambda pid: os.kill(pid, signal.SIGTERM)
        )
        self._identity: HarnessIdentity | None = None
        self.identity_evidence: dict[str, str] = {}
        self.last_capability_matrix: dict[str, CapabilityEvidence] = {}
        self._path_lookup_evidence: str | None = None
        self._trusted_bindings: dict[Path, dict[str, Any]] = {}
        self._trusted_materializations: dict[Path, dict[str, Any]] = {}

    def _isolation_environment(self) -> dict[str, str]:
        home = self.run_dir / f"probe-home-kimi-{self.run_id}"
        kimi_home = self.run_dir / f"probe-config-kimi-{self.run_id}"
        cache = self.run_dir / f"probe-cache-kimi-{self.run_id}"
        config = self.run_dir / f"probe-xdg-config-kimi-{self.run_id}"
        data = self.run_dir / f"probe-xdg-data-kimi-{self.run_id}"
        temp = self.run_dir / f"probe-tmp-kimi-{self.run_id}"
        for directory in (home, kimi_home, cache, config, data, temp):
            directory.mkdir(parents=True, exist_ok=True)
        environment = {
            "PATH": self._base_environment.get("PATH", os.defpath),
            "HOME": str(home),
            "KIMI_CODE_HOME": str(kimi_home),
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
            "XDG_DATA_HOME": str(data),
            "TMPDIR": str(temp),
            "KIMI_DISABLE_TELEMETRY": "1",
            "NO_COLOR": "1",
            "CI": "1",
            "SAFETY_BENCH_HARNESS": "kimi",
            "SAFETY_BENCH_RUN_ID": self.run_id,
        }
        for key in ("LANG", "LC_ALL"):
            value = self._base_environment.get(key)
            if value:
                environment[key] = value
        return environment

    def _record_path_lookup(self, executable: Path | None, searches: list[dict[str, Any]]) -> str:
        path = self.evidence_dir / f"identity-path-kimi-{self.run_id}.json"
        _write_json(
            path,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "search_path": self._search_path
                if self._search_path is not None
                else self._base_environment.get("PATH", os.defpath),
                "searches": searches,
                "resolved_executable": str(executable) if executable else None,
            },
        )
        self._path_lookup_evidence = str(path)
        return str(path)

    def _find_executable(self) -> Path | None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        searches: list[dict[str, Any]] = []
        if self._explicit_executable is not None:
            candidate = self._explicit_executable.expanduser().absolute()
            accepted = candidate.is_file() and os.access(candidate, os.X_OK)
            searches.append(
                {"kind": "explicit", "candidate": str(candidate), "accepted": accepted}
            )
            self._record_path_lookup(candidate if accepted else None, searches)
            return candidate if accepted else None
        effective_search_path = (
            self._search_path
            if self._search_path is not None
            else self._base_environment.get("PATH", os.defpath)
        )
        for name in self.executable_candidates:
            located = shutil.which(name, path=effective_search_path)
            searches.append({"kind": "PATH", "candidate": name, "result": located})
            if located:
                candidate = Path(located).absolute()
                self._record_path_lookup(candidate, searches)
                return candidate
        self._record_path_lookup(None, searches)
        return None

    def _run_probe(self, executable: Path, args: Sequence[str], label: str) -> dict[str, Any]:
        command = [str(executable), *args]
        try:
            completed = subprocess.run(
                command,
                cwd=self.run_dir,
                env=self._isolation_environment(),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            record = {
                "command": command,
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            def decoded(value: str | bytes | None) -> str:
                if isinstance(value, bytes):
                    return value.decode("utf-8", errors="replace")
                return value or ""

            record = {
                "command": command,
                "exit_code": None,
                "stdout": decoded(exc.stdout),
                "stderr": decoded(exc.stderr),
                "timed_out": True,
            }
        except OSError as exc:
            record = {
                "command": command,
                "exit_code": None,
                "stdout": "",
                "stderr": f"{type(exc).__name__}: {exc}",
                "timed_out": False,
                "os_error": type(exc).__name__,
            }
        path = self.evidence_dir / f"identity-{label}-kimi-{self.run_id}.json"
        _write_json(
            path,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                **record,
            },
        )
        record["evidence_locator"] = str(path)
        return record

    def detect_identity(self) -> HarnessIdentity:
        if self._identity is not None:
            return self._identity
        executable = self._find_executable()
        path_locator = self._path_lookup_evidence or "kimi:path-lookup-unavailable"
        self.identity_evidence["path_lookup"] = path_locator
        if executable is None:
            raise KimiExecutableNotFound(
                f"Kimi executable not found; evidence: {path_locator}"
            )

        version = self._run_probe(executable, ("--version",), "version")
        top_help = self._run_probe(executable, ("--help",), "help")
        export_help = self._run_probe(executable, ("export", "--help"), "export-help")
        doctor_help = self._run_probe(executable, ("doctor", "--help"), "doctor-help")
        acp_help = self._run_probe(executable, ("acp", "--help"), "acp-help")
        server_help = self._run_probe(executable, ("server", "--help"), "server-help")
        server_run_help = self._run_probe(
            executable, ("server", "run", "--help"), "server-run-help"
        )
        for name, record in (
            ("version", version),
            ("help", top_help),
            ("export_help", export_help),
            ("doctor_help", doctor_help),
            ("acp_help", acp_help),
            ("server_help", server_help),
            ("server_run_help", server_run_help),
        ):
            self.identity_evidence[name] = record["evidence_locator"]
        if version["exit_code"] != 0 or version["timed_out"]:
            raise KimiProbeError(
                f"Kimi version probe failed; evidence: {version['evidence_locator']}"
            )
        if top_help["exit_code"] != 0 or top_help["timed_out"]:
            raise KimiProbeError(
                f"Kimi help probe failed; evidence: {top_help['evidence_locator']}"
            )

        help_text = f"{top_help['stdout']}\n{top_help['stderr']}"
        resolved_binary = executable.resolve()
        binary_sha256 = sha256_file(resolved_binary)
        flags: dict[str, bool | str | int | float] = {
            "executable_found": True,
            "headless_prompt": "--prompt" in help_text,
            "stream_json": "stream-json" in help_text,
            "skills_dir": "--skills-dir" in help_text,
            "session_flag": "--session" in help_text,
            "continue_flag": "--continue" in help_text,
            "auto_mode": "--auto" in help_text,
            "resolved_executable": str(resolved_binary),
            "binary_sha256": binary_sha256,
            "identity_evidence": version["evidence_locator"],
            "help_evidence": top_help["evidence_locator"],
        }
        self._identity = HarnessIdentity(
            harness_id="kimi",
            version=_parse_version(version["stdout"], version["stderr"]),
            executable=str(executable),
            feature_flags=flags,
        )
        identity_manifest = self.evidence_dir / f"identity-kimi-{self.run_id}.json"
        _write_json(
            identity_manifest,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "identity": {
                    "version": self._identity.version,
                    "executable": self._identity.executable,
                    "feature_flags": flags,
                },
                "evidence": self.identity_evidence,
            },
        )
        self.identity_evidence["manifest"] = str(identity_manifest)
        return self._identity

    def _identity_binary_is_current(self, identity: HarnessIdentity) -> bool:
        """Recheck the probed executable target and bytes immediately before use."""

        if self._identity is None or identity != self._identity:
            return False
        expected_executable = identity.feature_flags.get("resolved_executable")
        expected_binary_sha256 = identity.feature_flags.get("binary_sha256")
        if not isinstance(expected_executable, str) or not isinstance(
            expected_binary_sha256, str
        ):
            return False
        try:
            resolved_executable = Path(identity.executable).resolve(strict=True)
            return (
                resolved_executable == Path(expected_executable)
                and resolved_executable.is_file()
                and os.access(resolved_executable, os.X_OK)
                and sha256_file(resolved_executable) == expected_binary_sha256
            )
        except (FileNotFoundError, OSError, RuntimeError):
            return False

    def probe_capabilities(
        self, required_capabilities: Sequence[str]
    ) -> CapabilityProbe:
        required = tuple(required_capabilities)
        if not required:
            raise ValueError("required_capabilities must not be empty")
        try:
            identity = self.detect_identity()
            found = True
            flags = identity.feature_flags
            detected_version: str | None = identity.version
            detected_binary_sha256 = identity.feature_flags.get("binary_sha256")
            if not isinstance(detected_binary_sha256, str):
                detected_binary_sha256 = None
        except KimiExecutableNotFound:
            found = False
            flags = {}
            detected_version = None
            detected_binary_sha256 = None
        except (KimiProbeError, OSError):
            # The executable exists, but its version/help identity is not
            # trustworthy. Native surfaces stay UNVALIDATED; adapter-owned
            # path/process construction can still be described separately.
            found = True
            flags = {}
            detected_version = None
            detected_binary_sha256 = None
        path_evidence = self._path_lookup_evidence or "kimi:path-lookup-unavailable"
        isolation_path = self.evidence_dir / f"isolation-kimi-{self.run_id}.json"
        isolation_env = self._isolation_environment()
        _write_json(
            isolation_path,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "cwd_policy": "materialized stage workspace",
                "project_root_boundary": (
                    "materializer creates a run-local .git sentinel so Kimi does not "
                    "inherit parent AGENTS.md, .mcp.json, or project state"
                ),
                "environment_roots": {
                    key: value
                    for key, value in isolation_env.items()
                    if key in {
                        "HOME",
                        "KIMI_CODE_HOME",
                        "XDG_CACHE_HOME",
                        "XDG_CONFIG_HOME",
                        "XDG_DATA_HOME",
                        "TMPDIR",
                    }
                },
                "note": "Configuration proves adapter intent; tests prove construction. "
                "It is not a native runtime smoke.",
            },
        )
        matrix = default_capability_matrix(
            executable_found=found,
            feature_flags=flags,
            path_lookup_evidence=path_evidence,
            help_evidence=self.identity_evidence.get("help"),
            isolation_evidence=str(isolation_path),
            detected_version=detected_version,
            detected_binary_sha256=detected_binary_sha256,
        )
        self.last_capability_matrix = matrix
        status, evidence, reasons = aggregate_required_capabilities(required, matrix)
        matrix_path = self.evidence_dir / f"capabilities-kimi-{self.run_id}.json"
        _write_json(
            matrix_path,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "required_capabilities": list(required),
                "aggregate_status": status,
                "capabilities": {
                    key: value.as_dict() for key, value in sorted(matrix.items())
                },
            },
        )
        evidence = tuple(dict.fromkeys((*evidence, str(matrix_path))))
        return CapabilityProbe(
            status=status,
            required_capabilities=required,
            evidence=evidence,
            reasons=reasons,
        )

    def materialize_binding(
        self,
        *,
        case_dir: Path,
        binding_document: Mapping[str, Any],
        run_dir: Path,
    ) -> MaterializedBinding:
        if Path(run_dir).resolve() != self.run_dir.resolve():
            raise KimiMaterializationError(
                f"run_dir must equal adapter-owned path {self.run_dir}"
            )
        from ...bindings.kimi import load_kimi_common_bindings

        reviewed = load_kimi_common_bindings(repo_root=_REPO_ROOT).get(
            binding_document.get("case_id")
        )
        if reviewed is None or binding_document_sha256(
            reviewed
        ) != binding_document_sha256(binding_document):
            raise KimiMaterializationError(
                "formal Kimi materialization requires an exact reviewed common binding"
            )
        expected_case_dir = _reviewed_case_dir(reviewed["case_id"])
        try:
            supplied_case_dir = Path(case_dir).resolve(strict=True)
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            raise KimiMaterializationError(
                "supplied canonical case_dir is unavailable"
            ) from exc
        if supplied_case_dir != expected_case_dir:
            raise KimiMaterializationError(
                "formal Kimi materialization requires the inventory-reviewed "
                "canonical case_dir"
            )
        materialized = materialize_kimi_binding(
            run_id=self.run_id,
            case_dir=expected_case_dir,
            binding_document=reviewed,
            run_dir=self.run_dir,
        )
        # Retain immutable JSON snapshots outside the materialized manifest.
        # A re-signed run-local manifest is never allowed to become its own
        # capability, event, transition, or artifact trust root.
        self._trusted_bindings[materialized.manifest_path.resolve()] = json.loads(
            json.dumps(reviewed, ensure_ascii=False)
        )
        manifest_snapshot = load_materialization_manifest(materialized)
        self._trusted_materializations[
            materialized.manifest_path.resolve()
        ] = json.loads(
            json.dumps(manifest_snapshot, ensure_ascii=False)
        )
        return materialized

    def _trusted_binding(self, materialized: MaterializedBinding) -> Mapping[str, Any]:
        cached = self._trusted_bindings.get(materialized.manifest_path.resolve())
        if cached is not None:
            return cached
        from ...bindings.kimi import load_kimi_common_bindings

        reviewed = load_kimi_common_bindings(repo_root=_REPO_ROOT)
        binding = reviewed.get(materialized.case_id)
        if binding is None:
            raise KimiMaterializationError(
                "no independently trusted Kimi binding is available for this run"
            )
        return binding

    def _load_trusted_manifest(
        self, materialized: MaterializedBinding
    ) -> tuple[dict[str, Any], Mapping[str, Any]]:
        manifest = load_materialization_manifest(materialized)
        binding = self._trusted_binding(materialized)
        validate_manifest_against_binding(manifest, binding)
        snapshot = self._trusted_materializations.get(
            materialized.manifest_path.resolve()
        )
        if snapshot is None:
            raise KimiMaterializationError(
                "trusted materialization snapshot is unavailable; refuse to resume "
                "a formal Kimi lifecycle from run-local state alone"
            )
        if manifest != snapshot:
            raise KimiMaterializationError(
                "materialization manifest drifted from the adapter-owned snapshot"
            )
        return manifest, binding

    def _stage(self, manifest: Mapping[str, Any]) -> Mapping[str, Any]:
        for stage in manifest["stages"]:
            if stage["index"] == self.stage_index:
                return stage
        raise KimiMaterializationError(f"unknown stage index {self.stage_index}")

    def build_launch_spec(
        self,
        *,
        materialized: MaterializedBinding,
        prompt: str,
        timeout_seconds: int,
    ) -> LaunchSpec:
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("prompt must be non-empty")
        manifest, _ = self._load_trusted_manifest(materialized)
        probe = self.probe_capabilities(manifest["required_capabilities"])
        if probe.status != "SUPPORTED":
            raise KimiPreflightError(
                f"Kimi scored trial blocked ({probe.status}); outcome=NOT_RUN; "
                + "; ".join(probe.reasons)
            )
        identity = self.detect_identity()
        if not self._identity_binary_is_current(identity):
            raise KimiPreflightError(
                "Kimi executable identity drifted after the recorded probe; "
                "outcome=NOT_RUN"
            )
        missing_launch_flags = [
            flag
            for flag in ("headless_prompt", "stream_json", "skills_dir")
            if identity.feature_flags.get(flag) is not True
        ]
        if missing_launch_flags:
            raise KimiPreflightError(
                "detected Kimi version lacks required non-interactive launch flags: "
                + ", ".join(missing_launch_flags)
            )
        stage = self._stage(manifest)
        validate_prelaunch_artifacts(
            manifest,
            stage_index=self.stage_index,
            trusted_manifest_document=self._trusted_materializations[
                materialized.manifest_path.resolve()
            ],
        )
        workspace = Path(manifest["materialized"]["workspace_dir"])
        if stage.get("prompt_path") is not None:
            expected_prompt = Path(stage["prompt_path"]).read_text(encoding="utf-8")
            if prompt != expected_prompt:
                raise KimiPreflightError(
                    "launch prompt does not match the hashed Kimi stage materialization"
                )
        environment = {
            "PATH": self._base_environment.get("PATH", os.defpath),
            "HOME": stage["home_dir"],
            "KIMI_CODE_HOME": stage["kimi_home"],
            "XDG_CACHE_HOME": stage["cache_dir"],
            "XDG_CONFIG_HOME": str(Path(stage["home_dir"]) / f"xdg-config-kimi-{self.run_id}"),
            "XDG_DATA_HOME": str(Path(stage["home_dir"]) / f"xdg-data-kimi-{self.run_id}"),
            "TMPDIR": stage["temp_dir"],
            "KIMI_DISABLE_TELEMETRY": "1",
            "NO_COLOR": "1",
            "CI": "1",
            "SAFETY_BENCH_HARNESS": "kimi",
            "SAFETY_BENCH_RUN_ID": self.run_id,
        }
        for key in ("LANG", "LC_ALL"):
            value = self._base_environment.get(key)
            if value:
                environment[key] = value
        if any(_SENSITIVE_ENV_RE.search(key) for key in environment):
            raise KimiPreflightError("launch environment contains a credential-like key")
        if any(key.startswith("CLAUDE") or key.startswith("CODEX") for key in environment):
            raise KimiPreflightError("launch environment contains another harness state key")
        for path_key in (
            "HOME",
            "KIMI_CODE_HOME",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "TMPDIR",
        ):
            path = Path(environment[path_key]).resolve()
            try:
                path.relative_to(self.run_dir.resolve())
            except ValueError as exc:
                raise KimiPreflightError(f"{path_key} escapes the Kimi run") from exc
            path.mkdir(parents=True, exist_ok=True)

        argv = (
            identity.executable,
            "--prompt",
            prompt,
            "--output-format",
            "stream-json",
            "--skills-dir",
            stage["skills_dir"],
        )
        trace_path = Path(stage["trace_path"])
        launch_evidence = self.evidence_dir / (
            f"launch-kimi-{self.run_id}-stage-{self.stage_index:03d}.json"
        )
        _write_json(
            launch_evidence,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "stage": {"name": stage["name"], "index": stage["index"]},
                "argv": [
                    identity.executable,
                    "--prompt",
                    "<sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest() + ">",
                    "--output-format",
                    "stream-json",
                    "--skills-dir",
                    stage["skills_dir"],
                ],
                "cwd": str(workspace),
                "env_keys": sorted(environment),
                "trace_path": str(trace_path),
                "timeout_seconds": timeout_seconds,
                "preflight_evidence": list(probe.evidence),
            },
        )
        return LaunchSpec(
            argv=argv,
            cwd=workspace,
            env=environment,
            trace_path=trace_path,
            timeout_seconds=timeout_seconds,
        )

    def normalize_trace(
        self,
        *,
        identity: HarnessIdentity,
        materialized: MaterializedBinding,
        raw_trace_path: Path,
    ) -> Iterable[Mapping[str, Any]]:
        _, binding = self._load_trusted_manifest(materialized)
        detected_identity = self.detect_identity()
        if identity != detected_identity:
            raise KimiTraceNormalizationError(
                "trace identity does not match the adapter-detected Kimi identity"
            )
        if not self._identity_binary_is_current(detected_identity):
            raise KimiTraceNormalizationError(
                "Kimi executable identity drifted after the recorded probe"
            )
        return normalize_kimi_trace(
            identity=detected_identity,
            materialized=materialized,
            raw_trace_path=Path(raw_trace_path),
            stage_index=self.stage_index,
            trusted_binding_document=binding,
            trusted_manifest_document=self._trusted_materializations[
                materialized.manifest_path.resolve()
            ],
        )

    def cleanup(self, *, materialized: MaterializedBinding) -> None:
        if materialized.run_dir.resolve() != self.run_dir.resolve():
            raise KimiMaterializationError("cleanup materialization is not adapter-owned")
        manifest, _ = self._load_trusted_manifest(materialized)
        if manifest.get("run_id") != self.run_id:
            raise KimiMaterializationError("cleanup run_id does not match adapter")
        terminated: list[int] = []
        skipped: list[dict[str, Any]] = []
        seen_pids: set[int] = set()
        for stage in manifest["stages"]:
            pid_path = Path(stage["pid_record"])
            if not pid_path.is_file():
                continue
            pid_document = json.loads(pid_path.read_text(encoding="utf-8"))
            records = pid_document.get("processes", [])
            if not isinstance(records, list):
                raise KimiMaterializationError("PID record processes must be an array")
            for raw in records:
                if not isinstance(raw, Mapping):
                    skipped.append({"reason": "malformed_pid_record"})
                    continue
                pid = raw.get("pid")
                if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
                    skipped.append({"pid": pid, "reason": "invalid_pid"})
                    continue
                if pid in seen_pids:
                    skipped.append({"pid": pid, "reason": "duplicate_pid_record"})
                    continue
                seen_pids.add(pid)
                if raw.get("run_id") != self.run_id or raw.get("harness_id") != "kimi":
                    skipped.append({"pid": pid, "reason": "record_owner_mismatch"})
                    continue
                observed = self._process_inspector(pid)
                if observed is None:
                    skipped.append({"pid": pid, "reason": "process_not_observable"})
                    continue
                environment = observed.get("environ", {})
                argv = observed.get("argv", [])
                if observed.get("start_time") != str(raw.get("start_time")):
                    skipped.append({"pid": pid, "reason": "start_time_mismatch"})
                    continue
                if not isinstance(environment, Mapping) or (
                    environment.get("SAFETY_BENCH_HARNESS") != "kimi"
                    or environment.get("SAFETY_BENCH_RUN_ID") != self.run_id
                ):
                    skipped.append({"pid": pid, "reason": "environment_owner_mismatch"})
                    continue
                if not isinstance(argv, list) or not any(
                    self.run_id in str(argument) for argument in argv
                ):
                    skipped.append({"pid": pid, "reason": "argv_owner_mismatch"})
                    continue
                self._process_terminator(pid)
                terminated.append(pid)

        removed: list[str] = []
        for raw_path in manifest.get("cleanup_paths", []):
            path = Path(raw_path)
            if path.is_symlink():
                raise KimiMaterializationError("cleanup refuses symlink resources")
            resolved = path.resolve()
            try:
                resolved.relative_to(self.run_dir.resolve())
            except ValueError as exc:
                raise KimiMaterializationError("cleanup path escapes current run") from exc
            if resolved.is_dir():
                shutil.rmtree(resolved)
                removed.append(str(resolved))
            elif resolved.exists():
                resolved.unlink()
                removed.append(str(resolved))

        cleanup_report = self.evidence_dir / f"cleanup-kimi-{self.run_id}.json"
        _write_json(
            cleanup_report,
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "stage_indexes": [stage["index"] for stage in manifest["stages"]],
                "terminated_pids": terminated,
                "skipped_pids": skipped,
                "removed_paths": removed,
                "preserved": [
                    "raw_trace",
                    "event_ir",
                    "result",
                    "materialization_manifest",
                    "provenance",
                ],
            },
        )
