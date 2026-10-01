"""Run-local lifecycle primitives for the Kimi benchmark runner.

This module deliberately does not know how to start Kimi Code.  It owns the
parts which must remain true regardless of the eventual process executor:
run-scoped paths, dynamic loopback ports, and PID ownership checks.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import tempfile
from typing import Any, Callable, Mapping


_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")
_CASE_ATTEMPT_COMPONENT_RE = re.compile(r"^c-([0-9a-f]{16})-a([0-9]{3,})$")

# Linux reserves 108 bytes for ``sockaddr_un.sun_path``, including the
# terminating NUL.  Host-side broker paths must therefore be at most 107
# encoded bytes.  These names are intentionally terse: the full path still
# carries ``kimi``, the exact run id, a case identity digest, and the attempt.
LINUX_AF_UNIX_PATH_LIMIT = 108
CASE_IDENTITY_DIGEST_HEX_LENGTH = 16
SERVICE_IDENTITY_DIGEST_HEX_LENGTH = 16
PROVIDER_SERVICE_PREFIX = "p"
CALLBACK_SERVICE_PREFIX = "b"
PROVIDER_SOCKET_BASENAME = "p.sock"
CALLBACK_SOCKET_BASENAME = "c.sock"


class KimiLifecycleError(RuntimeError):
    """A run-local ownership or lifecycle invariant was violated."""


def validate_bench_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError(
            "run_id must be 1-80 safe ASCII characters and start with an "
            "alphanumeric character"
        )
    return run_id


def safe_component(value: str, *, fallback: str = "case") -> str:
    """Return a bounded path component without accepting traversal syntax."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("path component source must be a non-empty string")
    component = _SAFE_COMPONENT_RE.sub("-", value.strip()).strip(".-_")
    if not component:
        component = fallback
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{component[:80]}-{digest}"


def case_identity_digest(case_id: str) -> str:
    """Return the fixed-width run-path identity for one canonical case id."""

    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    return hashlib.sha256(case_id.encode("utf-8")).hexdigest()[
        :CASE_IDENTITY_DIGEST_HEX_LENGTH
    ]


def case_attempt_component(case_id: str, *, attempt: int) -> str:
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    return f"c-{case_identity_digest(case_id)}-a{attempt:03d}"


def parse_case_attempt_component(value: str) -> tuple[str, int]:
    """Parse a path identity without treating a display label as authority."""

    match = _CASE_ATTEMPT_COMPONENT_RE.fullmatch(value)
    if match is None:
        raise KimiLifecycleError(
            "case root must be c-<case-sha256-prefix>-a<attempt>"
        )
    attempt = int(match.group(2))
    if attempt < 1:
        raise KimiLifecycleError("case root attempt must be positive")
    return match.group(1), attempt


def service_identity_digest(run_id: str, case_id: str, trial_id: str) -> str:
    """Bind a short service directory to the full run/case/trial identity."""

    validate_bench_run_id(run_id)
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case_id must be a non-empty string")
    if not isinstance(trial_id, str) or not trial_id:
        raise ValueError("trial_id must be a non-empty string")
    return hashlib.sha256(
        f"{run_id}\0{case_id}\0{trial_id}".encode("utf-8")
    ).hexdigest()[:SERVICE_IDENTITY_DIGEST_HEX_LENGTH]


def provider_service_component(run_id: str, case_id: str, trial_id: str) -> str:
    return f"{PROVIDER_SERVICE_PREFIX}-{service_identity_digest(run_id, case_id, trial_id)}"


def callback_service_component(run_id: str, case_id: str, trial_id: str) -> str:
    return f"{CALLBACK_SERVICE_PREFIX}-{service_identity_digest(run_id, case_id, trial_id)}"


def encoded_unix_socket_path_length(path: Path | str) -> int:
    return len(os.fsencode(Path(path)))


def validate_linux_unix_socket_path(path: Path | str, *, label: str) -> Path:
    """Fail before bind when a pathname cannot fit Linux ``sockaddr_un``."""

    candidate = Path(path).absolute()
    length = encoded_unix_socket_path_length(candidate)
    if length >= LINUX_AF_UNIX_PATH_LIMIT:
        raise KimiLifecycleError(
            f"{label} is {length} bytes and exceeds the Linux AF_UNIX "
            f"pathname limit ({LINUX_AF_UNIX_PATH_LIMIT - 1} bytes); choose a "
            "shorter --result-root or --run-id"
        )
    return candidate


def production_service_paths(
    case_root: Path | str,
    *,
    run_id: str,
    case_id: str,
    trial_id: str,
) -> tuple[Path, Path]:
    """Return and validate both run-local service sockets without creating them."""

    root = Path(case_root).absolute()
    case_digest, _attempt = parse_case_attempt_component(root.name)
    if case_digest != case_identity_digest(case_id):
        raise KimiLifecycleError("case root digest does not match case_id")
    if root.parent.name != f"kimi-{validate_bench_run_id(run_id)}":
        raise KimiLifecycleError("case root parent lacks exact kimi/run_id identity")
    provider = (
        root / provider_service_component(run_id, case_id, trial_id) / PROVIDER_SOCKET_BASENAME
    )
    callback = (
        root / callback_service_component(run_id, case_id, trial_id) / CALLBACK_SOCKET_BASENAME
    )
    validate_linux_unix_socket_path(provider, label="Kimi provider socket path")
    validate_linux_unix_socket_path(callback, label="Kimi callback socket path")
    return provider, callback


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class CaseRunLayout:
    run_id: str
    case_id: str
    root: Path
    workspace: Path
    config: Path
    trace: Path
    result: Path
    session: Path
    cache: Path
    artifact: Path
    pid_record: Path
    case_digest: str = ""
    attempt: int = 1

    def owned_paths(self) -> tuple[Path, ...]:
        return (
            self.root,
            self.workspace,
            self.config,
            self.trace,
            self.result,
            self.session,
            self.cache,
            self.artifact,
            self.pid_record,
        )


@dataclass(frozen=True)
class RunLayout:
    """All writable paths for one Kimi run, outside canonical ``runs/``."""

    repo_root: Path
    result_root: Path
    run_id: str

    def __post_init__(self) -> None:
        validate_bench_run_id(self.run_id)
        repo_root = Path(self.repo_root).resolve()
        result_root = Path(self.result_root).resolve()
        if _is_relative_to(result_root, repo_root):
            raise KimiLifecycleError(
                "Kimi result_root must be external to the repository"
            )
        if any(
            part.casefold() in {".claude", ".codex", ".kimi-code"}
            for part in result_root.parts
        ):
            raise KimiLifecycleError(
                "Kimi result_root must not use any harness user-state path"
            )
        object.__setattr__(self, "repo_root", repo_root)
        object.__setattr__(self, "result_root", result_root)

    @property
    def run_dir(self) -> Path:
        return self.result_root / f"kimi-{self.run_id}"

    @property
    def state_path(self) -> Path:
        return self.run_dir / f"state-kimi-{self.run_id}.json"

    @property
    def plan_path(self) -> Path:
        return self.run_dir / f"plan-kimi-{self.run_id}.json"

    @property
    def lifecycle_log_path(self) -> Path:
        return self.run_dir / f"lifecycle-kimi-{self.run_id}.json"

    def for_case(self, case_id: str, *, attempt: int = 1) -> CaseRunLayout:
        component = case_attempt_component(case_id, attempt=attempt)
        digest = case_identity_digest(case_id)
        case_root = self.run_dir / component
        return CaseRunLayout(
            run_id=self.run_id,
            case_id=case_id,
            root=case_root,
            workspace=case_root / "w",
            config=case_root / "cfg",
            trace=case_root / "tr",
            result=case_root / "r",
            session=case_root / "s",
            cache=case_root / "k",
            artifact=case_root / "a",
            pid_record=case_root / "pids.json",
            case_digest=digest,
            attempt=attempt,
        )

    def production_service_paths(
        self, case: CaseRunLayout, *, trial_id: str
    ) -> tuple[Path, Path]:
        if case.run_id != self.run_id:
            raise KimiLifecycleError("case layout run_id mismatch")
        if case.root.parent != self.run_dir:
            raise KimiLifecycleError("case layout is not a direct child of this run")
        return production_service_paths(
            case.root,
            run_id=self.run_id,
            case_id=case.case_id,
            trial_id=trial_id,
        )

    def assert_owned(self, path: Path) -> Path:
        candidate = Path(path).resolve()
        if not _is_relative_to(candidate, self.run_dir.resolve()):
            raise KimiLifecycleError(f"path escapes Kimi run {self.run_id}: {path}")
        return candidate

    def initialize(self) -> None:
        if self.result_root.is_symlink() or self.run_dir.is_symlink():
            raise KimiLifecycleError("Kimi result/run directory must not be a symlink")
        self.result_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.result_root.resolve(strict=True) != self.result_root:
            raise KimiLifecycleError("Kimi result_root has a symlink component")
        self.run_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        resolved = self.run_dir.resolve(strict=True)
        if not _is_relative_to(resolved, self.result_root.resolve(strict=True)):
            raise KimiLifecycleError("Kimi run_dir escapes the external result root")

    def initialize_case(self, case: CaseRunLayout) -> None:
        """Create an empty per-attempt leaf for the injected materializer."""

        self.initialize()
        if case.run_id != self.run_id:
            raise KimiLifecycleError("case layout run_id mismatch")
        expected_component = case_attempt_component(case.case_id, attempt=case.attempt)
        if (
            case.root.parent != self.run_dir
            or case.root.name != expected_component
            or case.case_digest != case_identity_digest(case.case_id)
        ):
            raise KimiLifecycleError("case layout identity does not match run/case/attempt")
        if case.root.is_symlink():
            raise KimiLifecycleError(
                f"Kimi case resource must not be a symlink: {case.root}"
            )
        case.root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(case.root, 0o700)
        self.assert_owned(case.root)
        if any(case.root.iterdir()):
            raise KimiLifecycleError(
                "per-attempt Kimi materialization leaf must start empty"
            )


def atomic_write_json(path: Path, document: Mapping[str, Any], *, run_id: str) -> None:
    """Atomically replace one run-local JSON file without a shared temp name."""

    validate_bench_run_id(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f"tmp-kimi-{run_id}-",
        suffix=".json",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class LoopbackPortLease:
    """Reserve an OS-assigned loopback port until an executor claims it."""

    def __init__(self) -> None:
        self._socket: socket.socket | None = None
        self._port: int | None = None

    def __enter__(self) -> "LoopbackPortLease":
        if self._socket is not None:
            raise KimiLifecycleError("loopback port lease is already active")
        lease = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lease.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        lease.bind(("127.0.0.1", 0))
        lease.listen(1)
        self._socket = lease
        self._port = int(lease.getsockname()[1])
        return self

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        if self._port is None:
            raise KimiLifecycleError("loopback port lease is not active")
        return self._port

    @property
    def active(self) -> bool:
        return self._socket is not None

    def claim(self) -> int:
        """Release the reservation immediately before a run-owned bind."""

        port = self.port
        self.close()
        return port

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True)
class ProcessSnapshot:
    start_time: str
    environment: Mapping[str, str]
    argv: tuple[str, ...]


ProcessInspector = Callable[[int], ProcessSnapshot | None]
ProcessTerminator = Callable[[int], None]


def inspect_process(pid: int) -> ProcessSnapshot | None:
    """Inspect a Linux process without relying on its executable name."""

    process_dir = Path("/proc") / str(pid)
    try:
        raw_stat = (process_dir / "stat").read_text(encoding="utf-8")
        raw_environment = (process_dir / "environ").read_bytes()
        raw_argv = (process_dir / "cmdline").read_bytes()
    except (FileNotFoundError, OSError, PermissionError):
        return None
    # The parenthesized comm field may contain spaces or ``)`` characters;
    # split after its final closing parenthesis.  The remaining field 20 is
    # Linux procfs field 22 (process start time).
    closing = raw_stat.rfind(")")
    if closing < 0:
        return None
    stat_tail = raw_stat[closing + 1 :].split()
    if len(stat_tail) < 20:
        return None
    environment: dict[str, str] = {}
    for item in raw_environment.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        environment[key.decode("utf-8", errors="replace")] = value.decode(
            "utf-8", errors="replace"
        )
    argv = tuple(
        value.decode("utf-8", errors="replace")
        for value in raw_argv.split(b"\0")
        if value
    )
    return ProcessSnapshot(
        start_time=stat_tail[19], environment=environment, argv=argv
    )


class OwnedProcessRegistry:
    """Persist and clean up only PIDs proven to belong to this Kimi run."""

    def __init__(
        self,
        *,
        run_id: str,
        record_path: Path,
        inspector: ProcessInspector = inspect_process,
        terminator: ProcessTerminator | None = None,
    ) -> None:
        self.run_id = validate_bench_run_id(run_id)
        self.record_path = Path(record_path)
        record_text = str(self.record_path)
        if "kimi" not in record_text or self.run_id not in record_text:
            raise KimiLifecycleError(
                "PID record path must include both kimi and the current run_id"
            )
        self._inspector = inspector
        self._terminator = terminator or (lambda pid: os.kill(pid, signal.SIGTERM))
        self._records: list[dict[str, Any]] = []

    def register(self, pid: int, *, role: str) -> None:
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
            raise KimiLifecycleError("refusing invalid process id")
        if not isinstance(role, str) or not role.strip():
            raise KimiLifecycleError("process role must be non-empty")
        snapshot = self._inspector(pid)
        if snapshot is None:
            raise KimiLifecycleError("cannot establish process ownership")
        if (
            snapshot.environment.get("SAFETY_BENCH_HARNESS") != "kimi"
            or snapshot.environment.get("SAFETY_BENCH_RUN_ID") != self.run_id
        ):
            raise KimiLifecycleError("process environment does not prove Kimi run ownership")
        if any(record["pid"] == pid for record in self._records):
            raise KimiLifecycleError("process id is already registered")
        self._records.append(
            {
                "harness_id": "kimi",
                "run_id": self.run_id,
                "pid": pid,
                "role": role,
                "start_time": snapshot.start_time,
            }
        )
        self._write()

    def _write(self) -> None:
        atomic_write_json(
            self.record_path,
            {
                "schema_name": "safety_bench_kimi_pid_record",
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": self.run_id,
                "processes": list(self._records),
            },
            run_id=self.run_id,
        )

    def cleanup(self) -> dict[str, list[Any]]:
        terminated: list[int] = []
        skipped: list[dict[str, Any]] = []
        for record in self._records:
            pid = int(record["pid"])
            try:
                snapshot = self._inspector(pid)
            except Exception as exc:
                skipped.append(
                    {
                        "pid": pid,
                        "reason": "inspection_failed",
                        "error": type(exc).__name__,
                    }
                )
                continue
            if snapshot is None:
                skipped.append({"pid": pid, "reason": "not_observable"})
                continue
            if snapshot.start_time != record["start_time"]:
                skipped.append({"pid": pid, "reason": "start_time_mismatch"})
                continue
            if (
                snapshot.environment.get("SAFETY_BENCH_HARNESS") != "kimi"
                or snapshot.environment.get("SAFETY_BENCH_RUN_ID") != self.run_id
            ):
                skipped.append({"pid": pid, "reason": "owner_mismatch"})
                continue
            try:
                self._terminator(pid)
            except Exception as exc:
                skipped.append(
                    {
                        "pid": pid,
                        "reason": "termination_failed",
                        "error": type(exc).__name__,
                    }
                )
                continue
            terminated.append(pid)
        return {"terminated": terminated, "skipped": skipped}
