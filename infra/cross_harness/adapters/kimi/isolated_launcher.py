"""Linux bubblewrap launcher for credential-separated Kimi stages.

The launcher mounts one Kimi materialized run plus read-only system runtime
paths into a fresh mount/pid/net/ipc/uts/cgroup namespace.  The isolated Kimi
process can reach only an in-namespace loopback relay.  That relay authenticates
to an injected, run-scoped Unix-socket broker; this module neither reads nor
implements an upstream credential.

The relay nonce is broker-owned.  It reaches bubblewrap as a sealed memfd and
is copied by ``bwrap --file`` to a transient sandbox path.  The launcher never
reads the memfd, and the sandbox helper removes the copied file before starting
Kimi.  No nonce or upstream credential is placed in argv, an environment, or a
persistent evidence file.
"""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from .executor import (
    ATTESTATION_SCHEMA_NAME,
    ATTESTATION_SCHEMA_VERSION,
    StageMount,
    StageLaunchRequest,
)
from .callback_collector import CALLBACK_SOCKET_BASENAME, callback_root_name
from .lifecycle import (
    case_identity_digest,
    parse_case_attempt_component,
    validate_bench_run_id,
)
from .materializer import runtime_tree_sha256, sha256_file, tree_sha256
from .provider_broker import BROKER_SOCKET_BASENAME, broker_root_name
from .sandbox_entry import broker_ack_proof


BROKER_ATTESTATION_SCHEMA_NAME = "safety_bench_kimi_external_broker_attestation"
BROKER_ATTESTATION_SCHEMA_VERSION = 1
ISOLATION_EVIDENCE_SCHEMA_NAME = "safety_bench_kimi_bwrap_verified_isolation"
ISOLATION_EVIDENCE_SCHEMA_VERSION = 1
HANDSHAKE_SCHEMA_NAME = "safety_bench_kimi_relay_handshake"
CALLBACK_ATTESTATION_SCHEMA_NAME = "safety_bench_kimi_callback_collector_attestation"
CALLBACK_ATTESTATION_SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_LEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_SENSITIVE_ENV_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|credential|bearer|auth)", re.IGNORECASE
)
_OTHER_HARNESS_ENV_RE = re.compile(r"^(?:CLAUDE|CODEX|GEMINI|HERMES|OPENCLAW)")
_REQUIRED_NAMESPACES = ("mnt", "pid", "net", "ipc", "uts", "cgroup")
_ENV_PATH_KEYS = {
    "HOME",
    "KIMI_CODE_HOME",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "TMPDIR",
}
_STAGE_ENV_KEYS = _ENV_PATH_KEYS | {
    "PATH",
    "KIMI_DISABLE_TELEMETRY",
    "NO_COLOR",
    "CI",
    "SAFETY_BENCH_HARNESS",
    "SAFETY_BENCH_RUN_ID",
}
_SELF_TEST_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/run/kimi/empty-home",
    "TMPDIR": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONSAFEPATH": "1",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "KIMI_DISABLE_TELEMETRY": "1",
    "NO_COLOR": "1",
    "CI": "1",
    "SAFETY_BENCH_HARNESS": "kimi",
}
_DEFAULT_FORBIDDEN_PATHS = (
    Path("/root/.kimi"),
    Path("/root/.kimi-code"),
    Path("/root/.claude"),
    Path("/root/.codex"),
    Path("/root/.config/kimi"),
    Path("/root/.local/share/kimi"),
)
_WRITE_MOUNT_KINDS = frozenset(
    {
        "workspace",
        "current_stage_runtime",
        "shared_native_session",
        "shared_artifact_carrier",
    }
)
_READ_ONLY_MOUNT_KINDS = frozenset(
    {
        "current_stage_assets",
        "run_local_mcp_proxy",
        "mcp_child_file",
        "reviewed_stage_file",
    }
)
_OTHER_HARNESS_PATH_PARTS = frozenset(
    {".claude", ".claude-plugin", ".codex", "claude", "codex"}
)


class KimiBubblewrapLauncherError(RuntimeError):
    """The launcher could not uphold its fail-closed isolation contract."""


class KimiBubblewrapUnavailable(KimiBubblewrapLauncherError):
    """The installed kernel/bubblewrap combination cannot enforce the contract."""


@dataclass(frozen=True)
class BrokerNonceFD:
    """Opaque broker lease; the descriptor contains a sealed 32-byte nonce."""

    fd: int
    lease_id: str


class RunScopedRelayBroker(Protocol):
    """Narrow injected interface; no upstream credential crosses this boundary."""

    run_id: str
    case_id: str
    trial_id: str
    ownership_root: Path
    root: Path
    socket_path: Path
    attestation_path: Path

    def issue_nonce_fd(
        self, *, run_id: str, stage_index: int, purpose: str
    ) -> BrokerNonceFD: ...

    def release_nonce(
        self,
        lease_id: str,
        *,
        run_id: str,
        stage_index: int,
        purpose: str,
    ) -> None: ...


class RunScopedCallbackSink(Protocol):
    """Run/case/trial-owned callback sink using its own one-use nonce."""

    run_id: str
    case_id: str
    trial_id: str
    ownership_root: Path
    root: Path
    socket_path: Path
    attestation_path: Path
    evidence_path: Path
    evidence_manifest_path: Path
    process_executable_path: Path
    process_executable_sha256: str
    implementation_path: Path
    implementation_sha256: str

    def issue_nonce_fd(
        self, *, run_id: str, stage_index: int, purpose: str
    ) -> BrokerNonceFD: ...

    def release_nonce(
        self,
        lease_id: str,
        *,
        run_id: str,
        stage_index: int,
        purpose: str,
    ) -> None: ...

    def wait_for_stage_manifest(
        self, stage_index: int, *, timeout: float = 5.0
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class _RunContext:
    run_id: str
    run_root: Path
    launcher_dir: Path
    helper_copy: Path
    attestation_path: Path
    attestation_sha256: str
    broker_document: Mapping[str, Any]
    broker_attestation_sha256: str
    broker_attestation_source: Path
    callback_document: Mapping[str, Any]
    callback_attestation_sha256: str
    callback_attestation_source: Path


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _payload_sha256(document: Mapping[str, Any], field: str) -> str:
    return _canonical_sha256({key: value for key, value in document.items() if key != field})


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise KimiBubblewrapLauncherError(f"{label} must be a lowercase SHA-256")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise KimiBubblewrapLauncherError(f"{label} must be a non-empty safe string")
    return value


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiBubblewrapLauncherError(f"{label} must be an object")
    return value


def _reject_symlink_chain(path: Path, *, stop: Path, label: str) -> None:
    candidate = path.absolute()
    boundary = stop.absolute()
    while True:
        if candidate.is_symlink():
            raise KimiBubblewrapLauncherError(f"{label} has a symlink component")
        if candidate == boundary:
            return
        if candidate.parent == candidate or not _is_relative_to(candidate, boundary):
            raise KimiBubblewrapLauncherError(f"{label} escapes its Kimi run")
        candidate = candidate.parent


def _owned_path(
    path: Path | str,
    *,
    run_root: Path,
    label: str,
    must_exist: bool = True,
) -> Path:
    candidate = Path(path).absolute()
    _reject_symlink_chain(candidate, stop=run_root, label=label)
    resolved = candidate.resolve(strict=must_exist)
    if not _is_relative_to(resolved, run_root):
        raise KimiBubblewrapLauncherError(f"{label} escapes its Kimi run")
    return resolved


def _atomic_bytes(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise KimiBubblewrapLauncherError(f"refusing to overwrite launcher evidence: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, prefix="tmp-kimi-launcher-", delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_json(path: Path, document: Mapping[str, Any]) -> None:
    _atomic_bytes(
        path,
        (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
            "utf-8"
        ),
    )


def _process_start_time(pid: int) -> str:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    except OSError as exc:
        raise KimiBubblewrapLauncherError("broker process is not observable") from exc
    if len(fields) < 22:
        raise KimiBubblewrapLauncherError("broker process stat record is malformed")
    return fields[21]


def _process_cmdline_sha256(pid: int) -> str:
    try:
        content = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as exc:
        raise KimiBubblewrapLauncherError("broker process cmdline is not observable") from exc
    if not content:
        raise KimiBubblewrapLauncherError("broker process cmdline is empty")
    return hashlib.sha256(content).hexdigest()


def _namespace_identifiers(pid: str = "self") -> dict[str, str]:
    result: dict[str, str] = {}
    for name in _REQUIRED_NAMESPACES:
        try:
            result[name] = os.readlink(f"/proc/{pid}/ns/{name}")
        except OSError as exc:
            raise KimiBubblewrapLauncherError(
                f"cannot observe host {name} namespace"
            ) from exc
    return result


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KimiBubblewrapLauncherError(f"{label} is malformed") from exc
    return _require_mapping(value, label)


def _validate_nonce_fd(lease: BrokerNonceFD, *, run_id: str) -> int:
    if not isinstance(lease, BrokerNonceFD):
        raise KimiBubblewrapLauncherError("broker returned an invalid nonce lease")
    if (
        not isinstance(lease.fd, int)
        or isinstance(lease.fd, bool)
        or lease.fd < 3
        or not isinstance(lease.lease_id, str)
        or _SAFE_LEASE_RE.fullmatch(lease.lease_id) is None
        or "kimi" not in lease.lease_id.casefold()
        or run_id not in lease.lease_id
    ):
        raise KimiBubblewrapLauncherError("broker nonce lease identity is invalid")
    try:
        metadata = os.fstat(lease.fd)
        descriptor_flags = fcntl.fcntl(lease.fd, fcntl.F_GETFD)
        seals = fcntl.fcntl(lease.fd, fcntl.F_GET_SEALS)
        offset = os.lseek(lease.fd, 0, os.SEEK_CUR)
        target = os.readlink(f"/proc/self/fd/{lease.fd}")
    except OSError as exc:
        raise KimiBubblewrapLauncherError("broker nonce descriptor is invalid") from exc
    required_seals = (
        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != 32
        or descriptor_flags & fcntl.FD_CLOEXEC == 0
        or seals & required_seals != required_seals
        or offset != 0
        or "memfd:" not in target
    ):
        raise KimiBubblewrapLauncherError(
            "broker nonce must be an unread sealed 32-byte memfd at offset zero"
        )
    return lease.fd


def bubblewrap_namespace_support(
    bwrap_path: Path | str = "/usr/bin/bwrap",
) -> tuple[bool, str]:
    """Return whether all required namespaces and capability dropping are usable."""

    path = Path(bwrap_path)
    if not path.is_file() or not os.access(path, os.X_OK):
        return False, f"bubblewrap executable is unavailable: {path}"
    command = [
        str(path),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--clearenv",
        "--",
        "/usr/bin/true",
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            env={},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"bubblewrap namespace probe failed: {type(exc).__name__}: {exc}"
    detail = completed.stderr.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        return False, detail or f"bubblewrap exited {completed.returncode}"
    return True, "bubblewrap enforced unshare-all with cap-drop ALL"


class BubblewrapStageProcess:
    """Owned bwrap process with deterministic sequential JSON-RPC support."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        release: Callable[[], None],
    ) -> None:
        self._process = process
        self._release = release
        self._released = False
        self._prefix_stdout = bytearray()
        self._prefix_stderr = bytearray()

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def returncode(self) -> int | None:
        result = self._process.poll()
        if result is not None:
            self._release_once()
        return result

    def _release_once(self) -> None:
        if self._released:
            return
        self._released = True
        self._release()

    def communicate(
        self,
        input: bytes | None = None,
        timeout: int | float | None = None,
    ) -> tuple[bytes, bytes]:
        try:
            stdout, stderr = self._process.communicate(input=input, timeout=timeout)
        finally:
            if self._process.poll() is not None:
                self._release_once()
        if self._prefix_stdout:
            stdout = bytes(self._prefix_stdout) + stdout
            self._prefix_stdout.clear()
        if self._prefix_stderr:
            stderr = bytes(self._prefix_stderr) + stderr
            self._prefix_stderr.clear()
        return stdout, stderr

    def terminate(self) -> None:
        if self._process.poll() is None:
            try:
                os.killpg(self._process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def kill(self) -> None:
        if self._process.poll() is None:
            try:
                os.killpg(self._process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def exchange_jsonrpc(
        self,
        *,
        request_frames: tuple[bytes, ...],
        expected_response_ids: tuple[str | int, ...],
        timeout: int | float,
    ) -> tuple[bytes, bytes]:
        if len(request_frames) != len(expected_response_ids) or not request_frames:
            raise KimiBubblewrapLauncherError("invalid sequential JSON-RPC exchange")
        if self._process.stdin is None or self._process.stdout is None or self._process.stderr is None:
            raise KimiBubblewrapLauncherError("bubblewrap process pipes are unavailable")
        deadline = time.monotonic() + float(timeout)
        selector = selectors.DefaultSelector()
        selector.register(self._process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(self._process.stderr, selectors.EVENT_READ, "stderr")
        stdout = bytearray()
        stderr = bytearray()
        line_buffer = bytearray()
        observed_responses: list[str | int] = []

        def consume_stdout(chunk: bytes) -> None:
            stdout.extend(chunk)
            line_buffer.extend(chunk)
            while b"\n" in line_buffer:
                raw_line, _, remainder = line_buffer.partition(b"\n")
                line_buffer[:] = remainder
                if not raw_line.strip():
                    continue
                try:
                    record = json.loads(raw_line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise KimiBubblewrapLauncherError(
                        "ACP emitted malformed JSON before its expected response"
                    ) from exc
                if isinstance(record, Mapping) and "method" not in record:
                    response_id = record.get("id")
                    if response_id in expected_response_ids:
                        observed_responses.append(response_id)

        def read_once() -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self._process.args, timeout)
            events = selector.select(timeout=remaining)
            if not events:
                raise subprocess.TimeoutExpired(self._process.args, timeout)
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    consume_stdout(chunk)
                else:
                    stderr.extend(chunk)

        try:
            for ordinal, (frame, expected_id) in enumerate(
                zip(request_frames, expected_response_ids), 1
            ):
                if not isinstance(frame, bytes) or not frame:
                    raise KimiBubblewrapLauncherError("JSON-RPC request frame is empty")
                self._process.stdin.write(frame)
                self._process.stdin.flush()
                while len(observed_responses) < ordinal:
                    if self._process.poll() is not None and not selector.get_map():
                        raise KimiBubblewrapLauncherError(
                            f"ACP exited before response {expected_id!r}"
                        )
                    read_once()
                if tuple(observed_responses[:ordinal]) != expected_response_ids[:ordinal]:
                    raise KimiBubblewrapLauncherError(
                        "ACP response arrived before its sequential request"
                    )
            self._process.stdin.close()
            self._process.stdin = None
            while selector.get_map():
                read_once()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self._process.args, timeout)
            self._process.wait(timeout=remaining)
            self._release_once()
            return bytes(stdout), bytes(stderr)
        except subprocess.TimeoutExpired:
            self._prefix_stdout.extend(stdout)
            self._prefix_stderr.extend(stderr)
            if self._process.stdin is not None:
                self._process.stdin.close()
                self._process.stdin = None
            raise
        except BaseException:
            self.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.kill()
                self._process.wait(timeout=2)
            self._release_once()
            raise
        finally:
            selector.close()


class LinuxBubblewrapLauncher:
    """Strict per-run attested launcher implementing ``IsolatedStageLauncher``."""

    jsonrpc_exchange_supported = True

    def __init__(
        self,
        *,
        broker: RunScopedRelayBroker,
        callback_collector: RunScopedCallbackSink,
        run_id: str,
        ownership_root: Path | str,
        model_name: str,
        reviewed_broker_implementation_path: Path | str,
        reviewed_broker_implementation_sha256: str,
        reviewed_broker_process_executable_path: Path | str,
        reviewed_broker_process_executable_sha256: str,
        reviewed_kimi_package_root: Path | str | None = None,
        reviewed_kimi_package_tree_sha256: str | None = None,
        reviewed_kimi_entrypoint_path: Path | str | None = None,
        reviewed_kimi_entrypoint_sha256: str | None = None,
        reviewed_node_executable_path: Path | str | None = None,
        reviewed_node_executable_sha256: str | None = None,
        bwrap_path: Path | str = "/usr/bin/bwrap",
        python_executable: Path | str | None = None,
        system_runtime_roots: Sequence[Path | str] = (
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
        ),
        forbidden_paths: Sequence[Path | str] = (),
    ) -> None:
        self.broker = broker
        self.callback_collector = callback_collector
        self.run_id = validate_bench_run_id(run_id)
        ownership = Path(ownership_root).absolute()
        if not ownership.is_dir() or ownership.is_symlink():
            raise KimiBubblewrapLauncherError("ownership_root must be an existing directory")
        self.ownership_root = ownership.resolve(strict=True)
        if (
            self.ownership_root != ownership
            or "kimi" not in self.ownership_root.as_posix().casefold()
            or self.run_id not in self.ownership_root.as_posix()
            or any(
                part.casefold() in {".claude", ".codex", ".kimi-code"}
                for part in self.ownership_root.parts
            )
        ):
            raise KimiBubblewrapLauncherError(
                "ownership_root lacks direct kimi/run_id ownership"
            )
        self.model_name = _require_string(model_name, "model_name")
        self.reviewed_broker_implementation_path = Path(
            reviewed_broker_implementation_path
        ).resolve(strict=True)
        self.reviewed_broker_implementation_sha256 = _require_sha256(
            reviewed_broker_implementation_sha256,
            "reviewed broker implementation SHA-256",
        )
        self.reviewed_broker_process_executable_path = Path(
            reviewed_broker_process_executable_path
        ).resolve(strict=True)
        self.reviewed_broker_process_executable_sha256 = _require_sha256(
            reviewed_broker_process_executable_sha256,
            "reviewed broker process executable SHA-256",
        )
        for path, expected, label in (
            (
                self.reviewed_broker_implementation_path,
                self.reviewed_broker_implementation_sha256,
                "reviewed broker implementation",
            ),
            (
                self.reviewed_broker_process_executable_path,
                self.reviewed_broker_process_executable_sha256,
                "reviewed broker process executable",
            ),
        ):
            if not path.is_file() or not hmac.compare_digest(sha256_file(path), expected):
                raise KimiBubblewrapLauncherError(f"{label} trust pin does not match bytes")
        self.bwrap_path = Path(bwrap_path).resolve(strict=True)
        if not self.bwrap_path.is_file() or not os.access(self.bwrap_path, os.X_OK):
            raise KimiBubblewrapUnavailable("bubblewrap executable is not executable")
        base_python = python_executable or getattr(sys, "_base_executable", sys.executable)
        self.python_executable = Path(base_python).resolve(strict=True)
        if not self.python_executable.is_file() or not os.access(
            self.python_executable, os.X_OK
        ):
            raise KimiBubblewrapLauncherError("system Python is not executable")
        roots: list[Path] = []
        for raw in system_runtime_roots:
            path = Path(raw)
            if path.exists():
                resolved = path.resolve(strict=True)
                if resolved != Path("/usr").resolve(strict=True) and _is_relative_to(
                    resolved, Path("/usr/local").resolve(strict=True)
                ):
                    raise KimiBubblewrapLauncherError(
                        "/usr/local must use exact reviewed Kimi/Node mounts"
                    )
                if not _is_relative_to(self.python_executable, resolved) and str(path) == "/usr":
                    raise KimiBubblewrapLauncherError("system Python is outside /usr")
                roots.append(path.absolute())
        if not roots or not any(str(path) == "/usr" for path in roots):
            raise KimiBubblewrapLauncherError("read-only /usr runtime mount is mandatory")
        self.system_runtime_roots = tuple(dict.fromkeys(roots))
        reviewed_runtime_values = (
            reviewed_kimi_package_root,
            reviewed_kimi_package_tree_sha256,
            reviewed_kimi_entrypoint_path,
            reviewed_kimi_entrypoint_sha256,
            reviewed_node_executable_path,
            reviewed_node_executable_sha256,
        )
        if any(value is not None for value in reviewed_runtime_values) and not all(
            value is not None for value in reviewed_runtime_values
        ):
            raise KimiBubblewrapLauncherError(
                "reviewed Kimi Node runtime pins must be supplied as one complete set"
            )
        self.reviewed_kimi_package_root: Path | None = None
        self.reviewed_kimi_package_tree_sha256: str | None = None
        self.reviewed_kimi_entrypoint_path: Path | None = None
        self.reviewed_kimi_entrypoint_sha256: str | None = None
        self.reviewed_node_executable_path: Path | None = None
        self.reviewed_node_executable_sha256: str | None = None
        if all(value is not None for value in reviewed_runtime_values):
            package_root = Path(str(reviewed_kimi_package_root)).resolve(strict=True)
            entrypoint = Path(str(reviewed_kimi_entrypoint_path)).resolve(strict=True)
            node = Path(str(reviewed_node_executable_path)).resolve(strict=True)
            package_sha = _require_sha256(
                reviewed_kimi_package_tree_sha256,
                "reviewed Kimi package tree SHA-256",
            )
            entrypoint_sha = _require_sha256(
                reviewed_kimi_entrypoint_sha256,
                "reviewed Kimi entrypoint SHA-256",
            )
            node_sha = _require_sha256(
                reviewed_node_executable_sha256,
                "reviewed Node executable SHA-256",
            )
            expected_package_parent = Path(
                "/usr/local/lib/node_modules/@moonshot-ai"
            ).resolve(strict=True)
            if (
                package_root.parent != expected_package_parent
                or package_root.name != "kimi-code"
                or package_root.is_symlink()
                or not package_root.is_dir()
                or entrypoint != package_root / "dist" / "main.mjs"
                or entrypoint.is_symlink()
                or not entrypoint.is_file()
                or not os.access(entrypoint, os.X_OK)
                or node != Path("/usr/local/bin/node").resolve(strict=True)
                or node.is_symlink()
                or not node.is_file()
                or not os.access(node, os.X_OK)
                or not hmac.compare_digest(tree_sha256(package_root), package_sha)
                or not hmac.compare_digest(sha256_file(entrypoint), entrypoint_sha)
                or not hmac.compare_digest(sha256_file(node), node_sha)
            ):
                raise KimiBubblewrapLauncherError(
                    "reviewed Kimi Node runtime pin does not match installed bytes"
                )
            self.reviewed_kimi_package_root = package_root
            self.reviewed_kimi_package_tree_sha256 = package_sha
            self.reviewed_kimi_entrypoint_path = entrypoint
            self.reviewed_kimi_entrypoint_sha256 = entrypoint_sha
            self.reviewed_node_executable_path = node
            self.reviewed_node_executable_sha256 = node_sha
        self.forbidden_paths = tuple(
            dict.fromkeys((*_DEFAULT_FORBIDDEN_PATHS, *(Path(item).absolute() for item in forbidden_paths)))
        )
        self._contexts: dict[tuple[str, Path], _RunContext] = {}
        self._spawned_stages: set[tuple[str, Path, int]] = set()
        self._owned_processes: list[BubblewrapStageProcess] = []

    def _validate_run_root(self, run_id: str, run_root: Path) -> Path:
        validate_bench_run_id(run_id)
        if run_id != self.run_id:
            raise KimiBubblewrapLauncherError("launcher run_id is fixed")
        absolute = Path(run_root).absolute()
        if not absolute.is_dir() or absolute.is_symlink():
            raise KimiBubblewrapLauncherError("run_root must be an existing directory")
        resolved = absolute.resolve(strict=True)
        case_digest: str | None = None
        try:
            case_digest, _attempt = parse_case_attempt_component(resolved.name)
        except (RuntimeError, ValueError):
            pass
        callback_case_id = getattr(self.callback_collector, "case_id", None)
        if (
            resolved != absolute
            or resolved != self.ownership_root
            or resolved.parent.name != f"kimi-{run_id}"
            or not isinstance(callback_case_id, str)
            or not callback_case_id
            or case_digest != case_identity_digest(callback_case_id)
        ):
            raise KimiBubblewrapLauncherError("run_root lacks direct kimi/run_id ownership")
        if any(part.casefold() in {".claude", ".codex", ".kimi-code"} for part in resolved.parts):
            raise KimiBubblewrapLauncherError("run_root uses forbidden harness user state")
        if resolved.stat().st_mode & 0o022:
            raise KimiBubblewrapLauncherError("run_root is group/world writable")
        return resolved

    def _validate_broker(self, *, run_id: str, run_root: Path) -> tuple[Mapping[str, Any], str]:
        broker = self.broker
        broker_case_id = getattr(broker, "case_id", None)
        broker_trial_id = getattr(broker, "trial_id", None)
        expected_root = run_root / broker_root_name(
            run_id,
            _require_string(broker_case_id, "broker case_id"),
            _require_string(broker_trial_id, "broker trial_id"),
        )
        if (
            getattr(broker, "run_id", None) != run_id
            or Path(getattr(broker, "ownership_root", "")).resolve(strict=True)
            != run_root
            or Path(getattr(broker, "root", "")).resolve(strict=True)
            != expected_root
        ):
            raise KimiBubblewrapLauncherError("broker run/case/trial ownership mismatch")
        socket_path = _owned_path(
            Path(broker.socket_path),
            run_root=self.ownership_root,
            label="broker socket",
        )
        metadata = socket_path.stat()
        if (
            socket_path.parent != expected_root
            or socket_path.name != BROKER_SOCKET_BASENAME
            or not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or socket_path.parent.stat().st_mode & 0o077
        ):
            raise KimiBubblewrapLauncherError("broker socket is not a private run-owned socket")
        attestation_path = _owned_path(
            Path(self.broker.attestation_path),
            run_root=self.ownership_root,
            label="broker attestation",
        )
        if not attestation_path.is_file() or attestation_path.is_symlink():
            raise KimiBubblewrapLauncherError("broker attestation is not a regular file")
        document = _read_json(attestation_path, "broker attestation")
        expected_keys = {
            "schema_name",
            "schema_version",
            "harness_id",
            "run_id",
            "broker_kind",
            "socket_path",
            "socket_identity",
            "process",
            "implementation",
            "credential_boundary",
            "nonce_boundary",
            "attestation_payload_sha256",
        }
        if set(document) != expected_keys:
            raise KimiBubblewrapLauncherError("broker attestation field set drifted")
        if (
            document.get("schema_name") != BROKER_ATTESTATION_SCHEMA_NAME
            or document.get("schema_version") != BROKER_ATTESTATION_SCHEMA_VERSION
            or document.get("harness_id") != "kimi"
            or document.get("run_id") != run_id
            or Path(str(document.get("socket_path"))).resolve() != socket_path
        ):
            raise KimiBubblewrapLauncherError("broker attestation identity mismatch")
        _require_string(document.get("broker_kind"), "broker_kind")
        claimed = _require_sha256(
            document.get("attestation_payload_sha256"), "broker attestation payload"
        )
        if not hmac.compare_digest(claimed, _payload_sha256(document, "attestation_payload_sha256")):
            raise KimiBubblewrapLauncherError("broker attestation self-hash mismatch")
        socket_identity = _require_mapping(document.get("socket_identity"), "socket identity")
        if set(socket_identity) != {"device", "inode", "uid", "gid", "mode"} or (
            socket_identity.get("device") != metadata.st_dev
            or socket_identity.get("inode") != metadata.st_ino
            or socket_identity.get("uid") != metadata.st_uid
            or socket_identity.get("gid") != metadata.st_gid
            or socket_identity.get("mode") != stat.S_IMODE(metadata.st_mode)
        ):
            raise KimiBubblewrapLauncherError("broker socket identity drifted")
        process = _require_mapping(document.get("process"), "broker process")
        if set(process) != {
            "pid",
            "start_time",
            "executable_path",
            "executable_sha256",
            "cmdline_sha256",
        }:
            raise KimiBubblewrapLauncherError("broker process field set drifted")
        pid = process.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1 or process.get(
            "start_time"
        ) != _process_start_time(pid):
            raise KimiBubblewrapLauncherError("broker process identity drifted")
        try:
            observed_process_executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        except OSError as exc:
            raise KimiBubblewrapLauncherError("broker process executable is unavailable") from exc
        if (
            observed_process_executable
            != self.reviewed_broker_process_executable_path
            or Path(str(process.get("executable_path"))).resolve()
            != self.reviewed_broker_process_executable_path
            or not hmac.compare_digest(
                sha256_file(observed_process_executable),
                self.reviewed_broker_process_executable_sha256,
            )
            or process.get("executable_sha256")
            != self.reviewed_broker_process_executable_sha256
            or process.get("cmdline_sha256") != _process_cmdline_sha256(pid)
        ):
            raise KimiBubblewrapLauncherError("broker process executable/cmdline drifted")
        implementation = _require_mapping(document.get("implementation"), "broker implementation")
        if set(implementation) != {"path", "sha256"}:
            raise KimiBubblewrapLauncherError("broker implementation field set drifted")
        implementation_path = Path(
            _require_string(implementation.get("path"), "broker implementation path")
        ).resolve(strict=True)
        if (
            implementation_path != self.reviewed_broker_implementation_path
            or not implementation_path.is_file()
            or not hmac.compare_digest(
                sha256_file(implementation_path),
                self.reviewed_broker_implementation_sha256,
            )
            or implementation.get("sha256")
            != self.reviewed_broker_implementation_sha256
        ):
            raise KimiBubblewrapLauncherError("broker implementation bytes drifted")
        credential = _require_mapping(
            document.get("credential_boundary"), "broker credential boundary"
        )
        if set(credential) != {
            "upstream_credential_transport",
            "credential_fd_cloexec",
            "external_credentials_in_environment",
            "external_credentials_in_filesystem",
            "external_credentials_persisted",
        } or (
            credential.get("upstream_credential_transport") != "inherited_fd"
            or credential.get("credential_fd_cloexec") is not True
            or credential.get("external_credentials_in_environment") is not False
            or credential.get("external_credentials_in_filesystem") is not False
            or credential.get("external_credentials_persisted") is not False
        ):
            raise KimiBubblewrapLauncherError("broker credential boundary is insufficient")
        nonce = _require_mapping(document.get("nonce_boundary"), "broker nonce boundary")
        if set(nonce) != {
            "issuance_transport",
            "nonce_length_bytes",
            "volatile_only",
            "unauthorized_nonce_rejected",
            "released_nonce_rejected",
        } or (
            nonce.get("issuance_transport") != "sealed_memfd"
            or nonce.get("nonce_length_bytes") != 32
            or nonce.get("volatile_only") is not True
            or nonce.get("unauthorized_nonce_rejected") is not True
            or nonce.get("released_nonce_rejected") is not True
        ):
            raise KimiBubblewrapLauncherError("broker nonce boundary is insufficient")
        return document, sha256_file(attestation_path)

    def _validate_callback_collector(
        self, *, run_id: str, run_root: Path
    ) -> tuple[Mapping[str, Any], str]:
        collector = self.callback_collector
        if (
            getattr(collector, "run_id", None) != run_id
            or Path(getattr(collector, "ownership_root", "")).resolve(strict=True)
            != run_root
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector run ownership mismatch"
            )
        callback_root = _owned_path(
            Path(collector.root),
            run_root=run_root,
            label="callback collector root",
        )
        socket_path = _owned_path(
            Path(collector.socket_path),
            run_root=run_root,
            label="callback collector socket",
        )
        socket_metadata = socket_path.stat()
        if (
            callback_root.parent != run_root
            or socket_path.parent != callback_root
            or socket_path.name != CALLBACK_SOCKET_BASENAME
            or callback_root.name
            != callback_root_name(
                run_id,
                _require_string(getattr(collector, "case_id", None), "callback case_id"),
                _require_string(getattr(collector, "trial_id", None), "callback trial_id"),
            )
            or callback_root.is_symlink()
            or not callback_root.is_dir()
            or stat.S_IMODE(callback_root.stat().st_mode) != 0o700
            or not stat.S_ISSOCK(socket_metadata.st_mode)
            or socket_metadata.st_uid != os.getuid()
            or stat.S_IMODE(socket_metadata.st_mode) != 0o600
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector socket is not private and run-owned"
            )
        attestation_path = _owned_path(
            Path(collector.attestation_path),
            run_root=run_root,
            label="callback collector attestation",
        )
        if (
            attestation_path.parent != callback_root
            or not attestation_path.is_file()
            or attestation_path.is_symlink()
            or stat.S_IMODE(attestation_path.stat().st_mode) != 0o600
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector attestation is not private"
            )
        document = _read_json(attestation_path, "callback collector attestation")
        expected_keys = {
            "schema_name",
            "schema_version",
            "harness_id",
            "run_id",
            "case_id",
            "trial_id",
            "process",
            "implementation",
            "socket",
            "evidence",
            "nonce",
            "attestation_payload_sha256",
        }
        if set(document) != expected_keys or (
            document.get("schema_name") != CALLBACK_ATTESTATION_SCHEMA_NAME
            or document.get("schema_version") != CALLBACK_ATTESTATION_SCHEMA_VERSION
            or document.get("harness_id") != "kimi"
            or document.get("run_id") != run_id
            or document.get("case_id") != getattr(collector, "case_id", None)
            or document.get("trial_id") != getattr(collector, "trial_id", None)
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector attestation identity mismatch"
            )
        _require_string(document.get("case_id"), "callback case_id")
        _require_string(document.get("trial_id"), "callback trial_id")
        claimed = _require_sha256(
            document.get("attestation_payload_sha256"),
            "callback collector attestation payload",
        )
        if not hmac.compare_digest(
            claimed,
            _payload_sha256(document, "attestation_payload_sha256"),
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector attestation self-hash mismatch"
            )

        process = _require_mapping(document.get("process"), "callback process")
        if set(process) != {
            "pid",
            "start_time",
            "executable_path",
            "executable_sha256",
            "cmdline_sha256",
        }:
            raise KimiBubblewrapLauncherError(
                "callback collector process field set drifted"
            )
        pid = process.get("pid")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 1
            or process.get("start_time") != _process_start_time(pid)
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector process identity drifted"
            )
        try:
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        except OSError as exc:
            raise KimiBubblewrapLauncherError(
                "callback collector process is unavailable"
            ) from exc
        expected_executable = self.python_executable
        if (
            executable != expected_executable
            or Path(str(process.get("executable_path"))).resolve()
            != expected_executable
            or Path(collector.process_executable_path).resolve(strict=True)
            != expected_executable
            or process.get("executable_sha256") != sha256_file(expected_executable)
            or getattr(collector, "process_executable_sha256", None)
            != process.get("executable_sha256")
            or process.get("cmdline_sha256") != _process_cmdline_sha256(pid)
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector executable/cmdline drifted"
            )

        implementation = _require_mapping(
            document.get("implementation"), "callback implementation"
        )
        if set(implementation) != {"path", "sha256"}:
            raise KimiBubblewrapLauncherError(
                "callback collector implementation field set drifted"
            )
        expected_implementation = Path(__file__).with_name(
            "callback_collector.py"
        ).resolve(strict=True)
        implementation_path = Path(
            _require_string(
                implementation.get("path"), "callback implementation path"
            )
        ).resolve(strict=True)
        implementation_sha = sha256_file(expected_implementation)
        if (
            implementation_path != expected_implementation
            or Path(collector.implementation_path).resolve(strict=True)
            != expected_implementation
            or implementation.get("sha256") != implementation_sha
            or getattr(collector, "implementation_sha256", None)
            != implementation_sha
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector implementation bytes drifted"
            )

        socket_record = _require_mapping(
            document.get("socket"), "callback socket record"
        )
        if set(socket_record) != {
            "path",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "parent_mode",
        } or (
            Path(str(socket_record.get("path"))).resolve() != socket_path
            or socket_record.get("device") != socket_metadata.st_dev
            or socket_record.get("inode") != socket_metadata.st_ino
            or socket_record.get("uid") != socket_metadata.st_uid
            or socket_record.get("gid") != socket_metadata.st_gid
            or socket_record.get("mode") != 0o600
            or socket_record.get("parent_mode") != 0o700
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector socket identity drifted"
            )

        evidence = _require_mapping(document.get("evidence"), "callback evidence")
        if set(evidence) != {
            "path",
            "manifest_path",
            "inode",
            "mode",
            "write_mode",
            "body_policy",
            "sensitive_header_policy",
        }:
            raise KimiBubblewrapLauncherError(
                "callback collector evidence field set drifted"
            )
        evidence_path = _owned_path(
            Path(collector.evidence_path),
            run_root=run_root,
            label="callback evidence",
        )
        evidence_metadata = evidence_path.stat()
        manifest_path = Path(collector.evidence_manifest_path).absolute()
        _reject_symlink_chain(
            manifest_path,
            stop=run_root,
            label="callback evidence manifest",
        )
        if (
            evidence_path.parent != callback_root
            or Path(str(evidence.get("path"))).resolve() != evidence_path
            or Path(str(evidence.get("manifest_path"))).absolute() != manifest_path
            or evidence.get("inode") != evidence_metadata.st_ino
            or evidence.get("mode") != 0o600
            or evidence.get("write_mode") != "append_only"
            or evidence.get("body_policy")
            != "preserve_utf8_for_exact_canary_evidence"
            or evidence.get("sensitive_header_policy") != "drop_name_and_value"
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector evidence identity drifted"
            )
        nonce = _require_mapping(document.get("nonce"), "callback nonce boundary")
        if set(nonce) != {
            "purpose",
            "transport",
            "length_bytes",
            "successful_connections_per_nonce",
            "replay_rejected",
            "cross_identity_rejected",
        } or (
            nonce.get("purpose") != "callback_relay"
            or nonce.get("transport")
            != "sealed_memfd_over_private_control_socket"
            or nonce.get("length_bytes") != 32
            or nonce.get("successful_connections_per_nonce") != 1
            or nonce.get("replay_rejected") is not True
            or nonce.get("cross_identity_rejected") is not True
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector nonce boundary is insufficient"
            )
        return document, sha256_file(attestation_path)

    def _negative_handshake_probe(self, *, run_id: str, socket_path: Path) -> None:
        nonce = bytearray(secrets.token_bytes(32))
        purpose = "unauthorized_probe"
        stage_index = -1
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5)
        try:
            connection.connect(str(socket_path))
            import base64

            request = {
                "schema_name": HANDSHAKE_SCHEMA_NAME,
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": run_id,
                "stage_index": stage_index,
                "purpose": purpose,
                "nonce": base64.b64encode(bytes(nonce)).decode("ascii"),
            }
            connection.sendall(
                json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
                + b"\n"
            )
            buffer = bytearray()
            while b"\n" not in buffer and len(buffer) <= 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
            line, separator, trailing = bytes(buffer).partition(b"\n")
            if not separator or trailing:
                raise KimiBubblewrapLauncherError("broker negative response framing drifted")
            response = _require_mapping(json.loads(line), "broker negative response")
            if (
                response.get("schema_name") != HANDSHAKE_SCHEMA_NAME
                or response.get("ok") is not False
                or response.get("reason") != "unauthorized_nonce"
                or response.get("run_id") != run_id
                or response.get("stage_index") != stage_index
                or response.get("purpose") != purpose
                or not hmac.compare_digest(
                    str(response.get("proof") or ""),
                    broker_ack_proof(
                        nonce,
                        run_id=run_id,
                        stage_index=stage_index,
                        purpose=purpose,
                        ok=False,
                    ),
                )
            ):
                raise KimiBubblewrapLauncherError(
                    "broker did not reject an unauthorized run-local nonce"
                )
        except (OSError, json.JSONDecodeError) as exc:
            raise KimiBubblewrapLauncherError("broker negative handshake probe failed") from exc
        finally:
            connection.close()
            for index in range(len(nonce)):
                nonce[index] = 0

    def _prepare_launcher_files(self, *, run_id: str, run_root: Path) -> tuple[Path, Path]:
        launcher_dir = run_root / f"isolated-launcher-kimi-{run_id}"
        if launcher_dir.exists() or launcher_dir.is_symlink():
            raise KimiBubblewrapLauncherError("launcher directory already exists")
        launcher_dir.mkdir(mode=0o700)
        helper_source = Path(__file__).with_name("sandbox_entry.py").resolve(strict=True)
        helper_copy = launcher_dir / f"sandbox-entry-kimi-{run_id}.py"
        _atomic_bytes(helper_copy, helper_source.read_bytes(), mode=0o500)
        system_dir = launcher_dir / f"system-files-kimi-{run_id}"
        system_dir.mkdir(mode=0o700)
        _atomic_bytes(
            system_dir / f"passwd-kimi-{run_id}",
            b"root:x:0:0:Kimi Sandbox:/run/kimi/empty-home:/usr/sbin/nologin\n",
            mode=0o400,
        )
        _atomic_bytes(
            system_dir / f"group-kimi-{run_id}", b"root:x:0:\n", mode=0o400
        )
        _atomic_bytes(
            system_dir / f"hosts-kimi-{run_id}",
            b"127.0.0.1 localhost\n::1 localhost\n",
            mode=0o400,
        )
        return launcher_dir, helper_copy

    def _base_bwrap_argv(
        self,
        *,
        run_id: str,
        launcher_dir: Path,
        helper_copy: Path,
        provider_nonce_fd: int,
        callback_nonce_fd: int | None = None,
        cwd: Path,
        environment: Mapping[str, str],
        writable_paths: Sequence[Path],
        read_only_paths: Sequence[Path] = (),
        protect_launcher_dir: bool,
    ) -> list[str]:
        socket_parent = Path(self.broker.socket_path).resolve(strict=True).parent
        callback_socket_parent = Path(
            self.callback_collector.socket_path
        ).resolve(strict=True).parent
        system_dir = launcher_dir / f"system-files-kimi-{run_id}"
        command = [
            str(self.bwrap_path),
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--hostname",
            f"kimi-{hashlib.sha256(run_id.encode()).hexdigest()[:16]}",
        ]
        for source in self.system_runtime_roots:
            command.extend(("--ro-bind", str(source), str(source)))
        command.extend(
            (
                "--tmpfs",
                "/usr/local",
                "--dir",
                "/usr/local/bin",
                "--dir",
                "/usr/local/lib",
                "--dir",
                "/usr/local/lib/node_modules",
                "--dir",
                "/usr/local/lib/node_modules/@moonshot-ai",
            )
        )
        if self.reviewed_kimi_package_root is not None:
            assert self.reviewed_node_executable_path is not None
            command.extend(
                (
                    "--ro-bind",
                    str(self.reviewed_node_executable_path),
                    str(self.reviewed_node_executable_path),
                    "--ro-bind",
                    str(self.reviewed_kimi_package_root),
                    str(self.reviewed_kimi_package_root),
                )
            )
        command.extend(
            (
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--dir",
                "/run",
                "--dir",
                "/run/kimi",
                "--dir",
                "/run/kimi/empty-home",
                "--dir",
                "/etc",
            )
        )
        for path in writable_paths:
            command.extend(("--bind", str(path), str(path)))
        for path in read_only_paths:
            command.extend(("--ro-bind", str(path), str(path)))
        command.extend(
            (
                "--ro-bind",
                str(socket_parent),
                "/run/kimi/bridge",
                "--ro-bind",
                str(helper_copy),
                str(helper_copy),
                "--ro-bind",
                str(system_dir / f"passwd-kimi-{run_id}"),
                "/etc/passwd",
                "--ro-bind",
                str(system_dir / f"group-kimi-{run_id}"),
                "/etc/group",
                "--ro-bind",
                str(system_dir / f"hosts-kimi-{run_id}"),
                "/etc/hosts",
            )
        )
        if callback_nonce_fd is not None:
            if callback_socket_parent == socket_parent:
                raise KimiBubblewrapLauncherError(
                    "provider and callback sockets must use independent roots"
                )
            command.extend(
                (
                    "--ro-bind",
                    str(callback_socket_parent),
                    "/run/kimi/callback-bridge",
                )
            )
        for host_file in (Path("/etc/ld.so.cache"), Path("/etc/localtime")):
            if host_file.is_file():
                command.extend(("--ro-bind", str(host_file), str(host_file)))
        if protect_launcher_dir:
            command.extend(("--ro-bind", str(launcher_dir), str(launcher_dir)))
        command.extend(
            (
                "--perms",
                "0400",
                "--file",
                str(provider_nonce_fd),
                "/run/kimi/provider-nonce",
            )
        )
        if callback_nonce_fd is not None:
            command.extend(
                (
                    "--perms",
                    "0400",
                    "--file",
                    str(callback_nonce_fd),
                    "/run/kimi/callback-nonce",
                )
            )
        command.append("--clearenv")
        for key, value in sorted(environment.items()):
            command.extend(("--setenv", key, value))
        command.extend(("--setenv", "PWD", str(cwd)))
        command.extend(("--chdir", str(cwd), "--", str(self.python_executable), str(helper_copy)))
        return command

    def _issue_nonce(
        self,
        authority: RunScopedRelayBroker | RunScopedCallbackSink,
        *,
        run_id: str,
        stage_index: int,
        purpose: str,
    ) -> BrokerNonceFD:
        try:
            lease = authority.issue_nonce_fd(
                run_id=run_id, stage_index=stage_index, purpose=purpose
            )
            _validate_nonce_fd(lease, run_id=run_id)
            return lease
        except Exception:
            if "lease" in locals() and isinstance(lease, BrokerNonceFD):
                try:
                    os.close(lease.fd)
                except OSError:
                    pass
                try:
                    self._release_nonce(
                        authority,
                        lease,
                        run_id=run_id,
                        stage_index=stage_index,
                        purpose=purpose,
                    )
                except Exception:
                    pass
            raise

    def _release_nonce(
        self,
        authority: RunScopedRelayBroker | RunScopedCallbackSink,
        lease: BrokerNonceFD,
        *,
        run_id: str,
        stage_index: int,
        purpose: str,
    ) -> None:
        authority.release_nonce(
            lease.lease_id,
            run_id=run_id,
            stage_index=stage_index,
            purpose=purpose,
        )

    def _validate_self_test(
        self,
        *,
        run_id: str,
        run_root: Path,
        isolation_path: Path,
        broker_path: Path,
        host_namespaces: Mapping[str, str],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        isolation = _read_json(isolation_path, "bubblewrap isolation self-test")
        required_isolation_keys = {
            "schema_name",
            "schema_version",
            "harness_id",
            "run_id",
            "pid_inside_namespace",
            "namespaces",
            "mount_points",
            "network_interfaces",
            "effective_capabilities_hex",
            "inherited_nonstandard_file_descriptors",
            "forbidden_paths_visible",
            "nonce_file_removed_before_probe",
            "environment_keys",
        }
        if set(isolation) != required_isolation_keys or (
            isolation.get("schema_name") != "safety_bench_kimi_bwrap_isolation_evidence"
            or isolation.get("schema_version") != 1
            or isolation.get("harness_id") != "kimi"
            or isolation.get("run_id") != run_id
            or isolation.get("network_interfaces") != ["lo"]
            or isolation.get("nonce_file_removed_before_probe") is not True
        ):
            raise KimiBubblewrapLauncherError("bubblewrap self-test identity/policy drifted")
        capabilities = isolation.get("effective_capabilities_hex")
        try:
            capabilities_are_zero = isinstance(capabilities, str) and int(
                capabilities, 16
            ) == 0
        except ValueError:
            capabilities_are_zero = False
        if not capabilities_are_zero:
            raise KimiBubblewrapLauncherError("bubblewrap self-test retained capabilities")
        sandbox_namespaces = _require_mapping(
            isolation.get("namespaces"), "sandbox namespaces"
        )
        if set(sandbox_namespaces) != set(_REQUIRED_NAMESPACES) or any(
            sandbox_namespaces[name] == host_namespaces[name] for name in _REQUIRED_NAMESPACES
        ):
            raise KimiBubblewrapLauncherError("a required Linux namespace was not isolated")
        forbidden = _require_mapping(
            isolation.get("forbidden_paths_visible"), "forbidden path evidence"
        )
        expected_forbidden = {str(path) for path in self.forbidden_paths}
        if set(forbidden) != expected_forbidden or any(value is not False for value in forbidden.values()):
            raise KimiBubblewrapLauncherError("host harness/worktree state is visible")
        descriptors = _require_mapping(
            isolation.get("inherited_nonstandard_file_descriptors"),
            "inherited descriptor evidence",
        )
        if any("memfd:" in str(value) or "nonce" in str(value) for value in descriptors.values()):
            raise KimiBubblewrapLauncherError("nonce descriptor reached sandbox helper")
        environment_keys = isolation.get("environment_keys")
        expected_environment_keys = set(_SELF_TEST_ENV) | {
            "PWD",
            "SAFETY_BENCH_RUN_ID",
        }
        if not isinstance(environment_keys, list) or set(
            environment_keys
        ) != expected_environment_keys:
            raise KimiBubblewrapLauncherError(
                "self-test environment allowlist drifted: "
                f"observed={sorted(environment_keys) if isinstance(environment_keys, list) else environment_keys!r}"
            )
        mount_points = isolation.get("mount_points")
        if not isinstance(mount_points, list) or not any(
            mount.startswith(str(run_root) + "/isolated-launcher-kimi-")
            for mount in mount_points
        ):
            raise KimiBubblewrapLauncherError(
                "run-local launcher evidence directory was not mounted in self-test"
            )
        for forbidden_path in self.forbidden_paths:
            if any(
                mount == str(forbidden_path) or mount.startswith(str(forbidden_path) + "/")
                for mount in mount_points
            ):
                raise KimiBubblewrapLauncherError("forbidden host path is mounted")

        broker = _read_json(broker_path, "bubblewrap broker self-test")
        required_broker_keys = {
            "schema_name",
            "schema_version",
            "harness_id",
            "run_id",
            "transport",
            "socket_path_inside_sandbox",
            "handshake_verified",
            "nonce_file_removed_before_handshake",
            "external_credentials_observed",
        }
        if set(broker) != required_broker_keys or (
            broker.get("schema_name") != "safety_bench_kimi_broker_handshake_evidence"
            or broker.get("schema_version") != 1
            or broker.get("harness_id") != "kimi"
            or broker.get("run_id") != run_id
            or broker.get("transport") != "run_scoped_unix_socket"
            or broker.get("socket_path_inside_sandbox") != "/run/kimi/bridge/p.sock"
            or broker.get("handshake_verified") is not True
            or broker.get("nonce_file_removed_before_handshake") is not True
            or broker.get("external_credentials_observed") is not False
        ):
            raise KimiBubblewrapLauncherError("broker handshake self-test drifted")
        return isolation, broker

    def attest(self, *, run_id: str, run_root: Path) -> Path:
        root = self._validate_run_root(run_id, Path(run_root))
        key = (run_id, root)
        if key in self._contexts:
            context = self._contexts[key]
            broker_document, broker_sha = self._validate_broker(
                run_id=run_id, run_root=root
            )
            callback_document, callback_sha = self._validate_callback_collector(
                run_id=run_id, run_root=root
            )
            if (
                not hmac.compare_digest(
                    sha256_file(context.attestation_path),
                    context.attestation_sha256,
                )
                or broker_document != context.broker_document
                or callback_document != context.callback_document
                or not hmac.compare_digest(
                    broker_sha, context.broker_attestation_sha256
                )
                or not hmac.compare_digest(
                    callback_sha, context.callback_attestation_sha256
                )
            ):
                raise KimiBubblewrapLauncherError(
                    "cached launcher/broker/callback attestation drifted"
                )
            return context.attestation_path
        broker_document, broker_attestation_sha = self._validate_broker(
            run_id=run_id, run_root=root
        )
        callback_document, callback_attestation_sha = (
            self._validate_callback_collector(run_id=run_id, run_root=root)
        )
        self._negative_handshake_probe(
            run_id=run_id, socket_path=Path(self.broker.socket_path)
        )
        self._negative_handshake_probe(
            run_id=run_id,
            socket_path=Path(self.callback_collector.socket_path),
        )
        launcher_dir, helper_copy = self._prepare_launcher_files(
            run_id=run_id, run_root=root
        )
        isolation_raw = launcher_dir / f"self-test-isolation-kimi-{run_id}.json"
        broker_raw = launcher_dir / f"self-test-broker-kimi-{run_id}.json"
        stdout_path = launcher_dir / f"self-test-stdout-kimi-{run_id}.log"
        stderr_path = launcher_dir / f"self-test-stderr-kimi-{run_id}.log"
        host_namespaces = _namespace_identifiers()
        lease = self._issue_nonce(
            self.broker,
            run_id=run_id,
            stage_index=-1,
            purpose="attestation",
        )
        environment = dict(_SELF_TEST_ENV)
        environment["SAFETY_BENCH_RUN_ID"] = run_id
        command = self._base_bwrap_argv(
            run_id=run_id,
            launcher_dir=launcher_dir,
            helper_copy=helper_copy,
            provider_nonce_fd=lease.fd,
            cwd=launcher_dir,
            environment=environment,
            writable_paths=(launcher_dir,),
            protect_launcher_dir=False,
        )
        command.extend(
            (
                "self-test",
                "--run-id",
                run_id,
                "--isolation-output",
                str(isolation_raw),
                "--broker-output",
                str(broker_raw),
            )
        )
        for forbidden_path in self.forbidden_paths:
            command.extend(("--forbidden-path", str(forbidden_path)))
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
                env={
                    "SAFETY_BENCH_HARNESS": "kimi",
                    "SAFETY_BENCH_RUN_ID": run_id,
                },
                pass_fds=(lease.fd,),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise KimiBubblewrapUnavailable(
                f"bubblewrap self-test could not execute: {type(exc).__name__}: {exc}"
            ) from exc
        finally:
            try:
                os.close(lease.fd)
            finally:
                self._release_nonce(
                    self.broker,
                    lease,
                    run_id=run_id,
                    stage_index=-1,
                    purpose="attestation",
                )
        _atomic_bytes(stdout_path, completed.stdout)
        _atomic_bytes(stderr_path, completed.stderr)
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise KimiBubblewrapUnavailable(
                f"bubblewrap self-test exited {completed.returncode}: {detail}"
            )
        self._validate_self_test(
            run_id=run_id,
            run_root=root,
            isolation_path=isolation_raw,
            broker_path=broker_raw,
            host_namespaces=host_namespaces,
        )
        isolation_verified = launcher_dir / f"verified-isolation-kimi-{run_id}.json"
        verified_document = {
            "schema_name": ISOLATION_EVIDENCE_SCHEMA_NAME,
            "schema_version": ISOLATION_EVIDENCE_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": run_id,
            "bwrap": {
                "path": str(self.bwrap_path),
                "sha256": sha256_file(self.bwrap_path),
                "unshare_all": True,
                "cap_drop_all": True,
                "new_procfs": True,
            },
            "host_namespaces": dict(host_namespaces),
            "sandbox_namespaces": dict(
                _read_json(isolation_raw, "isolation raw")["namespaces"]
            ),
            "all_required_namespaces_distinct": True,
            "network_interfaces": ["lo"],
            "mount_policy": {
                "writable_roots": "per_stage_workspace_and_runtime_allowlist",
                "read_only_system_runtime": [
                    str(path) for path in self.system_runtime_roots
                ],
                "masked_system_subtree": "/usr/local",
                "reviewed_kimi_node_runtime": (
                    {
                        "package_root": str(self.reviewed_kimi_package_root),
                        "package_tree_sha256": self.reviewed_kimi_package_tree_sha256,
                        "entrypoint_path": str(self.reviewed_kimi_entrypoint_path),
                        "entrypoint_sha256": self.reviewed_kimi_entrypoint_sha256,
                        "node_path": str(self.reviewed_node_executable_path),
                        "node_sha256": self.reviewed_node_executable_sha256,
                    }
                    if self.reviewed_kimi_package_root is not None
                    else None
                ),
                "user_harness_state_mounted": False,
                "other_worktree_mounted": False,
            },
            "nonce_transport": {
                "source": "broker_owned_sealed_memfd",
                "sandbox_delivery": "bwrap_file_fd",
                "launcher_read_nonce": False,
                "nonce_in_argv": False,
                "nonce_in_environment": False,
                "nonce_source_fd_in_helper": False,
                "transient_file_removed_before_handshake": True,
            },
            "unauthorized_nonce_probe_rejected": True,
            "self_test": {
                "isolation_path": str(isolation_raw),
                "isolation_sha256": sha256_file(isolation_raw),
                "broker_path": str(broker_raw),
                "broker_sha256": sha256_file(broker_raw),
                "stdout_path": str(stdout_path),
                "stdout_sha256": sha256_file(stdout_path),
                "stderr_path": str(stderr_path),
                "stderr_sha256": sha256_file(stderr_path),
                "exit_code": completed.returncode,
            },
        }
        _atomic_json(isolation_verified, verified_document)
        broker_attestation_copy = (
            launcher_dir / f"broker-attestation-kimi-{run_id}.json"
        )
        broker_attestation_source = Path(self.broker.attestation_path).resolve()
        _atomic_bytes(
            broker_attestation_copy,
            broker_attestation_source.read_bytes(),
            mode=0o400,
        )
        if not hmac.compare_digest(
            sha256_file(broker_attestation_copy), broker_attestation_sha
        ):
            raise KimiBubblewrapLauncherError("copied broker attestation drifted")
        callback_attestation_copy = (
            launcher_dir / f"callback-attestation-kimi-{run_id}.json"
        )
        callback_attestation_source = Path(
            self.callback_collector.attestation_path
        ).resolve()
        _atomic_bytes(
            callback_attestation_copy,
            callback_attestation_source.read_bytes(),
            mode=0o400,
        )
        if not hmac.compare_digest(
            sha256_file(callback_attestation_copy), callback_attestation_sha
        ):
            raise KimiBubblewrapLauncherError(
                "copied callback collector attestation drifted"
            )
        attestation_path = launcher_dir / f"attestation-kimi-{run_id}.json"
        attestation: dict[str, Any] = {
            "schema_name": ATTESTATION_SCHEMA_NAME,
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": run_id,
            "run_root": str(root),
            "launcher_id": "linux-bubblewrap-run-local-provider-callback-v1",
            "isolation": {
                "kind": "linux_bubblewrap_allowlist_namespaces_v1",
                "enforced": True,
                "host_user_state_mounted": False,
                "other_harness_state_mounted": False,
                "network_egress": "run_local_broker_only",
            },
            "credential_broker": {
                "kind": broker_document["broker_kind"],
                "run_id": run_id,
                "run_local": True,
                "verified": True,
                "external_credentials_in_kimi_env": False,
                "external_credentials_in_tool_child_env": False,
                "external_credentials_persisted": False,
            },
            "evidence": [
                {
                    "kind": "os_isolation",
                    "path": str(isolation_verified),
                    "sha256": sha256_file(isolation_verified),
                },
                {
                    "kind": "credential_broker",
                    "path": str(broker_attestation_copy),
                    "sha256": broker_attestation_sha,
                },
                {
                    "kind": "sandbox_self_test",
                    "path": str(broker_raw),
                    "sha256": sha256_file(broker_raw),
                },
                {
                    "kind": "callback_collector",
                    "path": str(callback_attestation_copy),
                    "sha256": callback_attestation_sha,
                },
            ],
        }
        attestation["attestation_payload_sha256"] = _canonical_sha256(attestation)
        _atomic_json(attestation_path, attestation)
        context = _RunContext(
            run_id=run_id,
            run_root=root,
            launcher_dir=launcher_dir,
            helper_copy=helper_copy,
            attestation_path=attestation_path,
            attestation_sha256=sha256_file(attestation_path),
            broker_document=broker_document,
            broker_attestation_sha256=broker_attestation_sha,
            broker_attestation_source=broker_attestation_source,
            callback_document=callback_document,
            callback_attestation_sha256=callback_attestation_sha,
            callback_attestation_source=callback_attestation_source,
        )
        self._contexts[key] = context
        return attestation_path

    def _context_for_request(self, request: StageLaunchRequest) -> _RunContext:
        candidates = [
            context
            for (run_id, _), context in self._contexts.items()
            if run_id == request.run_id
            and _is_relative_to(Path(request.cwd).resolve(strict=True), context.run_root)
        ]
        if len(candidates) != 1:
            raise KimiBubblewrapLauncherError("stage has no unique attested Kimi run")
        context = candidates[0]
        if (
            Path(request.launcher_attestation_path).resolve(strict=True)
            != context.attestation_path
            or not hmac.compare_digest(
                sha256_file(context.attestation_path), context.attestation_sha256
            )
            or not hmac.compare_digest(
                sha256_file(context.broker_attestation_source),
                context.broker_attestation_sha256,
            )
            or not hmac.compare_digest(
                sha256_file(context.callback_attestation_source),
                context.callback_attestation_sha256,
            )
            or context.callback_document.get("case_id") != request.case_id
        ):
            raise KimiBubblewrapLauncherError(
                "launcher, broker, or callback attestation drifted"
            )
        callback_document, callback_sha = self._validate_callback_collector(
            run_id=request.run_id,
            run_root=context.run_root,
        )
        if (
            callback_document != context.callback_document
            or not hmac.compare_digest(callback_sha, context.callback_attestation_sha256)
        ):
            raise KimiBubblewrapLauncherError(
                "callback collector live identity drifted"
            )
        return context

    def _validate_mount_manifest(
        self,
        request: StageLaunchRequest,
        context: _RunContext,
    ) -> tuple[tuple[Path, ...], tuple[Path, ...], int]:
        manifest_path = _owned_path(
            request.materialization_manifest_path,
            run_root=context.run_root,
            label="materialization manifest",
        )
        if (
            manifest_path.parent != context.run_root
            or manifest_path.name != f"manifest-kimi-{request.run_id}.json"
            or manifest_path.is_symlink()
            or not manifest_path.is_file()
        ):
            raise KimiBubblewrapLauncherError(
                "materialization manifest identity is invalid"
            )
        manifest_sha256 = _require_sha256(
            request.materialization_manifest_sha256,
            "materialization manifest SHA-256",
        )
        if not hmac.compare_digest(sha256_file(manifest_path), manifest_sha256):
            raise KimiBubblewrapLauncherError("materialization manifest drifted")
        manifest = _read_json(manifest_path, "materialization manifest")
        if (
            manifest.get("harness_id") != "kimi"
            or manifest.get("run_id") != request.run_id
            or manifest.get("case_id") != request.case_id
            or manifest.get("disposition") != "READY"
            or _require_sha256(
                manifest.get("manifest_payload_sha256"),
                "materialization manifest payload SHA-256",
            )
            != _payload_sha256(manifest, "manifest_payload_sha256")
        ):
            raise KimiBubblewrapLauncherError(
                "materialization manifest run/case identity drifted"
            )
        callback = _require_mapping(
            manifest.get("callback"), "materialization callback"
        )
        if set(callback) != {"origin", "credentials_copied"} or callback.get(
            "credentials_copied"
        ) is not False:
            raise KimiBubblewrapLauncherError(
                "materialization callback boundary drifted"
            )
        callback_origin = _require_string(
            callback.get("origin"), "materialization callback origin"
        )
        try:
            parsed_callback = urlsplit(callback_origin)
            callback_port = parsed_callback.port
            callback_username = parsed_callback.username
            callback_password = parsed_callback.password
        except ValueError as exc:
            raise KimiBubblewrapLauncherError(
                "materialization callback URL is malformed"
            ) from exc
        if (
            parsed_callback.scheme != "http"
            or parsed_callback.hostname != "127.0.0.1"
            or callback_port is None
            or not 1024 <= callback_port <= 65535
            or callback_username is not None
            or callback_password is not None
            or parsed_callback.fragment
            or parsed_callback.query
            or any(character in callback_origin for character in "\r\n\0")
        ):
            raise KimiBubblewrapLauncherError(
                "materialization callback is not an exact uncredentialed loopback URL"
            )
        materialized = _require_mapping(
            manifest.get("materialized"), "materialized case record"
        )
        case_dir = _owned_path(
            _require_string(materialized.get("case_dir"), "materialized case path"),
            run_root=context.run_root,
            label="materialized case path",
        )
        workspace = _owned_path(
            _require_string(
                materialized.get("workspace_dir"), "materialized workspace path"
            ),
            run_root=context.run_root,
            label="materialized workspace path",
        )
        raw_stages = manifest.get("stages")
        if not isinstance(raw_stages, list):
            raise KimiBubblewrapLauncherError("materialization stages are malformed")
        matching_stages = [
            _require_mapping(raw, "materialization stage")
            for raw in raw_stages
            if isinstance(raw, Mapping) and raw.get("index") == request.stage_index
        ]
        if len(matching_stages) != 1:
            raise KimiBubblewrapLauncherError("current stage is not unique in manifest")
        stage = matching_stages[0]
        if stage.get("name") != request.stage_name or stage.get("disposition") != "READY":
            raise KimiBubblewrapLauncherError("current stage identity drifted")
        stage_root = _owned_path(
            _require_string(stage.get("stage_root"), "current stage root"),
            run_root=context.run_root,
            label="current stage root",
        )
        runtime = _require_mapping(stage.get("runtime_paths"), "stage runtime paths")
        runtime_root = _owned_path(
            Path(_require_string(runtime.get("trace"), "stage trace path")).parent,
            run_root=context.run_root,
            label="current stage runtime root",
        )
        prompt = _require_mapping(stage.get("prompt"), "stage prompt")
        assets_root = _owned_path(
            Path(
                _require_string(
                    prompt.get("materialized_path"), "stage prompt materialized path"
                )
            ).parent,
            run_root=context.run_root,
            label="current stage assets root",
        )
        stage_prefix = f"stage-kimi-{request.run_id}-stage-{request.stage_index:03d}-"
        if (
            stage_root.parent != context.run_root
            or not stage_root.name.startswith(stage_prefix)
            or runtime_root.parent != stage_root
            or assets_root.parent != stage_root
            or not runtime_root.name.startswith(
                f"runtime-kimi-{request.run_id}-stage-{request.stage_index:03d}-"
            )
            or not assets_root.name.startswith(
                f"assets-kimi-{request.run_id}-stage-{request.stage_index:03d}-"
            )
            or Path(request.cwd).resolve(strict=True) != workspace
        ):
            raise KimiBubblewrapLauncherError(
                "current stage mount roots differ from verified manifest"
            )

        Expected = tuple[str, str, str, str | None, int | None]
        expected_write: dict[Path, Expected] = {}
        expected_read_only: dict[Path, Expected] = {}

        def add_expected(
            collection: dict[Path, Expected],
            *,
            path: Path,
            kind: str,
            path_type: str,
            provenance: str,
            digest: str | None = None,
            mode: int | None = None,
        ) -> None:
            resolved = _owned_path(path, run_root=context.run_root, label=f"{kind} mount")
            record = (kind, path_type, provenance, digest, mode)
            prior = collection.get(resolved)
            if prior is not None and prior != record:
                raise KimiBubblewrapLauncherError(
                    "manifest assigns conflicting provenance to one mount"
                )
            collection[resolved] = record

        add_expected(
            expected_write,
            path=workspace,
            kind="workspace",
            path_type="tree",
            provenance="verified_materialized_workspace_v1",
        )
        add_expected(
            expected_write,
            path=runtime_root,
            kind="current_stage_runtime",
            path_type="tree",
            provenance="verified_current_stage_runtime_v1",
        )
        surfaces = _require_mapping(stage.get("surfaces"), "stage surfaces")
        session = _require_mapping(surfaces.get("session", {}), "session surface")
        kimi_home = _owned_path(
            _require_string(runtime.get("kimi_home"), "stage Kimi home"),
            run_root=context.run_root,
            label="stage Kimi home",
        )
        session_path = _owned_path(
            _require_string(runtime.get("session"), "stage session path"),
            run_root=context.run_root,
            label="stage session path",
        )
        if not _is_relative_to(kimi_home, runtime_root):
            if (
                session.get("state_scope") != "run_local_shared_native_session"
                or kimi_home.parent != context.run_root
                or kimi_home.name
                != f"config-kimi-{request.run_id}-native-session"
                or not _is_relative_to(session_path, kimi_home)
            ):
                raise KimiBubblewrapLauncherError(
                    "shared native session is not manifest-bound"
                )
            add_expected(
                expected_write,
                path=kimi_home,
                kind="shared_native_session",
                path_type="tree",
                provenance="verified_shared_native_session_surface_v1",
            )
        elif not _is_relative_to(session_path, runtime_root):
            raise KimiBubblewrapLauncherError("stage session escapes current runtime")

        add_expected(
            expected_read_only,
            path=assets_root,
            kind="current_stage_assets",
            path_type="tree",
            provenance="verified_current_stage_assets_v1",
        )
        reviewed_stage_files = stage.get("read_only_mount_files", [])
        if not isinstance(reviewed_stage_files, list):
            raise KimiBubblewrapLauncherError(
                "stage reviewed read-only files are malformed"
            )
        for raw_file in reviewed_stage_files:
            record = _require_mapping(raw_file, "reviewed stage file")
            declarations = record.get("declarations")
            mode = record.get("mode")
            if (
                set(record)
                != {
                    "kind",
                    "path",
                    "sha256",
                    "mode",
                    "provenance",
                    "declarations",
                }
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
            ):
                raise KimiBubblewrapLauncherError(
                    "reviewed stage file provenance is malformed"
                )
            add_expected(
                expected_read_only,
                path=Path(
                    _require_string(record.get("path"), "reviewed stage file path")
                ),
                kind="reviewed_stage_file",
                path_type="file",
                provenance="verified_case_declared_stage_file_v1",
                digest=_require_sha256(
                    record.get("sha256"), "reviewed stage file SHA-256"
                ),
                mode=mode,
            )
        mcp = _require_mapping(surfaces.get("mcp"), "stage MCP surface")
        activation = _require_mapping(mcp.get("activation"), "MCP activation")
        if activation.get("operation") == "replace_file":
            prepared = _require_mapping(
                mcp.get("prepared_config"), "prepared MCP config"
            )
            proxy = _require_mapping(
                prepared.get("evidence_proxy"), "prepared MCP proxy"
            )
            proxy_path = Path(
                _require_string(
                    proxy.get("run_local_proxy_copy_path"),
                    "run-local MCP proxy path",
                )
            )
            add_expected(
                expected_read_only,
                path=proxy_path,
                kind="run_local_mcp_proxy",
                path_type="file",
                provenance="verified_run_local_mcp_proxy_copy_v1",
                digest=_require_sha256(
                    proxy.get("run_local_proxy_copy_sha256"),
                    "run-local MCP proxy SHA-256",
                ),
                mode=0o400,
            )
            proxy_contract = _require_mapping(
                mcp.get("evidence_proxy"), "MCP evidence proxy contract"
            )
            reservations = proxy_contract.get("server_reservations")
            if not isinstance(reservations, list) or not reservations:
                raise KimiBubblewrapLauncherError(
                    "MCP stage has no child file reservations"
                )
            for raw_reservation in reservations:
                reservation = _require_mapping(
                    raw_reservation, "MCP server reservation"
                )
                required_files = reservation.get("required_run_local_files")
                if not isinstance(required_files, list) or not required_files:
                    raise KimiBubblewrapLauncherError(
                        "MCP reservation has no child file allowlist"
                    )
                for raw_file in required_files:
                    record = _require_mapping(raw_file, "MCP child file record")
                    if (
                        record.get("kind") != "reviewed_mcp_child_file"
                        or record.get("provenance")
                        != "materialized_canonical_mcp_argument_v1"
                    ):
                        raise KimiBubblewrapLauncherError(
                            "MCP child file provenance is not reviewed"
                        )
                    mode = record.get("mode")
                    if not isinstance(mode, int) or isinstance(mode, bool):
                        raise KimiBubblewrapLauncherError(
                            "MCP child file mode is malformed"
                        )
                    add_expected(
                        expected_read_only,
                        path=Path(
                            _require_string(record.get("path"), "MCP child file path")
                        ),
                        kind="mcp_child_file",
                        path_type="file",
                        provenance="verified_mcp_child_file_record_v1",
                        digest=_require_sha256(
                            record.get("sha256"), "MCP child file SHA-256"
                        ),
                        mode=mode,
                    )
        elif activation.get("operation") != "remove_file_if_present":
            raise KimiBubblewrapLauncherError("MCP activation operation is invalid")

        all_stage_roots = {
            _owned_path(
                _require_string(item.get("stage_root"), "materialization stage root"),
                run_root=context.run_root,
                label="materialization stage root",
            )
            for item in (
                _require_mapping(raw, "materialization stage") for raw in raw_stages
            )
        }

        def validate_mounts(
            mounts: tuple[StageMount, ...],
            *,
            expected: Mapping[Path, Expected],
            allowed_kinds: frozenset[str],
            access: str,
        ) -> tuple[Path, ...]:
            if not isinstance(mounts, tuple) or len(mounts) != len(expected):
                raise KimiBubblewrapLauncherError(
                    f"{access} mount allowlist differs from manifest"
                )
            observed: dict[Path, Expected] = {}
            for mount in mounts:
                if not isinstance(mount, StageMount) or mount.kind not in allowed_kinds:
                    raise KimiBubblewrapLauncherError(
                        f"{access} mount kind is invalid"
                    )
                path = _owned_path(
                    mount.path,
                    run_root=context.run_root,
                    label=f"{access} {mount.kind} mount",
                )
                if (
                    path in observed
                    or path in {context.run_root, case_dir, stage_root, manifest_path}
                    or path.name == "case_meta.json"
                    or path.name.startswith("manifest-")
                    or "control-plan" in path.name.casefold()
                    or any(
                        part.casefold() in _OTHER_HARNESS_PATH_PARTS
                        for part in path.parts
                    )
                    or any(
                        other != stage_root and _is_relative_to(path, other)
                        for other in all_stage_roots
                    )
                ):
                    raise KimiBubblewrapLauncherError(
                        f"{access} mount exposes a forbidden or non-current path"
                    )
                expected_record = expected.get(path)
                if expected_record is None:
                    raise KimiBubblewrapLauncherError(
                        f"{access} mount is not declared by current stage manifest"
                    )
                kind, path_type, provenance, expected_digest, expected_mode = (
                    expected_record
                )
                if (
                    mount.kind != kind
                    or mount.path_type != path_type
                    or mount.provenance != provenance
                    or mount.provenance_sha256 != manifest_sha256
                    or _require_sha256(mount.sha256, f"{access} mount SHA-256")
                    != mount.sha256
                    or not isinstance(mount.mode, int)
                    or isinstance(mount.mode, bool)
                    or mount.mode != stat.S_IMODE(path.stat().st_mode)
                ):
                    raise KimiBubblewrapLauncherError(
                        f"{access} mount metadata or provenance drifted"
                    )
                if path_type == "tree":
                    if path.is_symlink() or not path.is_dir():
                        raise KimiBubblewrapLauncherError(
                            f"{access} tree mount is unsafe"
                        )
                    observed_digest = (
                        runtime_tree_sha256(path)
                        if mount.kind == "workspace"
                        else tree_sha256(path)
                    )
                elif path_type == "file":
                    if path.is_symlink() or not path.is_file():
                        raise KimiBubblewrapLauncherError(
                            f"{access} file mount is unsafe"
                        )
                    observed_digest = sha256_file(path)
                else:
                    raise KimiBubblewrapLauncherError(
                        f"{access} mount path type is invalid"
                    )
                if (
                    not hmac.compare_digest(observed_digest, mount.sha256)
                    or (
                        expected_digest is not None
                        and not hmac.compare_digest(observed_digest, expected_digest)
                    )
                    or (expected_mode is not None and mount.mode != expected_mode)
                ):
                    raise KimiBubblewrapLauncherError(
                        f"{access} mount content or mode drifted"
                    )
                observed[path] = expected_record
            if observed != dict(expected):
                raise KimiBubblewrapLauncherError(
                    f"{access} mount allowlist is incomplete"
                )
            return tuple(sorted(observed, key=str))

        write_paths = validate_mounts(
            request.write_mounts,
            expected=expected_write,
            allowed_kinds=_WRITE_MOUNT_KINDS,
            access="writable",
        )
        read_only_paths = validate_mounts(
            request.read_only_mounts,
            expected=expected_read_only,
            allowed_kinds=_READ_ONLY_MOUNT_KINDS,
            access="read-only",
        )
        all_paths = (*write_paths, *read_only_paths)
        for index, path in enumerate(all_paths):
            if any(
                _is_relative_to(path, other) or _is_relative_to(other, path)
                for other in all_paths[index + 1 :]
            ):
                raise KimiBubblewrapLauncherError("stage mount paths overlap")
        return write_paths, read_only_paths, callback_port

    def _validate_request(
        self, request: StageLaunchRequest, context: _RunContext
    ) -> tuple[tuple[Path, ...], tuple[Path, ...], int]:
        if (
            request.run_id != context.run_id
            or not isinstance(request.stage_index, int)
            or isinstance(request.stage_index, bool)
            or request.stage_index < 0
            or not isinstance(request.timeout_seconds, int)
            or isinstance(request.timeout_seconds, bool)
            or request.timeout_seconds < 1
            or not request.argv
            or any(not isinstance(item, str) or not item or "\0" in item for item in request.argv)
        ):
            raise KimiBubblewrapLauncherError("stage launch request identity is invalid")
        stage_key = (request.run_id, context.run_root, request.stage_index)
        if stage_key in self._spawned_stages:
            raise KimiBubblewrapLauncherError("stage process was already launched")
        writable_paths, read_only_paths, callback_port = self._validate_mount_manifest(
            request, context
        )
        cwd = _owned_path(request.cwd, run_root=context.run_root, label="stage cwd")
        if not cwd.is_dir():
            raise KimiBubblewrapLauncherError("stage cwd is not a directory")
        for label, path in (
            ("stage stdout", request.stdout_path),
            ("stage wire", request.wire_copy_path),
            ("stage result", request.result_path),
        ):
            candidate = _owned_path(
                Path(path).parent,
                run_root=context.run_root,
                label=f"{label} parent",
            ) / Path(path).name
            if candidate.exists() or candidate.is_symlink():
                raise KimiBubblewrapLauncherError(f"{label} already exists")
            if not any(_is_relative_to(candidate.parent, root) for root in writable_paths):
                raise KimiBubblewrapLauncherError(
                    f"{label} is outside the explicit writable mount allowlist"
                )
        executable = Path(request.argv[0]).resolve(strict=True)
        executable_sha256 = _require_sha256(
            request.executable_sha256, "stage executable SHA-256"
        )
        allowed_executable = any(
            _is_relative_to(executable, source.resolve(strict=True))
            for source in self.system_runtime_roots
        ) or any(
            _is_relative_to(executable, root)
            for root in (*writable_paths, *read_only_paths)
        )
        under_usr_local = _is_relative_to(
            executable, Path("/usr/local").resolve(strict=True)
        )
        if (
            not executable.is_file()
            or not os.access(executable, os.X_OK)
            or not allowed_executable
            or not hmac.compare_digest(sha256_file(executable), executable_sha256)
            or (
                under_usr_local
                and (
                    self.reviewed_kimi_entrypoint_path is None
                    or executable != self.reviewed_kimi_entrypoint_path
                    or executable_sha256 != self.reviewed_kimi_entrypoint_sha256
                    or self.reviewed_kimi_package_root is None
                    or self.reviewed_kimi_package_tree_sha256 is None
                    or not hmac.compare_digest(
                        tree_sha256(self.reviewed_kimi_package_root),
                        self.reviewed_kimi_package_tree_sha256,
                    )
                    or self.reviewed_node_executable_path is None
                    or self.reviewed_node_executable_sha256 is None
                    or not hmac.compare_digest(
                        sha256_file(self.reviewed_node_executable_path),
                        self.reviewed_node_executable_sha256,
                    )
                )
            )
        ):
            raise KimiBubblewrapLauncherError("stage executable is outside allowed runtime mounts")
        environment = request.env
        if not isinstance(environment, Mapping) or set(environment) != _STAGE_ENV_KEYS:
            raise KimiBubblewrapLauncherError("stage environment field set drifted")
        if any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or "\0" in key
            or "\0" in value
            for key, value in environment.items()
        ):
            raise KimiBubblewrapLauncherError("stage environment contains invalid text")
        if any(_SENSITIVE_ENV_RE.search(key) for key in environment) or any(
            _OTHER_HARNESS_ENV_RE.search(key) for key in environment
        ):
            raise KimiBubblewrapLauncherError("credential/other-harness environment reached launcher")
        if (
            environment.get("SAFETY_BENCH_HARNESS") != "kimi"
            or environment.get("SAFETY_BENCH_RUN_ID") != request.run_id
            or environment.get("KIMI_DISABLE_TELEMETRY") != "1"
        ):
            raise KimiBubblewrapLauncherError("stage environment identity drifted")
        for key in _ENV_PATH_KEYS:
            path = _owned_path(
                environment[key], run_root=context.run_root, label=f"stage {key}"
            )
            if not path.is_dir():
                raise KimiBubblewrapLauncherError(f"stage {key} is not a directory")
            if not any(_is_relative_to(path, root) for root in writable_paths):
                raise KimiBubblewrapLauncherError(
                    f"stage {key} is outside the explicit writable mount allowlist"
                )
        path_entries = environment["PATH"].split(os.pathsep)
        if not path_entries or any(
            not entry
            or not Path(entry).is_absolute()
            or not any(
                _is_relative_to(Path(entry).resolve(strict=False), root.resolve(strict=True))
                for root in self.system_runtime_roots
            )
            for entry in path_entries
        ):
            raise KimiBubblewrapLauncherError("stage PATH escapes read-only system runtime")
        return writable_paths, read_only_paths, callback_port

    def spawn(self, request: StageLaunchRequest) -> BubblewrapStageProcess:
        context = self._context_for_request(request)
        writable_paths, read_only_paths, callback_port = self._validate_request(
            request, context
        )
        stage_key = (request.run_id, context.run_root, request.stage_index)
        provider_lease = self._issue_nonce(
            self.broker,
            run_id=request.run_id,
            stage_index=request.stage_index,
            purpose="model_relay",
        )
        try:
            callback_lease = self._issue_nonce(
                self.callback_collector,
                run_id=request.run_id,
                stage_index=request.stage_index,
                purpose="callback_relay",
            )
        except BaseException:
            try:
                os.close(provider_lease.fd)
            except OSError:
                pass
            self._release_nonce(
                self.broker,
                provider_lease,
                run_id=request.run_id,
                stage_index=request.stage_index,
                purpose="model_relay",
            )
            raise
        relay_port = 20000 + (
            int(
                hashlib.sha256(
                    f"kimi:{request.run_id}:{request.stage_index}".encode("utf-8")
                ).hexdigest()[:8],
                16,
            )
            % 30000
        )
        if relay_port == callback_port:
            relay_port = 20000 + ((relay_port - 20000 + 1) % 30000)
        environment = dict(request.env)
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
            }
        )
        released = False

        def release(*, wait_for_callback: bool = True) -> None:
            nonlocal released
            if released:
                return
            released = True
            errors: list[BaseException] = []
            if wait_for_callback:
                try:
                    self.callback_collector.wait_for_stage_manifest(
                        request.stage_index, timeout=5.0
                    )
                except BaseException as exc:
                    errors.append(exc)
            for authority, lease, purpose in (
                (self.broker, provider_lease, "model_relay"),
                (self.callback_collector, callback_lease, "callback_relay"),
            ):
                try:
                    self._release_nonce(
                        authority,
                        lease,
                        run_id=request.run_id,
                        stage_index=request.stage_index,
                        purpose=purpose,
                    )
                except BaseException as exc:
                    errors.append(exc)
            if errors:
                raise KimiBubblewrapLauncherError(
                    "stage relay/callback cleanup failed closed"
                ) from errors[0]

        try:
            command = self._base_bwrap_argv(
                run_id=request.run_id,
                launcher_dir=context.launcher_dir,
                helper_copy=context.helper_copy,
                provider_nonce_fd=provider_lease.fd,
                callback_nonce_fd=callback_lease.fd,
                cwd=request.cwd,
                environment=environment,
                writable_paths=writable_paths,
                read_only_paths=read_only_paths,
                protect_launcher_dir=True,
            )
            command.extend(
                (
                    "run",
                    "--run-id",
                    request.run_id,
                    "--stage-index",
                    str(request.stage_index),
                    "--relay-port",
                    str(relay_port),
                    "--callback-port",
                    str(callback_port),
                    "--model-name",
                    self.model_name,
                    "--",
                    *request.argv,
                )
            )
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(provider_lease.fd, callback_lease.fd),
                env={
                    "SAFETY_BENCH_HARNESS": "kimi",
                    "SAFETY_BENCH_RUN_ID": request.run_id,
                },
                start_new_session=True,
            )
        except BaseException as exc:
            release(wait_for_callback=False)
            if isinstance(exc, OSError):
                raise KimiBubblewrapUnavailable(
                    "bubblewrap stage could not start"
                ) from exc
            raise
        finally:
            for descriptor in (provider_lease.fd, callback_lease.fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self._spawned_stages.add(stage_key)
        owned = BubblewrapStageProcess(process, release=release)
        self._owned_processes.append(owned)
        return owned

    def resource_snapshot(self) -> Mapping[str, Any]:
        """Return non-scoring ownership state without releasing any resource.

        ``Popen.poll`` is used directly so this observation cannot trigger the
        stage process wrapper's manifest wait or nonce-release callback.
        Completed processes remain included in ``owned_process_count`` until
        the exact launcher ``close`` boundary clears its ownership records.
        """

        active_processes: list[dict[str, Any]] = []
        for owned in tuple(self._owned_processes):
            returncode = owned._process.poll()
            if returncode is None:
                active_processes.append(
                    {
                        "pid": owned.pid,
                        "returncode": None,
                    }
                )
        return {
            "run_id": self.run_id,
            "owned_process_count": len(self._owned_processes),
            "active_processes": active_processes,
            "attested_context_count": len(self._contexts),
            "spawned_stage_count": len(self._spawned_stages),
        }

    def close(self) -> None:
        """Terminate only bwrap processes spawned by this per-case launcher."""

        for process in tuple(self._owned_processes):
            if process.returncode is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
        self._owned_processes.clear()
        self._contexts.clear()
        self._spawned_stages.clear()


__all__ = [
    "BROKER_ATTESTATION_SCHEMA_NAME",
    "BROKER_ATTESTATION_SCHEMA_VERSION",
    "BrokerNonceFD",
    "BubblewrapStageProcess",
    "KimiBubblewrapLauncherError",
    "KimiBubblewrapUnavailable",
    "LinuxBubblewrapLauncher",
    "RunScopedCallbackSink",
    "RunScopedRelayBroker",
    "bubblewrap_namespace_support",
]
