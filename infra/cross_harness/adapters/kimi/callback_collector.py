"""Run-scoped callback evidence collector for isolated Kimi stages.

One collector subprocess belongs to exactly one ``run_id/case_id/trial_id``.
The parent issues one-use nonces as sealed memfds over a private control
socket.  An authenticated stage connection may then send newline-delimited
JSON callback observations over the collector's private AF_UNIX socket.

The worker appends normalized records to a run-local JSONL file.  It removes
credential-bearing HTTP headers, but intentionally preserves callback query
and UTF-8 body text so exact benchmark canaries remain observable.  When the
stage connection closes, the worker atomically publishes a hash/line-count/
hash-chain manifest.  No external network or provider credential is used.
"""

from __future__ import annotations

from array import array
import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Mapping, Sequence


CALLBACK_ATTESTATION_SCHEMA_NAME = (
    "safety_bench_kimi_callback_collector_attestation"
)
CALLBACK_ATTESTATION_SCHEMA_VERSION = 1
CALLBACK_EVIDENCE_SCHEMA_NAME = "safety_bench_kimi_callback_evidence"
CALLBACK_MANIFEST_SCHEMA_NAME = "safety_bench_kimi_callback_evidence_manifest"
CALLBACK_MANIFEST_SCHEMA_VERSION = 1
HANDSHAKE_SCHEMA_NAME = "safety_bench_kimi_relay_handshake"
CALLBACK_ROOT_PREFIX = "b"
CALLBACK_SOCKET_BASENAME = "c.sock"
LINUX_AF_UNIX_PATH_LIMIT = 108
SERVICE_IDENTITY_DIGEST_HEX_LENGTH = 16

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_HTTP_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
_SENSITIVE_HEADER_RE = re.compile(
    r"(?:authorization|cookie|token|secret|password|credential|api[-_]?key)",
    re.IGNORECASE,
)
_MAX_CONTROL_PACKET = 64 * 1024
_MAX_HANDSHAKE_LINE = 64 * 1024
_MAX_RECORD_LINE = 2 * 1024 * 1024
_MAX_BODY_CHARS = 1024 * 1024
_MAX_PATH_CHARS = 8192
_MAX_QUERY_CHARS = 32768
_MAX_HEADERS = 128
_MAX_HEADER_CHARS = 8192


class KimiCallbackCollectorError(RuntimeError):
    """The callback collector could not preserve its evidence boundary."""


@dataclass(frozen=True)
class CallbackNonceFD:
    """Opaque fallback type used only by the standalone worker module."""

    fd: int
    lease_id: str


@dataclass
class _Lease:
    run_id: str
    stage_index: int
    purpose: str
    nonce: bytearray
    consumed: bool = False


def _require_run_id(value: str) -> str:
    if not isinstance(value, str) or _RUN_ID_RE.fullmatch(value) is None:
        raise KimiCallbackCollectorError(
            "run_id must be 1-80 safe ASCII characters"
        )
    return value


def _require_id(value: str, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise KimiCallbackCollectorError(
            f"{label} must be 1-160 safe ASCII characters"
        )
    return value


def callback_identity_digest(run_id: str, case_id: str, trial_id: str) -> str:
    """Return the short directory identity bound to all collector principals."""

    checked_run = _require_run_id(run_id)
    checked_case = _require_id(case_id, "case_id")
    checked_trial = _require_id(trial_id, "trial_id")
    return hashlib.sha256(
        f"{checked_run}\0{checked_case}\0{checked_trial}".encode("utf-8")
    ).hexdigest()[:SERVICE_IDENTITY_DIGEST_HEX_LENGTH]


def callback_root_name(run_id: str, case_id: str, trial_id: str) -> str:
    return f"{CALLBACK_ROOT_PREFIX}-{callback_identity_digest(run_id, case_id, trial_id)}"


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _canonical_sha256(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def _payload_sha256(document: Mapping[str, Any], field: str) -> str:
    return _canonical_sha256({key: value for key, value in document.items() if key != field})


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _process_start_time(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise KimiCallbackCollectorError("collector process is not observable") from exc
    closing = raw.rfind(")")
    fields = raw[closing + 1 :].split() if closing >= 0 else []
    if len(fields) < 20:
        raise KimiCallbackCollectorError("collector process stat is malformed")
    return fields[19]


def _process_cmdline_sha256(pid: int) -> str:
    try:
        content = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as exc:
        raise KimiCallbackCollectorError("collector cmdline is not observable") from exc
    if not content:
        raise KimiCallbackCollectorError("collector cmdline is empty")
    return hashlib.sha256(content).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _reject_symlink_chain(path: Path, *, stop: Path, label: str) -> None:
    candidate = path.absolute()
    boundary = stop.absolute()
    while True:
        if candidate.is_symlink():
            raise KimiCallbackCollectorError(f"{label} has a symlink component")
        if candidate == boundary:
            return
        if candidate.parent == candidate or not _is_relative_to(candidate, boundary):
            raise KimiCallbackCollectorError(f"{label} escapes ownership_root")
        candidate = candidate.parent


def _atomic_json(path: Path, document: Mapping[str, Any], *, replace: bool) -> None:
    if path.is_symlink() or (path.exists() and not replace):
        raise KimiCallbackCollectorError(f"refusing to replace collector evidence: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix="tmp-kimi-callback-"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise KimiCallbackCollectorError("callback evidence append failed")
        view = view[written:]


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _ack_proof(
    nonce: bytes | bytearray,
    *,
    run_id: str,
    stage_index: int,
    purpose: str,
    ok: bool,
) -> str:
    message = "\0".join(
        (
            HANDSHAKE_SCHEMA_NAME,
            run_id,
            str(stage_index),
            purpose,
            "ok" if ok else "rejected",
        )
    ).encode("utf-8")
    return hmac.new(bytes(nonce), message, hashlib.sha256).hexdigest()


def _recv_packet(connection: socket.socket) -> tuple[Mapping[str, Any], list[int]]:
    flags = getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    payload, ancillary, message_flags, _ = connection.recvmsg(
        _MAX_CONTROL_PACKET,
        socket.CMSG_SPACE(array("i", [0]).itemsize),
        flags,
    )
    if not payload or message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise KimiCallbackCollectorError(
            "collector control packet is absent or truncated"
        )
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiCallbackCollectorError("collector control packet is malformed") from exc
    if not isinstance(document, Mapping):
        raise KimiCallbackCollectorError("collector control packet must be an object")
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array("i")
            values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
            descriptors.extend(values)
    return document, descriptors


def _send_packet(
    connection: socket.socket,
    document: Mapping[str, Any],
    *,
    descriptor: int | None = None,
) -> None:
    payload = _canonical_bytes(document)
    ancillary: list[tuple[int, int, bytes]] = []
    if descriptor is not None:
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [descriptor])))
    if connection.sendmsg([payload], ancillary) != len(payload):
        raise KimiCallbackCollectorError("collector control packet was partially sent")


class RunScopedCallbackCollector:
    """Parent handle for one case/trial-owned collector subprocess."""

    def __init__(
        self,
        *,
        ownership_root: Path | str,
        run_id: str,
        case_id: str,
        trial_id: str,
        python_executable: Path | str | None = None,
        startup_timeout: float = 15.0,
    ) -> None:
        self.run_id = _require_run_id(run_id)
        self.case_id = _require_id(case_id, "case_id")
        self.trial_id = _require_id(trial_id, "trial_id")
        ownership = Path(ownership_root).absolute()
        if not ownership.is_dir() or ownership.is_symlink():
            raise KimiCallbackCollectorError(
                "ownership_root must be an existing directory"
            )
        self.ownership_root = ownership.resolve(strict=True)
        if self.ownership_root != ownership or self.ownership_root.stat().st_mode & 0o077:
            raise KimiCallbackCollectorError(
                "ownership_root must be private and symlink-free"
            )
        if (
            "kimi" not in self.ownership_root.as_posix().casefold()
            or self.run_id not in self.ownership_root.as_posix()
            or any(
                part.casefold() in {".claude", ".codex", ".kimi-code"}
                for part in self.ownership_root.parts
            )
        ):
            raise KimiCallbackCollectorError(
                "ownership_root lacks Kimi/run ownership"
            )
        self.root = self.ownership_root / callback_root_name(
            self.run_id, self.case_id, self.trial_id
        )
        _reject_symlink_chain(self.root, stop=self.ownership_root, label="collector root")
        if self.root.exists() or self.root.is_symlink():
            raise KimiCallbackCollectorError("collector root already exists")
        self.socket_path = self.root / CALLBACK_SOCKET_BASENAME
        socket_path_length = len(os.fsencode(self.socket_path))
        if socket_path_length >= LINUX_AF_UNIX_PATH_LIMIT:
            raise KimiCallbackCollectorError(
                f"run-owned callback socket path is {socket_path_length} bytes and "
                "exceeds the Linux AF_UNIX pathname limit (107 bytes); choose "
                "a shorter --result-root or --run-id"
            )
        self.root.mkdir(mode=0o700)
        suffix = f"kimi-{self.run_id}"
        self.attestation_path = self.root / f"callback-attestation-{suffix}.json"
        self.evidence_path = self.root / f"callback-evidence-{suffix}.jsonl"
        self.evidence_manifest_path = (
            self.root / f"callback-manifest-{suffix}.json"
        )
        executable = Path(
            python_executable or getattr(sys, "_base_executable", sys.executable)
        ).resolve(strict=True)
        implementation = Path(__file__).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise KimiCallbackCollectorError("collector Python is unavailable")
        self.process_executable_path = executable
        self.process_executable_sha256 = _file_sha256(executable)
        self.implementation_path = implementation
        self.implementation_sha256 = _file_sha256(implementation)
        parent_control, child_control = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
        )
        parent_control.settimeout(startup_timeout)
        command = [
            str(executable),
            str(implementation),
            "--worker",
            "--control-fd",
            str(child_control.fileno()),
            "--root",
            str(self.root),
            "--run-id",
            self.run_id,
            "--case-id",
            self.case_id,
            "--trial-id",
            self.trial_id,
        ]
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        self._control = parent_control
        self._rpc_lock = threading.Lock()
        self._closed = False
        self._process: subprocess.Popen[bytes] | None = None
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=self.root,
                env=environment,
                close_fds=True,
                pass_fds=(child_control.fileno(),),
                start_new_session=True,
            )
            self.pid = self._process.pid
            self.start_time = _process_start_time(self.pid)
            child_control.close()
            try:
                ready, descriptors = _recv_packet(self._control)
            except KimiCallbackCollectorError as exc:
                try:
                    self._process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                detail = ""
                if self._process.poll() is not None and self._process.stderr is not None:
                    detail = self._process.stderr.read(4096).decode(
                        "utf-8", errors="replace"
                    ).strip()
                raise KimiCallbackCollectorError(
                    "collector exited before readiness "
                    f"(returncode={self._process.poll()}): {detail or 'no diagnostic'}"
                ) from exc
            for descriptor in descriptors:
                os.close(descriptor)
            if (
                set(ready) != {"ok", "operation", "pid"}
                or ready.get("ok") is not True
                or ready.get("operation") != "ready"
                or ready.get("pid") != self.pid
            ):
                raise KimiCallbackCollectorError(
                    "collector worker did not attest readiness"
                )
            self._control.settimeout(10)
            self._validate_live_identity()
            self._validate_initial_evidence()
        except BaseException:
            child_control.close()
            self._stop_owned_process()
            self._control.close()
            self._closed = True
            raise

    def _validate_live_identity(self) -> None:
        if self._process is None or self._process.poll() is not None:
            raise KimiCallbackCollectorError("collector worker is not running")
        if _process_start_time(self.pid) != self.start_time:
            raise KimiCallbackCollectorError("collector PID identity drifted")
        executable = Path(f"/proc/{self.pid}/exe").resolve(strict=True)
        if (
            executable != self.process_executable_path
            or not hmac.compare_digest(
                _file_sha256(executable), self.process_executable_sha256
            )
        ):
            raise KimiCallbackCollectorError("collector executable identity drifted")

    def _validate_initial_evidence(self) -> None:
        for path in (self.attestation_path, self.evidence_path):
            if (
                not path.is_file()
                or path.is_symlink()
                or stat.S_IMODE(path.stat().st_mode) != 0o600
            ):
                raise KimiCallbackCollectorError(
                    "collector evidence is absent or not private"
                )
        if self.evidence_path.stat().st_size != 0:
            raise KimiCallbackCollectorError("new collector evidence must be empty")
        if (
            not self.socket_path.exists()
            or self.socket_path.is_symlink()
            or not stat.S_ISSOCK(self.socket_path.stat().st_mode)
            or stat.S_IMODE(self.socket_path.stat().st_mode) != 0o600
        ):
            raise KimiCallbackCollectorError("collector socket is not private")
        document = json.loads(self.attestation_path.read_text(encoding="utf-8"))
        if (
            document.get("schema_name") != CALLBACK_ATTESTATION_SCHEMA_NAME
            or document.get("run_id") != self.run_id
            or document.get("case_id") != self.case_id
            or document.get("trial_id") != self.trial_id
            or document.get("process", {}).get("pid") != self.pid
            or not hmac.compare_digest(
                str(document.get("attestation_payload_sha256", "")),
                _payload_sha256(document, "attestation_payload_sha256"),
            )
        ):
            raise KimiCallbackCollectorError("collector attestation identity drifted")

    def _rpc(
        self, request: Mapping[str, Any], *, expect_descriptor: bool = False
    ) -> tuple[Mapping[str, Any], int | None]:
        with self._rpc_lock:
            if self._closed:
                raise KimiCallbackCollectorError("collector is closed")
            self._validate_live_identity()
            _send_packet(self._control, request)
            response, descriptors = _recv_packet(self._control)
        if response.get("ok") is not True:
            for descriptor in descriptors:
                os.close(descriptor)
            raise KimiCallbackCollectorError(
                f"collector rejected {request.get('operation')}: {response.get('reason')}"
            )
        if expect_descriptor:
            if len(descriptors) != 1:
                for descriptor in descriptors:
                    os.close(descriptor)
                raise KimiCallbackCollectorError(
                    "collector returned an invalid descriptor set"
                )
            return response, descriptors[0]
        if descriptors:
            for descriptor in descriptors:
                os.close(descriptor)
            raise KimiCallbackCollectorError(
                "collector returned an unexpected descriptor"
            )
        return response, None

    def issue_nonce_fd(
        self, *, run_id: str, stage_index: int, purpose: str
    ) -> CallbackNonceFD:
        if run_id != self.run_id:
            raise KimiCallbackCollectorError("cross-run nonce issuance rejected")
        if purpose != "callback_relay":
            raise KimiCallbackCollectorError(
                "callback collector only issues callback_relay nonces"
            )
        if (
            not isinstance(stage_index, int)
            or isinstance(stage_index, bool)
            or stage_index < 0
        ):
            raise KimiCallbackCollectorError("stage_index must be non-negative")
        response, descriptor = self._rpc(
            {
                "operation": "issue_nonce",
                "run_id": self.run_id,
                "case_id": self.case_id,
                "trial_id": self.trial_id,
                "stage_index": stage_index,
                "purpose": purpose,
            },
            expect_descriptor=True,
        )
        assert descriptor is not None
        lease_id = response.get("lease_id")
        try:
            if (
                not isinstance(lease_id, str)
                or _SAFE_ID_RE.fullmatch(lease_id) is None
                or self.run_id not in lease_id
            ):
                raise KimiCallbackCollectorError(
                    "collector returned an invalid lease id"
                )
            metadata = os.fstat(descriptor)
            seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            required = (
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE
            )
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size != 32
                or flags & fcntl.FD_CLOEXEC == 0
                or seals & required != required
                or os.lseek(descriptor, 0, os.SEEK_CUR) != 0
                or "memfd:" not in os.readlink(f"/proc/self/fd/{descriptor}")
            ):
                raise KimiCallbackCollectorError(
                    "collector returned an unsafe nonce descriptor"
                )
        except BaseException:
            os.close(descriptor)
            raise
        from .isolated_launcher import BrokerNonceFD as LauncherBrokerNonceFD

        return LauncherBrokerNonceFD(fd=descriptor, lease_id=lease_id)

    def release_nonce(
        self,
        lease_id: str,
        *,
        run_id: str,
        stage_index: int,
        purpose: str,
    ) -> None:
        if run_id != self.run_id:
            raise KimiCallbackCollectorError("cross-run nonce release rejected")
        if purpose != "callback_relay":
            raise KimiCallbackCollectorError("nonce purpose mismatch")
        self._rpc(
            {
                "operation": "release_nonce",
                "lease_id": lease_id,
                "run_id": self.run_id,
                "case_id": self.case_id,
                "trial_id": self.trial_id,
                "stage_index": stage_index,
                "purpose": purpose,
            }
        )

    @property
    def active_lease_count(self) -> int:
        response, _ = self._rpc(
            {
                "operation": "status",
                "run_id": self.run_id,
                "case_id": self.case_id,
                "trial_id": self.trial_id,
            }
        )
        count = response.get("active_lease_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise KimiCallbackCollectorError("collector returned an invalid lease count")
        return count

    def verify_evidence_manifest(self) -> Mapping[str, Any]:
        if (
            not self.evidence_manifest_path.is_file()
            or self.evidence_manifest_path.is_symlink()
        ):
            raise KimiCallbackCollectorError("callback evidence manifest is absent")
        try:
            manifest = json.loads(
                self.evidence_manifest_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise KimiCallbackCollectorError(
                "callback evidence manifest is malformed"
            ) from exc
        if not isinstance(manifest, Mapping) or (
            manifest.get("schema_name") != CALLBACK_MANIFEST_SCHEMA_NAME
            or manifest.get("schema_version") != CALLBACK_MANIFEST_SCHEMA_VERSION
            or manifest.get("harness_id") != "kimi"
            or manifest.get("run_id") != self.run_id
            or manifest.get("case_id") != self.case_id
            or manifest.get("trial_id") != self.trial_id
            or Path(str(manifest.get("evidence_path"))).resolve()
            != self.evidence_path.resolve()
            or not hmac.compare_digest(
                str(manifest.get("manifest_payload_sha256", "")),
                _payload_sha256(manifest, "manifest_payload_sha256"),
            )
        ):
            raise KimiCallbackCollectorError("callback evidence manifest identity drifted")
        if self.evidence_path.is_symlink() or not self.evidence_path.is_file():
            raise KimiCallbackCollectorError("callback evidence path is unsafe")
        evidence_metadata = self.evidence_path.stat()
        if (
            manifest.get("evidence_inode") != evidence_metadata.st_ino
            or stat.S_IMODE(evidence_metadata.st_mode) != 0o600
        ):
            raise KimiCallbackCollectorError("callback evidence inode or mode drifted")
        raw = self.evidence_path.read_bytes()
        if not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), str(manifest.get("evidence_sha256", ""))
        ):
            raise KimiCallbackCollectorError("callback evidence SHA-256 drifted")
        lines = raw.splitlines()
        if manifest.get("line_count") != len(lines):
            raise KimiCallbackCollectorError("callback evidence line count drifted")
        previous: str | None = None
        for expected_sequence, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise KimiCallbackCollectorError(
                    "callback evidence contains malformed JSON"
                ) from exc
            if not isinstance(record, Mapping):
                raise KimiCallbackCollectorError("callback record is not an object")
            claimed = record.get("record_sha256")
            calculated = _payload_sha256(record, "record_sha256")
            if (
                record.get("schema_name") != CALLBACK_EVIDENCE_SCHEMA_NAME
                or record.get("run_id") != self.run_id
                or record.get("case_id") != self.case_id
                or record.get("trial_id") != self.trial_id
                or record.get("sequence") != expected_sequence
                or record.get("previous_record_sha256") != previous
                or not isinstance(claimed, str)
                or not hmac.compare_digest(claimed, calculated)
            ):
                raise KimiCallbackCollectorError("callback record hash chain drifted")
            previous = claimed
        if manifest.get("hash_chain_head_sha256") != previous:
            raise KimiCallbackCollectorError("callback evidence chain head drifted")
        return manifest

    def wait_for_stage_manifest(
        self, stage_index: int, *, timeout: float = 5.0
    ) -> Mapping[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.evidence_manifest_path.exists():
                try:
                    document = self.verify_evidence_manifest()
                except KimiCallbackCollectorError:
                    pass
                else:
                    stages = document.get("completed_stage_connections", [])
                    if any(
                        isinstance(item, Mapping)
                        and item.get("stage_index") == stage_index
                        for item in stages
                    ):
                        return document
            time.sleep(0.02)
        raise KimiCallbackCollectorError(
            f"stage {stage_index} callback manifest was not published"
        )

    def _stop_owned_process(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            if _process_start_time(process.pid) != getattr(self, "start_time", None):
                return
            process.terminate()
            process.wait(timeout=3)
        except (KimiCallbackCollectorError, subprocess.TimeoutExpired):
            if process.poll() is None:
                try:
                    if _process_start_time(process.pid) == getattr(
                        self, "start_time", None
                    ):
                        process.kill()
                        process.wait(timeout=3)
                except KimiCallbackCollectorError:
                    pass

    def close(self) -> None:
        if self._closed:
            return
        try:
            try:
                self._rpc(
                    {
                        "operation": "shutdown",
                        "run_id": self.run_id,
                        "case_id": self.case_id,
                        "trial_id": self.trial_id,
                    }
                )
            except (KimiCallbackCollectorError, OSError):
                pass
            if self._process is not None:
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._stop_owned_process()
        finally:
            self._closed = True
            self._control.close()
            if self._process is not None and self._process.stderr is not None:
                self._process.stderr.close()

    def __enter__(self) -> "RunScopedCallbackCollector":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class _Worker:
    def __init__(self, args: argparse.Namespace) -> None:
        self.run_id = _require_run_id(args.run_id)
        self.case_id = _require_id(args.case_id, "case_id")
        self.trial_id = _require_id(args.trial_id, "trial_id")
        self.root = Path(args.root).absolute()
        if (
            not self.root.is_dir()
            or self.root.is_symlink()
            or self.root.resolve(strict=True) != self.root
            or self.root.stat().st_uid != os.getuid()
            or stat.S_IMODE(self.root.stat().st_mode) != 0o700
            or "kimi" not in self.root.as_posix().casefold()
            or self.run_id not in self.root.as_posix()
            or self.root.name
            != callback_root_name(self.run_id, self.case_id, self.trial_id)
        ):
            raise KimiCallbackCollectorError("worker root lacks private Kimi ownership")
        self.control = socket.socket(fileno=args.control_fd)
        if (
            self.control.family != socket.AF_UNIX
            or self.control.type & 0xF != socket.SOCK_SEQPACKET
        ):
            raise KimiCallbackCollectorError(
                "worker control descriptor is not SOCK_SEQPACKET"
            )
        self.control.settimeout(0.25)
        suffix = f"kimi-{self.run_id}"
        self.socket_path = self.root / CALLBACK_SOCKET_BASENAME
        self.attestation_path = self.root / f"callback-attestation-{suffix}.json"
        self.evidence_path = self.root / f"callback-evidence-{suffix}.jsonl"
        self.manifest_path = self.root / f"callback-manifest-{suffix}.json"
        for path in (
            self.socket_path,
            self.attestation_path,
            self.evidence_path,
            self.manifest_path,
        ):
            if path.exists() or path.is_symlink():
                raise KimiCallbackCollectorError("worker output path already exists")
        evidence_flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            evidence_flags |= os.O_NOFOLLOW
        self.evidence_fd = os.open(self.evidence_path, evidence_flags, 0o600)
        self.evidence_inode = os.fstat(self.evidence_fd).st_ino
        self.expected_size = 0
        self.evidence_sha256 = hashlib.sha256(b"").hexdigest()
        self.line_count = 0
        self.chain_head: str | None = None
        self.completed_connections: list[Mapping[str, Any]] = []
        self.expected_manifest_sha256: str | None = None
        self.evidence_lock = threading.Lock()
        self.lease_lock = threading.Lock()
        self.leases: dict[str, _Lease] = {}
        self.active_connection = False
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.server.listen(16)
        self.server.settimeout(0.25)
        self.stop = threading.Event()
        self.connections_lock = threading.Lock()
        self.clients: set[socket.socket] = set()
        self.connection_threads: set[threading.Thread] = set()
        self.data_thread = threading.Thread(target=self._serve_data, daemon=True)

    def _write_attestation(self) -> None:
        pid = os.getpid()
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        implementation = Path(__file__).resolve(strict=True)
        socket_metadata = self.socket_path.stat()
        evidence_metadata = self.evidence_path.stat()
        document: dict[str, Any] = {
            "schema_name": CALLBACK_ATTESTATION_SCHEMA_NAME,
            "schema_version": CALLBACK_ATTESTATION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": self.run_id,
            "case_id": self.case_id,
            "trial_id": self.trial_id,
            "process": {
                "pid": pid,
                "start_time": _process_start_time(pid),
                "executable_path": str(executable),
                "executable_sha256": _file_sha256(executable),
                "cmdline_sha256": _process_cmdline_sha256(pid),
            },
            "implementation": {
                "path": str(implementation),
                "sha256": _file_sha256(implementation),
            },
            "socket": {
                "path": str(self.socket_path),
                "device": socket_metadata.st_dev,
                "inode": socket_metadata.st_ino,
                "uid": socket_metadata.st_uid,
                "gid": socket_metadata.st_gid,
                "mode": stat.S_IMODE(socket_metadata.st_mode),
                "parent_mode": stat.S_IMODE(self.root.stat().st_mode),
            },
            "evidence": {
                "path": str(self.evidence_path),
                "manifest_path": str(self.manifest_path),
                "inode": evidence_metadata.st_ino,
                "mode": stat.S_IMODE(evidence_metadata.st_mode),
                "write_mode": "append_only",
                "body_policy": "preserve_utf8_for_exact_canary_evidence",
                "sensitive_header_policy": "drop_name_and_value",
            },
            "nonce": {
                "purpose": "callback_relay",
                "transport": "sealed_memfd_over_private_control_socket",
                "length_bytes": 32,
                "successful_connections_per_nonce": 1,
                "replay_rejected": True,
                "cross_identity_rejected": True,
            },
        }
        document["attestation_payload_sha256"] = _canonical_sha256(document)
        _atomic_json(self.attestation_path, document, replace=False)

    def _assert_evidence_unchanged(self) -> None:
        metadata = self.evidence_path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_ino != self.evidence_inode
            or metadata.st_size != self.expected_size
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not hmac.compare_digest(
                _file_sha256(self.evidence_path), self.evidence_sha256
            )
        ):
            raise KimiCallbackCollectorError("callback evidence was externally modified")
        if self.manifest_path.exists():
            if self.manifest_path.is_symlink() or self.expected_manifest_sha256 is None:
                raise KimiCallbackCollectorError("callback manifest path was replaced")
            if not hmac.compare_digest(
                _file_sha256(self.manifest_path), self.expected_manifest_sha256
            ):
                raise KimiCallbackCollectorError("callback manifest was externally modified")

    @staticmethod
    def _sanitize_record(document: Mapping[str, Any]) -> Mapping[str, Any]:
        if set(document) != {"method", "path", "query", "headers", "body"}:
            raise KimiCallbackCollectorError("callback record field set drifted")
        method = document.get("method")
        path = document.get("path")
        query = document.get("query")
        headers = document.get("headers")
        body = document.get("body")
        if not isinstance(method, str):
            raise KimiCallbackCollectorError("callback method is not text")
        method = method.upper()
        if _HTTP_METHOD_RE.fullmatch(method) is None:
            raise KimiCallbackCollectorError("callback method is malformed")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or len(path) > _MAX_PATH_CHARS
            or any(character in path for character in "\r\n\0")
        ):
            raise KimiCallbackCollectorError("callback path is malformed")
        if (
            not isinstance(query, str)
            or len(query) > _MAX_QUERY_CHARS
            or any(character in query for character in "\r\n\0")
        ):
            raise KimiCallbackCollectorError("callback query is malformed")
        if (
            not isinstance(body, str)
            or len(body) > _MAX_BODY_CHARS
            or "\0" in body
        ):
            raise KimiCallbackCollectorError("callback body is not bounded UTF-8 text")
        if not isinstance(headers, Mapping) or len(headers) > _MAX_HEADERS:
            raise KimiCallbackCollectorError("callback headers are malformed")
        sanitized_headers: dict[str, str] = {}
        redacted_count = 0
        for raw_name, raw_value in headers.items():
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise KimiCallbackCollectorError("callback header is not text")
            name = raw_name.strip().casefold()
            value = raw_value.strip()
            if (
                not name
                or len(name) > 256
                or len(value) > _MAX_HEADER_CHARS
                or any(character in name + value for character in "\r\n\0")
            ):
                raise KimiCallbackCollectorError("callback header is malformed")
            if _SENSITIVE_HEADER_RE.search(name):
                redacted_count += 1
                continue
            sanitized_headers[name] = value
        return {
            "method": method,
            "path": path,
            "query": query,
            "headers": dict(sorted(sanitized_headers.items())),
            "redacted_header_count": redacted_count,
            "body": body,
        }

    def _append_record(
        self, *, stage_index: int, connection_id: str, document: Mapping[str, Any]
    ) -> str:
        sanitized = self._sanitize_record(document)
        with self.evidence_lock:
            self._assert_evidence_unchanged()
            observed_ns = time.time_ns()
            base: dict[str, Any] = {
                "schema_name": CALLBACK_EVIDENCE_SCHEMA_NAME,
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": self.run_id,
                "case_id": self.case_id,
                "trial_id": self.trial_id,
                "stage_index": stage_index,
                "connection_id": connection_id,
                "sequence": self.line_count + 1,
                "observed_at": datetime.fromtimestamp(
                    observed_ns / 1_000_000_000, timezone.utc
                ).isoformat(),
                "observed_at_unix_ns": observed_ns,
                "previous_record_sha256": self.chain_head,
                **sanitized,
            }
            base["record_sha256"] = _canonical_sha256(base)
            line = _canonical_bytes(base) + b"\n"
            _write_all(self.evidence_fd, line)
            os.fsync(self.evidence_fd)
            self.expected_size += len(line)
            self.line_count += 1
            self.chain_head = str(base["record_sha256"])
            self.evidence_sha256 = _file_sha256(self.evidence_path)
            return self.chain_head

    def _finalize_connection(
        self,
        *,
        stage_index: int,
        connection_id: str,
        opened_at_ns: int,
        first_line: int,
        first_hash: str | None,
        outcome: str,
    ) -> None:
        with self.evidence_lock:
            self._assert_evidence_unchanged()
            closed_at_ns = time.time_ns()
            record_count = self.line_count - first_line + 1 if first_hash else 0
            segment = {
                "stage_index": stage_index,
                "connection_id": connection_id,
                "opened_at_unix_ns": opened_at_ns,
                "closed_at_unix_ns": closed_at_ns,
                "record_count": record_count,
                "first_line": first_line if record_count else None,
                "last_line": self.line_count if record_count else None,
                "first_record_sha256": first_hash,
                "last_record_sha256": self.chain_head if record_count else None,
                "outcome": outcome,
            }
            self.completed_connections.append(segment)
            manifest: dict[str, Any] = {
                "schema_name": CALLBACK_MANIFEST_SCHEMA_NAME,
                "schema_version": CALLBACK_MANIFEST_SCHEMA_VERSION,
                "harness_id": "kimi",
                "run_id": self.run_id,
                "case_id": self.case_id,
                "trial_id": self.trial_id,
                "evidence_path": str(self.evidence_path),
                "evidence_inode": self.evidence_inode,
                "evidence_sha256": self.evidence_sha256,
                "line_count": self.line_count,
                "hash_chain_head_sha256": self.chain_head,
                "completed_stage_connections": list(self.completed_connections),
                "published_at_unix_ns": time.time_ns(),
            }
            manifest["manifest_payload_sha256"] = _canonical_sha256(manifest)
            _atomic_json(self.manifest_path, manifest, replace=True)
            self.expected_manifest_sha256 = _file_sha256(self.manifest_path)

    def _issue(self, request: Mapping[str, Any]) -> tuple[Mapping[str, Any], int]:
        expected = {
            "operation",
            "run_id",
            "case_id",
            "trial_id",
            "stage_index",
            "purpose",
        }
        if set(request) != expected or (
            request.get("run_id") != self.run_id
            or request.get("case_id") != self.case_id
            or request.get("trial_id") != self.trial_id
            or request.get("purpose") != "callback_relay"
            or not isinstance(request.get("stage_index"), int)
            or isinstance(request.get("stage_index"), bool)
            or int(request["stage_index"]) < 0
        ):
            raise KimiCallbackCollectorError("cross-identity nonce issue rejected")
        nonce = bytearray(secrets.token_bytes(32))
        lease_id = f"nonce-kimi-{self.run_id}-{secrets.token_hex(8)}"
        lease = _Lease(
            run_id=self.run_id,
            stage_index=int(request["stage_index"]),
            purpose="callback_relay",
            nonce=nonce,
        )
        with self.lease_lock:
            self.leases[lease_id] = lease
        descriptor = os.memfd_create(
            f"callback-nonce-kimi-{self.run_id}",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        try:
            _write_all(descriptor, nonce)
            os.lseek(descriptor, 0, os.SEEK_SET)
            fcntl.fcntl(
                descriptor,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE,
            )
        except BaseException:
            os.close(descriptor)
            with self.lease_lock:
                removed = self.leases.pop(lease_id, None)
            if removed is not None:
                _wipe(removed.nonce)
            raise
        return {
            "ok": True,
            "operation": "issue_nonce",
            "lease_id": lease_id,
        }, descriptor

    def _release(self, request: Mapping[str, Any]) -> None:
        expected = {
            "operation",
            "lease_id",
            "run_id",
            "case_id",
            "trial_id",
            "stage_index",
            "purpose",
        }
        if set(request) != expected or (
            request.get("run_id") != self.run_id
            or request.get("case_id") != self.case_id
            or request.get("trial_id") != self.trial_id
            or request.get("purpose") != "callback_relay"
        ):
            raise KimiCallbackCollectorError("cross-identity nonce release rejected")
        lease_id = request.get("lease_id")
        if not isinstance(lease_id, str):
            raise KimiCallbackCollectorError("nonce lease id is malformed")
        with self.lease_lock:
            lease = self.leases.get(lease_id)
            if lease is None or (
                lease.run_id != request.get("run_id")
                or lease.stage_index != request.get("stage_index")
                or lease.purpose != request.get("purpose")
            ):
                raise KimiCallbackCollectorError("nonce lease identity mismatch")
            self.leases.pop(lease_id)
        _wipe(lease.nonce)

    def _authorize(
        self, *, run_id: str, stage_index: int, purpose: str, nonce: bytes
    ) -> bool:
        with self.lease_lock:
            for lease in self.leases.values():
                if (
                    lease.run_id == run_id
                    and lease.stage_index == stage_index
                    and lease.purpose == purpose == "callback_relay"
                    and hmac.compare_digest(bytes(lease.nonce), nonce)
                ):
                    if lease.consumed or self.active_connection:
                        return False
                    lease.consumed = True
                    self.active_connection = True
                    return True
        return False

    def _finish_active_connection(self) -> None:
        with self.lease_lock:
            self.active_connection = False

    def _handle_client(self, client: socket.socket) -> None:
        stage_index = -1
        authorized = False
        with client:
            client.settimeout(15)
            buffer = bytearray()
            while b"\n" not in buffer and len(buffer) <= _MAX_HANDSHAKE_LINE:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buffer.extend(chunk)
            line, separator, trailing = bytes(buffer).partition(b"\n")
            if not separator or trailing or len(line) > _MAX_HANDSHAKE_LINE:
                return
            try:
                request = json.loads(line.decode("utf-8"))
                if not isinstance(request, Mapping) or set(request) != {
                    "schema_name",
                    "schema_version",
                    "harness_id",
                    "run_id",
                    "stage_index",
                    "purpose",
                    "nonce",
                }:
                    return
                requested_run = str(request["run_id"])
                stage_index = int(request["stage_index"])
                purpose = str(request["purpose"])
                nonce = base64.b64decode(str(request["nonce"]), validate=True)
            except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                return
            if len(nonce) != 32:
                return
            authorized = (
                request.get("schema_name") == HANDSHAKE_SCHEMA_NAME
                and request.get("schema_version") == 1
                and request.get("harness_id") == "kimi"
                and self._authorize(
                    run_id=requested_run,
                    stage_index=stage_index,
                    purpose=purpose,
                    nonce=nonce,
                )
            )
            response: dict[str, Any] = {
                "schema_name": HANDSHAKE_SCHEMA_NAME,
                "schema_version": 1,
                "ok": authorized,
                "run_id": requested_run,
                "stage_index": stage_index,
                "purpose": purpose,
                "proof": _ack_proof(
                    nonce,
                    run_id=requested_run,
                    stage_index=stage_index,
                    purpose=purpose,
                    ok=authorized,
                ),
            }
            if not authorized:
                response["reason"] = "unauthorized_nonce"
            try:
                client.sendall(_canonical_bytes(response) + b"\n")
            except OSError:
                if authorized:
                    self._finish_active_connection()
                return
            if not authorized:
                return
            connection_id = f"callback-kimi-{self.run_id}-{secrets.token_hex(8)}"
            opened_at_ns = time.time_ns()
            first_line = self.line_count + 1
            first_hash: str | None = None
            outcome = "completed"
            client.settimeout(None)
            reader = None
            try:
                reader = client.makefile("rb")
                while not self.stop.is_set():
                    raw = reader.readline(_MAX_RECORD_LINE + 1)
                    if not raw:
                        break
                    if len(raw) > _MAX_RECORD_LINE or not raw.endswith(b"\n"):
                        outcome = "malformed_record"
                        break
                    try:
                        document = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        outcome = "malformed_record"
                        break
                    if not isinstance(document, Mapping):
                        outcome = "malformed_record"
                        break
                    try:
                        record_hash = self._append_record(
                            stage_index=stage_index,
                            connection_id=connection_id,
                            document=document,
                        )
                    except KimiCallbackCollectorError:
                        outcome = "evidence_integrity_failure"
                        self.stop.set()
                        break
                    if first_hash is None:
                        first_hash = record_hash
            finally:
                if reader is not None:
                    reader.close()
                try:
                    self._finalize_connection(
                        stage_index=stage_index,
                        connection_id=connection_id,
                        opened_at_ns=opened_at_ns,
                        first_line=first_line,
                        first_hash=first_hash,
                        outcome=outcome,
                    )
                except KimiCallbackCollectorError:
                    self.stop.set()
                self._finish_active_connection()

    def _connection_entry(self, client: socket.socket) -> None:
        try:
            self._handle_client(client)
        finally:
            with self.connections_lock:
                self.clients.discard(client)
                self.connection_threads.discard(threading.current_thread())

    def _serve_data(self) -> None:
        while not self.stop.is_set():
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(
                target=self._connection_entry, args=(client,), daemon=True
            )
            with self.connections_lock:
                self.clients.add(client)
                self.connection_threads.add(thread)
            thread.start()

    def _control_loop(self) -> None:
        while not self.stop.is_set():
            try:
                request, descriptors = _recv_packet(self.control)
            except socket.timeout:
                continue
            except (OSError, KimiCallbackCollectorError):
                self.stop.set()
                return
            for descriptor in descriptors:
                os.close(descriptor)
            operation = request.get("operation")
            try:
                if operation == "issue_nonce":
                    response, descriptor = self._issue(request)
                    try:
                        _send_packet(self.control, response, descriptor=descriptor)
                    finally:
                        os.close(descriptor)
                elif operation == "release_nonce":
                    self._release(request)
                    _send_packet(
                        self.control, {"ok": True, "operation": "release_nonce"}
                    )
                elif operation == "status" and set(request) == {
                    "operation",
                    "run_id",
                    "case_id",
                    "trial_id",
                } and (
                    request.get("run_id"),
                    request.get("case_id"),
                    request.get("trial_id"),
                ) == (self.run_id, self.case_id, self.trial_id):
                    with self.lease_lock:
                        count = len(self.leases)
                    _send_packet(
                        self.control,
                        {
                            "ok": True,
                            "operation": "status",
                            "active_lease_count": count,
                        },
                    )
                elif operation == "shutdown" and set(request) == {
                    "operation",
                    "run_id",
                    "case_id",
                    "trial_id",
                } and (
                    request.get("run_id"),
                    request.get("case_id"),
                    request.get("trial_id"),
                ) == (self.run_id, self.case_id, self.trial_id):
                    _send_packet(
                        self.control, {"ok": True, "operation": "shutdown"}
                    )
                    self.stop.set()
                else:
                    raise KimiCallbackCollectorError(
                        "control identity or operation rejected"
                    )
            except KimiCallbackCollectorError as exc:
                _send_packet(
                    self.control,
                    {
                        "ok": False,
                        "operation": str(operation),
                        "reason": type(exc).__name__,
                    },
                )

    def run(self) -> int:
        self._write_attestation()
        self.data_thread.start()
        _send_packet(
            self.control,
            {"ok": True, "operation": "ready", "pid": os.getpid()},
        )
        try:
            self._control_loop()
        finally:
            self.stop.set()
            self.server.close()
            with self.connections_lock:
                clients = tuple(self.clients)
            for client in clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
            self.data_thread.join(timeout=2)
            with self.connections_lock:
                threads = tuple(self.connection_threads)
            for thread in threads:
                thread.join(timeout=2)
            with self.lease_lock:
                leases = tuple(self.leases.values())
                self.leases.clear()
            for lease in leases:
                _wipe(lease.nonce)
            os.close(self.evidence_fd)
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
            self.control.close()
        return 0


def _worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker", action="store_true", required=True)
    parser.add_argument("--control-fd", required=True, type=int)
    parser.add_argument("--root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--trial-id", required=True)
    return parser


def _worker_main(argv: Sequence[str]) -> int:
    args = _worker_parser().parse_args(argv)
    worker = _Worker(args)

    def stop_worker(_signal: int, _frame: object) -> None:
        worker.stop.set()

    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    return worker.run()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--worker" not in arguments:
        raise SystemExit("callback_collector.py is an internal worker")
    try:
        return _worker_main(arguments)
    except KimiCallbackCollectorError as exc:
        print(f"kimi-callback-collector: {exc}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CALLBACK_ATTESTATION_SCHEMA_NAME",
    "CALLBACK_EVIDENCE_SCHEMA_NAME",
    "CALLBACK_MANIFEST_SCHEMA_NAME",
    "CallbackNonceFD",
    "KimiCallbackCollectorError",
    "RunScopedCallbackCollector",
]
