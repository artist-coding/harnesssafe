"""Inside-bubblewrap entry point for the Kimi isolated launcher.

This helper is mounted read-only into an otherwise allowlisted filesystem.  A
per-stage nonce arrives only through bubblewrap's ``--file`` descriptor at the
fixed in-sandbox path below.  The helper reads and unlinks it before either a
self-test or Kimi starts; it never places the nonce in argv, the environment,
or an evidence file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


PROVIDER_NONCE_PATH = Path("/run/kimi/provider-nonce")
CALLBACK_NONCE_PATH = Path("/run/kimi/callback-nonce")
PROVIDER_SOCKET_PATH = Path("/run/kimi/bridge/p.sock")
CALLBACK_SOCKET_PATH = Path("/run/kimi/callback-bridge/c.sock")
# Kept as a compatibility alias for the attestation field name.  Runtime code
# uses the explicit provider/callback names above.
BROKER_SOCKET_PATH = PROVIDER_SOCKET_PATH
_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|credential|bearer|auth)", re.IGNORECASE
)
_HTTP_TOKEN_RE = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HANDSHAKE_SCHEMA = "safety_bench_kimi_relay_handshake"
_MAX_CONTROL_LINE = 64 * 1024
_MAX_HTTP_LINE = 64 * 1024
_MAX_HTTP_HEADERS = 256
_MAX_CALLBACK_HEADERS = 128
_MAX_PROVIDER_BODY = 64 * 1024 * 1024
_MAX_CALLBACK_BODY = 1024 * 1024
_MAX_CALLBACK_RECORD = 2 * 1024 * 1024
_MAX_CALLBACK_PATH = 8192
_MAX_CALLBACK_QUERY = 32768
_MAX_CALLBACK_HEADER_VALUE = 8192
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


class SandboxEntryError(RuntimeError):
    """The sandbox entry point could not preserve its isolation contract."""


def broker_ack_proof(
    nonce: bytes | bytearray,
    *,
    run_id: str,
    stage_index: int,
    purpose: str,
    ok: bool,
) -> str:
    """Return the protocol-v1 acknowledgement proof without exposing ``nonce``."""

    outcome = "ok" if ok else "rejected"
    message = "\0".join(
        (_HANDSHAKE_SCHEMA, run_id, str(stage_index), purpose, outcome)
    ).encode("utf-8")
    return hmac.new(bytes(nonce), message, hashlib.sha256).hexdigest()


def _read_and_remove_nonce(path: Path, *, label: str) -> bytearray:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SandboxEntryError(f"run-local {label} nonce is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != 32:
            raise SandboxEntryError(f"run-local {label} nonce has an invalid shape")
        value = bytearray()
        while len(value) <= 32:
            chunk = os.read(descriptor, 33 - len(value))
            if not chunk:
                break
            value.extend(chunk)
    finally:
        os.close(descriptor)
    try:
        path.unlink()
    except OSError as exc:
        raise SandboxEntryError(f"run-local {label} nonce could not be removed") from exc
    if path.exists() or path.is_symlink():
        raise SandboxEntryError(f"run-local {label} nonce remained visible")
    if len(value) != 32:
        _wipe(value)
        raise SandboxEntryError(f"run-local {label} nonce is not exactly 32 bytes")
    return value


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _recv_control_line(connection: socket.socket) -> Mapping[str, Any]:
    buffer = bytearray()
    while b"\n" not in buffer:
        chunk = connection.recv(4096)
        if not chunk:
            raise SandboxEntryError("broker closed before handshake response")
        buffer.extend(chunk)
        if len(buffer) > _MAX_CONTROL_LINE:
            raise SandboxEntryError("broker handshake response is too large")
    line, _, trailing = bytes(buffer).partition(b"\n")
    if trailing:
        raise SandboxEntryError("broker sent payload before handshake completed")
    try:
        document = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxEntryError("broker handshake response is malformed") from exc
    if not isinstance(document, Mapping):
        raise SandboxEntryError("broker handshake response must be an object")
    return document


def _connect_bridge(
    *,
    socket_path: Path,
    nonce: bytearray,
    run_id: str,
    stage_index: int,
    purpose: str,
) -> socket.socket:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(10)
    try:
        connection.connect(str(socket_path))
        handshake = {
            "schema_name": _HANDSHAKE_SCHEMA,
            "schema_version": 1,
            "harness_id": "kimi",
            "run_id": run_id,
            "stage_index": stage_index,
            "purpose": purpose,
            "nonce": base64.b64encode(bytes(nonce)).decode("ascii"),
        }
        connection.sendall(
            json.dumps(handshake, separators=(",", ":"), sort_keys=True).encode("utf-8")
            + b"\n"
        )
        response = _recv_control_line(connection)
        if (
            response.get("schema_name") != _HANDSHAKE_SCHEMA
            or response.get("ok") is not True
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
                    ok=True,
                ),
            )
        ):
            raise SandboxEntryError("broker rejected the run-local relay handshake")
        connection.settimeout(None)
        return connection
    except Exception:
        connection.close()
        raise


def _connect_broker(
    *, nonce: bytearray, run_id: str, stage_index: int, purpose: str
) -> socket.socket:
    """Compatibility wrapper used by the provider-only self-test."""

    return _connect_bridge(
        socket_path=PROVIDER_SOCKET_PATH,
        nonce=nonce,
        run_id=run_id,
        stage_index=stage_index,
        purpose=purpose,
    )


def _namespace_identifiers() -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("mnt", "pid", "net", "ipc", "uts", "cgroup"):
        try:
            result[name] = os.readlink(f"/proc/self/ns/{name}")
        except OSError as exc:
            raise SandboxEntryError(f"cannot observe {name} namespace") from exc
    return result


def _mount_points() -> list[str]:
    points: list[str] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SandboxEntryError("cannot observe sandbox mount table") from exc
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            raise SandboxEntryError("sandbox mount table is malformed")
        points.append(fields[4].replace("\\040", " "))
    return sorted(set(points))


def _network_interfaces() -> list[str]:
    """Observe interfaces from the new procfs without mounting host sysfs."""

    try:
        lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
    except OSError as exc:
        raise SandboxEntryError("cannot observe sandbox network interfaces") from exc
    interfaces = sorted(
        line.split(":", 1)[0].strip() for line in lines if ":" in line
    )
    if interfaces != ["lo"]:
        raise SandboxEntryError("sandbox network namespace exposes a non-loopback interface")
    return interfaces


def _effective_capabilities() -> str:
    try:
        lines = Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SandboxEntryError("cannot observe sandbox capability state") from exc
    value = next(
        (line.split(":", 1)[1].strip() for line in lines if line.startswith("CapEff:")),
        None,
    )
    if value is None or int(value, 16) != 0:
        raise SandboxEntryError("sandbox process retained Linux capabilities")
    return value


def _open_file_descriptors() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        entries = list(Path("/proc/self/fd").iterdir())
    except OSError as exc:
        raise SandboxEntryError("cannot inspect inherited file descriptors") from exc
    for entry in entries:
        try:
            descriptor = int(entry.name)
        except ValueError:
            continue
        if descriptor <= 2:
            continue
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        result[str(descriptor)] = target
    if any("memfd:" in target or "nonce" in target for target in result.values()):
        raise SandboxEntryError("nonce source descriptor reached sandbox helper")
    return result


def _atomic_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f"tmp-{path.name}-{os.getpid()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _self_test(args: argparse.Namespace, nonce: bytearray) -> int:
    sensitive_keys = sorted(key for key in os.environ if _SENSITIVE_KEY_RE.search(key))
    if sensitive_keys:
        raise SandboxEntryError("credential-like environment keys reached self-test")
    forbidden = {path: Path(path).exists() for path in args.forbidden_path}
    if any(forbidden.values()):
        raise SandboxEntryError("forbidden host state is visible inside bubblewrap")
    connection = _connect_broker(
        nonce=nonce,
        run_id=args.run_id,
        stage_index=-1,
        purpose="attestation",
    )
    connection.close()
    namespaces = _namespace_identifiers()
    mounts = _mount_points()
    interfaces = _network_interfaces()
    effective_capabilities = _effective_capabilities()
    inherited_descriptors = _open_file_descriptors()
    isolation = {
        "schema_name": "safety_bench_kimi_bwrap_isolation_evidence",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": args.run_id,
        "pid_inside_namespace": os.getpid(),
        "namespaces": namespaces,
        "mount_points": mounts,
        "network_interfaces": interfaces,
        "effective_capabilities_hex": effective_capabilities,
        "inherited_nonstandard_file_descriptors": inherited_descriptors,
        "forbidden_paths_visible": forbidden,
        "nonce_file_removed_before_probe": not PROVIDER_NONCE_PATH.exists(),
        "environment_keys": sorted(os.environ),
    }
    broker = {
        "schema_name": "safety_bench_kimi_broker_handshake_evidence",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": args.run_id,
        "transport": "run_scoped_unix_socket",
        "socket_path_inside_sandbox": str(BROKER_SOCKET_PATH),
        "handshake_verified": True,
        "nonce_file_removed_before_handshake": not PROVIDER_NONCE_PATH.exists(),
        "external_credentials_observed": False,
    }
    _atomic_json(Path(args.isolation_output), isolation)
    _atomic_json(Path(args.broker_output), broker)
    return 0


class _BridgeFatalError(SandboxEntryError):
    """The authenticated UDS stream can no longer be safely reused."""


class _SocketReader:
    """Small bounded buffered reader that never reads an unframed body."""

    def __init__(self, connection: socket.socket) -> None:
        self.connection = connection
        self.buffer = bytearray()

    def read_line(self, *, label: str, limit: int = _MAX_HTTP_LINE) -> bytes:
        while b"\n" not in self.buffer:
            if len(self.buffer) > limit:
                raise SandboxEntryError(f"{label} is too large")
            chunk = self.connection.recv(min(65536, limit + 1 - len(self.buffer)))
            if not chunk:
                if not self.buffer:
                    return b""
                raise SandboxEntryError(f"{label} ended unexpectedly")
            self.buffer.extend(chunk)
        line, separator, remainder = bytes(self.buffer).partition(b"\n")
        line += separator
        if len(line) > limit:
            raise SandboxEntryError(f"{label} is too large")
        self.buffer[:] = remainder
        return line

    def read_exact(self, length: int, *, label: str) -> bytes:
        while len(self.buffer) < length:
            chunk = self.connection.recv(min(65536, length - len(self.buffer)))
            if not chunk:
                raise SandboxEntryError(f"{label} ended unexpectedly")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result


def _parse_http_headers(
    reader: _SocketReader,
    *,
    max_headers: int,
) -> tuple[list[tuple[str, str]], int, str | None]:
    headers: list[tuple[str, str]] = []
    observed_names: set[str] = set()
    content_length: int | None = None
    transfer_encoding: str | None = None
    for _ in range(max_headers):
        raw = reader.read_line(label="HTTP header")
        if raw in {b"\r\n", b"\n"}:
            break
        if not raw or raw[:1] in {b" ", b"\t"} or b":" not in raw:
            raise SandboxEntryError("HTTP header is malformed")
        raw_name, raw_value = raw.rstrip(b"\r\n").split(b":", 1)
        if not _HTTP_TOKEN_RE.fullmatch(raw_name):
            raise SandboxEntryError("HTTP header name is malformed")
        name = raw_name.decode("ascii")
        lowered = name.casefold()
        if lowered in observed_names:
            raise SandboxEntryError("duplicate HTTP header rejected")
        observed_names.add(lowered)
        try:
            value = raw_value.strip().decode("latin-1")
        except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 is total
            raise SandboxEntryError("HTTP header value is malformed") from exc
        if any(character in value for character in "\r\n\0"):
            raise SandboxEntryError("HTTP header value is malformed")
        if lowered == "content-length":
            if not value.isascii() or not value.isdigit():
                raise SandboxEntryError("Content-Length is malformed")
            content_length = int(value)
        elif lowered == "transfer-encoding":
            transfer_encoding = value.casefold()
        headers.append((name, value))
    else:
        raise SandboxEntryError("too many HTTP headers")
    return headers, content_length or 0, transfer_encoding


def _read_http_request(
    client: socket.socket,
    *,
    max_body: int,
    max_headers: int = _MAX_HTTP_HEADERS,
) -> tuple[str, str, list[tuple[str, str]], bytes]:
    reader = _SocketReader(client)
    line = reader.read_line(label="HTTP request line")
    try:
        method, target, version = line.rstrip(b"\r\n").decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise SandboxEntryError("HTTP request line is malformed") from exc
    parsed = urlsplit(target)
    if (
        method not in {"GET", "POST"}
        or version != "HTTP/1.1"
        or not target.startswith("/")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or ".." in parsed.path.split("/")
        or any(character in target for character in "\r\n\0")
    ):
        raise SandboxEntryError("HTTP request target or method is not allowed")
    headers, content_length, transfer_encoding = _parse_http_headers(
        reader, max_headers=max_headers
    )
    if transfer_encoding is not None:
        raise SandboxEntryError("chunked client requests are not accepted")
    if any(name.casefold() == "expect" for name, _ in headers):
        raise SandboxEntryError("Expect requests are not accepted")
    if content_length < 0 or content_length > max_body:
        raise SandboxEntryError("HTTP request body is too large")
    body = reader.read_exact(content_length, label="HTTP request body")
    if reader.buffer:
        raise SandboxEntryError("pipelined HTTP requests are not accepted")
    return method, target, headers, body


def _send_http_error(client: socket.socket, status: int) -> None:
    phrases = {400: "Bad Request", 502: "Bad Gateway"}
    phrase = phrases.get(status, "Rejected")
    body = b'{"error":"request rejected"}'
    client.sendall(
        f"HTTP/1.1 {status} {phrase}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )


def _normalized_request_bytes(
    method: str,
    target: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    output = bytearray(f"{method} {target} HTTP/1.1\r\n".encode("ascii"))
    for name, value in headers:
        lowered = name.casefold()
        if lowered not in _HOP_BY_HOP_HEADERS | {
            "authorization",
            "content-length",
            "host",
            "proxy-connection",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        }:
            output.extend(f"{name}: {value}\r\n".encode("latin-1"))
    output.extend(f"Content-Length: {len(body)}\r\n".encode("ascii"))
    output.extend(b"Connection: keep-alive\r\n\r\n")
    output.extend(body)
    return bytes(output)


def _read_chunked_body(reader: _SocketReader) -> bytes:
    body = bytearray()
    while True:
        line = reader.read_line(label="HTTP chunk size")
        token = line.rstrip(b"\r\n").split(b";", 1)[0].strip()
        if not token or len(token) > 16 or any(
            character not in b"0123456789abcdefABCDEF" for character in token
        ):
            raise _BridgeFatalError("provider response chunk size is malformed")
        size = int(token, 16)
        if size > _MAX_PROVIDER_BODY - len(body):
            raise _BridgeFatalError("provider response body is too large")
        if size == 0:
            for _ in range(_MAX_HTTP_HEADERS):
                trailer = reader.read_line(label="HTTP trailer")
                if trailer in {b"\r\n", b"\n"}:
                    return bytes(body)
                if not trailer or trailer[:1] in {b" ", b"\t"} or b":" not in trailer:
                    raise _BridgeFatalError("provider response trailer is malformed")
            raise _BridgeFatalError("too many provider response trailers")
        body.extend(reader.read_exact(size, label="HTTP chunk body"))
        if reader.read_exact(2, label="HTTP chunk terminator") != b"\r\n":
            raise _BridgeFatalError("provider response chunk terminator is malformed")


def _read_provider_response(
    reader: _SocketReader,
) -> tuple[str, list[tuple[str, str]], bytes, bool]:
    line = reader.read_line(label="HTTP response line")
    try:
        version, raw_status, reason = (
            line.rstrip(b"\r\n").decode("latin-1").split(" ", 2)
        )
        status = int(raw_status)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _BridgeFatalError("provider response line is malformed") from exc
    if (
        version != "HTTP/1.1"
        or not 100 <= status <= 599
        or any(character in reason for character in "\r\n\0")
    ):
        raise _BridgeFatalError("provider response line is malformed")
    headers, content_length, transfer_encoding = _parse_http_headers(
        reader, max_headers=_MAX_HTTP_HEADERS
    )
    if transfer_encoding is not None and transfer_encoding != "chunked":
        raise _BridgeFatalError("provider response transfer encoding is unsupported")
    has_content_length = any(name.casefold() == "content-length" for name, _ in headers)
    if transfer_encoding is not None and has_content_length:
        raise _BridgeFatalError("provider response framing is ambiguous")
    if transfer_encoding == "chunked":
        body = _read_chunked_body(reader)
    elif has_content_length:
        if content_length > _MAX_PROVIDER_BODY:
            raise _BridgeFatalError("provider response body is too large")
        body = reader.read_exact(content_length, label="HTTP response body")
    elif status in {*range(100, 200), 204, 304}:
        body = b""
    else:
        raise _BridgeFatalError("provider response has no bounded body framing")
    if reader.buffer:
        raise _BridgeFatalError("provider response framing has trailing bytes")
    connection_close = any(
        name.casefold() == "connection"
        and any(token.strip() == "close" for token in value.casefold().split(","))
        for name, value in headers
    )
    status_line = f"{status} {reason}".rstrip()
    return status_line, headers, body, connection_close


class _ProviderHandler:
    def __init__(self, bridge: socket.socket) -> None:
        self.bridge = bridge
        self.reader = _SocketReader(bridge)
        self.reusable = True

    def __call__(self, client: socket.socket) -> None:
        method, target, headers, body = _read_http_request(
            client, max_body=_MAX_PROVIDER_BODY
        )
        if not self.reusable:
            raise _BridgeFatalError("provider bridge is no longer reusable")
        try:
            self.bridge.sendall(_normalized_request_bytes(method, target, headers, body))
            status_line, response_headers, response_body, connection_close = (
                _read_provider_response(self.reader)
            )
        except (OSError, SandboxEntryError) as exc:
            self.reusable = False
            if isinstance(exc, _BridgeFatalError):
                raise
            raise _BridgeFatalError("provider bridge transport failed") from exc
        output = bytearray(f"HTTP/1.1 {status_line}\r\n".encode("latin-1"))
        for name, value in response_headers:
            if name.casefold() not in _HOP_BY_HOP_HEADERS | {"content-length"}:
                output.extend(f"{name}: {value}\r\n".encode("latin-1"))
        output.extend(f"Content-Length: {len(response_body)}\r\n".encode("ascii"))
        output.extend(b"Connection: close\r\n\r\n")
        output.extend(response_body)
        client.sendall(output)
        if connection_close:
            self.reusable = False


class _CallbackHandler:
    def __init__(self, bridge: socket.socket) -> None:
        self.bridge = bridge

    def __call__(self, client: socket.socket) -> None:
        method, target, headers, body = _read_http_request(
            client,
            max_body=_MAX_CALLBACK_BODY,
            max_headers=_MAX_CALLBACK_HEADERS,
        )
        parsed = urlsplit(target)
        try:
            body_text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SandboxEntryError("callback body is not UTF-8") from exc
        if (
            len(parsed.path or "/") > _MAX_CALLBACK_PATH
            or len(parsed.query) > _MAX_CALLBACK_QUERY
            or "\0" in body_text
            or any(
                len(name) > 256 or len(value) > _MAX_CALLBACK_HEADER_VALUE
                for name, value in headers
            )
        ):
            raise SandboxEntryError("callback record exceeds collector bounds")
        document = {
            "method": method,
            "path": parsed.path or "/",
            "query": parsed.query,
            "headers": {name: value for name, value in headers},
            "body": body_text,
        }
        record = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            + b"\n"
        )
        if len(record) > _MAX_CALLBACK_RECORD:
            raise SandboxEntryError("callback record is too large")
        try:
            self.bridge.sendall(record)
        except OSError as exc:
            raise _BridgeFatalError("callback bridge transport failed") from exc
        client.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


class _SerialLoopbackRelay:
    """One serial loopback listener backed by one authenticated UDS stream."""

    def __init__(
        self,
        *,
        port: int,
        bridge: socket.socket,
        handler: _ProviderHandler | _CallbackHandler,
        label: str,
    ) -> None:
        self.port = port
        self.bridge = bridge
        self.handler = handler
        self.label = label
        self.server: socket.socket | None = None
        self.active_client: socket.socket | None = None
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            server.bind(("127.0.0.1", self.port))
            server.listen(16)
            server.settimeout(0.25)
            self.server = server
            self.ready_event.set()
            while not self.stop_event.is_set():
                try:
                    client, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        return
                    raise
                self.active_client = client
                with client:
                    client.settimeout(30)
                    try:
                        self.handler(client)
                    except _BridgeFatalError as exc:
                        self.error = exc
                        try:
                            _send_http_error(client, 502)
                        except OSError:
                            pass
                        self.stop_event.set()
                    except (OSError, SandboxEntryError):
                        try:
                            _send_http_error(client, 400)
                        except OSError:
                            pass
                self.active_client = None
        except BaseException as exc:
            if not self.stop_event.is_set():
                self.error = exc
            self.ready_event.set()

    def start(self) -> None:
        self.thread.start()
        if not self.ready_event.wait(timeout=10):
            raise SandboxEntryError(f"{self.label} loopback relay did not become ready")
        self.assert_healthy()

    def assert_healthy(self) -> None:
        if self.error is not None:
            raise SandboxEntryError(
                f"{self.label} loopback relay failed closed"
            ) from self.error

    def close(self) -> None:
        self.stop_event.set()
        if self.server is not None:
            self.server.close()
        if self.active_client is not None:
            try:
                self.active_client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(timeout=2)
        try:
            self.bridge.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.bridge.close()


def _run(
    args: argparse.Namespace,
    provider_nonce: bytearray,
    callback_nonce: bytearray,
) -> int:
    if not args.command:
        raise SandboxEntryError("sandbox target command is empty")
    if (
        not 1024 <= args.relay_port <= 65535
        or not 1024 <= args.callback_port <= 65535
        or args.relay_port == args.callback_port
    ):
        raise SandboxEntryError("loopback relay ports are invalid or overlap")
    _network_interfaces()
    _effective_capabilities()
    provider_bridge: socket.socket | None = None
    callback_bridge: socket.socket | None = None
    try:
        provider_bridge = _connect_bridge(
            socket_path=PROVIDER_SOCKET_PATH,
            nonce=provider_nonce,
            run_id=args.run_id,
            stage_index=args.stage_index,
            purpose="model_relay",
        )
        callback_bridge = _connect_bridge(
            socket_path=CALLBACK_SOCKET_PATH,
            nonce=callback_nonce,
            run_id=args.run_id,
            stage_index=args.stage_index,
            purpose="callback_relay",
        )
    except BaseException as exc:
        if provider_bridge is not None:
            provider_bridge.close()
        if callback_bridge is not None:
            callback_bridge.close()
        if isinstance(exc, SandboxEntryError):
            raise
        if isinstance(exc, OSError):
            raise SandboxEntryError(
                "a run-local relay bridge could not connect"
            ) from exc
        raise
    finally:
        # Both transient files were already unlinked by main().  Erase both
        # in-memory copies before a listener is opened or Kimi is executed.
        _wipe(provider_nonce)
        _wipe(callback_nonce)
    if PROVIDER_NONCE_PATH.exists() or CALLBACK_NONCE_PATH.exists():
        provider_bridge.close()
        callback_bridge.close()
        raise SandboxEntryError("a sandbox nonce file remained visible")
    provider_relay = _SerialLoopbackRelay(
        port=args.relay_port,
        bridge=provider_bridge,
        handler=_ProviderHandler(provider_bridge),
        label="provider",
    )
    callback_relay = _SerialLoopbackRelay(
        port=args.callback_port,
        bridge=callback_bridge,
        handler=_CallbackHandler(callback_bridge),
        label="callback",
    )
    try:
        provider_relay.start()
        callback_relay.start()
        environment = dict(os.environ)
        if any(_SENSITIVE_KEY_RE.search(key) for key in environment):
            raise SandboxEntryError("credential-like host environment reached Kimi entry")
        environment.update(
            {
                "KIMI_MODEL_NAME": args.model_name,
                "KIMI_MODEL_PROVIDER_TYPE": "openai",
                "KIMI_MODEL_BASE_URL": f"http://127.0.0.1:{args.relay_port}/v1",
                # Kimi's custom-provider parser requires a non-empty value.  This
                # fixed marker authenticates nothing; the external broker remains
                # the only component allowed to hold an upstream credential.
                "KIMI_MODEL_API_KEY": "sandbox-relay-noncredential-placeholder",
            }
        )
        child: subprocess.Popen[bytes] | None = None

        def terminate_child(_signal: int, _frame: object) -> None:
            if child is not None and child.poll() is None:
                child.terminate()

        previous_term = signal.signal(signal.SIGTERM, terminate_child)
        previous_int = signal.signal(signal.SIGINT, terminate_child)
        try:
            try:
                child = subprocess.Popen(
                    args.command,
                    stdin=sys.stdin.buffer,
                    stdout=sys.stdout.buffer,
                    stderr=sys.stderr.buffer,
                    env=environment,
                    close_fds=True,
                )
            except OSError as exc:
                raise SandboxEntryError("sandbox target could not start") from exc
            return_code = child.wait()
            provider_relay.assert_healthy()
            callback_relay.assert_healthy()
            return return_code
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            signal.signal(signal.SIGINT, previous_int)
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
    finally:
        # Closing the authenticated callback stream is the collector's exact
        # stage boundary and causes its evidence manifest to be published.
        callback_relay.close()
        provider_relay.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    probe = subparsers.add_parser("self-test")
    probe.add_argument("--run-id", required=True)
    probe.add_argument("--isolation-output", required=True)
    probe.add_argument("--broker-output", required=True)
    probe.add_argument("--forbidden-path", action="append", default=[])
    run = subparsers.add_parser("run")
    run.add_argument("--run-id", required=True)
    run.add_argument("--stage-index", required=True, type=int)
    run.add_argument("--relay-port", required=True, type=int)
    run.add_argument("--callback-port", required=True, type=int)
    run.add_argument("--model-name", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if getattr(args, "command", None) and args.command[0] == "--":
        args.command = args.command[1:]
    provider_nonce: bytearray | None = None
    callback_nonce: bytearray | None = None
    try:
        provider_nonce = _read_and_remove_nonce(
            PROVIDER_NONCE_PATH, label="provider relay"
        )
        if args.mode == "self-test":
            return _self_test(args, provider_nonce)
        callback_nonce = _read_and_remove_nonce(
            CALLBACK_NONCE_PATH, label="callback relay"
        )
        return _run(args, provider_nonce, callback_nonce)
    except SandboxEntryError as exc:
        print(f"sandbox-entry: {exc}", file=sys.stderr)
        return 125
    finally:
        if provider_nonce is not None:
            _wipe(provider_nonce)
        if callback_nonce is not None:
            _wipe(callback_nonce)


if __name__ == "__main__":
    raise SystemExit(main())
