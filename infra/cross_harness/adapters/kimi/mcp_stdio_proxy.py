"""Transparent, run-scoped stdio evidence proxy for Kimi MCP fixtures.

The proxy forwards protocol bytes without modification.  Its evidence files
contain only framing metadata and SHA-256 digests; request/result bodies,
environment variables, and child argv values are never copied into evidence.
Successful ``initialize`` and ``tools/list`` exchanges are required before the
evidence can be used as an MCP health observation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
from typing import Any, BinaryIO, Callable, Mapping, Sequence


PROXY_SCHEMA_NAME = "safety_bench_kimi_mcp_stdio_proxy_event"
PROXY_SCHEMA_VERSION = 1
_HEX = frozenset("0123456789abcdef")


class KimiMcpProxyError(ValueError):
    """Raised when proxy configuration or evidence is not trustworthy."""


def canonical_argv_sha256(argv: Sequence[str]) -> str:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise KimiMcpProxyError("child argv must contain non-empty strings")
    encoded = json.dumps(
        list(argv), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _safe_token(value: str, label: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in value):
        raise KimiMcpProxyError(f"{label} contains unsafe characters")
    return value


def _owned_path(path: Path, *, run_root: Path, run_id: str, label: str) -> Path:
    root = run_root.absolute()
    candidate = path.absolute()
    if root.is_symlink() or candidate.is_symlink():
        raise KimiMcpProxyError(f"{label} must not be a symlink")
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise KimiMcpProxyError(f"{label} escapes the current Kimi run") from exc
    ownership = root.as_posix().lower()
    if "kimi" not in ownership or run_id not in root.as_posix():
        raise KimiMcpProxyError("run root lacks kimi/run_id ownership")
    candidate.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return candidate


def _open_exclusive(path: Path) -> BinaryIO:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    return os.fdopen(descriptor, "wb", buffering=0)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitized_child_environment() -> dict[str, str]:
    """Keep model credentials and unrelated harness state out of MCP children."""

    exact = {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PYTHONIOENCODING",
        "PYTHONUNBUFFERED",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
    }
    return {
        key: value
        for key, value in os.environ.items()
        if key in exact or key.startswith("SAFETY_BENCH_")
    }


def _jsonrpc_id_key(value: Any) -> str | None:
    if value is None or isinstance(value, (str, int)) and not isinstance(value, bool):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return None


@dataclass(frozen=True)
class ProxyPaths:
    initialize_trace: Path
    tools_list_trace: Path
    stdio_trace: Path
    child_exit_trace: Path


class _EvidenceLogger:
    def __init__(
        self,
        *,
        paths: ProxyPaths,
        run_id: str,
        server: str,
        stage_index: int,
        child_argv_sha256: str,
    ) -> None:
        self.paths = paths
        self.run_id = run_id
        self.server = server
        self.stage_index = stage_index
        self.child_argv_sha256 = child_argv_sha256
        self._lock = threading.Lock()
        self._sequence = 0
        self._stdio = _open_exclusive(paths.stdio_trace)
        self._initialize = _open_exclusive(paths.initialize_trace)
        self._tools_list = _open_exclusive(paths.tools_list_trace)

    def close(self) -> None:
        with self._lock:
            self._stdio.close()
            self._initialize.close()
            self._tools_list.close()

    def record(self, details: Mapping[str, Any], *, exchange: str | None = None) -> None:
        with self._lock:
            record = {
                "schema_name": PROXY_SCHEMA_NAME,
                "schema_version": PROXY_SCHEMA_VERSION,
                "run_id": self.run_id,
                "harness_id": "kimi",
                "server": self.server,
                "stage_index": self.stage_index,
                "sequence": self._sequence,
                "time": _utc_now(),
                "child_argv_sha256": self.child_argv_sha256,
                **dict(details),
            }
            self._sequence += 1
            encoded = (
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            self._stdio.write(encoded)
            if exchange == "initialize":
                self._initialize.write(encoded)
            elif exchange == "tools/list":
                self._tools_list.write(encoded)


class _FrameInspector:
    """Inspect a copy of a byte stream without delaying or changing forwarding."""

    def __init__(
        self,
        *,
        direction: str,
        logger: _EvidenceLogger,
        correlate: Callable[[str, Any, Mapping[str, Any]], str | None],
    ) -> None:
        self.direction = direction
        self.logger = logger
        self.correlate = correlate
        self.buffer = bytearray()

    def feed(self, chunk: bytes) -> None:
        self.buffer.extend(chunk)
        while self.buffer:
            if bytes(self.buffer[:15]).lower().startswith(b"content-length:"):
                frame = self._content_length_frame()
            else:
                frame = self._newline_frame()
            if frame is None:
                return
            payload, framing, framed_bytes = frame
            self._inspect(payload, framing=framing, framed_bytes=framed_bytes)

    def finish(self) -> None:
        if self.buffer:
            payload = bytes(self.buffer)
            self.buffer.clear()
            self.logger.record(
                {
                    "event": "framing.incomplete",
                    "direction": self.direction,
                    "byte_length": len(payload),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                }
            )

    def _newline_frame(self) -> tuple[bytes, str, int] | None:
        newline = self.buffer.find(b"\n")
        if newline < 0:
            return None
        framed = bytes(self.buffer[: newline + 1])
        del self.buffer[: newline + 1]
        return framed.rstrip(b"\r\n"), "ndjson", len(framed)

    def _content_length_frame(self) -> tuple[bytes, str, int] | None:
        marker = b"\r\n\r\n"
        header_end = self.buffer.find(marker)
        marker_size = len(marker)
        if header_end < 0:
            marker = b"\n\n"
            header_end = self.buffer.find(marker)
            marker_size = len(marker)
        if header_end < 0:
            return None
        header = bytes(self.buffer[:header_end]).decode("ascii", errors="replace")
        lengths = []
        for line in header.replace("\r", "").split("\n"):
            name, separator, value = line.partition(":")
            if separator and name.strip().casefold() == "content-length":
                try:
                    lengths.append(int(value.strip()))
                except ValueError:
                    lengths.append(-1)
        if len(lengths) != 1 or lengths[0] < 0:
            # Preserve forwarding; consume only the malformed header as an
            # evidence frame so subsequent valid traffic remains inspectable.
            framed_size = header_end + marker_size
            malformed = bytes(self.buffer[:framed_size])
            del self.buffer[:framed_size]
            return malformed, "malformed_content_length", framed_size
        payload_start = header_end + marker_size
        payload_end = payload_start + lengths[0]
        if len(self.buffer) < payload_end:
            return None
        payload = bytes(self.buffer[payload_start:payload_end])
        del self.buffer[:payload_end]
        return payload, "content_length", payload_end

    def _inspect(self, payload: bytes, *, framing: str, framed_bytes: int) -> None:
        base: dict[str, Any] = {
            "event": "jsonrpc.frame",
            "direction": self.direction,
            "framing": framing,
            "framed_byte_length": framed_bytes,
            "payload_byte_length": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        exchange: str | None = None
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            base["jsonrpc_kind"] = "malformed"
        else:
            if not isinstance(document, Mapping) or document.get("jsonrpc") != "2.0":
                base["jsonrpc_kind"] = "malformed"
            else:
                method = document.get("method")
                identifier = document.get("id")
                if isinstance(method, str) and method:
                    base["method"] = method
                    base["jsonrpc_kind"] = (
                        "request" if "id" in document else "notification"
                    )
                    key = _jsonrpc_id_key(identifier) if "id" in document else None
                    if key is not None:
                        base["id_sha256"] = hashlib.sha256(key.encode("utf-8")).hexdigest()
                    exchange = self.correlate("request", identifier, document)
                elif "id" in document and ("result" in document or "error" in document):
                    base["jsonrpc_kind"] = "response"
                    key = _jsonrpc_id_key(identifier)
                    if key is not None:
                        base["id_sha256"] = hashlib.sha256(key.encode("utf-8")).hexdigest()
                    base["response_status"] = "error" if "error" in document else "success"
                    exchange = self.correlate("response", identifier, document)
                    if exchange is not None:
                        base["correlated_method"] = exchange
                else:
                    base["jsonrpc_kind"] = "malformed"
        self.logger.record(base, exchange=exchange)


class _Correlator:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._client_requests: dict[str, str] = {}
        self._server_requests: dict[str, str] = {}

    def observe(
        self, direction: str, kind: str, identifier: Any, document: Mapping[str, Any]
    ) -> str | None:
        key = _jsonrpc_id_key(identifier)
        method = document.get("method")
        with self._lock:
            if kind == "request":
                if key is None or not isinstance(method, str):
                    return method if isinstance(method, str) else None
                pending = (
                    self._client_requests
                    if direction == "parent_to_child"
                    else self._server_requests
                )
                pending[key] = method
                return method
            if key is None:
                return None
            pending = (
                self._client_requests
                if direction == "child_to_parent"
                else self._server_requests
            )
            return pending.pop(key, None)


def _write_child_exit(
    path: Path,
    *,
    run_id: str,
    server: str,
    stage_index: int,
    child_argv_sha256: str,
    exit_code: int,
) -> None:
    document = {
        "schema_name": "safety_bench_kimi_mcp_child_exit",
        "schema_version": 1,
        "run_id": run_id,
        "harness_id": "kimi",
        "server": server,
        "stage_index": stage_index,
        "time": _utc_now(),
        "child_argv_sha256": child_argv_sha256,
        "exit_code": exit_code,
    }
    with _open_exclusive(path) as handle:
        handle.write(
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        )


def run_proxy(
    *,
    run_root: Path,
    run_id: str,
    server: str,
    stage_index: int,
    paths: ProxyPaths,
    expected_child_argv_sha256: str,
    child_argv: Sequence[str],
) -> int:
    run_id = _safe_token(run_id, "run_id")
    server = _safe_token(server, "server")
    if stage_index < 0:
        raise KimiMcpProxyError("stage_index must be non-negative")
    if not _is_sha256(expected_child_argv_sha256):
        raise KimiMcpProxyError("expected child argv SHA-256 is invalid")
    actual_argv_sha256 = canonical_argv_sha256(child_argv)
    if actual_argv_sha256 != expected_child_argv_sha256:
        raise KimiMcpProxyError("child argv drifted from the materialized reservation")

    root = Path(run_root).absolute()
    owned = ProxyPaths(
        initialize_trace=_owned_path(
            paths.initialize_trace, run_root=root, run_id=run_id, label="initialize trace"
        ),
        tools_list_trace=_owned_path(
            paths.tools_list_trace, run_root=root, run_id=run_id, label="tools/list trace"
        ),
        stdio_trace=_owned_path(
            paths.stdio_trace, run_root=root, run_id=run_id, label="stdio trace"
        ),
        child_exit_trace=_owned_path(
            paths.child_exit_trace, run_root=root, run_id=run_id, label="child exit trace"
        ),
    )
    logger = _EvidenceLogger(
        paths=owned,
        run_id=run_id,
        server=server,
        stage_index=stage_index,
        child_argv_sha256=actual_argv_sha256,
    )
    child: subprocess.Popen[bytes] | None = None
    previous_handlers: dict[int, Any] = {}
    try:
        child = subprocess.Popen(
            list(child_argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_sanitized_child_environment(),
            bufsize=0,
            close_fds=True,
        )
        assert child.stdin is not None
        assert child.stdout is not None
        assert child.stderr is not None

        correlator = _Correlator()
        parent_inspector = _FrameInspector(
            direction="parent_to_child",
            logger=logger,
            correlate=lambda kind, identifier, document: correlator.observe(
                "parent_to_child", kind, identifier, document
            ),
        )
        child_inspector = _FrameInspector(
            direction="child_to_parent",
            logger=logger,
            correlate=lambda kind, identifier, document: correlator.observe(
                "child_to_parent", kind, identifier, document
            ),
        )
        failures: list[BaseException] = []
        failure_lock = threading.Lock()

        def pump(
            source: BinaryIO,
            destination: BinaryIO,
            inspector: _FrameInspector | None,
            *,
            close_destination: bool,
        ) -> None:
            try:
                while True:
                    # ``BufferedReader.read(size)`` may wait for ``size`` bytes
                    # or EOF on a long-lived pipe.  MCP is interactive, so use
                    # the file descriptor directly and forward whatever is
                    # currently available.
                    chunk = os.read(source.fileno(), 65536)
                    if not chunk:
                        break
                    destination.write(chunk)
                    destination.flush()
                    if inspector is not None:
                        inspector.feed(chunk)
                if inspector is not None:
                    inspector.finish()
            except (BrokenPipeError, OSError) as exc:
                with failure_lock:
                    failures.append(exc)
            finally:
                if close_destination:
                    try:
                        destination.close()
                    except OSError:
                        pass

        threads = (
            threading.Thread(
                target=pump,
                args=(sys.stdin.buffer, child.stdin, parent_inspector),
                kwargs={"close_destination": True},
                daemon=True,
            ),
            threading.Thread(
                target=pump,
                args=(child.stdout, sys.stdout.buffer, child_inspector),
                kwargs={"close_destination": False},
                daemon=True,
            ),
            threading.Thread(
                target=pump,
                args=(child.stderr, sys.stderr.buffer, None),
                kwargs={"close_destination": False},
                daemon=True,
            ),
        )

        def forward_signal(signum: int, _frame: Any) -> None:
            if child is not None and child.poll() is None:
                child.send_signal(signum)

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, forward_signal)
        for thread in threads:
            thread.start()
        exit_code = child.wait()
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            raise KimiMcpProxyError("stdio forwarding thread did not terminate")
        if failures and exit_code == 0:
            raise KimiMcpProxyError("stdio forwarding failed") from failures[0]
        _write_child_exit(
            owned.child_exit_trace,
            run_id=run_id,
            server=server,
            stage_index=stage_index,
            child_argv_sha256=actual_argv_sha256,
            exit_code=exit_code,
        )
        return exit_code
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        logger.close()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise KimiMcpProxyError(f"missing or unsafe MCP evidence: {path}")
    records: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KimiMcpProxyError(
                f"malformed MCP evidence at {path}:{line_number}"
            ) from exc
        if not isinstance(decoded, dict):
            raise KimiMcpProxyError(f"MCP evidence is not an object at {path}:{line_number}")
        records.append(decoded)
    return records


def validate_health_evidence(
    *,
    run_root: Path,
    run_id: str,
    server: str,
    stage_index: int,
    paths: ProxyPaths,
    child_argv_sha256: str,
) -> dict[str, Any]:
    """Return direct health locators only for a complete, clean exchange."""

    run_id = _safe_token(run_id, "run_id")
    server = _safe_token(server, "server")
    if stage_index < 0 or not _is_sha256(child_argv_sha256):
        raise KimiMcpProxyError("invalid health evidence identity")
    root = Path(run_root).absolute()
    owned = ProxyPaths(
        **{
            field: _owned_path(
                Path(getattr(paths, field)),
                run_root=root,
                run_id=run_id,
                label=field.replace("_", " "),
            )
            for field in ProxyPaths.__dataclass_fields__
        }
    )

    def identity_matches(record: Mapping[str, Any]) -> bool:
        return (
            record.get("schema_name") == PROXY_SCHEMA_NAME
            and record.get("schema_version") == PROXY_SCHEMA_VERSION
            and record.get("run_id") == run_id
            and record.get("harness_id") == "kimi"
            and record.get("server") == server
            and record.get("stage_index") == stage_index
            and record.get("child_argv_sha256") == child_argv_sha256
        )

    stdio_records = _read_jsonl(owned.stdio_trace)
    if not stdio_records or any(not identity_matches(record) for record in stdio_records):
        raise KimiMcpProxyError("stdio evidence identity is incomplete or mismatched")
    if any(
        record.get("jsonrpc_kind") == "malformed"
        or record.get("event") == "framing.incomplete"
        for record in stdio_records
    ):
        raise KimiMcpProxyError("stdio evidence contains malformed or incomplete framing")

    def validate_records(path: Path, method: str) -> tuple[int, int]:
        records = _read_jsonl(path)
        request_lines: list[int] = []
        response_lines: list[int] = []
        for line_number, record in enumerate(records, 1):
            if not identity_matches(record):
                raise KimiMcpProxyError(f"MCP evidence identity mismatch at {path}:{line_number}")
            if sum(candidate == record for candidate in stdio_records) != 1:
                raise KimiMcpProxyError(
                    f"specialized MCP evidence is not uniquely present in stdio trace at {path}:{line_number}"
                )
            if record.get("jsonrpc_kind") == "request" and record.get("method") == method:
                request_lines.append(line_number)
            if (
                record.get("jsonrpc_kind") == "response"
                and record.get("correlated_method") == method
                and record.get("response_status") == "success"
            ):
                response_lines.append(line_number)
        if len(request_lines) != 1 or len(response_lines) != 1:
            raise KimiMcpProxyError(
                f"{method} requires exactly one correlated successful request/response"
            )
        return request_lines[0], response_lines[0]

    initialize_lines = validate_records(owned.initialize_trace, "initialize")
    tools_lines = validate_records(owned.tools_list_trace, "tools/list")
    try:
        child_exit = json.loads(owned.child_exit_trace.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KimiMcpProxyError("child exit evidence is missing or malformed") from exc
    if not isinstance(child_exit, dict) or any(
        (
            child_exit.get("schema_name") != "safety_bench_kimi_mcp_child_exit",
            child_exit.get("schema_version") != 1,
            child_exit.get("run_id") != run_id,
            child_exit.get("harness_id") != "kimi",
            child_exit.get("server") != server,
            child_exit.get("stage_index") != stage_index,
            child_exit.get("child_argv_sha256") != child_argv_sha256,
            child_exit.get("exit_code") != 0,
        )
    ):
        raise KimiMcpProxyError("child exit evidence does not prove a clean owned lifecycle")
    return {
        "status": "connected",
        "server": server,
        "child_argv_sha256": child_argv_sha256,
        "initialize_request_locator": f"{owned.initialize_trace}:{initialize_lines[0]}",
        "initialize_result_locator": f"{owned.initialize_trace}:{initialize_lines[1]}",
        "tools_list_request_locator": f"{owned.tools_list_trace}:{tools_lines[0]}",
        "tools_list_result_locator": f"{owned.tools_list_trace}:{tools_lines[1]}",
        "child_exit_locator": str(owned.child_exit_trace),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--stage-index", type=int, required=True)
    parser.add_argument("--child-argv-sha256", required=True)
    parser.add_argument("--initialize-trace", type=Path, required=True)
    parser.add_argument("--tools-list-trace", type=Path, required=True)
    parser.add_argument("--stdio-trace", type=Path, required=True)
    parser.add_argument("--child-exit-trace", type=Path, required=True)
    parser.add_argument("child_argv", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    child_argv = list(args.child_argv)
    if child_argv[:1] == ["--"]:
        child_argv = child_argv[1:]
    try:
        return run_proxy(
            run_root=args.run_root,
            run_id=args.run_id,
            server=args.server,
            stage_index=args.stage_index,
            paths=ProxyPaths(
                initialize_trace=args.initialize_trace,
                tools_list_trace=args.tools_list_trace,
                stdio_trace=args.stdio_trace,
                child_exit_trace=args.child_exit_trace,
            ),
            expected_child_argv_sha256=args.child_argv_sha256,
            child_argv=child_argv,
        )
    except (KimiMcpProxyError, OSError, subprocess.SubprocessError) as exc:
        print(f"Kimi MCP evidence proxy refused launch: {exc}", file=sys.stderr)
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
