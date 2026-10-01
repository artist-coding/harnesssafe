from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import shutil
import subprocess
import tempfile
import threading
from typing import Any

import pytest

from infra.cross_harness.adapters.kimi.callback_collector import (
    RunScopedCallbackCollector,
)
from infra.cross_harness.adapters.kimi.executor import (
    KimiStageExecutor,
    StageLaunchRequest,
    StageMount,
)
from infra.cross_harness.adapters.kimi.isolated_launcher import (
    BROKER_ATTESTATION_SCHEMA_NAME,
    BROKER_ATTESTATION_SCHEMA_VERSION,
    BrokerNonceFD,
    KimiBubblewrapLauncherError,
    LinuxBubblewrapLauncher,
    bubblewrap_namespace_support,
)
from infra.cross_harness.adapters.kimi.materializer import (
    runtime_tree_sha256,
    sha256_file,
    tree_sha256,
)
from infra.cross_harness.adapters.kimi.mcp_stdio_proxy import canonical_argv_sha256
from infra.cross_harness.adapters.kimi.lifecycle import case_attempt_component
from infra.cross_harness.adapters.kimi.provider_broker import (
    BROKER_SOCKET_BASENAME,
    broker_root_name,
)
from infra.cross_harness.adapters.kimi.sandbox_entry import (
    SandboxEntryError,
    _SocketReader,
    _read_http_request,
    _read_provider_response,
    broker_ack_proof,
)


RUN_ID = "launch-001"
CASE_ID = "fixture-case"
TRIAL_ID = "fixture-trial"
CALLBACK_PORT = 20000 + (
    int(hashlib.sha256(f"kimi:{RUN_ID}:callback".encode()).hexdigest()[:8], 16)
    % 30000
)
CALLBACK_ORIGIN = f"http://127.0.0.1:{CALLBACK_PORT}/callback"


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _process_start_time(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[21]


def _process_cmdline_sha256(pid: int) -> str:
    return hashlib.sha256(Path(f"/proc/{pid}/cmdline").read_bytes()).hexdigest()


@dataclass
class _FakeLease:
    run_id: str
    stage_index: int
    purpose: str
    nonce: bytearray
    consumed: bool = False


class FakeFDRelayBroker:
    """Credential-free local broker exercising the production FD boundary."""

    def __init__(
        self,
        ownership_root: Path,
        *,
        run_id: str,
        case_id: str,
        trial_id: str,
    ) -> None:
        self.run_id = run_id
        self.case_id = case_id
        self.trial_id = trial_id
        self.ownership_root = ownership_root
        self.root = ownership_root / broker_root_name(run_id, case_id, trial_id)
        self.root.mkdir(mode=0o700)
        self.socket_path = self.root / BROKER_SOCKET_BASENAME
        self.attestation_path = self.root / f"attestation-kimi-{run_id}.json"
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(self.socket_path))
        self._server.listen(16)
        self._server.settimeout(0.2)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._leases: dict[str, _FakeLease] = {}
        self._counter = 0
        self.handshakes: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        self.released: list[str] = []

        # Inert input traverses an FD, proving the broker-side credential
        # transport shape without introducing an external secret or network.
        credential_read, credential_write = os.pipe2(os.O_CLOEXEC)
        os.write(credential_write, b"credential-free-fixture")
        os.close(credential_write)
        self._inert_credential = os.read(credential_read, 64)
        os.close(credential_read)

        metadata = self.socket_path.stat()
        process_executable = Path("/proc/self/exe").resolve(strict=True)
        document: dict[str, Any] = {
            "schema_name": BROKER_ATTESTATION_SCHEMA_NAME,
            "schema_version": BROKER_ATTESTATION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": run_id,
            "broker_kind": "deterministic-inert-fd-test-broker",
            "socket_path": str(self.socket_path.resolve()),
            "socket_identity": {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
            },
            "process": {
                "pid": os.getpid(),
                "start_time": _process_start_time(os.getpid()),
                "executable_path": str(process_executable),
                "executable_sha256": sha256_file(process_executable),
                "cmdline_sha256": _process_cmdline_sha256(os.getpid()),
            },
            "implementation": {
                "path": str(Path(__file__).resolve()),
                "sha256": sha256_file(Path(__file__).resolve()),
            },
            "credential_boundary": {
                "upstream_credential_transport": "inherited_fd",
                "credential_fd_cloexec": True,
                "external_credentials_in_environment": False,
                "external_credentials_in_filesystem": False,
                "external_credentials_persisted": False,
            },
            "nonce_boundary": {
                "issuance_transport": "sealed_memfd",
                "nonce_length_bytes": 32,
                "volatile_only": True,
                "unauthorized_nonce_rejected": True,
                "released_nonce_rejected": True,
            },
        }
        document["attestation_payload_sha256"] = _canonical_sha256(document)
        self.attestation_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def issue_nonce_fd(
        self, *, run_id: str, stage_index: int, purpose: str
    ) -> BrokerNonceFD:
        assert run_id == self.run_id
        nonce = bytearray(secrets.token_bytes(32))
        self._counter += 1
        lease_id = f"nonce-kimi-{run_id}-{self._counter:04d}"
        descriptor = os.memfd_create(
            f"nonce-kimi-{run_id}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        )
        os.write(descriptor, nonce)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        with self._lock:
            self._leases[lease_id] = _FakeLease(
                run_id=run_id,
                stage_index=stage_index,
                purpose=purpose,
                nonce=nonce,
            )
        return BrokerNonceFD(fd=descriptor, lease_id=lease_id)

    def release_nonce(
        self,
        lease_id: str,
        *,
        run_id: str,
        stage_index: int,
        purpose: str,
    ) -> None:
        with self._lock:
            record = self._leases.pop(lease_id)
        assert (record.run_id, record.stage_index, record.purpose) == (
            run_id,
            stage_index,
            purpose,
        )
        nonce = record.nonce
        for index in range(len(nonce)):
            nonce[index] = 0
        self.released.append(lease_id)

    @property
    def active_lease_count(self) -> int:
        with self._lock:
            return len(self._leases)

    def _authorized(
        self, *, run_id: str, stage_index: int, purpose: str, nonce: bytes
    ) -> bool:
        with self._lock:
            for lease in self._leases.values():
                if (
                    lease.run_id == run_id
                    and lease.stage_index == stage_index
                    and lease.purpose == purpose
                    and hmac.compare_digest(bytes(lease.nonce), nonce)
                ):
                    if lease.consumed:
                        return False
                    lease.consumed = True
                    return True
            return False

    def _handle(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(5)
            buffer = bytearray()
            while b"\n" not in buffer and len(buffer) <= 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    return
                buffer.extend(chunk)
            line, _, trailing = bytes(buffer).partition(b"\n")
            if trailing:
                return
            request = json.loads(line)
            nonce = base64.b64decode(request["nonce"], validate=True)
            run_id = str(request["run_id"])
            stage_index = int(request["stage_index"])
            purpose = str(request["purpose"])
            authorized = self._authorized(
                run_id=run_id,
                stage_index=stage_index,
                purpose=purpose,
                nonce=nonce,
            )
            response = {
                "schema_name": "safety_bench_kimi_relay_handshake",
                "ok": authorized,
                "run_id": run_id,
                "stage_index": stage_index,
                "purpose": purpose,
                "proof": broker_ack_proof(
                    nonce,
                    run_id=run_id,
                    stage_index=stage_index,
                    purpose=purpose,
                    ok=authorized,
                ),
            }
            if not authorized:
                response["reason"] = "unauthorized_nonce"
            connection.sendall(
                json.dumps(response, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
            self.handshakes.append(
                {
                    "run_id": run_id,
                    "stage_index": stage_index,
                    "purpose": purpose,
                    "authorized": authorized,
                }
            )
            if authorized and purpose == "model_relay":
                reader = connection.makefile("rb")
                try:
                    while True:
                        request_line = reader.readline(65537)
                        if not request_line:
                            return
                        assert len(request_line) <= 65536
                        method, target, version = (
                            request_line.rstrip(b"\r\n").decode("ascii").split(" ")
                        )
                        assert method in {"GET", "POST"}
                        assert version == "HTTP/1.1"
                        headers: dict[str, str] = {}
                        for _ in range(256):
                            raw = reader.readline(65537)
                            assert raw and len(raw) <= 65536
                            if raw in {b"\r\n", b"\n"}:
                                break
                            name, value = raw.decode("latin-1").rstrip("\r\n").split(
                                ":", 1
                            )
                            headers[name.casefold()] = value.strip()
                        else:  # pragma: no cover - relay enforces the bound
                            raise AssertionError("too many request headers")
                        length = int(headers.get("content-length", "0"))
                        body = reader.read(length)
                        assert len(body) == length
                        with self._lock:
                            ordinal = len(self.requests) + 1
                            self.requests.append(
                                {
                                    "method": method,
                                    "target": target,
                                    "body_sha256": hashlib.sha256(body).hexdigest(),
                                    "connection": headers.get("connection"),
                                    "authorization_present": "authorization" in headers,
                                }
                            )
                        response_body = f"provider-response-{ordinal}:{target}".encode()
                        midpoint = max(1, len(response_body) // 2)
                        chunks = (response_body[:midpoint], response_body[midpoint:])
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Transfer-Encoding: chunked\r\n"
                            b"Connection: keep-alive\r\n\r\n"
                        )
                        for chunk in chunks:
                            if chunk:
                                connection.sendall(
                                    f"{len(chunk):x}\r\n".encode()
                                    + chunk
                                    + b"\r\n"
                                )
                        connection.sendall(b"0\r\n\r\n")
                finally:
                    reader.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        self._server.close()
        self._thread.join(timeout=2)
        with self._lock:
            leases = tuple(self._leases.values())
            self._leases.clear()
        for lease in leases:
            for index in range(len(lease.nonce)):
                lease.nonce[index] = 0


@pytest.fixture
def broker_layout():
    base_root = Path(tempfile.mkdtemp(prefix="k-launch-", dir="/tmp"))
    run_root = base_root / f"kimi-{RUN_ID}"
    run_root.mkdir(mode=0o700)
    case_root = run_root / case_attempt_component(CASE_ID, attempt=1)
    case_root.mkdir(mode=0o700)
    probe_path = case_root / "probe.sock"
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.bind(str(probe_path))
    except OSError as exc:
        probe.close()
        shutil.rmtree(base_root)
        pytest.skip(f"local Unix sockets unavailable in this sandbox: {exc}")
    else:
        probe.close()
        probe_path.unlink()
    broker = FakeFDRelayBroker(
        case_root,
        run_id=RUN_ID,
        case_id=CASE_ID,
        trial_id=TRIAL_ID,
    )
    callback = RunScopedCallbackCollector(
        ownership_root=case_root,
        run_id=RUN_ID,
        case_id=CASE_ID,
        trial_id=TRIAL_ID,
    )
    try:
        yield case_root, broker, callback
    finally:
        callback.close()
        broker.close()
        shutil.rmtree(base_root)


def _launcher(
    ownership_root: Path,
    broker: FakeFDRelayBroker,
    callback: RunScopedCallbackCollector,
) -> LinuxBubblewrapLauncher:
    return LinuxBubblewrapLauncher(
        broker=broker,
        callback_collector=callback,
        run_id=RUN_ID,
        ownership_root=ownership_root,
        model_name="kimi-local-fixture",
        reviewed_broker_implementation_path=Path(__file__).resolve(),
        reviewed_broker_implementation_sha256=sha256_file(Path(__file__).resolve()),
        reviewed_broker_process_executable_path=Path("/proc/self/exe").resolve(),
        reviewed_broker_process_executable_sha256=sha256_file(
            Path("/proc/self/exe").resolve()
        ),
    )


def _launcher_with_installed_kimi(
    ownership_root: Path,
    broker: FakeFDRelayBroker,
    callback: RunScopedCallbackCollector,
) -> LinuxBubblewrapLauncher:
    package_root = Path(
        "/usr/local/lib/node_modules/@moonshot-ai/kimi-code"
    ).resolve(strict=True)
    entrypoint = (package_root / "dist/main.mjs").resolve(strict=True)
    node = Path("/usr/local/bin/node").resolve(strict=True)
    return LinuxBubblewrapLauncher(
        broker=broker,
        callback_collector=callback,
        run_id=RUN_ID,
        ownership_root=ownership_root,
        model_name="kimi-local-fixture",
        reviewed_broker_implementation_path=Path(__file__).resolve(),
        reviewed_broker_implementation_sha256=sha256_file(Path(__file__).resolve()),
        reviewed_broker_process_executable_path=Path("/proc/self/exe").resolve(),
        reviewed_broker_process_executable_sha256=sha256_file(
            Path("/proc/self/exe").resolve()
        ),
        reviewed_kimi_package_root=package_root,
        reviewed_kimi_package_tree_sha256=tree_sha256(package_root),
        reviewed_kimi_entrypoint_path=entrypoint,
        reviewed_kimi_entrypoint_sha256=sha256_file(entrypoint),
        reviewed_node_executable_path=node,
        reviewed_node_executable_sha256=sha256_file(node),
    )


def _stage_layout(
    case_root: Path,
    *,
    case_id: str,
    stage_name: str,
) -> dict[str, object]:
    case_dir = case_root / "materialized_case"
    workspace = case_dir / "workspace"
    workspace.mkdir(mode=0o700, parents=True)
    stage_root = case_root / f"stage-kimi-{RUN_ID}-stage-000-{stage_name}"
    assets = stage_root / f"assets-kimi-{RUN_ID}-stage-000-{stage_name}"
    runtime = stage_root / f"runtime-kimi-{RUN_ID}-stage-000-{stage_name}"
    assets.mkdir(mode=0o700, parents=True)
    runtime.mkdir(mode=0o700)
    prompt = assets / f"prompt-kimi-{RUN_ID}-stage-000.txt"
    prompt.write_text("fixture prompt\n", encoding="utf-8")
    paths = {
        "HOME": runtime / f"home-kimi-{RUN_ID}-stage-000",
        "KIMI_CODE_HOME": runtime / f"config-kimi-{RUN_ID}-stage-000",
        "XDG_CACHE_HOME": runtime / f"cache-kimi-{RUN_ID}-stage-000",
        "XDG_CONFIG_HOME": runtime / f"xdg-config-kimi-{RUN_ID}-stage-000",
        "XDG_DATA_HOME": runtime / f"xdg-data-kimi-{RUN_ID}-stage-000",
        "TMPDIR": runtime / f"tmp-kimi-{RUN_ID}-stage-000",
    }
    for path in paths.values():
        path.mkdir(mode=0o700)
    session = paths["KIMI_CODE_HOME"] / "sessions"
    session.mkdir(mode=0o700)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        **{key: str(value) for key, value in paths.items()},
        "KIMI_DISABLE_TELEMETRY": "1",
        "NO_COLOR": "1",
        "CI": "1",
        "SAFETY_BENCH_HARNESS": "kimi",
        "SAFETY_BENCH_RUN_ID": RUN_ID,
    }
    return {
        "case_id": case_id,
        "stage_name": stage_name,
        "case_dir": case_dir,
        "workspace": workspace,
        "stage_root": stage_root,
        "assets": assets,
        "runtime": runtime,
        "prompt": prompt,
        "session": session,
        "environment": environment,
    }


def _stage_request(
    layout: dict[str, object],
    *,
    executable: Path,
    argv: tuple[str, ...],
    attestation_path: Path,
    mcp_surface: dict[str, object] | None = None,
    reviewed_stage_files: tuple[dict[str, object], ...] = (),
    extra_read_only_mounts: tuple[StageMount, ...] = (),
) -> StageLaunchRequest:
    case_root = Path(attestation_path).parent.parent
    workspace = Path(layout["workspace"])
    stage_root = Path(layout["stage_root"])
    assets = Path(layout["assets"])
    runtime = Path(layout["runtime"])
    prompt = Path(layout["prompt"])
    session = Path(layout["session"])
    environment = dict(layout["environment"])
    mcp = mcp_surface or {
        "activation": {
            "operation": "remove_file_if_present",
            "target": "workspace/.kimi-code/mcp.json",
        }
    }
    stage_document = {
        "index": 0,
        "name": str(layout["stage_name"]),
        "disposition": "READY",
        "stage_root": str(stage_root),
        "prompt": {"materialized_path": str(prompt)},
        "runtime_paths": {
            "trace": str(runtime / "stdout.jsonl"),
            "wire": str(runtime / "wire.jsonl"),
            "result": str(runtime / "result.json"),
            "kimi_home": environment["KIMI_CODE_HOME"],
            "session": str(session),
        },
        "surfaces": {
            "session": {"state_scope": "stage_local"},
            "mcp": mcp,
        },
        "read_only_mount_files": list(reviewed_stage_files),
    }
    manifest = {
        "schema_name": "safety_bench_kimi_bench_plan",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": RUN_ID,
        "case_id": str(layout["case_id"]),
        "disposition": "READY",
        "materialized": {
            "case_dir": str(layout["case_dir"]),
            "workspace_dir": str(workspace),
        },
        "callback": {
            "origin": CALLBACK_ORIGIN,
            "credentials_copied": False,
        },
        "stages": [stage_document],
    }
    manifest["manifest_payload_sha256"] = _canonical_sha256(manifest)
    manifest_path = case_root / f"manifest-kimi-{RUN_ID}.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_sha256 = sha256_file(manifest_path)
    write_mounts = (
        StageMount(
            kind="workspace",
            path=workspace.resolve(),
            path_type="tree",
            sha256=runtime_tree_sha256(workspace),
            mode=workspace.stat().st_mode & 0o777,
            provenance="verified_materialized_workspace_v1",
            provenance_sha256=manifest_sha256,
        ),
        StageMount(
            kind="current_stage_runtime",
            path=runtime.resolve(),
            path_type="tree",
            sha256=tree_sha256(runtime),
            mode=runtime.stat().st_mode & 0o777,
            provenance="verified_current_stage_runtime_v1",
            provenance_sha256=manifest_sha256,
        ),
    )
    read_only_mounts = (
        StageMount(
            kind="current_stage_assets",
            path=assets.resolve(),
            path_type="tree",
            sha256=tree_sha256(assets),
            mode=assets.stat().st_mode & 0o777,
            provenance="verified_current_stage_assets_v1",
            provenance_sha256=manifest_sha256,
        ),
        *(
            replace(mount, provenance_sha256=manifest_sha256)
            for mount in extra_read_only_mounts
        ),
    )
    return StageLaunchRequest(
        run_id=RUN_ID,
        case_id=str(layout["case_id"]),
        stage_index=0,
        stage_name=str(layout["stage_name"]),
        argv=argv,
        executable_sha256=sha256_file(executable),
        cwd=workspace,
        env=environment,
        timeout_seconds=10,
        stdout_path=runtime / "stdout.jsonl",
        wire_copy_path=runtime / "wire.jsonl",
        result_path=runtime / "result.json",
        launcher_attestation_path=attestation_path,
        materialization_manifest_path=manifest_path,
        materialization_manifest_sha256=manifest_sha256,
        write_mounts=write_mounts,
        read_only_mounts=read_only_mounts,
    )


def _write_fake_executable(workspace: Path) -> Path:
    executable = workspace / f"fake-kimi-{RUN_ID}"
    lines = [
        "#!/usr/bin/python3",
        "import json, os, socket, sys, time",
        "from pathlib import Path",
        "from urllib.parse import urlparse",
        "def exchange(url, method='GET', body=b'', headers=None):",
        "    endpoint = urlparse(url)",
        "    target = endpoint.path or '/'",
        "    if endpoint.query:",
        "        target += '?' + endpoint.query",
        "    request_headers = {'Host': f'{endpoint.hostname}:{endpoint.port}', 'Content-Length': str(len(body)), 'Connection': 'close'}",
        "    request_headers.update(headers or {})",
        "    request = f'{method} {target} HTTP/1.1\\r\\n'.encode('ascii') + b''.join(f'{name}: {value}\\r\\n'.encode('latin-1') for name, value in request_headers.items()) + b'\\r\\n' + body",
        "    connection = socket.create_connection((endpoint.hostname, endpoint.port), timeout=5)",
        "    connection.sendall(request)",
        "    chunks = []",
        "    while True:",
        "        chunk = connection.recv(65536)",
        "        if not chunk:",
        "            break",
        "        chunks.append(chunk)",
        "    connection.close()",
        "    head, payload = b''.join(chunks).split(b'\\r\\n\\r\\n', 1)",
        "    response_headers = {}",
        "    response_lines = head.split(b'\\r\\n')",
        "    for raw in response_lines[1:]:",
        "        name, value = raw.decode('latin-1').split(':', 1)",
        "        response_headers[name.casefold()] = value.strip()",
        "    assert response_headers['connection'].casefold() == 'close'",
        "    assert int(response_headers['content-length']) == len(payload)",
        "    return response_lines[0].decode('latin-1'), payload.decode('utf-8')",
        "future_path = Path(sys.argv[1])",
        "other_case_path = Path(sys.argv[2])",
        "callback_url = sys.argv[3]",
        "provider_replies = []",
        "for attempt in (1, 2):",
        "    _, reply = exchange(os.environ['KIMI_MODEL_BASE_URL'] + f'/chat/completions?attempt={attempt}', method='POST', body=json.dumps({'attempt': attempt}).encode(), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer sandbox-placeholder'})",
        "    provider_replies.append(reply)",
        "exchange(callback_url + '?canary=KIMI_CALLBACK_CANARY', headers={'Authorization': 'Bearer CALLBACK_SECRET_ONE', 'Cookie': 'session=CALLBACK_SECRET_TWO', 'X-Fixture': 'first'})",
        "exchange(callback_url + '/second?step=2', method='POST', body='KIMI_CALLBACK_CANARY-正文'.encode('utf-8'), headers={'Content-Type': 'text/plain; charset=utf-8', 'X-Api-Key': 'CALLBACK_SECRET_THREE', 'X-Fixture': 'second'})",
        "wire = Path(os.environ['KIMI_CODE_HOME']) / 'sessions/wd_fixture/session_fixture/agents/main/wire.jsonl'",
        "wire.parent.mkdir(parents=True, exist_ok=True)",
        "wire.write_text(json.dumps({'type': 'fixture.wire'}) + '\\n', encoding='utf-8')",
        "print(json.dumps({'role': 'assistant', 'content': 'isolated-fixture', 'provider_replies': provider_replies, 'future_stage_visible': future_path.exists(), 'other_case_visible': other_case_path.exists(), 'user_codex_state_visible': Path('/root/.codex').exists(), 'provider_key_is_placeholder': os.environ.get('KIMI_MODEL_API_KEY') == 'sandbox-relay-noncredential-placeholder', 'nonce_files_visible': Path('/run/kimi/provider-nonce').exists() or Path('/run/kimi/callback-nonce').exists()}), flush=True)",
        "(Path(os.environ['TMPDIR']) / 'fake-kimi-process-started').write_text('started\\n', encoding='utf-8')",
        "time.sleep(0.4)",
    ]
    executable.write_text("\n".join(lines) + "\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def _write_fake_acp_executable(workspace: Path) -> Path:
    executable = workspace / f"fake-acp-kimi-{RUN_ID}"
    lines = [
        "#!/usr/bin/python3",
        "import json, sys",
        "for expected in (1, 2, 3):",
        "    request = json.loads(sys.stdin.readline())",
        "    assert request['id'] == expected",
        "    print(json.dumps({'jsonrpc': '2.0', 'method': 'fixture/progress', 'params': {'request_id': expected}}), flush=True)",
        "    print(json.dumps({'jsonrpc': '2.0', 'id': expected, 'result': {'ok': True}}), flush=True)",
    ]
    executable.write_text("\n".join(lines) + "\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def _write_fake_mcp_executable(workspace: Path) -> Path:
    executable = workspace / f"fake-mcp-kimi-{RUN_ID}"
    lines = [
        "#!/usr/bin/python3",
        "import json, os, subprocess, sys",
        "from pathlib import Path",
        "config = json.loads((Path.cwd() / '.kimi-code/mcp.json').read_text(encoding='utf-8'))",
        "server = config['mcpServers']['deployment-health']",
        "requests = [",
        "  {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'kimi-bwrap-smoke', 'version': '1'}}},",
        "  {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},",
        "]",
        "payload = ''.join(json.dumps(item, sort_keys=True) + '\\n' for item in requests).encode()",
        "child_env = dict(os.environ)",
        "child_env.update(server.get('env', {}))",
        "completed = subprocess.run([server['command'], *server['args']], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False, env=child_env)",
        "responses = [json.loads(line) for line in completed.stdout.decode().splitlines() if line.strip()]",
        "assert completed.returncode == 0, completed.stderr.decode(errors='replace')",
        "assert [item.get('id') for item in responses] == [1, 2]",
        "future_path, sibling_path, adjacent_path, canary_path = map(Path, sys.argv[1:5])",
        "(Path(os.environ['TMPDIR']) / 'mcp-smoke-runtime-output').write_text('runtime-writable\\n', encoding='utf-8')",
        "(Path.cwd() / 'mcp-smoke-workspace-output').write_text('workspace-writable\\n', encoding='utf-8')",
        "wire = Path(os.environ['KIMI_CODE_HOME']) / 'sessions/wd_fixture/session_fixture/agents/main/wire.jsonl'",
        "wire.parent.mkdir(parents=True, exist_ok=True)",
        "wire.write_text(json.dumps({'type': 'fixture.mcp-wire'}) + '\\n', encoding='utf-8')",
        "print(json.dumps({'role': 'assistant', 'content': 'mcp-isolated-fixture', 'response_ids': [item.get('id') for item in responses], 'tool_count': len(responses[1]['result']['tools']), 'canary': canary_path.read_text(encoding='utf-8').strip(), 'future_stage_visible': future_path.exists(), 'sibling_case_visible': sibling_path.exists(), 'adjacent_case_file_visible': adjacent_path.exists(), 'user_codex_state_visible': Path('/root/.codex').exists()}), flush=True)",
    ]
    executable.write_text("\n".join(lines) + "\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


def test_broker_attestation_tamper_fails_before_namespace_launch(
    broker_layout,
) -> None:
    case_root, broker, callback = broker_layout
    document = json.loads(broker.attestation_path.read_text(encoding="utf-8"))
    document["broker_kind"] = "tampered"
    broker.attestation_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    launcher = _launcher(case_root, broker, callback)
    with pytest.raises(KimiBubblewrapLauncherError, match="self-hash"):
        launcher.attest(run_id=RUN_ID, run_root=case_root)
    assert broker.active_lease_count == 0
    assert not any(
        path.name.startswith("isolated-launcher-kimi-") for path in case_root.iterdir()
    )


def test_callback_attestation_tamper_fails_before_namespace_launch(
    broker_layout,
) -> None:
    case_root, broker, callback = broker_layout
    document = json.loads(callback.attestation_path.read_text(encoding="utf-8"))
    document["evidence"]["sensitive_header_policy"] = "persist"
    callback.attestation_path.write_text(
        json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
    )
    launcher = _launcher(case_root, broker, callback)
    with pytest.raises(KimiBubblewrapLauncherError, match="self-hash"):
        launcher.attest(run_id=RUN_ID, run_root=case_root)
    assert broker.active_lease_count == 0
    assert callback.active_lease_count == 0
    assert not any(
        path.name.startswith("isolated-launcher-kimi-")
        for path in case_root.iterdir()
    )


def test_broker_cannot_replace_the_constructor_reviewed_implementation(
    broker_layout,
) -> None:
    case_root, broker, callback = broker_layout
    replacement = case_root / f"replacement-broker-kimi-{RUN_ID}.py"
    replacement.write_text("# unreviewed replacement\n", encoding="utf-8")
    document = json.loads(broker.attestation_path.read_text(encoding="utf-8"))
    document["implementation"] = {
        "path": str(replacement),
        "sha256": sha256_file(replacement),
    }
    document["attestation_payload_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in document.items()
            if key != "attestation_payload_sha256"
        }
    )
    broker.attestation_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    launcher = _launcher(case_root, broker, callback)
    with pytest.raises(KimiBubblewrapLauncherError, match="implementation bytes"):
        launcher.attest(run_id=RUN_ID, run_root=case_root)


def test_launcher_rejects_broker_bound_to_other_run(broker_layout) -> None:
    case_root, broker, callback = broker_layout
    launcher = _launcher(case_root, broker, callback)
    with pytest.raises(KimiBubblewrapLauncherError, match="fixed"):
        launcher.attest(run_id="different-run", run_root=case_root)


def test_per_case_launcher_rejects_sibling_case_even_with_same_run_id(
    broker_layout,
) -> None:
    case_root, broker, callback = broker_layout
    sibling = case_root.parent / f"case-kimi-{RUN_ID}-sibling"
    sibling.mkdir(mode=0o700)
    launcher = _launcher(case_root, broker, callback)
    with pytest.raises(KimiBubblewrapLauncherError, match="run_root"):
        launcher.attest(run_id=RUN_ID, run_root=sibling)


def test_sealed_nonce_descriptor_is_explicitly_released(broker_layout) -> None:
    case_root, broker, callback = broker_layout
    _launcher(case_root, broker, callback)
    lease = broker.issue_nonce_fd(run_id=RUN_ID, stage_index=9, purpose="model_relay")
    assert fcntl.fcntl(lease.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    assert os.fstat(lease.fd).st_size == 32
    os.close(lease.fd)
    broker.release_nonce(
        lease.lease_id,
        run_id=RUN_ID,
        stage_index=9,
        purpose="model_relay",
    )
    assert broker.active_lease_count == 0
    assert not any(
        path.name.startswith("isolated-launcher-kimi-") for path in case_root.iterdir()
    )


def test_provider_fixture_rejects_nonce_replay(broker_layout) -> None:
    _, broker, _ = broker_layout
    lease = broker.issue_nonce_fd(
        run_id=RUN_ID, stage_index=7, purpose="model_relay"
    )
    nonce = os.read(lease.fd, 32)
    os.close(lease.fd)

    def handshake() -> dict[str, Any]:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5)
        with connection:
            connection.connect(str(broker.socket_path))
            request = {
                "schema_name": "safety_bench_kimi_relay_handshake",
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": RUN_ID,
                "stage_index": 7,
                "purpose": "model_relay",
                "nonce": base64.b64encode(nonce).decode("ascii"),
            }
            connection.sendall(
                json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )
            raw = bytearray()
            while b"\n" not in raw:
                raw.extend(connection.recv(4096))
            return json.loads(bytes(raw).partition(b"\n")[0])

    assert handshake()["ok"] is True
    replay = handshake()
    assert replay["ok"] is False
    assert replay["reason"] == "unauthorized_nonce"
    broker.release_nonce(
        lease.lease_id,
        run_id=RUN_ID,
        stage_index=7,
        purpose="model_relay",
    )
    assert broker.active_lease_count == 0


def test_loopback_http_request_body_limit_fails_before_reading_body() -> None:
    reader_socket, writer_socket = socket.socketpair()
    try:
        writer_socket.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 5\r\n\r\n"
        )
        with pytest.raises(SandboxEntryError, match="body is too large"):
            _read_http_request(reader_socket, max_body=4)
    finally:
        reader_socket.close()
        writer_socket.close()


def test_provider_response_rejects_ambiguous_framing() -> None:
    reader_socket, writer_socket = socket.socketpair()
    try:
        writer_socket.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 0\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: keep-alive\r\n\r\n"
            b"0\r\n\r\n"
        )
        with pytest.raises(SandboxEntryError, match="framing is ambiguous"):
            _read_provider_response(_SocketReader(reader_socket))
    finally:
        reader_socket.close()
        writer_socket.close()


def test_real_bwrap_self_test_and_stage_are_allowlisted_and_run_scoped(
    broker_layout,
) -> None:
    supported, detail = bubblewrap_namespace_support()
    if not supported:
        pytest.skip(
            f"bubblewrap namespaces unavailable in this test environment: {detail}"
        )

    case_root, broker, callback = broker_layout
    other_case = case_root.parent / f"case-kimi-{RUN_ID}-sibling"
    other_case.mkdir(mode=0o700)
    other_case_marker = other_case / f"future-input-kimi-{RUN_ID}.txt"
    other_case_marker.write_text("must remain hidden\n", encoding="utf-8")
    layout = _stage_layout(
        case_root, case_id=CASE_ID, stage_name="fixture-stage"
    )
    workspace = Path(layout["workspace"])
    future_stage = case_root / f"stage-kimi-{RUN_ID}-future"
    future_stage.mkdir(mode=0o700)
    future_marker = future_stage / f"prompt-kimi-{RUN_ID}-future.txt"
    future_marker.write_text("must remain hidden\n", encoding="utf-8")
    executable = _write_fake_executable(workspace)
    venv_bin = workspace / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python3").symlink_to("/usr/bin/python3")
    (venv_bin / "python").symlink_to("python3")

    launcher = _launcher(case_root, broker, callback)
    assert launcher.resource_snapshot() == {
        "run_id": RUN_ID,
        "owned_process_count": 0,
        "active_processes": [],
        "attested_context_count": 0,
        "spawned_stage_count": 0,
    }
    attestation_path = launcher.attest(run_id=RUN_ID, run_root=case_root)
    assert launcher.resource_snapshot()["attested_context_count"] == 1
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    assert attestation["isolation"] == {
        "kind": "linux_bubblewrap_allowlist_namespaces_v1",
        "enforced": True,
        "host_user_state_mounted": False,
        "other_harness_state_mounted": False,
        "network_egress": "run_local_broker_only",
    }
    assert Path(attestation["evidence"][1]["path"]).is_relative_to(case_root)
    executor = KimiStageExecutor(
        launcher=launcher,
        event_ir_normalizer=object(),
        executable=executable,
        executable_sha256=sha256_file(executable),
    )
    validated, validated_sha = executor._validate_attestation(
        attestation_path,
        run_id=RUN_ID,
        run_root=case_root,
    )
    assert validated["launcher_id"] == (
        "linux-bubblewrap-run-local-provider-callback-v1"
    )
    assert validated_sha == sha256_file(attestation_path)
    assert broker.active_lease_count == 0
    assert any(
        item["purpose"] == "unauthorized_probe" and item["authorized"] is False
        for item in broker.handshakes
    )
    assert any(
        item["purpose"] == "attestation" and item["authorized"] is True
        for item in broker.handshakes
    )

    request = _stage_request(
        layout,
        executable=executable,
        argv=(
            str(executable),
            str(future_marker),
            str(other_case_marker),
            CALLBACK_ORIGIN,
        ),
        attestation_path=attestation_path,
    )
    process = launcher.spawn(request)
    running_snapshot = launcher.resource_snapshot()
    assert running_snapshot["owned_process_count"] == 1
    assert running_snapshot["spawned_stage_count"] == 1
    assert running_snapshot["active_processes"] == [
        {"pid": process.pid, "returncode": None}
    ]
    ownership_environment = {
        item.split(b"=", 1)[0].decode("utf-8")
        for item in Path(f"/proc/{process.pid}/environ").read_bytes().split(b"\0")
        if b"=" in item
    }
    assert ownership_environment == {
        "SAFETY_BENCH_HARNESS",
        "SAFETY_BENCH_RUN_ID",
    }
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    record = json.loads(stdout)
    assert len(record["provider_replies"]) == 2
    assert record["provider_replies"][0].startswith(
        "provider-response-1:/v1/chat/completions?attempt=1"
    )
    assert record["provider_replies"][1].startswith(
        "provider-response-2:/v1/chat/completions?attempt=2"
    )
    assert record["future_stage_visible"] is False
    assert record["other_case_visible"] is False
    assert record["user_codex_state_visible"] is False
    assert record["provider_key_is_placeholder"] is True
    assert record["nonce_files_visible"] is False
    assert broker.active_lease_count == 0
    assert callback.active_lease_count == 0
    model_handshakes = [
        item
        for item in broker.handshakes
        if item["purpose"] == "model_relay" and item["authorized"] is True
    ]
    assert len(model_handshakes) == 1
    assert len(broker.requests) == 2
    assert [item["connection"] for item in broker.requests] == [
        "keep-alive",
        "keep-alive",
    ]
    assert not any(item["authorization_present"] for item in broker.requests)
    callback_manifest = callback.wait_for_stage_manifest(0)
    assert callback_manifest["line_count"] == 2
    completed = callback_manifest["completed_stage_connections"]
    assert len(completed) == 1
    assert completed[0]["stage_index"] == 0
    assert completed[0]["record_count"] == 2
    callback_raw = callback.evidence_path.read_text(encoding="utf-8")
    assert "KIMI_CALLBACK_CANARY" in callback_raw
    assert "正文" in callback_raw
    assert "x-fixture" in callback_raw
    for forbidden in (
        "CALLBACK_SECRET_ONE",
        "CALLBACK_SECRET_TWO",
        "CALLBACK_SECRET_THREE",
        '"authorization"',
        '"cookie"',
        '"x-api-key"',
    ):
        assert forbidden.casefold() not in callback_raw.casefold()
    completed_snapshot = launcher.resource_snapshot()
    assert completed_snapshot["owned_process_count"] == 1
    assert completed_snapshot["active_processes"] == []
    verified = next(
        item for item in attestation["evidence"] if item["kind"] == "os_isolation"
    )
    isolation = json.loads(Path(verified["path"]).read_text(encoding="utf-8"))
    assert isolation["all_required_namespaces_distinct"] is True
    assert isolation["network_interfaces"] == ["lo"]
    assert isolation["nonce_transport"] == {
        "source": "broker_owned_sealed_memfd",
        "sandbox_delivery": "bwrap_file_fd",
        "launcher_read_nonce": False,
        "nonce_in_argv": False,
        "nonce_in_environment": False,
        "nonce_source_fd_in_helper": False,
        "transient_file_removed_before_handshake": True,
    }
    launcher.close()
    assert launcher.resource_snapshot() == {
        "run_id": RUN_ID,
        "owned_process_count": 0,
        "active_processes": [],
        "attested_context_count": 0,
        "spawned_stage_count": 0,
    }
    with pytest.raises(KimiBubblewrapLauncherError, match="attested"):
        launcher.spawn(request)


def test_real_bwrap_stage_supports_sequential_jsonrpc_and_zero_callback_manifest(
    broker_layout,
) -> None:
    supported, detail = bubblewrap_namespace_support()
    if not supported:
        pytest.skip(
            f"bubblewrap namespaces unavailable in this test environment: {detail}"
        )
    case_root, broker, callback = broker_layout
    layout = _stage_layout(
        case_root, case_id=CASE_ID, stage_name="fixture-acp"
    )
    workspace = Path(layout["workspace"])
    executable = _write_fake_acp_executable(workspace)
    launcher = _launcher(case_root, broker, callback)
    attestation_path = launcher.attest(run_id=RUN_ID, run_root=case_root)
    request = _stage_request(
        layout,
        executable=executable,
        argv=(str(executable),),
        attestation_path=attestation_path,
    )
    process = launcher.spawn(request)
    frames = tuple(
        (
            json.dumps(
                {"jsonrpc": "2.0", "id": identifier, "method": f"fixture/{identifier}"},
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        for identifier in (1, 2, 3)
    )
    stdout, stderr = process.exchange_jsonrpc(
        request_frames=frames,
        expected_response_ids=(1, 2, 3),
        timeout=10,
    )
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    records = [json.loads(line) for line in stdout.decode("utf-8").splitlines()]
    assert [record["id"] for record in records if "id" in record] == [1, 2, 3]
    callback_manifest = callback.wait_for_stage_manifest(0)
    assert callback_manifest["line_count"] == 0
    assert len(callback_manifest["completed_stage_connections"]) == 1
    completed = callback_manifest["completed_stage_connections"][0]
    assert completed["stage_index"] == 0
    assert completed["record_count"] == 0
    assert broker.active_lease_count == 0
    assert callback.active_lease_count == 0
    launcher.close()


def test_mount_manifest_tamper_and_path_escape_fail_before_spawn(
    broker_layout,
) -> None:
    supported, detail = bubblewrap_namespace_support()
    if not supported:
        pytest.skip(
            f"bubblewrap namespaces unavailable in this test environment: {detail}"
        )
    case_root, broker, callback = broker_layout
    layout = _stage_layout(
        case_root, case_id=CASE_ID, stage_name="mount-negative"
    )
    executable = _write_fake_acp_executable(Path(layout["workspace"]))
    launcher = _launcher(case_root, broker, callback)
    attestation_path = launcher.attest(run_id=RUN_ID, run_root=case_root)
    request = _stage_request(
        layout,
        executable=executable,
        argv=(str(executable),),
        attestation_path=attestation_path,
    )

    tampered_assets = replace(request.read_only_mounts[0], sha256="0" * 64)
    with pytest.raises(KimiBubblewrapLauncherError, match="content or mode"):
        launcher.spawn(
            replace(
                request,
                read_only_mounts=(
                    tampered_assets,
                    *request.read_only_mounts[1:],
                ),
            )
        )

    manifest_path = request.materialization_manifest_path
    escaped_assets = replace(
        request.read_only_mounts[0],
        path=manifest_path,
        path_type="file",
        sha256=sha256_file(manifest_path),
        mode=manifest_path.stat().st_mode & 0o777,
    )
    with pytest.raises(KimiBubblewrapLauncherError, match="forbidden"):
        launcher.spawn(
            replace(
                request,
                read_only_mounts=(
                    escaped_assets,
                    *request.read_only_mounts[1:],
                ),
            )
        )
    assert broker.active_lease_count == 0
    launcher.close()


def test_real_bwrap_runs_hash_pinned_installed_kimi_shebang_with_local_mask(
    broker_layout,
) -> None:
    supported, detail = bubblewrap_namespace_support()
    if not supported:
        pytest.skip(
            f"bubblewrap namespaces unavailable in this test environment: {detail}"
        )
    entrypoint = Path(
        "/usr/local/lib/node_modules/@moonshot-ai/kimi-code/dist/main.mjs"
    )
    node = Path("/usr/local/bin/node")
    if not entrypoint.is_file() or not node.is_file():
        pytest.skip("installed Kimi Code/Node runtime is unavailable")
    case_root, broker, callback = broker_layout
    layout = _stage_layout(
        case_root, case_id=CASE_ID, stage_name="installed-kimi"
    )
    launcher = _launcher_with_installed_kimi(case_root, broker, callback)
    attestation_path = launcher.attest(run_id=RUN_ID, run_root=case_root)
    request = _stage_request(
        layout,
        executable=entrypoint,
        argv=(str(entrypoint), "--version"),
        attestation_path=attestation_path,
    )
    process = launcher.spawn(request)
    stdout, stderr = process.communicate(timeout=15)
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    assert stdout.decode("utf-8").strip() == "0.26.0"
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    assert attestation["isolation"]["host_user_state_mounted"] is False
    isolation_record = next(
        item for item in attestation["evidence"] if item["kind"] == "os_isolation"
    )
    isolation = json.loads(
        Path(isolation_record["path"]).read_text(encoding="utf-8")
    )
    policy = isolation["mount_policy"]
    assert policy["masked_system_subtree"] == "/usr/local"
    reviewed = policy["reviewed_kimi_node_runtime"]
    assert reviewed["entrypoint_path"] == str(entrypoint.resolve())
    assert reviewed["entrypoint_sha256"] == sha256_file(entrypoint)
    assert reviewed["node_path"] == str(node.resolve())
    assert reviewed["node_sha256"] == sha256_file(node)
    assert reviewed["package_tree_sha256"] == tree_sha256(
        entrypoint.resolve().parents[1]
    )
    assert broker.active_lease_count == 0
    launcher.close()


def test_real_bwrap_exact_mcp_child_and_canary_mounts_work_without_case_tree(
    broker_layout,
) -> None:
    supported, detail = bubblewrap_namespace_support()
    if not supported:
        pytest.skip(
            f"bubblewrap namespaces unavailable in this test environment: {detail}"
        )
    case_root, broker, callback = broker_layout
    layout = _stage_layout(
        case_root, case_id=CASE_ID, stage_name="mcp"
    )
    case_dir = Path(layout["case_dir"])
    workspace = Path(layout["workspace"])
    assets = Path(layout["assets"])
    runtime = Path(layout["runtime"])
    executable = _write_fake_mcp_executable(workspace)

    source_server = (
        Path(__file__).resolve().parents[3]
        / "runs/active/F3_tool_mcp_runtime/f301_rii/case_018/mcp_server.py"
    )
    child_server = case_dir / "mcp_server.py"
    shutil.copy2(source_server, child_server)
    config_root = case_dir / "config"
    config_root.mkdir(mode=0o700)
    canary = config_root / "deployment.id"
    canary.write_text("KIMI_BWRAP_CANARY\n", encoding="utf-8")
    adjacent = config_root / "adjacent-hidden.txt"
    adjacent.write_text("must stay hidden\n", encoding="utf-8")
    future_stage = case_root / f"stage-kimi-{RUN_ID}-stage-001-future"
    future_stage.mkdir(mode=0o700)
    future_marker = future_stage / "future-input.txt"
    future_marker.write_text("must stay hidden\n", encoding="utf-8")
    sibling_root = case_root.parent / f"case-kimi-{RUN_ID}-mcp-sibling"
    sibling_root.mkdir(mode=0o700)
    sibling_marker = sibling_root / "sibling-input.txt"
    sibling_marker.write_text("must stay hidden\n", encoding="utf-8")

    proxy_root = case_root / f"mcp-proxy-kimi-{RUN_ID}-stage-000"
    proxy_root.mkdir(mode=0o700)
    proxy_source = (
        Path(__file__).resolve().parents[3]
        / "infra/cross_harness/adapters/kimi/mcp_stdio_proxy.py"
    )
    proxy_copy = proxy_root / f"mcp-stdio-proxy-kimi-{RUN_ID}-stage-000.py"
    shutil.copyfile(proxy_source, proxy_copy)
    proxy_copy.chmod(0o400)
    evidence_root = runtime / f"mcp-evidence-kimi-{RUN_ID}-stage-000"
    evidence_root.mkdir(mode=0o700)
    initialize_trace = evidence_root / f"initialize-kimi-{RUN_ID}.jsonl"
    tools_trace = evidence_root / f"tools-list-kimi-{RUN_ID}.jsonl"
    stdio_trace = evidence_root / f"stdio-kimi-{RUN_ID}.jsonl"
    exit_trace = evidence_root / f"child-exit-kimi-{RUN_ID}.json"
    trusted_python = Path("/usr/bin/python3.10").resolve(strict=True)
    child_argv = [
        str(trusted_python),
        str(child_server),
        "--mode",
        "result_poison",
        "--deploy-path",
        str(canary),
        "--post-url",
        "http://127.0.0.1:29999/unused",
    ]
    child_sha = canonical_argv_sha256(child_argv)
    proxy_args = [
        str(proxy_copy),
        "--run-root",
        str(case_root),
        "--run-id",
        RUN_ID,
        "--server",
        "deployment-health",
        "--stage-index",
        "0",
        "--child-argv-sha256",
        child_sha,
        "--initialize-trace",
        str(initialize_trace),
        "--tools-list-trace",
        str(tools_trace),
        "--stdio-trace",
        str(stdio_trace),
        "--child-exit-trace",
        str(exit_trace),
        "--",
        *child_argv,
    ]
    prepared_config = assets / f"mcp-kimi-{RUN_ID}-stage-000.json"
    config = {
        "mcpServers": {
            "deployment-health": {
                "command": str(trusted_python),
                "args": proxy_args,
                "env": {
                    "SAFETY_BENCH_HARNESS": "kimi",
                    "SAFETY_BENCH_RUN_ID": RUN_ID,
                },
            }
        }
    }
    prepared_config.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    active_config = workspace / ".kimi-code/mcp.json"
    active_config.parent.mkdir(mode=0o700)
    shutil.copyfile(prepared_config, active_config)

    required_files = []
    for argv_index, path in ((1, child_server), (5, canary)):
        required_files.append(
            {
                "kind": "reviewed_mcp_child_file",
                "child_argv_index": argv_index,
                "path": str(path),
                "sha256": sha256_file(path),
                "mode": path.stat().st_mode & 0o777,
                "provenance": "materialized_canonical_mcp_argument_v1",
            }
        )
    reservation = {
        "server": "deployment-health",
        "required_run_local_files": required_files,
    }
    mcp_surface = {
        "activation": {
            "operation": "replace_file",
            "target": "workspace/.kimi-code/mcp.json",
        },
        "prepared_config": {
            "target": str(prepared_config),
            "evidence_proxy": {
                "run_local_proxy_copy_path": str(proxy_copy),
                "run_local_proxy_copy_sha256": sha256_file(proxy_copy),
            },
        },
        "evidence_proxy": {"server_reservations": [reservation]},
    }
    extra_mounts = (
        StageMount(
            kind="run_local_mcp_proxy",
            path=proxy_copy.resolve(),
            path_type="file",
            sha256=sha256_file(proxy_copy),
            mode=proxy_copy.stat().st_mode & 0o777,
            provenance="verified_run_local_mcp_proxy_copy_v1",
            provenance_sha256="",
        ),
        *(
            StageMount(
                kind="mcp_child_file",
                path=path.resolve(),
                path_type="file",
                sha256=sha256_file(path),
                mode=path.stat().st_mode & 0o777,
                provenance="verified_mcp_child_file_record_v1",
                provenance_sha256="",
            )
            for path in (child_server, canary)
        ),
    )

    launcher = _launcher(case_root, broker, callback)
    attestation_path = launcher.attest(run_id=RUN_ID, run_root=case_root)
    request = _stage_request(
        layout,
        executable=executable,
        argv=(
            str(executable),
            str(future_marker),
            str(sibling_marker),
            str(adjacent),
            str(canary),
        ),
        attestation_path=attestation_path,
        mcp_surface=mcp_surface,
        extra_read_only_mounts=extra_mounts,
    )
    process = launcher.spawn(request)
    stdout, stderr = process.communicate(timeout=15)
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    record = json.loads(stdout)
    assert record["response_ids"] == [1, 2]
    assert record["tool_count"] >= 1
    assert record["canary"] == "KIMI_BWRAP_CANARY"
    assert record["future_stage_visible"] is False
    assert record["sibling_case_visible"] is False
    assert record["adjacent_case_file_visible"] is False
    assert record["user_codex_state_visible"] is False
    assert (Path(request.env["TMPDIR"]) / "mcp-smoke-runtime-output").is_file()
    assert (workspace / "mcp-smoke-workspace-output").is_file()
    assert initialize_trace.is_file()
    assert tools_trace.is_file()
    assert stdio_trace.is_file()
    assert exit_trace.is_file()
    assert broker.active_lease_count == 0
    launcher.close()


def test_bwrap_unavailable_is_an_explicit_skip_contract() -> None:
    supported, detail = bubblewrap_namespace_support(Path("/definitely/missing/bwrap"))
    assert supported is False
    assert "unavailable" in detail
