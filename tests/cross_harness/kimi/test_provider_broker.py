from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from typing import Any, Callable

import pytest

from infra.cross_harness.adapters.kimi.provider_broker import (
    AUDIT_ATTESTATION_SCHEMA_NAME,
    BROKER_ATTESTATION_SCHEMA_NAME,
    KimiProviderBrokerError,
    RunScopedProviderBroker,
    UpstreamEndpoint,
    _Worker,
)


RUN_ID = "broker-run-001"
CASE_ID = "case-001"
TRIAL_ID = "attack-attempt-001"


class _FakeUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler hook
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.records.append(  # type: ignore[attr-defined]
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "proxy_authorization": self.headers.get("Proxy-Authorization"),
                "body": body,
            }
        )
        payload = json.dumps({"ok": True, "received": len(body)}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *args: object) -> None:
        del args


@pytest.fixture
def fake_upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstreamHandler)
    server.records = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def ownership_root_factory() -> Callable[[str], Path]:
    roots: list[Path] = []

    def create(suffix: str = "one") -> Path:
        root = Path(
            tempfile.mkdtemp(prefix=f"case-kimi-{RUN_ID}-{suffix}-", dir="/tmp")
        )
        os.chmod(root, 0o700)
        roots.append(root)
        return root

    try:
        yield create
    finally:
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def _credential_pipe(value: bytes) -> int:
    read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
    try:
        os.write(write_descriptor, value)
    finally:
        os.close(write_descriptor)
    return read_descriptor


def _start_broker(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
    credential: bytes,
    *,
    case_id: str = CASE_ID,
    trial_id: str = TRIAL_ID,
    suffix: str = "one",
    upstream_url: str | None = None,
) -> RunScopedProviderBroker:
    descriptor = _credential_pipe(credential)
    try:
        return RunScopedProviderBroker(
            ownership_root=ownership_root_factory(suffix),
            run_id=RUN_ID,
            case_id=case_id,
            trial_id=trial_id,
            upstream_url=upstream_url
            or f"http://127.0.0.1:{fake_upstream.server_port}/v1",
            credential_fd=descriptor,
            upstream_timeout=10,
        )
    finally:
        os.close(descriptor)


def _nonce_bytes(descriptor: int) -> bytes:
    try:
        value = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    assert len(value) == 32
    return value


def _handshake(
    socket_path: Path,
    *,
    nonce: bytes,
    run_id: str = RUN_ID,
    stage_index: int = 0,
    purpose: str = "model_relay",
) -> tuple[socket.socket, dict[str, Any]]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    connection.connect(str(socket_path))
    request = {
        "schema_name": "safety_bench_kimi_relay_handshake",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": run_id,
        "stage_index": stage_index,
        "purpose": purpose,
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    connection.sendall(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    buffer = bytearray()
    while b"\n" not in buffer:
        buffer.extend(connection.recv(4096))
    line, _, trailing = bytes(buffer).partition(b"\n")
    assert trailing == b""
    return connection, json.loads(line)


def test_upstream_endpoint_rejects_proxy_and_unreviewed_network_shapes() -> None:
    endpoint = UpstreamEndpoint.parse("http://127.0.0.1:8123/v1")
    assert endpoint.authority == "127.0.0.1:8123"
    assert endpoint.tls_verified is False
    production = UpstreamEndpoint.parse(
        "https://api.example.test/v1",
        allowed_https_hosts=["api.example.test"],
    )
    assert production.host == "api.example.test"
    assert production.tls_verified is True

    rejected = (
        "http://example.test/v1",
        "http://10.0.0.2/v1",
        "http://user:password@127.0.0.1:8123/v1",
        "http://127.0.0.1:8123/v1?credential=value",
        "https://api.example.test/v1",
        "https://127.0.0.1/v1",
    )
    for value in rejected:
        with pytest.raises(KimiProviderBrokerError):
            UpstreamEndpoint.parse(value)


def test_worker_instruction_observer_is_body_redacting_and_freezes(
    tmp_path: Path,
) -> None:
    worker = object.__new__(_Worker)
    worker.run_id = RUN_ID
    worker.case_id = CASE_ID
    worker.trial_id = TRIAL_ID
    worker.root = tmp_path / f"observer-kimi-{RUN_ID}"
    worker.root.mkdir(mode=0o700)
    worker.observer_lock = threading.Lock()
    worker.instruction_observers = {}
    audit: list[tuple[str, dict[str, Any]]] = []
    worker._audit = lambda event, **fields: audit.append((event, fields))  # type: ignore[method-assign]
    marker = b"INERT_KIMI_PROJECT_INSTRUCTION_MARKER_001"
    marker_sha = hashlib.sha256(marker).hexdigest()
    configured = worker._configure_instruction_observer(
        {
            "operation": "configure_instruction_observer",
            "run_id": RUN_ID,
            "case_id": CASE_ID,
            "trial_id": TRIAL_ID,
            "stage_index": 2,
            "marker_base64": base64.b64encode(marker).decode("ascii"),
            "marker_sha256": marker_sha,
            "expected_roles": ["system", "user", "user"],
        }
    )
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": marker.decode("ascii")},
                {"role": "user", "content": "context"},
                {"role": "user", "content": "task"},
            ]
        },
        separators=(",", ":"),
    ).encode("utf-8")
    worker._observe_instruction_request(
        stage_index=2,
        target="/v1/chat/completions",
        body=body,
    )
    finalized = worker._finalize_instruction_observer(
        {
            "operation": "finalize_instruction_observer",
            "run_id": RUN_ID,
            "case_id": CASE_ID,
            "trial_id": TRIAL_ID,
            "stage_index": 2,
        }
    )
    evidence_path = Path(str(configured["path"]))
    raw = evidence_path.read_bytes()
    record = json.loads(raw)
    assert finalized["sha256"] == hashlib.sha256(raw).hexdigest()
    assert finalized["line_count"] == 1
    assert marker not in raw and body not in raw
    assert record["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert record["expected_substring_present"] is True
    assert record["expected_substring_sha256"] == marker_sha
    assert record["message_roles"] == ["system", "user", "user"]
    assert [event for event, _ in audit] == [
        "instruction_observer_configured",
        "instruction_observer_finalized",
    ]
    with pytest.raises(KimiProviderBrokerError, match="after observer finalization"):
        worker._observe_instruction_request(
            stage_index=2,
            target="/v1/chat/completions",
            body=body,
        )


def test_broker_attests_private_process_socket_and_redacted_identity(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    credential = f"fixture-{secrets.token_hex(20)}".encode("ascii")
    broker = _start_broker(ownership_root_factory, fake_upstream, credential)
    try:
        assert stat.S_IMODE(broker.root.stat().st_mode) == 0o700
        assert stat.S_IMODE(broker.socket_path.stat().st_mode) == 0o600
        assert broker.socket_path.stat().st_uid == os.getuid()
        launcher_attestation = json.loads(
            broker.attestation_path.read_text(encoding="utf-8")
        )
        assert launcher_attestation["schema_name"] == BROKER_ATTESTATION_SCHEMA_NAME
        assert launcher_attestation["run_id"] == RUN_ID
        assert f"case_id={CASE_ID}" in launcher_attestation["broker_kind"]
        assert f"trial_id={TRIAL_ID}" in launcher_attestation["broker_kind"]
        assert launcher_attestation["process"]["pid"] == broker.pid
        assert launcher_attestation["socket_identity"]["inode"] == (
            broker.socket_path.stat().st_ino
        )
        audit = json.loads(broker.audit_attestation_path.read_text(encoding="utf-8"))
        assert audit["schema_name"] == AUDIT_ATTESTATION_SCHEMA_NAME
        assert (audit["run_id"], audit["case_id"], audit["trial_id"]) == (
            RUN_ID,
            CASE_ID,
            TRIAL_ID,
        )
        assert audit["process_executable_sha256"] == (
            broker.process_executable_sha256
        )
        assert audit["implementation_sha256"] == broker.implementation_sha256
        assert audit["socket_mode"] == 0o600
        assert audit["root_mode"] == 0o700

        environment = Path(f"/proc/{broker.pid}/environ").read_bytes()
        command_line = Path(f"/proc/{broker.pid}/cmdline").read_bytes()
        assert credential not in environment
        assert credential not in command_line
        assert b"KIMI_MODEL_API_KEY" not in environment
        for path in broker.root.iterdir():
            if path.is_file():
                assert credential not in path.read_bytes()
    finally:
        broker.close()


def test_child_client_forwards_to_loopback_and_broker_injects_authorization(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    credential = f"fixture-{secrets.token_hex(20)}".encode("ascii")
    broker = _start_broker(ownership_root_factory, fake_upstream, credential)
    lease = broker.issue_nonce_fd(
        run_id=RUN_ID, stage_index=4, purpose="model_relay"
    )
    from infra.cross_harness.adapters.kimi.isolated_launcher import (
        BrokerNonceFD as LauncherBrokerNonceFD,
    )

    assert isinstance(lease, LauncherBrokerNonceFD)
    client_source = r'''
import base64, json, os, socket, sys
descriptor = int(sys.argv[1])
nonce = os.read(descriptor, 32)
os.close(descriptor)
connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
connection.connect(sys.argv[2])
request = {
    "schema_name": "safety_bench_kimi_relay_handshake",
    "schema_version": 1,
    "harness_id": "kimi",
    "run_id": sys.argv[3],
    "stage_index": int(sys.argv[4]),
    "purpose": "model_relay",
    "nonce": base64.b64encode(nonce).decode("ascii"),
}
connection.sendall(json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n")
buffer = bytearray()
while b"\n" not in buffer:
    buffer.extend(connection.recv(4096))
line, _, trailing = bytes(buffer).partition(b"\n")
assert not trailing
assert json.loads(line)["ok"] is True
body = b'{"model":"local-fixture","messages":[]}'
connection.sendall(
    b"POST /v1/chat/completions HTTP/1.1\r\n"
    b"Host: ignored.invalid\r\n"
    b"Authorization: Bearer child-must-not-control-this\r\n"
    b"Proxy-Authorization: Basic also-rejected\r\n"
    b"Content-Type: application/json\r\n"
    + f"Content-Length: {len(body)}\r\n\r\n".encode()
    + body
)
connection.shutdown(socket.SHUT_WR)
response = bytearray()
while True:
    chunk = connection.recv(65536)
    if not chunk:
        break
    response.extend(chunk)
connection.close()
sys.stdout.buffer.write(response)
'''
    try:
        child_environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        command = [
            str(Path(getattr(sys, "_base_executable", sys.executable)).resolve()),
            "-c",
            client_source,
            str(lease.fd),
            str(broker.socket_path),
            RUN_ID,
            "4",
        ]
        assert credential not in "\0".join(command).encode("utf-8")
        assert credential not in "\0".join(
            f"{key}={value}" for key, value in child_environment.items()
        ).encode("utf-8")
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment,
            close_fds=True,
            pass_fds=(lease.fd,),
            timeout=10,
            check=False,
        )
        os.close(lease.fd)
        assert completed.returncode == 0, completed.stderr.decode(
            "utf-8", errors="replace"
        )
        assert b"HTTP/1.1 200" in completed.stdout
        assert b'"ok": true' in completed.stdout
        assert len(fake_upstream.records) == 1
        observed = fake_upstream.records[0]
        assert observed["authorization"] == f"Bearer {credential.decode('ascii')}"
        assert observed["proxy_authorization"] is None
        assert observed["path"] == "/v1/chat/completions"
        broker.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=4,
            purpose="model_relay",
        )
        assert broker.active_lease_count == 0
        for path in broker.root.iterdir():
            if path.is_file():
                assert credential not in path.read_bytes()
    finally:
        try:
            os.close(lease.fd)
        except OSError:
            pass
        broker.close()


def test_child_relay_v1_target_maps_to_reviewed_upstream_prefix(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    credential = f"fixture-{secrets.token_hex(20)}".encode("ascii")
    broker = _start_broker(
        ownership_root_factory,
        fake_upstream,
        credential,
        upstream_url=f"http://127.0.0.1:{fake_upstream.server_port}/coding/v1",
        suffix="prefix",
    )
    lease = broker.issue_nonce_fd(
        run_id=RUN_ID, stage_index=5, purpose="model_relay"
    )
    nonce = _nonce_bytes(lease.fd)
    body = b'{"model":"local-fixture","messages":[]}'
    try:
        connection, handshake = _handshake(
            broker.socket_path,
            nonce=nonce,
            stage_index=5,
        )
        assert handshake["ok"] is True
        connection.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: ignored.invalid\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        connection.close()
        assert b"HTTP/1.1 200" in response
        assert len(fake_upstream.records) == 1
        observed = fake_upstream.records[0]
        assert observed["path"] == "/coding/v1/chat/completions"
        assert observed["authorization"] == f"Bearer {credential.decode('ascii')}"
        broker.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=5,
            purpose="model_relay",
        )
    finally:
        broker.close()


def test_instruction_observer_records_only_hash_roles_and_marker_presence(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    credential = f"fixture-{secrets.token_hex(20)}".encode("ascii")
    broker = _start_broker(ownership_root_factory, fake_upstream, credential)
    marker = b"INERT_KIMI_PROJECT_INSTRUCTION_MARKER_001"
    stage_index = 3
    observer_path = broker.configure_instruction_observer(
        run_id=RUN_ID,
        stage_index=stage_index,
        marker=marker,
    )
    lease = broker.issue_nonce_fd(
        run_id=RUN_ID, stage_index=stage_index, purpose="model_relay"
    )
    nonce = _nonce_bytes(lease.fd)
    body = json.dumps(
        {
            "model": "local-fixture",
            "messages": [
                {"role": "system", "content": f"project: {marker.decode()}"},
                {"role": "user", "content": "context"},
                {"role": "user", "content": "task"},
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        connection, handshake = _handshake(
            broker.socket_path,
            nonce=nonce,
            stage_index=stage_index,
        )
        assert handshake["ok"] is True
        connection.sendall(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: ignored.invalid\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        connection.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        connection.close()
        assert b"HTTP/1.1 200" in response

        observation = broker.finalize_instruction_observer(
            run_id=RUN_ID, stage_index=stage_index
        )
        assert observation.path == observer_path
        assert observation.line == 1
        assert observation.line_count == 1
        assert observation.body_sha256 == hashlib.sha256(body).hexdigest()
        assert observation.marker_sha256 == hashlib.sha256(marker).hexdigest()
        assert observation.message_roles == ("system", "user", "user")
        raw_evidence = observer_path.read_bytes()
        assert marker not in raw_evidence
        assert body not in raw_evidence
        assert credential not in raw_evidence
        record = json.loads(raw_evidence)
        assert record["expected_substring_present"] is True
        assert record["message_roles"] == ["system", "user", "user"]
        assert set(record).isdisjoint(
            {"messages", "headers", "authorization", "request_body"}
        )
        with pytest.raises(KimiProviderBrokerError, match="rejected"):
            broker.finalize_instruction_observer(
                run_id=RUN_ID, stage_index=stage_index
            )
        broker.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=stage_index,
            purpose="model_relay",
        )
    finally:
        broker.close()


def test_nonce_is_one_connection_only_and_wrong_run_is_rejected(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    broker = _start_broker(
        ownership_root_factory,
        fake_upstream,
        f"fixture-{secrets.token_hex(20)}".encode("ascii"),
    )
    lease = broker.issue_nonce_fd(
        run_id=RUN_ID, stage_index=0, purpose="model_relay"
    )
    nonce = _nonce_bytes(lease.fd)
    try:
        first, first_response = _handshake(broker.socket_path, nonce=nonce)
        first.close()
        assert first_response["ok"] is True

        replay, replay_response = _handshake(broker.socket_path, nonce=nonce)
        replay.close()
        assert replay_response["ok"] is False
        assert replay_response["reason"] == "unauthorized_nonce"

        wrong_run, wrong_run_response = _handshake(
            broker.socket_path,
            nonce=nonce,
            run_id="other-run-001",
        )
        wrong_run.close()
        assert wrong_run_response["ok"] is False
        with pytest.raises(KimiProviderBrokerError, match="cross-run"):
            broker.issue_nonce_fd(
                run_id="other-run-001", stage_index=0, purpose="model_relay"
            )
        broker.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=0,
            purpose="model_relay",
        )
    finally:
        broker.close()


def test_nonce_from_another_case_broker_is_rejected(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    first = _start_broker(
        ownership_root_factory,
        fake_upstream,
        f"fixture-{secrets.token_hex(20)}".encode("ascii"),
        suffix="first",
    )
    second = _start_broker(
        ownership_root_factory,
        fake_upstream,
        f"fixture-{secrets.token_hex(20)}".encode("ascii"),
        case_id="case-002",
        suffix="second",
    )
    lease = first.issue_nonce_fd(
        run_id=RUN_ID, stage_index=2, purpose="model_relay"
    )
    nonce = _nonce_bytes(lease.fd)
    try:
        connection, response = _handshake(
            second.socket_path,
            nonce=nonce,
            stage_index=2,
        )
        connection.close()
        assert response["ok"] is False
        first.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=2,
            purpose="model_relay",
        )
    finally:
        first.close()
        second.close()


def test_close_terminates_only_the_exact_broker_process(
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    first = _start_broker(
        ownership_root_factory,
        fake_upstream,
        f"fixture-{secrets.token_hex(20)}".encode("ascii"),
        suffix="first",
    )
    second = _start_broker(
        ownership_root_factory,
        fake_upstream,
        f"fixture-{secrets.token_hex(20)}".encode("ascii"),
        case_id="case-002",
        suffix="second",
    )
    first_pid = first.pid
    second_pid = second.pid
    try:
        first.close()
        assert not Path(f"/proc/{first_pid}").exists()
        assert Path(f"/proc/{second_pid}").exists()
        assert second.socket_path.exists()
        assert second.active_lease_count == 0
        assert first.attestation_path.exists()
        assert first.audit_log_path.exists()
    finally:
        first.close()
        second.close()


def test_ordinary_file_descriptor_cannot_be_used_as_credential(
    tmp_path: Path,
    ownership_root_factory: Callable[[str], Path],
    fake_upstream: ThreadingHTTPServer,
) -> None:
    credential_file = tmp_path / "credential.txt"
    credential_file.write_bytes(b"must-not-be-read")
    descriptor = os.open(credential_file, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(KimiProviderBrokerError, match="sealed memfd"):
            RunScopedProviderBroker(
                ownership_root=ownership_root_factory("ordinary-file"),
                run_id=RUN_ID,
                case_id=CASE_ID,
                trial_id=TRIAL_ID,
                upstream_url=f"http://127.0.0.1:{fake_upstream.server_port}/v1",
                credential_fd=descriptor,
            )
    finally:
        os.close(descriptor)
