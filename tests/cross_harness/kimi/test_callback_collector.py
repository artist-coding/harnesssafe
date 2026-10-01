from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import tempfile
import time
from typing import Any, Callable, Mapping, Sequence

import pytest

from infra.cross_harness.adapters.kimi.callback_collector import (
    CALLBACK_ATTESTATION_SCHEMA_NAME,
    CALLBACK_EVIDENCE_SCHEMA_NAME,
    CALLBACK_MANIFEST_SCHEMA_NAME,
    KimiCallbackCollectorError,
    RunScopedCallbackCollector,
)
from infra.cross_harness.adapters.kimi.isolated_launcher import BrokerNonceFD


RUN_ID = "callback-run-001"
CASE_ID = "case-001"
TRIAL_ID = "attack-attempt-001"


@pytest.fixture
def ownership_root_factory() -> Callable[[str], Path]:
    roots: list[Path] = []

    def create(suffix: str = "one") -> Path:
        root = Path(
            tempfile.mkdtemp(prefix=f"kimi-{RUN_ID}-{suffix[:1]}-", dir="/tmp")
        )
        os.chmod(root, 0o700)
        roots.append(root)
        return root

    try:
        yield create
    finally:
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def _start(
    ownership_root_factory: Callable[[str], Path],
    *,
    suffix: str = "one",
    case_id: str = CASE_ID,
    trial_id: str = TRIAL_ID,
) -> RunScopedCallbackCollector:
    return RunScopedCallbackCollector(
        ownership_root=ownership_root_factory(suffix),
        run_id=RUN_ID,
        case_id=case_id,
        trial_id=trial_id,
    )


def _read_nonce(descriptor: int) -> bytes:
    try:
        nonce = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    assert len(nonce) == 32
    return nonce


def _handshake(
    collector: RunScopedCallbackCollector,
    *,
    nonce: bytes,
    stage_index: int,
    run_id: str = RUN_ID,
    purpose: str = "callback_relay",
) -> tuple[socket.socket, Mapping[str, Any]]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    connection.connect(str(collector.socket_path))
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
        chunk = connection.recv(4096)
        assert chunk
        buffer.extend(chunk)
    line, _, trailing = bytes(buffer).partition(b"\n")
    assert trailing == b""
    return connection, json.loads(line)


def _run_stage(
    collector: RunScopedCallbackCollector,
    *,
    stage_index: int,
    records: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any]:
    lease = collector.issue_nonce_fd(
        run_id=RUN_ID,
        stage_index=stage_index,
        purpose="callback_relay",
    )
    assert isinstance(lease, BrokerNonceFD)
    nonce = _read_nonce(lease.fd)
    connection, response = _handshake(
        collector,
        nonce=nonce,
        stage_index=stage_index,
    )
    assert response["ok"] is True
    try:
        for record in records:
            connection.sendall(
                json.dumps(
                    record,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
                + b"\n"
            )
        connection.shutdown(socket.SHUT_WR)
    finally:
        connection.close()
    manifest = collector.wait_for_stage_manifest(stage_index, timeout=5)
    collector.release_nonce(
        lease.lease_id,
        run_id=RUN_ID,
        stage_index=stage_index,
        purpose="callback_relay",
    )
    return manifest


def _record(
    *,
    method: str = "POST",
    path: str = "/callback",
    query: str = "",
    headers: Mapping[str, str] | None = None,
    body: str = "",
) -> Mapping[str, Any]:
    return {
        "method": method,
        "path": path,
        "query": query,
        "headers": dict(headers or {}),
        "body": body,
    }


def test_private_attestation_has_exact_case_trial_and_process_identity(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    collector = _start(ownership_root_factory)
    try:
        assert stat.S_IMODE(collector.root.stat().st_mode) == 0o700
        assert stat.S_IMODE(collector.socket_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(collector.attestation_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(collector.evidence_path.stat().st_mode) == 0o600
        attestation = json.loads(
            collector.attestation_path.read_text(encoding="utf-8")
        )
        assert attestation["schema_name"] == CALLBACK_ATTESTATION_SCHEMA_NAME
        assert (
            attestation["run_id"],
            attestation["case_id"],
            attestation["trial_id"],
        ) == (RUN_ID, CASE_ID, TRIAL_ID)
        assert attestation["process"]["pid"] == collector.pid
        assert attestation["process"]["start_time"] == collector.start_time
        assert attestation["process"]["executable_sha256"] == (
            collector.process_executable_sha256
        )
        assert attestation["implementation"]["sha256"] == (
            collector.implementation_sha256
        )
        assert attestation["socket"]["inode"] == collector.socket_path.stat().st_ino
        assert attestation["socket"]["mode"] == 0o600
        assert attestation["nonce"]["purpose"] == "callback_relay"
        assert collector.evidence_path.read_bytes() == b""
        assert not collector.evidence_manifest_path.exists()
    finally:
        collector.close()


def test_empty_stage_connection_publishes_zero_line_manifest(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    collector = _start(ownership_root_factory)
    try:
        manifest = _run_stage(collector, stage_index=0, records=[])
        assert manifest["schema_name"] == CALLBACK_MANIFEST_SCHEMA_NAME
        assert manifest["line_count"] == 0
        assert manifest["evidence_sha256"] == (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        assert manifest["hash_chain_head_sha256"] is None
        segment = manifest["completed_stage_connections"][0]
        assert segment["stage_index"] == 0
        assert segment["record_count"] == 0
        assert segment["outcome"] == "completed"
        assert collector.evidence_path.read_bytes() == b""
    finally:
        collector.close()


def test_empty_hit_and_canary_are_preserved_while_sensitive_headers_are_absent(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    canary = f"KIMI-CALLBACK-{secrets.token_hex(12)}"
    authorization = f"Bearer {secrets.token_hex(20)}"
    cookie = f"session={secrets.token_hex(20)}"
    api_key = secrets.token_hex(20)
    collector = _start(ownership_root_factory)
    try:
        _run_stage(
            collector,
            stage_index=0,
            records=[_record(method="GET", path="/empty")],
        )
        manifest = _run_stage(
            collector,
            stage_index=1,
            records=[
                _record(
                    query=f"source=test&canary={canary}",
                    headers={
                        "Authorization": authorization,
                        "Cookie": cookie,
                        "X-API-Key": api_key,
                        "Content-Type": "text/plain; charset=utf-8",
                        "X-Safe-Trace": "local-only",
                    },
                    body=f"callback body with {canary} and 中文",
                )
            ],
        )
        assert manifest["line_count"] == 2
        assert len(manifest["completed_stage_connections"]) == 2
        raw = collector.evidence_path.read_text(encoding="utf-8")
        assert canary in raw
        assert authorization not in raw
        assert cookie not in raw
        assert api_key not in raw
        assert "authorization" not in raw.casefold()
        assert '"cookie"' not in raw.casefold()
        records = [json.loads(line) for line in raw.splitlines()]
        assert records[0]["schema_name"] == CALLBACK_EVIDENCE_SCHEMA_NAME
        assert records[0]["method"] == "GET"
        assert records[0]["query"] == ""
        assert records[0]["body"] == ""
        assert records[1]["query"].endswith(canary)
        assert canary in records[1]["body"]
        assert records[1]["headers"] == {
            "content-type": "text/plain; charset=utf-8",
            "x-safe-trace": "local-only",
        }
        assert records[1]["redacted_header_count"] == 3
        assert records[0]["previous_record_sha256"] is None
        assert records[1]["previous_record_sha256"] == records[0]["record_sha256"]
        assert manifest["hash_chain_head_sha256"] == records[1]["record_sha256"]
        assert isinstance(records[1]["observed_at"], str)
        assert isinstance(records[1]["observed_at_unix_ns"], int)
        assert collector.active_lease_count == 0
    finally:
        collector.close()


def test_nonce_is_one_use_and_wrong_purpose_or_run_is_rejected(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    collector = _start(ownership_root_factory)
    lease = collector.issue_nonce_fd(
        run_id=RUN_ID,
        stage_index=2,
        purpose="callback_relay",
    )
    nonce = _read_nonce(lease.fd)
    try:
        wrong_run, wrong_run_response = _handshake(
            collector,
            nonce=nonce,
            stage_index=2,
            run_id="other-run-001",
        )
        wrong_run.close()
        assert wrong_run_response["ok"] is False

        connection, response = _handshake(
            collector,
            nonce=nonce,
            stage_index=2,
        )
        assert response["ok"] is True
        connection.shutdown(socket.SHUT_WR)
        connection.close()
        collector.wait_for_stage_manifest(2)

        replay, replay_response = _handshake(
            collector,
            nonce=nonce,
            stage_index=2,
        )
        replay.close()
        assert replay_response["ok"] is False
        assert replay_response["reason"] == "unauthorized_nonce"
        with pytest.raises(KimiCallbackCollectorError, match="only issues"):
            collector.issue_nonce_fd(
                run_id=RUN_ID,
                stage_index=3,
                purpose="model_relay",
            )
        with pytest.raises(KimiCallbackCollectorError, match="cross-run"):
            collector.issue_nonce_fd(
                run_id="other-run-001",
                stage_index=3,
                purpose="callback_relay",
            )
        collector.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=2,
            purpose="callback_relay",
        )
    finally:
        collector.close()


def test_nonce_from_another_case_collector_is_rejected(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    first = _start(ownership_root_factory, suffix="first")
    second = _start(
        ownership_root_factory,
        suffix="second",
        case_id="case-002",
    )
    lease = first.issue_nonce_fd(
        run_id=RUN_ID,
        stage_index=1,
        purpose="callback_relay",
    )
    nonce = _read_nonce(lease.fd)
    try:
        connection, response = _handshake(
            second,
            nonce=nonce,
            stage_index=1,
        )
        connection.close()
        assert response["ok"] is False
        correct, correct_response = _handshake(
            first,
            nonce=nonce,
            stage_index=1,
        )
        assert correct_response["ok"] is True
        correct.shutdown(socket.SHUT_WR)
        correct.close()
        first.wait_for_stage_manifest(1)
        first.release_nonce(
            lease.lease_id,
            run_id=RUN_ID,
            stage_index=1,
            purpose="callback_relay",
        )
    finally:
        first.close()
        second.close()


def test_evidence_tamper_is_detected_against_manifest(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    collector = _start(ownership_root_factory)
    try:
        _run_stage(
            collector,
            stage_index=0,
            records=[_record(body="audited body")],
        )
        collector.verify_evidence_manifest()
        with collector.evidence_path.open("ab") as handle:
            handle.write(b'{"tampered":true}\n')
        with pytest.raises(KimiCallbackCollectorError, match="SHA-256"):
            collector.verify_evidence_manifest()
    finally:
        collector.close()


def test_close_terminates_only_exact_collector_and_keeps_evidence(
    ownership_root_factory: Callable[[str], Path],
) -> None:
    first = _start(ownership_root_factory, suffix="first")
    second = _start(
        ownership_root_factory,
        suffix="second",
        case_id="case-002",
    )
    first_pid = first.pid
    second_pid = second.pid
    try:
        _run_stage(
            first,
            stage_index=0,
            records=[_record(body="retained evidence")],
        )
        first.close()
        deadline = time.monotonic() + 2
        while Path(f"/proc/{first_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not Path(f"/proc/{first_pid}").exists()
        assert Path(f"/proc/{second_pid}").exists()
        assert second.socket_path.exists()
        assert second.active_lease_count == 0
        assert first.attestation_path.exists()
        assert first.evidence_path.exists()
        assert first.evidence_manifest_path.exists()
    finally:
        first.close()
        second.close()
