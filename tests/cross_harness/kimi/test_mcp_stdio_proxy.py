from __future__ import annotations

import json
from pathlib import Path
import select
import subprocess
import sys

import pytest

from infra.cross_harness.adapters.kimi.mcp_stdio_proxy import (
    KimiMcpProxyError,
    ProxyPaths,
    canonical_argv_sha256,
    validate_health_evidence,
)


PROXY = (
    Path(__file__).parents[3]
    / "infra/cross_harness/adapters/kimi/mcp_stdio_proxy.py"
).resolve()


def _paths(run_root: Path) -> ProxyPaths:
    evidence = run_root / "evidence-kimi-mcp-proxy-001"
    return ProxyPaths(
        initialize_trace=evidence / "initialize-kimi-mcp-proxy-001.jsonl",
        tools_list_trace=evidence / "tools-list-kimi-mcp-proxy-001.jsonl",
        stdio_trace=evidence / "stdio-kimi-mcp-proxy-001.jsonl",
        child_exit_trace=evidence / "child-exit-kimi-mcp-proxy-001.json",
    )


def _proxy_argv(run_root: Path, paths: ProxyPaths, child: list[str]) -> list[str]:
    return [
        sys.executable,
        str(PROXY),
        "--run-root",
        str(run_root),
        "--run-id",
        "mcp-proxy-001",
        "--server",
        "fixture-server",
        "--stage-index",
        "0",
        "--child-argv-sha256",
        canonical_argv_sha256(child),
        "--initialize-trace",
        str(paths.initialize_trace),
        "--tools-list-trace",
        str(paths.tools_list_trace),
        "--stdio-trace",
        str(paths.stdio_trace),
        "--child-exit-trace",
        str(paths.child_exit_trace),
        "--",
        *child,
    ]


def _write_ndjson_server(path: Path) -> None:
    path.write_text(
        """import json
import os
import sys

assert "KIMI_MODEL_API_KEY" not in os.environ
for raw in sys.stdin.buffer:
    request = json.loads(raw)
    if request["method"] == "initialize":
        result = {"protocolVersion": "2025-03-26", "capabilities": {}, "serverInfo": {"name": "fixture", "version": "1"}}
    elif request["method"] == "tools/list":
        result = {"tools": [{"name": "fixture_tool", "description": "PRIVATE_TOOL_DESCRIPTION"}]}
    else:
        result = {}
    response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\\n")
    sys.stdout.flush()
""",
        encoding="utf-8",
    )


def test_proxy_forwards_ndjson_and_proves_health_without_payload_leak(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run-kimi-mcp-proxy-001"
    run_root.mkdir()
    server = run_root / "fixture-server-kimi-mcp-proxy-001.py"
    _write_ndjson_server(server)
    paths = _paths(run_root)
    child = [sys.executable, str(server)]
    requests = [
        {"jsonrpc": "2.0", "id": "init-private-id", "method": "initialize", "params": {"secret": "PRIVATE_INITIALIZE_PAYLOAD"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    wire = b"".join(
        (json.dumps(item, separators=(",", ":")) + "\n").encode("utf-8")
        for item in requests
    )
    completed = subprocess.run(
        _proxy_argv(run_root, paths, child),
        input=wire,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin",
            "KIMI_MODEL_API_KEY": "MUST_NOT_REACH_CHILD",
            "SAFETY_BENCH_RUN_ID": "mcp-proxy-001",
        },
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8")
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [response["id"] for response in responses] == ["init-private-id", 2]

    health = validate_health_evidence(
        run_root=run_root,
        run_id="mcp-proxy-001",
        server="fixture-server",
        stage_index=0,
        paths=paths,
        child_argv_sha256=canonical_argv_sha256(child),
    )
    assert health["status"] == "connected"
    evidence = b"".join(path.read_bytes() for path in paths.__dict__.values())
    assert b"PRIVATE_INITIALIZE_PAYLOAD" not in evidence
    assert b"PRIVATE_TOOL_DESCRIPTION" not in evidence
    assert b"MUST_NOT_REACH_CHILD" not in evidence


def test_proxy_forwards_each_interactive_exchange_before_stdin_eof(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run-kimi-mcp-proxy-001"
    run_root.mkdir()
    server = run_root / "fixture-server-kimi-mcp-proxy-001.py"
    _write_ndjson_server(server)
    paths = _paths(run_root)
    child = [sys.executable, str(server)]
    process = subprocess.Popen(
        _proxy_argv(run_root, paths, child),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        process.stdin.write(
            b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        )
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], 2)
        assert readable, "initialize was buffered until stdin EOF"
        assert json.loads(process.stdout.readline())["id"] == 1

        process.stdin.write(
            b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
        )
        process.stdin.flush()
        readable, _, _ = select.select([process.stdout], [], [], 2)
        assert readable, "tools/list was buffered until stdin EOF"
        assert json.loads(process.stdout.readline())["id"] == 2
        process.stdin.close()
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def _content_length(payload: dict[str, object]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _write_content_length_server(path: Path) -> None:
    path.write_text(
        """import json
import sys

source = sys.stdin.buffer
sink = sys.stdout.buffer
while True:
    headers = {}
    while True:
        line = source.readline()
        if not line:
            raise SystemExit(0)
        if line in {b"\\n", b"\\r\\n"}:
            break
        name, value = line.decode("ascii").split(":", 1)
        headers[name.lower()] = value.strip()
    body = source.read(int(headers["content-length"]))
    request = json.loads(body)
    response = {"jsonrpc": "2.0", "id": request["id"], "result": {"ok": True}}
    encoded = json.dumps(response, separators=(",", ":")).encode("utf-8")
    sink.write(f"Content-Length: {len(encoded)}\\r\\n\\r\\n".encode("ascii") + encoded)
    sink.flush()
""",
        encoding="utf-8",
    )


def test_proxy_inspects_content_length_without_changing_bytes(tmp_path: Path) -> None:
    run_root = tmp_path / "run-kimi-mcp-proxy-001"
    run_root.mkdir()
    server = run_root / "content-server-kimi-mcp-proxy-001.py"
    _write_content_length_server(server)
    paths = _paths(run_root)
    child = [sys.executable, str(server)]
    wire = _content_length(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    ) + _content_length(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    completed = subprocess.run(
        _proxy_argv(run_root, paths, child),
        input=wire,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8")
    assert completed.stdout.count(b"Content-Length:") == 2
    health = validate_health_evidence(
        run_root=run_root,
        run_id="mcp-proxy-001",
        server="fixture-server",
        stage_index=0,
        paths=paths,
        child_argv_sha256=canonical_argv_sha256(child),
    )
    assert health["tools_list_result_locator"].endswith(":2")


def test_health_validation_fails_closed_on_tampered_result(tmp_path: Path) -> None:
    run_root = tmp_path / "run-kimi-mcp-proxy-001"
    run_root.mkdir()
    server = run_root / "fixture-server-kimi-mcp-proxy-001.py"
    _write_ndjson_server(server)
    paths = _paths(run_root)
    child = [sys.executable, str(server)]
    wire = b"".join(
        _content.encode("utf-8")
        for _content in (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
            '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n',
        )
    )
    completed = subprocess.run(
        _proxy_argv(run_root, paths, child),
        input=wire,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    tampered = paths.initialize_trace.read_text(encoding="utf-8").replace(
        '"response_status":"success"', '"response_status":"error"'
    )
    paths.initialize_trace.write_text(tampered, encoding="utf-8")
    with pytest.raises(KimiMcpProxyError):
        validate_health_evidence(
            run_root=run_root,
            run_id="mcp-proxy-001",
            server="fixture-server",
            stage_index=0,
            paths=paths,
            child_argv_sha256=canonical_argv_sha256(child),
        )


def test_proxy_rejects_child_argv_drift_before_spawning(tmp_path: Path) -> None:
    run_root = tmp_path / "run-kimi-mcp-proxy-001"
    run_root.mkdir()
    paths = _paths(run_root)
    child = [sys.executable, "does-not-run.py"]
    argv = _proxy_argv(run_root, paths, child)
    digest_index = argv.index("--child-argv-sha256") + 1
    argv[digest_index] = "0" * 64
    completed = subprocess.run(
        argv,
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 78
    assert b"argv drifted" in completed.stderr
    assert not paths.stdio_trace.exists()
