import json
from pathlib import Path

import pytest

from infra import mcp_interface_probe as probe


SERVER_SOURCE = r'''
from __future__ import annotations

import argparse
import json
import sys
import time


parser = argparse.ArgumentParser()
parser.add_argument("--mode", default="attack")
parser.add_argument("--behavior", default="line")
args = parser.parse_args()

if args.behavior == "sleep":
    time.sleep(10)


def result(method):
    if method == "initialize":
        return {
            "serverInfo": {"version": "1.0", "name": "fixture"},
            "capabilities": {"prompts": {}, "tools": {}, "resources": {}},
            "protocolVersion": "2024-11-05",
        }
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "z_tool",
                    "description": args.mode,
                    "inputSchema": {
                        "required": ["z", "a"],
                        "properties": {"z": {"type": "string"}, "a": {"type": "string"}},
                        "type": "object",
                    },
                },
                {"name": "a_tool", "description": "first", "inputSchema": {"type": "object"}},
            ]
        }
    if method == "resources/list":
        return {
            "resources": [
                {"name": "z-resource", "uri": "fixture://z"},
                {"name": "a-resource", "uri": "fixture://a"},
            ]
        }
    if method == "prompts/list":
        return {"prompts": [{"name": "z-prompt"}, {"name": "a-prompt"}]}
    return {}


for line in sys.stdin.buffer:
    request = json.loads(line.decode("utf-8"))
    request_id = request.get("id")
    if request_id is None:
        continue
    if args.behavior == "error" and request.get("method") == "resources/list":
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "not implemented"},
        }
    else:
        response = {"jsonrpc": "2.0", "id": request_id, "result": result(request["method"])}
    raw = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if args.behavior == "header":
        sys.stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
    else:
        sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()
'''


def _make_case(tmp_path, monkeypatch, *, behavior="line", script_arg="server.py", command="python"):
    repo = tmp_path / "repo"
    case = repo / "runs" / "case_001"
    (case / "workspace").mkdir(parents=True)
    server = case / "server.py"
    server.write_text(SERVER_SOURCE, encoding="utf-8")
    config = case / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture-server": {
                        "command": command,
                        "args": [script_arg, "--mode", "attack", "--behavior", behavior],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(probe, "REPO_ROOT", repo)
    return case, config, server


@pytest.mark.parametrize("behavior", ["line", "header"])
def test_probe_returns_normalized_snapshot_and_replaces_mode(tmp_path, monkeypatch, behavior):
    case, config, _ = _make_case(tmp_path, monkeypatch, behavior=behavior)

    snapshot = probe.probe_mcp_interface(case, config, clean_mode="clean", timeout_seconds=3)

    assert list(snapshot) == ["servers"]
    interface = snapshot["servers"]["fixture-server"]
    assert list(interface) == ["initialize", "tools/list", "resources/list", "prompts/list"]
    assert [tool["name"] for tool in interface["tools/list"]["tools"]] == ["a_tool", "z_tool"]
    assert interface["tools/list"]["tools"][1]["description"] == "clean"
    assert interface["tools/list"]["tools"][1]["inputSchema"]["required"] == ["a", "z"]
    assert [item["name"] for item in interface["resources/list"]["resources"]] == [
        "a-resource",
        "z-resource",
    ]
    assert [item["name"] for item in interface["prompts/list"]["prompts"]] == [
        "a-prompt",
        "z-prompt",
    ]


def test_probe_accepts_windows_absolute_case_local_script(tmp_path, monkeypatch):
    case, config, server = _make_case(tmp_path, monkeypatch)
    document = json.loads(config.read_text(encoding="utf-8"))
    document["mcpServers"]["fixture-server"]["args"][0] = str(server)
    config.write_text(json.dumps(document), encoding="utf-8")

    snapshot = probe.probe_mcp_interface(case, "mcp.json", timeout_seconds=3)

    assert "fixture-server" in snapshot["servers"]


def test_probe_rejects_non_case_local_script_and_non_python_command(tmp_path, monkeypatch):
    case, config, _ = _make_case(tmp_path, monkeypatch)
    outside = probe.REPO_ROOT / "shared.py"
    outside.write_text(SERVER_SOURCE, encoding="utf-8")
    document = json.loads(config.read_text(encoding="utf-8"))
    definition = document["mcpServers"]["fixture-server"]
    definition["args"][0] = str(outside)
    config.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(probe.ProbeError, match="not case-local"):
        probe.probe_mcp_interface(case, config)

    definition["args"][0] = "server.py"
    definition["command"] = "powershell"
    config.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(probe.ProbeError, match="not an allowed Python command"):
        probe.probe_mcp_interface(case, config)


def test_probe_fails_closed_on_json_rpc_error(tmp_path, monkeypatch):
    case, config, _ = _make_case(tmp_path, monkeypatch, behavior="error")

    with pytest.raises(probe.ProbeError, match="returned an error for resources/list"):
        probe.probe_mcp_interface(case, config, timeout_seconds=3)


def test_probe_fails_closed_on_timeout(tmp_path, monkeypatch):
    case, config, _ = _make_case(tmp_path, monkeypatch, behavior="sleep")

    with pytest.raises(probe.ProbeError, match="timed out"):
        probe.probe_mcp_interface(case, config, timeout_seconds=0.1)


def test_mode_override_is_explicit_and_fail_closed():
    assert probe.replace_mode_argument(("--mode", "attack", "--flag"), "clean") == (
        "--mode",
        "clean",
        "--flag",
    )
    with pytest.raises(probe.ProbeError, match="exactly one"):
        probe.replace_mode_argument(("--flag",), "clean")
    with pytest.raises(probe.ProbeError, match="exactly one"):
        probe.replace_mode_argument(("--mode", "a", "--mode", "b"), "clean")


def test_canonical_sha256_and_exact_json_pointer_diff():
    left = {"z": 1, "a/b": {"x~y": [1, {"old": True}]}, "removed": 4}
    right = {"a/b": {"x~y": [2, {"new": False}, 3]}, "z": 1, "added": 5}

    assert probe.canonical_sha256({"b": 2, "a": 1}) == probe.canonical_sha256({"a": 1, "b": 2})
    assert probe.json_pointer_diff(left, right) == [
        {"pointer": "/removed", "kind": "removed", "left": 4},
        {"pointer": "/added", "kind": "added", "right": 5},
        {"pointer": "/a~1b/x~0y/0", "kind": "changed", "left": 1, "right": 2},
        {"pointer": "/a~1b/x~0y/1/old", "kind": "removed", "left": True},
        {"pointer": "/a~1b/x~0y/1/new", "kind": "added", "right": False},
        {"pointer": "/a~1b/x~0y/2", "kind": "added", "right": 3},
    ]
