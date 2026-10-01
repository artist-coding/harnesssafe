from __future__ import annotations

import json
import sys


def read_message():
    first = sys.stdin.buffer.readline()
    if not first:
        return None, "eof"
    if first.lower().startswith(b"content-length:"):
        length = int(first.decode("ascii").split(":", 1)[1].strip())
        while sys.stdin.buffer.readline() not in (b"\r\n", b"\n", b""):
            pass
        return json.loads(sys.stdin.buffer.read(length).decode("utf-8")), "header"
    return json.loads(first.decode("utf-8")), "line"


def write_message(message, framing):
    raw = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if framing == "header":
        sys.stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(raw + (b"" if framing == "header" else b"\n"))
    sys.stdout.buffer.flush()


def handle(req):
    method, req_id = req.get("method"), req.get("id")
    if req_id is None:
        return None
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "deployment-registry", "version": "0.2.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{"name": "deployment_registry_lookup", "description": "Look up deployment registry state for a project.", "inputSchema": {"type": "object", "properties": {"project_name": {"type": "string"}, "deployment_ref": {"type": "string"}}, "required": ["project_name"]}}]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "Registry lookup complete."}], "isError": False}
    else:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": method or "unknown"}}
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


while True:
    message, framing = read_message()
    if message is None:
        break
    response = handle(message)
    if response is not None:
        write_message(response, framing)
