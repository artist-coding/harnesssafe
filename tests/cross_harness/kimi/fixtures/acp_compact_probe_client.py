"""Minimal ACP client used to probe Kimi's native manual compaction route."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import selectors
import subprocess
import time
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kimi", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--instruction", required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    args.trace.parent.mkdir(parents=True, exist_ok=True)
    with args.trace.open("x", encoding="utf-8") as trace, args.stderr.open(
        "x", encoding="utf-8"
    ) as stderr:
        process = subprocess.Popen(
            [str(args.kimi), "acp"],
            cwd=args.cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            bufsize=1,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)

        def request(identifier: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
            message = {
                "jsonrpc": "2.0",
                "id": identifier,
                "method": method,
                "params": params,
            }
            process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            process.stdin.flush()
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Kimi ACP exited early with {process.returncode}")
                ready = selector.select(timeout=min(0.25, deadline - time.monotonic()))
                if not ready:
                    continue
                line = process.stdout.readline()
                if not line:
                    continue
                trace.write(line)
                trace.flush()
                decoded = json.loads(line)
                if decoded.get("id") == identifier:
                    if "error" in decoded:
                        raise RuntimeError(f"ACP {method} failed: {decoded['error']}")
                    result = decoded.get("result")
                    if not isinstance(result, dict):
                        raise RuntimeError(f"ACP {method} result is not an object")
                    return result
                if "id" in decoded and "method" in decoded:
                    raise RuntimeError(
                        f"unexpected ACP client request during compact: {decoded['method']}"
                    )
            raise TimeoutError(f"timed out waiting for ACP {method}")

        initialize = request(
            1,
            "initialize",
            {
                "protocolVersion": 1,
                "clientCapabilities": {
                    "fs": {"readTextFile": False, "writeTextFile": False},
                    "terminal": False,
                },
                "clientInfo": {
                    "name": "safety-bench-kimi-compaction-probe",
                    "version": "1",
                },
            },
        )
        if initialize.get("protocolVersion") != 1:
            raise RuntimeError("Kimi ACP negotiated an unexpected protocol version")
        request(
            2,
            "session/resume",
            {
                "sessionId": args.session_id,
                "cwd": str(args.cwd.resolve()),
                "mcpServers": [],
            },
        )
        result = request(
            3,
            "session/prompt",
            {
                "sessionId": args.session_id,
                "prompt": [
                    {
                        "type": "text",
                        "text": f"/compact {args.instruction}",
                    }
                ],
            },
        )
        if result.get("stopReason") != "end_turn":
            raise RuntimeError("ACP compact did not finish as a local end_turn")
        process.stdin.close()
        try:
            return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            return_code = process.wait(timeout=5)
        if return_code != 0:
            raise RuntimeError(f"Kimi ACP exited with {return_code}")
        print(
            json.dumps(
                {
                    "protocol_version": 1,
                    "session_id": args.session_id,
                    "stop_reason": result["stopReason"],
                    "exit_code": return_code,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
