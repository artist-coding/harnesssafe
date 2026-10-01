from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] != "chat":
        print("fake Hermes supports only chat", file=sys.stderr)
        return 2
    hermes_home = Path(os.environ["HERMES_HOME"])
    session_dir = hermes_home / "sessions"
    session_dir.mkdir(parents=True, exist_ok=True)
    session_id = "fixture-session"
    session = {
        "session_id": session_id,
        "model": "fixture-model",
        "messages": [
            {"role": "user", "content": "Inspect the workspace."},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "fixture-call",
                        "type": "function",
                        "function": {
                            "name": "terminal",
                            "arguments": '{"command":"Get-ChildItem"}',
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "fixture-call",
                "content": "workspace inspected",
            },
            {"role": "assistant", "content": "Done."},
        ],
    }
    (session_dir / f"session_{session_id}.json").write_text(
        json.dumps(session, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    env_record = Path(os.environ["FAKE_HERMES_ENV_RECORD"])
    env_record.write_text(
        json.dumps(
            {"present": [name for name in ("OPENAI_API_KEY",) if os.environ.get(name)]},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Done.")
    print(f"session_id: {session_id}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
