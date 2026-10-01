"""Minimal Gemini hook recorder used by run-local materializations.

The recorder intentionally stores hashes and locators, not prompt, model,
tool-result, instruction, memory, or artifact bodies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_file(raw: Any, workspace: Path) -> tuple[str, Path] | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = Path(raw)
    supplied = candidate if candidate.is_absolute() else workspace / candidate
    if supplied.is_symlink():
        return None
    try:
        relative = supplied.absolute().relative_to(workspace)
    except ValueError:
        return None
    cursor = workspace
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return None
    resolved = supplied.resolve()
    try:
        relative = resolved.relative_to(workspace)
    except ValueError:
        return None
    if not relative.parts or not resolved.is_file():
        return None
    return relative.as_posix(), resolved


def _candidate_paths(tool_input: Mapping[str, Any]) -> Iterable[Any]:
    for key in ("file_path", "path", "absolute_path"):
        if key in tool_input:
            yield tool_input[key]
    for key in ("paths", "file_paths"):
        raw = tool_input.get(key)
        if isinstance(raw, list):
            yield from raw


def _append(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        for record in records:
            payload = (
                json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                + "\n"
            ).encode("utf-8")
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("failed to append Gemini hook evidence")
                view = view[written:]
    finally:
        os.close(descriptor)


def _base(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "hook_event_name": payload.get("hook_event_name"),
        "session_id": payload.get("session_id"),
        "timestamp": payload.get("timestamp"),
    }


def _system_text(payload: Mapping[str, Any]) -> str:
    request = payload.get("llm_request")
    if not isinstance(request, Mapping):
        return ""
    messages = request.get("messages")
    if not isinstance(messages, list):
        return ""
    parts: list[str] = []
    for message in messages:
        if not isinstance(message, Mapping) or message.get("role") != "system":
            continue
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
    return "\n".join(parts)


def _instruction_records(
    payload: Mapping[str, Any], *, workspace: Path, instructions: list[Path], memories: list[Path]
) -> list[dict[str, Any]]:
    system_text = _system_text(payload)
    if not system_text:
        return []
    records: list[dict[str, Any]] = []
    for path in instructions:
        safe = _safe_file(str(path), workspace)
        if safe is None:
            continue
        relative, resolved = safe
        content = resolved.read_text(encoding="utf-8")
        if content and content in system_text:
            records.append(
                {
                    **_base(payload),
                    "kind": "instruction_loaded",
                    "path": relative,
                    "sha256": _file_sha256(resolved),
                }
            )
    for path in memories:
        safe = _safe_file(str(path), workspace)
        if safe is None:
            continue
        relative, resolved = safe
        content = resolved.read_text(encoding="utf-8")
        if content and content in system_text:
            records.append(
                {
                    **_base(payload),
                    "kind": "memory_retrieved",
                    "path": relative,
                    "sha256": _file_sha256(resolved),
                }
            )
    return records


def _after_tool_records(
    payload: Mapping[str, Any],
    *,
    workspace: Path,
    memories: list[Path],
    shell_watch_files: list[Path],
) -> list[dict[str, Any]]:
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    response = payload.get("tool_response")
    if not isinstance(tool_name, str) or not isinstance(tool_input, Mapping):
        return []
    if isinstance(response, Mapping) and response.get("error") not in (None, False, ""):
        return []
    arguments_sha256 = _canonical_sha256(tool_input)
    response_sha256 = _canonical_sha256(response)
    base = {
        **_base(payload),
        "tool_name": tool_name,
        "arguments_sha256": arguments_sha256,
        "response_sha256": response_sha256,
    }
    records: list[dict[str, Any]] = []
    read_tools = {"read_file", "read_many_files"}
    write_tools = {"write_file", "replace", "replace_file"}
    if tool_name in read_tools | write_tools:
        operation = "read" if tool_name in read_tools else "write"
        for raw_path in _candidate_paths(tool_input):
            safe = _safe_file(raw_path, workspace)
            if safe is None:
                continue
            relative, resolved = safe
            records.append(
                {
                    **base,
                    "kind": "file_artifact",
                    "operation": operation,
                    "path": relative,
                    "sha256": _file_sha256(resolved),
                }
            )
            if operation == "write":
                for memory_path in memories:
                    memory_safe = _safe_file(str(memory_path), workspace)
                    if memory_safe is None:
                        continue
                    memory_relative, memory_resolved = memory_safe
                    if memory_resolved == resolved:
                        records.append(
                            {
                                **base,
                                "kind": "memory_written",
                                "path": memory_relative,
                                "sha256": _file_sha256(memory_resolved),
                            }
                        )
    if tool_name == "save_memory":
        for path in memories:
            safe = _safe_file(str(path), workspace)
            if safe is None:
                continue
            relative, resolved = safe
            records.append(
                {
                    **base,
                    "kind": "memory_written",
                    "path": relative,
                    "sha256": _file_sha256(resolved),
                }
            )
    if tool_name == "activate_skill":
        skill_name = tool_input.get("name", tool_input.get("skill_name"))
        if isinstance(skill_name, str) and skill_name:
            skill_file = workspace / ".gemini" / "skills" / skill_name / "SKILL.md"
            safe = _safe_file(str(skill_file), workspace)
            if safe is not None:
                relative, resolved = safe
                records.append(
                    {
                        **base,
                        "kind": "skill_activated",
                        "skill_name": skill_name,
                        "path": relative,
                            "sha256": _file_sha256(resolved),
                        }
                    )
    if tool_name == "run_shell_command":
        command = tool_input.get("command")
        if isinstance(command, str):
            for path in shell_watch_files:
                safe = _safe_file(str(path), workspace)
                if safe is None:
                    continue
                relative, resolved = safe
                if relative not in command and str(path) not in command:
                    continue
                records.append(
                    {
                        **base,
                        "kind": "file_artifact",
                        "operation": "write",
                        "path": relative,
                        "sha256": _file_sha256(resolved),
                    }
                )
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-log", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--instruction", action="append", type=Path, default=[])
    parser.add_argument("--memory", action="append", type=Path, default=[])
    parser.add_argument("--shell-watch-file", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 1
    if not isinstance(payload, Mapping):
        return 1
    workspace = args.workspace.resolve()
    event = payload.get("hook_event_name")
    records: list[dict[str, Any]] = []
    if event == "SessionStart":
        records.append(
            {
                **_base(payload),
                "kind": "session_start",
                "source": payload.get("source"),
            }
        )
    elif event == "PreCompress":
        records.append(
            {
                **_base(payload),
                "kind": "pre_compress",
                "trigger": payload.get("trigger"),
            }
        )
    elif event == "BeforeModel":
        records.extend(
            _instruction_records(
                payload,
                workspace=workspace,
                instructions=args.instruction,
                memories=args.memory,
            )
        )
    elif event == "AfterTool":
        records.extend(
            _after_tool_records(
                payload,
                workspace=workspace,
                memories=args.memory,
                shell_watch_files=args.shell_watch_file,
            )
        )
    if records:
        _append(args.event_log, records)
    sys.stdout.write("{}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
