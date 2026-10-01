from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from infra.harness_adapters.openclaw.config import (  # type: ignore
        io_path, load_or_create_paths, render_config, write_config,
    )
    from infra.harness_adapters.openclaw.gateway import (  # type: ignore
        OwnershipManifest,
        build_gateway_spec,
    )
    from infra.harness_adapters.openclaw.launch import build_agent_launch  # type: ignore
    from infra.harness_adapters.openclaw.events import (  # type: ignore
        OpenClawEvent,
        extract_session_file,
        extract_spawned_children,
        normalize_openclaw_run,
        normalize_openclaw_session_transcript,
    )
else:
    from .config import io_path, load_or_create_paths, render_config, write_config
    from .gateway import OwnershipManifest, build_gateway_spec
    from .launch import build_agent_launch
    from .events import (
        OpenClawEvent,
        extract_session_file,
        extract_spawned_children,
        normalize_openclaw_run,
        normalize_openclaw_session_transcript,
    )


def _build_compaction_argv(
    executable: Path,
    *,
    session_key: str,
    agent_id: str,
    gateway_port: int,
    timeout: int,
) -> list[str]:
    return [
        str(executable),
        "sessions",
        "compact",
        session_key,
        "--agent",
        agent_id,
        "--json",
        "--timeout",
        str(timeout * 1000),
    ]


def _agent_invocation_required(session_action: str) -> bool:
    """Native compaction is the complete compact stage operation.

    The canonical compact-stage prompt begins with ``/compact``. Replaying that
    text through ``openclaw agent --message`` after native compaction both
    duplicates the boundary and is rejected by the pinned CLI.
    """
    return session_action != "compact"


def _normalize_compaction_events(
    text: str,
    *,
    source_path: Path,
    run_id: str,
    stage_index: int,
    agent_id: str,
    native_session_key: str,
    boundary_session_id: str,
) -> list[OpenClawEvent]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("OpenClaw compaction output is not valid JSON") from exc
    result = payload.get("result") if isinstance(payload, dict) else None
    before = result.get("tokensBefore") if isinstance(result, dict) else None
    after = result.get("tokensAfter") if isinstance(result, dict) else None
    summary = result.get("summary") if isinstance(result, dict) else None
    estimated_after = False
    if after is None and isinstance(summary, str) and summary:
        after = max(1, (len(summary) + 3) // 4)
        estimated_after = True
    if not (
        isinstance(payload, dict)
        and payload.get("ok") is True
        and payload.get("compacted") is True
        and isinstance(before, int)
        and isinstance(after, int)
        and before > after >= 0
        and boundary_session_id
    ):
        raise ValueError("OpenClaw compaction lacks a real token-reduction boundary")
    source_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    compact_metadata: dict[str, object] = {
        "trigger": "manual", "pre_tokens": before, "post_tokens": after,
    }
    if estimated_after:
        compact_metadata.update({
            "post_tokens_source": "summary_chars_div_4_ceiling",
            "summary_sha256": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
        })
    common = {
        "timestamp": "",
        "run_id": run_id,
        "stage_index": stage_index,
        "agent_id": agent_id,
        "session_id": native_session_key,
        "call_id": "",
        "source_path": str(source_path),
        "source_record_index": 0,
        "source_sha256": source_sha256,
    }
    payloads = (
        {"type": "system", "subtype": "status", "status": "compacting",
         "session_id": boundary_session_id},
        {"type": "system", "subtype": "status", "status": "compact_success",
         "compact_result": "success", "session_id": boundary_session_id},
        {"type": "system", "subtype": "compact_boundary",
         "session_id": boundary_session_id,
         "compact_metadata": compact_metadata},
    )
    return [
        OpenClawEvent(kind="session.compact", payload=event_payload, **common)
        for event_payload in payloads
    ]


def _compat_session_event(
    kind: str,
    payload: dict[str, object],
    *,
    source_path: Path,
    run_id: str,
    stage_index: int,
    agent_id: str,
    native_session_key: str,
) -> OpenClawEvent:
    source_sha256 = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return OpenClawEvent(
        kind=kind,
        timestamp="",
        run_id=run_id,
        stage_index=stage_index,
        agent_id=agent_id,
        session_id=native_session_key,
        call_id="",
        source_path=str(source_path),
        source_record_index=0,
        source_sha256=source_sha256,
        payload=payload,
    )


def _project_agent_events(
    agent_text: str,
    *,
    raw_path: Path,
    run_dir: Path,
    state_dir: Path,
    stage_index: int,
    skill_dirs: tuple[Path, ...],
    run_id: str,
    agent_id: str,
    session_id: str,
    secrets_to_redact: tuple[str, ...] = (),
) -> list[OpenClawEvent]:
    events = normalize_openclaw_run(
        agent_text,
        source_path=raw_path,
        run_id=run_id,
        stage_index=stage_index,
        agent_id=agent_id,
        session_id=session_id,
    )
    session_file = extract_session_file(agent_text)
    if session_file is None:
        return events
    resolved_session = session_file.resolve()
    resolved_state = state_dir.resolve()
    try:
        resolved_session.relative_to(resolved_state)
    except ValueError as exc:
        raise ValueError("OpenClaw session file is outside owned state") from exc
    if not io_path(resolved_session).is_file():
        raise ValueError(f"OpenClaw session file is missing: {resolved_session}")
    copied = run_dir / f"openclaw-session-stage-{stage_index:03d}.jsonl"
    copied.parent.mkdir(parents=True, exist_ok=True)
    session_text = _redact(
        io_path(resolved_session).read_text(encoding="utf-8"),
        secrets_to_redact,
    )
    current_lines = session_text.splitlines()
    delta_lines = current_lines
    record_offset = 0
    previous_artifacts = sorted(
        path for path in io_path(run_dir).glob("openclaw-session-stage-*.jsonl")
        if path != copied
    )
    if previous_artifacts:
        previous_lines = io_path(previous_artifacts[-1]).read_text(
            encoding="utf-8"
        ).splitlines()
        if current_lines[:len(previous_lines)] == previous_lines:
            record_offset = len(previous_lines)
            delta_lines = current_lines[record_offset:]
    io_path(copied).write_text(session_text, encoding="utf-8")
    events.extend(normalize_openclaw_session_transcript(
        "\n".join(delta_lines),
        source_path=copied,
        skill_dirs=skill_dirs,
        run_id=run_id,
        stage_index=stage_index,
        agent_id=agent_id,
        session_id=session_id,
        record_offset=record_offset,
    ))
    return events


def _project_completed_subagents(
    completed: list[dict[str, object]],
    *,
    run_dir: Path,
    stage_index: int,
    run_id: str,
    parent_agent_id: str,
    parent_session_id: str,
    secrets_to_redact: tuple[str, ...] = (),
) -> list[OpenClawEvent]:
    events: list[OpenClawEvent] = []
    for child_index, child in enumerate(completed, start=1):
        child_key = str(child["child_session_key"])
        call_id = str(child["call_id"])
        session_file = Path(child["session_file"]).resolve()
        child_text = _redact(
            io_path(session_file).read_text(encoding="utf-8"),
            secrets_to_redact,
        )
        copied = run_dir / (
            f"openclaw-subagent-stage-{stage_index:03d}-{child_index:03d}.jsonl"
        )
        copied.parent.mkdir(parents=True, exist_ok=True)
        io_path(copied).write_text(child_text, encoding="utf-8")
        child_agent_id = child_key.split(":")[1]
        events.extend(normalize_openclaw_session_transcript(
            child_text,
            source_path=copied,
            run_id=run_id,
            stage_index=stage_index,
            agent_id=child_agent_id,
            session_id=child_key,
            parent_tool_use_id=call_id,
        ))
        child_trace_sha256 = hashlib.sha256(child_text.encode("utf-8")).hexdigest()
        events.append(OpenClawEvent(
            kind="subagent.complete",
            timestamp="",
            run_id=run_id,
            stage_index=stage_index,
            agent_id=parent_agent_id,
            session_id=parent_session_id,
            call_id=call_id,
            source_path=str(copied),
            source_record_index=max(0, len(child_text.splitlines()) - 1),
            source_sha256=child_trace_sha256,
            payload={
                "type": "subagent.complete",
                "runtime": "subagent",
                "parentId": parent_session_id,
                "childId": child_key,
                "childTraceSha256": child_trace_sha256,
                "status": str(child["status"]),
                "runId": str(child.get("run_id", "")),
            },
            parent_tool_use_id=call_id,
        ))
    return events


def _load_mcp(paths: list[Path]) -> dict[str, object]:
    servers: dict[str, object] = {}
    for path in paths:
        payload = json.loads(io_path(path).read_text(encoding="utf-8-sig"))
        declared = payload.get("mcpServers", payload.get("servers", {}))
        if not isinstance(declared, dict):
            raise ValueError(f"invalid MCP server registry: {path}")
        for name, config in declared.items():
            if name in servers:
                raise ValueError(f"duplicate MCP server: {name}")
            servers[str(name)] = config
    return servers


def _load_subagents(text: str) -> dict[str, object]:
    if not text:
        return {}
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("OpenClaw subagent declaration must be an object")
    return {str(name): config for name, config in payload.items()}


def _redact(text: str, secrets_to_redact: tuple[str, ...]) -> str:
    for value in secrets_to_redact:
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def _capture_stream(
    stream: TextIO,
    target: Path,
    secrets_to_redact: tuple[str, ...] = (),
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    chunks: list[str] = []
    while True:
        chunk = stream.read(4096)
        if not chunk:
            break
        chunks.append(chunk)
    io_path(target).write_text(
        _redact("".join(chunks), secrets_to_redact),
        encoding="utf-8",
        newline="",
    )


def _append_readiness_record(
    path: Path | None,
    payload: dict[str, object],
    secrets_to_redact: tuple[str, ...],
) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = _redact(
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
        secrets_to_redact,
    )
    with io_path(path).open("a", encoding="utf-8") as output:
        output.write(rendered + "\n")


def _http_ready(gateway_port: int) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{gateway_port}/readyz",
            timeout=0.5,
        ) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def _gateway_readiness_timeout(stage_timeout: int) -> int:
    return min(120, max(1, int(stage_timeout)))


def _operation_timeout(stage_timeout: int) -> float:
    """Keep the declared model/native-action budget independent of startup."""

    return max(1.0, float(stage_timeout))


def _subagent_completion_timeout(stage_timeout: int) -> float:
    """Allow native child turns a bounded completion window after the parent."""

    return min(120.0, max(1.0, float(stage_timeout)))


def _remaining_seconds(
    deadline: float,
    *,
    now: Callable[[], float] = time.monotonic,
) -> float:
    remaining = deadline - now()
    if remaining <= 0:
        raise TimeoutError("OpenClaw stage deadline exhausted")
    return remaining


def _wait_for_spawned_subagents(
    state_dir: Path,
    children: list[dict[str, str]],
    *,
    deadline: float,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, object]]:
    pending = {child["child_session_key"]: dict(child) for child in children}
    completed: list[dict[str, object]] = []
    failure_statuses = {"aborted", "cancelled", "error", "failed", "killed", "timeout"}
    while pending:
        if now() >= deadline:
            raise TimeoutError("OpenClaw subagent completion deadline exhausted")
        for child_key in list(pending):
            parts = child_key.split(":")
            if len(parts) < 4 or parts[0] != "agent" or parts[2] != "subagent":
                raise ValueError(f"invalid OpenClaw child session key: {child_key}")
            registry_path = (
                state_dir / "agents" / parts[1] / "sessions" / "sessions.json"
            )
            try:
                registry = json.loads(io_path(registry_path).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            entry = registry.get(child_key) if isinstance(registry, dict) else None
            if not isinstance(entry, dict):
                continue
            status = str(entry.get("status", "")).lower()
            if status in failure_statuses:
                raise RuntimeError(
                    f"OpenClaw subagent ended with terminal status: {status}"
                )
            if status in {"", "accepted", "pending", "running", "starting"}:
                continue
            session_file = Path(str(entry.get("sessionFile", ""))).resolve()
            try:
                session_file.relative_to(state_dir.resolve())
            except ValueError as exc:
                raise ValueError("OpenClaw child session is outside owned state") from exc
            if (
                not io_path(session_file).is_file()
                or io_path(Path(str(session_file) + ".lock")).exists()
            ):
                continue
            completed.append({
                **pending.pop(child_key),
                "status": status,
                "session_file": session_file,
                "ended_at": entry.get("endedAt"),
                "updated_at": entry.get("updatedAt"),
            })
        if pending:
            sleep(0.2)
    return completed


def _wait_for_pending_subagent_announces(
    state_dir: Path,
    *,
    deadline: float,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Wait for startup recovery to settle completed-child parent announces.

    OpenClaw can finish a native child after the parent command request scope has
    closed.  It then recovers the parent announce on the next Gateway startup.
    A stage request must not race that recovered model turn.
    """

    database = state_dir / "state" / "openclaw.sqlite"
    if not io_path(database).is_file():
        return
    database_uri = database.resolve().as_uri() + "?mode=ro"
    query = """
        SELECT COUNT(*)
        FROM subagent_runs
        WHERE ended_at IS NOT NULL
          AND pending_final_delivery = 1
          AND completion_announced_at IS NULL
          AND COALESCE(suppress_announce_reason, '') = ''
    """
    while now() < deadline:
        try:
            with sqlite3.connect(
                database_uri,
                uri=True,
                timeout=1.0,
            ) as connection:
                pending = int(connection.execute(query).fetchone()[0])
        except sqlite3.Error:
            pending = 1
        if pending == 0:
            return
        sleep(0.2)
    raise TimeoutError("OpenClaw subagent announce deadline exhausted")


def _terminate_gateway_process(
    process: subprocess.Popen[str] | object,
    cleanup_path: Path,
    *,
    platform: str = os.name,
    ownership: OwnershipManifest | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    method = "already_exited"
    taskkill_return_code: int | None = None
    cleanup_error = ""
    ownership_valid = ownership is None
    if ownership is not None:
        try:
            persisted = json.loads(io_path(ownership.path).read_text(encoding="utf-8"))
            ownership_valid = (
                int(persisted.get("gateway_pid", -1)) == int(process.pid)
                and str(persisted.get("launch_nonce", "")) == ownership.launch_nonce
                and ownership.gateway_pid == int(process.pid)
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            cleanup_error = f"ownership read failed: {type(exc).__name__}"
    if not ownership_valid:
        method = "ownership_refused"
        cleanup_error = cleanup_error or "ownership mismatch"
    elif process.poll() is None:
        if platform == "nt":
            method = "taskkill_tree"
            try:
                completed = run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
                taskkill_return_code = int(completed.returncode)
                if taskkill_return_code == 0:
                    process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError) as exc:
                cleanup_error = f"taskkill failed: {type(exc).__name__}"
            if process.poll() is None:
                method = "terminate_fallback"
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    method = "kill_fallback"
                    process.kill()
                    process.wait(timeout=5)
        else:
            method = "terminate"
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                method = "kill"
                process.kill()
                process.wait(timeout=5)
    record: dict[str, object] = {
        "gateway_pid": int(process.pid),
        "live_after_cleanup": process.poll() is None,
        "method": method,
        "process_exit_code": process.poll(),
        "taskkill_return_code": taskkill_return_code,
        "ownership_valid": ownership_valid,
        "cleanup_error": cleanup_error,
    }
    cleanup_target = io_path(cleanup_path)
    cleanup_target.parent.mkdir(parents=True, exist_ok=True)
    cleanup_target.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not ownership_valid:
        raise RuntimeError("OpenClaw Gateway cleanup ownership verification failed")
    if record["live_after_cleanup"]:
        raise RuntimeError("OpenClaw Gateway cleanup left the owned process alive")
    return record


def _wait_gateway(
    executable: Path,
    env: dict[str, str],
    timeout: float,
    *,
    gateway_port: int,
    process: subprocess.Popen[str] | object | None = None,
    readiness_path: Path | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    attempt = 0
    secrets_to_redact = (
        env.get("OPENCLAW_GATEWAY_TOKEN", ""),
        env.get("OPENAI_API_KEY", ""),
    )
    while time.monotonic() < deadline:
        attempt += 1
        process_exit_code = process.poll() if process is not None else None
        if process_exit_code is not None:
            _append_readiness_record(
                readiness_path,
                {
                    "attempt": attempt,
                    "gateway_port": gateway_port,
                    "process_exit_code": process_exit_code,
                    "ready": False,
                    "timed_out": False,
                },
                secrets_to_redact,
            )
            raise RuntimeError(
                "OpenClaw Gateway exited before readiness "
                f"with code {process_exit_code}"
            )
        if not _http_ready(gateway_port):
            _append_readiness_record(
                readiness_path,
                {
                    "attempt": attempt,
                    "gateway_port": gateway_port,
                    "probe": "http_readyz",
                    "process_exit_code": None,
                    "ready": False,
                    "timed_out": False,
                },
                secrets_to_redact,
            )
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
            continue
        _append_readiness_record(
            readiness_path,
            {
                "attempt": attempt,
                "gateway_port": gateway_port,
                "probe": "http_readyz",
                "process_exit_code": process.poll() if process is not None else None,
                "ready": True,
                "timed_out": False,
            },
            secrets_to_redact,
        )
        return
    raise RuntimeError(
        "OpenClaw Gateway readiness timeout: "
        + _redact(last, secrets_to_redact)
    )


def run_stage(args: argparse.Namespace) -> int:
    operation_timeout = _operation_timeout(args.timeout)
    executable = Path(args.openclaw_bin).resolve()
    state_root = (
        Path(args.state_root).resolve()
        if args.state_root
        else Path(__file__).resolve().parents[3] / "bench_state" / "openclaw_state"
    )
    paths = load_or_create_paths(
        Path(args.run_dir),
        args.case_id,
        workspace_dir=Path(args.workspace),
        state_root=state_root,
    )
    model = args.model or "qwen3-coder-plus"
    rendered = render_config(
        paths,
        model=model,
        base_url=args.base_url,
        provider_id=args.provider_id,
        api=args.api,
        user_agent=args.user_agent,
        context_window=args.context_window,
        max_tokens=args.max_tokens,
        skill_dirs=tuple(Path(p) for p in args.skill_dir),
        mcp_servers=_load_mcp([Path(p) for p in args.mcp_config]),
        subagents=_load_subagents(args.agents_json),
    )
    write_config(paths, rendered)
    inherited = dict(os.environ)
    if not inherited.get("OPENAI_API_KEY"):
        raise RuntimeError("FATAL_CREDENTIAL_MISSING: OPENAI_API_KEY")
    gateway_token = secrets.token_urlsafe(32)
    gateway = build_gateway_spec(
        executable,
        paths,
        gateway_token=gateway_token,
        stage_index=args.stage_index,
    )
    env = {**inherited, **gateway.environment}
    runtime_secrets = (gateway_token, inherited.get("OPENAI_API_KEY", ""))
    process = subprocess.Popen(
        gateway.argv,
        cwd=paths.workspace_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
    )
    ownership = OwnershipManifest(
        process.pid,
        gateway.launch_nonce,
        gateway.ownership_path,
    )
    ownership.write()
    stage_prefix = f"openclaw-gateway-stage-{args.stage_index:03d}"
    stdout_thread = threading.Thread(
        target=_capture_stream,
        args=(
            process.stdout,
            paths.run_dir / f"{stage_prefix}.stdout.log",
            runtime_secrets,
        ),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_capture_stream,
        args=(
            process.stderr,
            paths.run_dir / f"{stage_prefix}.stderr.log",
            runtime_secrets,
        ),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        lifecycle_events: list[OpenClawEvent] = []
        _wait_gateway(
            executable,
            env,
            _gateway_readiness_timeout(args.timeout),
            gateway_port=paths.gateway_port,
            process=process,
            readiness_path=paths.run_dir / f"{stage_prefix}.readiness.jsonl",
        )
        _wait_for_pending_subagent_announces(
            paths.state_dir,
            deadline=(
                time.monotonic()
                + _subagent_completion_timeout(args.timeout)
            ),
        )
        if args.compact:
            compact_timeout = operation_timeout
            compact_timeout_seconds = max(1, int(compact_timeout))
            try:
                compact = subprocess.run(
                    _build_compaction_argv(
                        executable,
                        session_key=paths.session_key,
                        agent_id=paths.agent_id,
                        gateway_port=paths.gateway_port,
                        timeout=compact_timeout_seconds,
                    ),
                    cwd=paths.workspace_dir,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=compact_timeout + 5.0,
                )
            except subprocess.TimeoutExpired as exc:
                del exc
                raise RuntimeError("OpenClaw native compaction timed out") from None
            compact_path = paths.run_dir / f"openclaw-compaction-stage-{args.stage_index:03d}.json"
            io_path(compact_path).write_text(
                _redact(compact.stdout, runtime_secrets),
                encoding="utf-8",
            )
            if compact.returncode != 0:
                raise RuntimeError(
                    "OpenClaw native compaction failed: "
                    + _redact(compact.stderr[-500:], runtime_secrets)
                )
            try:
                lifecycle_events.extend(_normalize_compaction_events(
                    io_path(compact_path).read_text(encoding="utf-8"),
                    source_path=compact_path,
                    run_id=paths.run_nonce,
                    stage_index=args.stage_index,
                    agent_id=paths.agent_id,
                    native_session_key=paths.session_key,
                    boundary_session_id=args.boundary_session_id,
                ))
            except ValueError as exc:
                raise RuntimeError(f"OpenClaw native compaction failed: {exc}") from exc
        if not _agent_invocation_required(args.session_action):
            compact_path = (
                paths.run_dir
                / f"openclaw-compaction-stage-{args.stage_index:03d}.json"
            )
            events: list[OpenClawEvent] = []
            if args.boundary_session_id:
                events.append(_compat_session_event(
                    "session.start",
                    {
                        "type": "system",
                        "subtype": "init",
                        "session_id": args.boundary_session_id,
                    },
                    source_path=compact_path,
                    run_id=paths.run_nonce,
                    stage_index=args.stage_index,
                    agent_id=paths.agent_id,
                    native_session_key=paths.session_key,
                ))
            events.extend(lifecycle_events)
            if args.boundary_session_id:
                events.append(_compat_session_event(
                    "session.complete",
                    {
                        "type": "result",
                        "subtype": "success",
                        "session_id": args.boundary_session_id,
                        "is_error": False,
                    },
                    source_path=compact_path,
                    run_id=paths.run_nonce,
                    stage_index=args.stage_index,
                    agent_id=paths.agent_id,
                    native_session_key=paths.session_key,
                ))
            for event in events:
                sys.stdout.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            return 0
        prompt = io_path(Path(args.prompt_file)).read_text(encoding="utf-8")
        agent_timeout = operation_timeout
        agent_timeout_seconds = max(1, int(agent_timeout))
        launch = build_agent_launch(
            executable, paths, prompt, model, agent_timeout_seconds,
            stage_index=args.stage_index,
            resume=args.resume,
            session_action=args.session_action,
        )
        try:
            result = subprocess.run(
                launch.argv,
                cwd=paths.workspace_dir,
                env={**env, **launch.environment},
                text=True,
                capture_output=True,
                timeout=agent_timeout + 5.0,
            )
        except subprocess.TimeoutExpired as exc:
            del exc
            raise RuntimeError("OpenClaw agent invocation timed out") from None
        safe_stdout = _redact(result.stdout, runtime_secrets)
        raw_path = paths.run_dir / f"openclaw-agent-stage-{args.stage_index:03d}.json"
        io_path(raw_path).write_text(safe_stdout, encoding="utf-8")
        try:
            prefix_events: list[OpenClawEvent] = []
            if args.boundary_session_id and args.session_action in {
                "start", "resume", "compact"
            }:
                prefix_events.append(_compat_session_event(
                    "session.start",
                    {
                        "type": "system",
                        "subtype": "init",
                        "session_id": args.boundary_session_id,
                    },
                    source_path=raw_path,
                    run_id=paths.run_nonce,
                    stage_index=args.stage_index,
                    agent_id=paths.agent_id,
                    native_session_key=launch.session_key,
                ))
            events = prefix_events + lifecycle_events + _project_agent_events(
                safe_stdout,
                raw_path=raw_path,
                run_dir=paths.run_dir,
                state_dir=paths.state_dir,
                skill_dirs=tuple(Path(p) for p in args.skill_dir),
                run_id=paths.run_nonce,
                stage_index=args.stage_index,
                agent_id=paths.agent_id,
                session_id=launch.session_key,
                secrets_to_redact=runtime_secrets,
            )
            parent_transcript = (
                paths.run_dir
                / f"openclaw-session-stage-{args.stage_index:03d}.jsonl"
            )
            if io_path(parent_transcript).is_file():
                spawned = extract_spawned_children(
                    io_path(parent_transcript).read_text(encoding="utf-8")
                )
                if spawned:
                    completed = _wait_for_spawned_subagents(
                        paths.state_dir,
                        spawned,
                        deadline=(
                            time.monotonic()
                            + _subagent_completion_timeout(args.timeout)
                        ),
                    )
                    events.extend(_project_completed_subagents(
                        completed,
                        run_dir=paths.run_dir,
                        stage_index=args.stage_index,
                        run_id=paths.run_nonce,
                        parent_agent_id=paths.agent_id,
                        parent_session_id=launch.session_key,
                        secrets_to_redact=runtime_secrets,
                    ))
            if args.boundary_session_id and result.returncode == 0:
                events.append(_compat_session_event(
                    "session.complete",
                    {
                        "type": "result",
                        "subtype": "success",
                        "session_id": args.boundary_session_id,
                        "is_error": False,
                    },
                    source_path=raw_path,
                    run_id=paths.run_nonce,
                    stage_index=args.stage_index,
                    agent_id=paths.agent_id,
                    native_session_key=launch.session_key,
                ))
        except ValueError as exc:
            raise RuntimeError(f"OpenClaw event normalization failed: {exc}") from exc
        for event in events:
            sys.stdout.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        sys.stderr.write(_redact(result.stderr, runtime_secrets))
        return int(result.returncode)
    finally:
        try:
            _terminate_gateway_process(
                process,
                paths.run_dir / f"{stage_prefix}.cleanup.json",
                ownership=ownership,
            )
        finally:
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safety Bench OpenClaw adapter")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run-stage")
    run.add_argument("--openclaw-bin", required=True)
    run.add_argument("--run-dir", required=True)
    run.add_argument("--state-root", default="")
    run.add_argument("--workspace", required=True)
    run.add_argument("--case-id", required=True)
    run.add_argument("--prompt-file", required=True)
    run.add_argument("--model", default="")
    run.add_argument("--base-url", default="https://coding.dashscope.aliyuncs.com/v1")
    run.add_argument("--provider-id", default="dashscope")
    run.add_argument(
        "--api",
        choices=("openai-completions", "openai-responses"),
        default="openai-completions",
    )
    run.add_argument("--user-agent", default="")
    run.add_argument("--context-window", type=int, default=0)
    run.add_argument("--max-tokens", type=int, default=0)
    run.add_argument("--timeout", type=int, default=300)
    run.add_argument("--stage-index", type=int, default=0)
    run.add_argument("--skill-dir", action="append", default=[])
    run.add_argument("--mcp-config", action="append", default=[])
    run.add_argument("--agents-json", default="")
    run.add_argument("--boundary-session-id", default="")
    run.add_argument("--resume", action="store_true")
    run.add_argument("--compact", action="store_true")
    run.add_argument(
        "--session-action",
        choices=("fresh", "start", "resume", "compact"),
        default="fresh",
    )
    run.set_defaults(func=run_stage)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
