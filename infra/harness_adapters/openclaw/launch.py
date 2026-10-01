from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .config import OpenClawPaths, io_path, runtime_environment


@dataclass(frozen=True)
class LaunchSpec:
    argv: tuple[str, ...]
    environment: dict[str, str]
    captured_env_names: tuple[str, ...]
    prompt_path: Path
    session_key: str
    resume: bool


def build_agent_launch(
    executable: Path,
    paths: OpenClawPaths,
    prompt: str,
    model: str,
    timeout_sec: int,
    *,
    stage_index: int = 0,
    resume: bool = False,
    session_action: str = "fresh",
    secret_env: Mapping[str, str] | None = None,
) -> LaunchSpec:
    prompt_path = paths.prompt_dir / f"stage-{stage_index:03d}.txt"
    io_path(prompt_path).write_text(prompt, encoding="utf-8")
    env = runtime_environment(paths)
    env.update({str(k): str(v) for k, v in (secret_env or {}).items()})
    persistent_action = session_action in {"start", "resume", "compact"} or resume
    session_key = (
        paths.session_key
        if persistent_action
        else f"{paths.session_key}:stage:{stage_index:03d}"
    )
    argv = (
        str(executable), "agent", "--agent", paths.agent_id,
        "--session-key", session_key,
        "--message-file", str(prompt_path), "--model", model,
        "--timeout", str(timeout_sec), "--json",
    )
    return LaunchSpec(
        argv=argv,
        environment=env,
        captured_env_names=tuple(sorted(secret_env or {})),
        prompt_path=prompt_path,
        session_key=session_key,
        resume=persistent_action,
    )
