from __future__ import annotations

import json
import os
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class OpenClawPaths:
    run_dir: Path
    state_dir: Path
    config_path: Path
    workspace_dir: Path
    prompt_dir: Path
    gateway_port: int
    gateway_token_env: str
    agent_id: str
    session_key: str
    run_nonce: str


@dataclass(frozen=True)
class RenderedConfig:
    text: str
    secret_env_names: tuple[str, ...]


def io_path(path: Path) -> Path:
    """Return a Windows extended-length path for local filesystem I/O."""
    resolved = str(Path(path).resolve())
    if os.name != "nt" or resolved.startswith("\\\\?\\"):
        return Path(resolved)
    if resolved.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + resolved.lstrip("\\"))
    return Path("\\\\?\\" + resolved)


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def build_paths(
    run_dir: Path,
    case_id: str,
    *,
    workspace_dir: Path | None = None,
    state_root: Path | None = None,
    run_nonce: str | None = None,
) -> OpenClawPaths:
    run_dir = Path(run_dir).resolve()
    nonce = run_nonce or uuid.uuid4().hex
    safe_case = "".join(c if c.isalnum() or c in "-_" else "-" for c in case_id)[:64]
    state_dir = Path(state_root).resolve() / nonce if state_root is not None else run_dir / "openclaw" / "state"
    # Results paths can exceed MAX_PATH on Windows. Keep all OpenClaw runtime
    # inputs beside the already-short persistent state root when one is given;
    # auditable transcripts and normalized traces still remain in run_dir.
    root = state_dir / "runtime" if state_root is not None else run_dir / "openclaw"
    paths = OpenClawPaths(
        run_dir=run_dir,
        state_dir=state_dir,
        config_path=root / "config.json",
        workspace_dir=(Path(workspace_dir).resolve() if workspace_dir else root / "workspace"),
        prompt_dir=root / "prompts",
        gateway_port=_reserve_port(),
        gateway_token_env="OPENCLAW_GATEWAY_TOKEN",
        agent_id="safety-bench",
        session_key=f"agent:safety-bench:{safe_case}-{nonce}",
        run_nonce=nonce,
    )
    for directory in (paths.state_dir, paths.workspace_dir, paths.prompt_dir):
        io_path(directory).mkdir(parents=True, exist_ok=True)
    return paths


def render_config(
    paths: OpenClawPaths,
    *,
    model: str,
    base_url: str = "https://coding.dashscope.aliyuncs.com/v1",
    provider_id: str = "dashscope",
    api: str = "openai-completions",
    user_agent: str = "",
    context_window: int = 0,
    max_tokens: int = 0,
    secret: str = "",
    skill_dirs: Sequence[Path] = (),
    mcp_servers: Mapping[str, object] | None = None,
    subagents: Mapping[str, object] | None = None,
) -> RenderedConfig:
    # `secret` is accepted only to make accidental serialization testable. The
    # runtime receives values through environment variables, never this file.
    del secret
    if not provider_id or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for character in provider_id
    ):
        raise ValueError(f"invalid OpenClaw provider id: {provider_id}")
    if api not in {"openai-completions", "openai-responses"}:
        raise ValueError(f"unsupported OpenClaw provider API: {api}")
    if user_agent and (len(user_agent) > 256 or "\r" in user_agent or "\n" in user_agent):
        raise ValueError("invalid OpenClaw provider User-Agent")
    if context_window < 0 or max_tokens < 0:
        raise ValueError("OpenClaw model token limits cannot be negative")
    declared_subagents: list[dict[str, object]] = []
    for agent_id, raw in sorted((subagents or {}).items()):
        if not agent_id or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for character in agent_id
        ):
            raise ValueError(f"invalid OpenClaw subagent id: {agent_id}")
        config = raw if isinstance(raw, Mapping) else {}
        declared_subagents.append({
            "id": agent_id,
            "name": agent_id,
            "description": str(config.get("description", "")),
            "workspace": str(paths.workspace_dir),
        })
    main_agent: dict[str, object] = {
        "id": paths.agent_id,
        "workspace": str(paths.workspace_dir),
    }
    if declared_subagents:
        main_agent["subagents"] = {
            "allowAgents": [str(entry["id"]) for entry in declared_subagents],
            "requireAgentId": True,
        }
    model_entry: dict[str, object] = {"id": model, "name": model}
    if context_window:
        model_entry["contextWindow"] = context_window
    if max_tokens:
        model_entry["maxTokens"] = max_tokens
    provider: dict[str, object] = {
        "baseUrl": base_url,
        "apiKey": "${OPENAI_API_KEY}",
        "api": api,
        "models": [model_entry],
    }
    if user_agent:
        provider["headers"] = {"User-Agent": user_agent}
    payload = {
        "gateway": {
            "mode": "local",
            "bind": "loopback",
            "port": paths.gateway_port,
            "auth": {"mode": "token", "token": "${OPENCLAW_GATEWAY_TOKEN}"},
        },
        "agents": {
            "defaults": {
                "workspace": str(paths.workspace_dir),
                "model": {"primary": f"{provider_id}/{model}"},
            },
            "list": [main_agent, *declared_subagents],
        },
        "models": {
            "providers": {
                provider_id: provider
            }
        },
        "skills": {"load": {"extraDirs": [str(Path(p).resolve()) for p in skill_dirs]}},
        "mcp": {"servers": dict(mcp_servers or {})},
        "plugins": {"enabled": False},
    }
    return RenderedConfig(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        ("OPENAI_API_KEY",),
    )


def write_config(paths: OpenClawPaths, rendered: RenderedConfig) -> Path:
    target = io_path(paths.config_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered.text, encoding="utf-8")
    return paths.config_path


def runtime_environment(paths: OpenClawPaths) -> dict[str, str]:
    return {
        "OPENCLAW_STATE_DIR": str(paths.state_dir),
        "OPENCLAW_CONFIG_PATH": str(paths.config_path),
        "OPENCLAW_CONFIG_DIR": str(paths.config_path.parent),
        "OPENCLAW_WORKSPACE_DIR": str(paths.workspace_dir),
    }


def load_or_create_paths(
    run_dir: Path,
    case_id: str,
    *,
    workspace_dir: Path,
    state_root: Path | None = None,
) -> OpenClawPaths:
    run_dir = Path(run_dir).resolve()
    identity_path = run_dir / "openclaw-identity.json"
    identity_io_path = io_path(identity_path)
    if not identity_io_path.is_file():
        paths = build_paths(
            run_dir,
            case_id,
            workspace_dir=workspace_dir,
            state_root=state_root,
        )
        identity_io_path.parent.mkdir(parents=True, exist_ok=True)
        identity_io_path.write_text(
            json.dumps({
                "case_id": case_id,
                "workspace_dir": str(paths.workspace_dir),
                "run_nonce": paths.run_nonce,
                "session_key": paths.session_key,
                "agent_id": paths.agent_id,
                "state_dir": str(paths.state_dir),
            }, indent=2) + "\n",
            encoding="utf-8",
        )
        return paths
    identity = json.loads(identity_io_path.read_text(encoding="utf-8"))
    required = {
        "case_id", "workspace_dir", "run_nonce", "session_key", "agent_id",
        "state_dir",
    }
    if not isinstance(identity, dict) or not required.issubset(identity):
        raise ValueError("OpenClaw identity is incomplete")
    resolved_workspace = Path(workspace_dir).resolve()
    if str(identity["case_id"]) != case_id:
        raise ValueError("OpenClaw identity case mismatch")
    if Path(str(identity["workspace_dir"])).resolve() != resolved_workspace:
        raise ValueError("OpenClaw identity workspace mismatch")
    nonce = str(identity["run_nonce"]).strip()
    if not nonce or any(character not in "0123456789abcdef" for character in nonce):
        raise ValueError("OpenClaw identity nonce is invalid")
    identity_state_dir = Path(str(identity["state_dir"])).resolve()
    expected_state_dir = (
        Path(state_root).resolve() / nonce
        if state_root is not None
        else run_dir / "openclaw" / "state"
    ).resolve()
    if identity_state_dir != expected_state_dir:
        raise ValueError("OpenClaw identity state path mismatch")
    fresh = build_paths(
        run_dir,
        case_id,
        workspace_dir=workspace_dir,
        state_root=state_root,
        run_nonce=nonce,
    )
    if str(identity["agent_id"]) != fresh.agent_id:
        raise ValueError("OpenClaw identity agent mismatch")
    if str(identity["session_key"]) != fresh.session_key:
        raise ValueError("OpenClaw identity session mismatch")
    return OpenClawPaths(
        run_dir=fresh.run_dir,
        state_dir=identity_state_dir,
        config_path=fresh.config_path,
        workspace_dir=fresh.workspace_dir,
        prompt_dir=fresh.prompt_dir,
        gateway_port=fresh.gateway_port,
        gateway_token_env=fresh.gateway_token_env,
        agent_id=str(identity["agent_id"]),
        session_key=str(identity["session_key"]),
        run_nonce=nonce,
    )
