import json
from pathlib import Path

import pytest

from infra.harness_adapters.openclaw.config import (
    build_paths,
    load_or_create_paths,
    render_config,
)


def test_each_run_has_unique_openclaw_identity(tmp_path: Path) -> None:
    first = build_paths(tmp_path / "run-a", "case-a")
    second = build_paths(tmp_path / "run-b", "case-a")
    assert first.state_dir != second.state_dir
    assert first.config_path != second.config_path
    assert first.session_key != second.session_key
    assert first.gateway_port != second.gateway_port


def test_config_contains_no_secret_values(tmp_path: Path) -> None:
    rendered = render_config(
        build_paths(tmp_path, "case-a"),
        model="qwen3-coder-plus",
        base_url="https://coding.dashscope.aliyuncs.com/v1",
        secret="secret-value",
    )
    assert "secret-value" not in rendered.text
    assert rendered.secret_env_names == ("OPENAI_API_KEY",)
    payload = json.loads(rendered.text)
    assert payload["gateway"]["bind"] == "loopback"
    assert payload["plugins"] == {"enabled": False}


def test_config_supports_named_openai_compatible_provider(tmp_path: Path) -> None:
    rendered = render_config(
        build_paths(tmp_path, "case-a"),
        model="gpt-5.6-sol",
        base_url="https://api-portal.evomap.work/v1",
        provider_id="evomap",
        api="openai-responses",
        user_agent="SafetyBench-OpenClaw/1.0",
        context_window=200000,
        max_tokens=32000,
    )
    payload = json.loads(rendered.text)
    assert payload["agents"]["defaults"]["model"]["primary"] == (
        "evomap/gpt-5.6-sol"
    )
    assert payload["models"]["providers"]["evomap"] == {
        "baseUrl": "https://api-portal.evomap.work/v1",
        "apiKey": "${OPENAI_API_KEY}",
        "api": "openai-responses",
        "models": [{
            "id": "gpt-5.6-sol",
            "name": "gpt-5.6-sol",
            "contextWindow": 200000,
            "maxTokens": 32000,
        }],
        "headers": {"User-Agent": "SafetyBench-OpenClaw/1.0"},
    }


def test_config_writes_only_stage_scoped_skill_and_mcp_entries(tmp_path: Path) -> None:
    paths = build_paths(tmp_path, "case-a")
    rendered = render_config(
        paths,
        model="qwen3-coder-plus",
        skill_dirs=(tmp_path / "skill",),
        mcp_servers={"case-server": {"command": "mock"}},
    )
    payload = json.loads(rendered.text)
    assert payload["skills"]["load"]["extraDirs"] == [str(tmp_path / "skill")]
    assert list(payload["mcp"]["servers"]) == ["case-server"]


def test_config_maps_declared_subagents_to_native_agent_allowlist(tmp_path: Path) -> None:
    paths = build_paths(tmp_path, "case-a")
    rendered = render_config(
        paths,
        model="qwen3.6-plus",
        subagents={
            "continuity-reviewer": {
                "description": "Reviews a project note.",
                "prompt": "Task-specific guidance is passed by the parent.",
            }
        },
    )

    payload = json.loads(rendered.text)
    main = payload["agents"]["list"][0]
    delegated = payload["agents"]["list"][1]
    assert main["subagents"] == {
        "allowAgents": ["continuity-reviewer"],
        "requireAgentId": True,
    }
    assert delegated == {
        "id": "continuity-reviewer",
        "name": "continuity-reviewer",
        "description": "Reviews a project note.",
        "workspace": str(paths.workspace_dir),
    }
    assert "Task-specific guidance" not in rendered.text


def test_long_result_path_uses_short_persistent_state_root(tmp_path: Path) -> None:
    run_dir = tmp_path / ("long-case-segment-" * 8) / "openclaw_runtime"
    state_root = tmp_path / "short-state"
    workspace = tmp_path / "workspace"

    first = load_or_create_paths(
        run_dir,
        "case-a",
        workspace_dir=workspace,
        state_root=state_root,
    )
    resumed = load_or_create_paths(
        run_dir,
        "case-a",
        workspace_dir=workspace,
        state_root=state_root,
    )

    assert first.state_dir.parent == state_root.resolve()
    assert first.config_path.is_relative_to(first.state_dir)
    assert first.prompt_dir.is_relative_to(first.state_dir)
    assert resumed.state_dir == first.state_dir
    assert resumed.run_nonce == first.run_nonce
    assert len(str(first.state_dir / "state" / "openclaw.sqlite")) < 240


@pytest.mark.parametrize("field", ["case_id", "workspace_dir", "state_dir"])
def test_persisted_identity_mismatch_fails_closed(tmp_path: Path, field: str) -> None:
    run_dir = tmp_path / "run"
    state_root = tmp_path / "state"
    workspace = tmp_path / "workspace"
    load_or_create_paths(
        run_dir,
        "case-a",
        workspace_dir=workspace,
        state_root=state_root,
    )
    identity_path = run_dir / "openclaw-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity[field] = (
        "case-b" if field == "case_id"
        else str(tmp_path / "different")
    )
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    with pytest.raises(ValueError, match="identity"):
        load_or_create_paths(
            run_dir,
            "case-a",
            workspace_dir=workspace,
            state_root=state_root,
        )
