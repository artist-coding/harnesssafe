import json
from pathlib import Path

import pytest

from infra.harness_adapters.hermes.launch import (
    LaunchContext,
    UnsupportedCapabilityError,
    build_launch_spec,
)
from infra.harness_adapters.hermes.model import CapabilityEvidence, HermesCapabilities


def evidence(supported: bool = True) -> CapabilityEvidence:
    return CapabilityEvidence(supported, "test", "fixture")


def capabilities(**overrides: bool) -> HermesCapabilities:
    values = {
        name: evidence(overrides.get(name, True))
        for name in (
            "instruction",
            "skill",
            "mcp",
            "session_resume",
            "compaction",
            "subagent",
            "durable_memory",
        )
    }
    return HermesCapabilities(**values)


def context(tmp_path: Path, *, secret: str = "secret-value") -> LaunchContext:
    return LaunchContext(
        hermes_python=Path("D:/hermes/venv/Scripts/python.exe"),
        hermes_launcher=Path("D:/hermes/hermes"),
        hermes_home=tmp_path / ".hermes",
        workspace_dir=tmp_path / "workspace",
        model="qwen3.6-plus",
        provider_base_url="https://coding.dashscope.aliyuncs.com/v1",
        timeout_sec=300,
        secret_env={"OPENAI_API_KEY": secret},
    )


def write_mcp(path: Path, server_name: str) -> Path:
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    server_name: {
                        "command": "python",
                        "args": ["mock_server.py"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_later_stage_does_not_inherit_prior_mcp(tmp_path: Path) -> None:
    first_mcp = write_mcp(tmp_path / "first.json", "server-a")

    first = build_launch_spec(
        {"user_prompt": "first", "mcp_configs": [str(first_mcp)]},
        context(tmp_path),
        capabilities(),
    )
    second = build_launch_spec(
        {"user_prompt": "second", "mcp_configs": []},
        context(tmp_path),
        capabilities(),
    )

    assert "server-a" in first.config_text
    assert "server-a" not in second.config_text


def test_secret_is_environment_only(tmp_path: Path) -> None:
    spec = build_launch_spec({}, context(tmp_path), capabilities())

    assert "secret-value" not in " ".join(spec.argv)
    assert "secret-value" not in spec.config_text
    assert spec.secret_env_names == ("OPENAI_API_KEY",)


def test_kimi_k3_uses_anthropic_messages_without_serializing_secret(
    tmp_path: Path,
) -> None:
    kimi_context = LaunchContext(
        hermes_python=Path("D:/hermes/venv/Scripts/python.exe"),
        hermes_launcher=Path("D:/hermes/hermes"),
        hermes_home=tmp_path / ".hermes",
        workspace_dir=tmp_path / "workspace",
        model="k3",
        provider_base_url="https://api.kimi.com/coding",
        timeout_sec=300,
        secret_env={"KIMI_API_KEY": "test-secret-value"},
        provider_id="safety-bench-kimi",
        provider_display_name="Kimi Coding",
        provider_key_env="KIMI_API_KEY",
        provider_api_mode="anthropic_messages",
        session_id="session-k3",
    )

    spec = build_launch_spec(
        {"session_action": "compact"},
        kimi_context,
        capabilities(),
    )
    config = json.loads(spec.config_text)

    assert config["model"] == {
        "default": "k3",
        "provider": "safety-bench-kimi",
        "base_url": "https://api.kimi.com/coding",
        "api_mode": "anthropic_messages",
    }
    assert config["providers"]["safety-bench-kimi"]["key_env"] == "KIMI_API_KEY"
    assert config["providers"]["safety-bench-kimi"]["api_mode"] == "anthropic_messages"
    assert config["auxiliary"]["compression"]["provider"] == "safety-bench-kimi"
    assert config["auxiliary"]["compression"]["api_mode"] == "anthropic_messages"
    assert "test-secret-value" not in spec.config_text
    assert spec.secret_env_names == ("KIMI_API_KEY",)


def test_stage_skill_paths_and_names_are_scoped(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    spec = build_launch_spec(
        {
            "user_prompt": "use the skill",
            "plugin_dirs": [str(plugin_dir)],
            "plugin_skills": ["case-skill"],
        },
        context(tmp_path),
        capabilities(),
    )

    config = json.loads(spec.config_text)
    assert config["skills"]["external_dirs"] == [plugin_dir.as_posix()]
    assert spec.argv[spec.argv.index("--skills") + 1] == "case-skill"


def test_missing_required_mcp_capability_fails_closed(tmp_path: Path) -> None:
    mcp = write_mcp(tmp_path / "mcp.json", "server-a")

    with pytest.raises(UnsupportedCapabilityError, match="mcp"):
        build_launch_spec(
            {"mcp_configs": [str(mcp)]},
            context(tmp_path),
            capabilities(mcp=False),
        )
