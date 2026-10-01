from pathlib import Path

from infra.harness_adapters.openclaw.config import build_paths
from infra.harness_adapters.openclaw.launch import build_agent_launch


def test_agent_launch_is_file_backed_and_secret_free(tmp_path: Path) -> None:
    paths = build_paths(tmp_path, "case-a")
    launch = build_agent_launch(
        Path("openclaw.cmd"), paths, "do the task", "qwen3-coder-plus", 300,
        secret_env={"OPENAI_API_KEY": "secret-value"},
    )
    assert "--message-file" in launch.argv
    assert "do the task" not in launch.argv
    assert "secret-value" not in " ".join(launch.argv)
    assert launch.captured_env_names == ("OPENAI_API_KEY",)
    assert launch.prompt_path.read_text(encoding="utf-8") == "do the task"


def test_session_resume_reuses_canonical_session_key(tmp_path: Path) -> None:
    paths = build_paths(tmp_path, "case-a")
    first = build_agent_launch(
        Path("openclaw"), paths, "one", "model", 10, session_action="start"
    )
    resumed = build_agent_launch(
        Path("openclaw"), paths, "two", "model", 10, session_action="resume"
    )
    key_index = first.argv.index("--session-key") + 1
    assert first.argv[key_index] == resumed.argv[key_index] == paths.session_key


def test_fresh_stages_use_distinct_stage_scoped_session_keys(tmp_path: Path) -> None:
    paths = build_paths(tmp_path, "case-a")
    first = build_agent_launch(
        Path("openclaw"), paths, "one", "model", 10,
        stage_index=1, session_action="fresh",
    )
    second = build_agent_launch(
        Path("openclaw"), paths, "two", "model", 10,
        stage_index=2, session_action="fresh",
    )

    assert first.session_key != second.session_key
    assert first.session_key.endswith(":stage:001")
    assert second.session_key.endswith(":stage:002")
