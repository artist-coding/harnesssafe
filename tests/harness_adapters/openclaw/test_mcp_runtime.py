from pathlib import Path

from infra.harness_adapters.openclaw.config import build_paths, render_config


def test_later_stage_can_render_empty_mcp_registry(tmp_path: Path) -> None:
    rendered = render_config(build_paths(tmp_path, "case"), model="model", mcp_servers={})
    assert '"servers": {}' in rendered.text
