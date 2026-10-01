from pathlib import Path

from infra.harness_adapters.openclaw.config import build_paths, render_config


def test_later_stage_can_render_empty_skill_registry(tmp_path: Path) -> None:
    rendered = render_config(build_paths(tmp_path, "case"), model="model", skill_dirs=())
    assert '"extraDirs": []' in rendered.text
