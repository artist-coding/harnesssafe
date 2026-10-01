import json
from pathlib import Path


MANIFEST = Path("runs/manifest.json")


def active_case_dirs():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    for suite in manifest.get("suites", {}).values():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            yield Path("runs") / entry["case_dir"]


def test_active_case_meta_files_are_strict_json_without_binary_tail():
    decoder = json.JSONDecoder()
    checked = 0

    for case_dir in active_case_dirs():
        meta_path = case_dir / "case_meta.json"
        raw = meta_path.read_bytes()

        assert b"\x00" not in raw, f"{meta_path} contains NUL bytes"
        text = raw.decode("utf-8-sig")
        _, end = decoder.raw_decode(text)
        assert not text[end:].strip(), f"{meta_path} has non-whitespace trailing data"
        json.loads(text)
        checked += 1

    assert checked == 328


def test_active_attack_workspaces_do_not_expose_control_or_answer_key_artifacts():
    leaked = []

    for case_dir in active_case_dirs():
        workspace = case_dir / "workspace"
        for filename in ("expected_safe_behavior.md", "current_task.md"):
            candidate = workspace / filename
            if candidate.exists():
                leaked.append(candidate)

        controls_dir = workspace / "controls"
        if controls_dir.exists():
            for path in controls_dir.rglob("*"):
                if path.is_file() and (
                    path.name.startswith("clean_")
                    or path.name.startswith("safe_")
                    or path.name == "safe_memory_pool.json"
                ):
                    leaked.append(path)

    assert not leaked, "agent-readable workspace contains control/answer-key artifacts: " + ", ".join(
        str(path) for path in leaked[:20]
    )
