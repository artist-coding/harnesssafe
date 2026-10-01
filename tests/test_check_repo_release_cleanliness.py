import json
from pathlib import Path

from infra import check_repo_release_cleanliness as cleanliness


def _write_inventory(root: Path, payload: dict) -> None:
    path = root / "docs/generated_artifacts/repo_change_inventory.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    for group in payload.get("release_staging_plan", {}).get("stage_groups", []):
        pathspec = root / group["pathspec_file"]
        pathspec.parent.mkdir(parents=True, exist_ok=True)
        pathspec.write_text("\n".join(group.get("paths", [])) + "\n", encoding="utf-8")


def _inventory(*, manual_review: int = 0, do_not_commit: int = 0) -> dict:
    return {
        "summary": {
            "changed_entries": 3,
            "logical_commits": {
                "paper-infra-and-gates": 1,
                "repo-cleanup-plan": 1,
            },
            "manual_review_entries": manual_review,
            "do_not_commit_entries": do_not_commit,
        },
        "release_staging_plan": {
            "ordered_logical_commits": [
                {
                    "logical_commit": "paper-infra-and-gates",
                    "entries": 1,
                    "categories": ["paper_infra"],
                    "policies": ["include"],
                }
            ],
            "manual_review_entries": manual_review,
            "do_not_commit_entries": do_not_commit,
            "stage_groups": [
                {
                    "logical_commit": "paper-infra-and-gates",
                    "entries": 1,
                    "pathspec_file": "docs/generated_artifacts/repo_release_stage_pathspecs/paper-infra-and-gates.txt",
                    "stage_command": "git add --pathspec-from-file docs/generated_artifacts/repo_release_stage_pathspecs/paper-infra-and-gates.txt",
                    "commit_command": 'git commit -m "paper-infra-and-gates: add paper validation and reporting gates"',
                    "paths": ["infra/check_repo_release_cleanliness.py"],
                }
            ],
            "validation_commands": list(cleanliness.REQUIRED_VALIDATION_COMMANDS),
            "release_blockers": [],
        },
    }


def test_default_mode_allows_do_not_commit_as_warning(tmp_path: Path):
    _write_inventory(tmp_path, _inventory(do_not_commit=1))

    report = cleanliness.build_report(tmp_path)

    assert report["ok"] is True
    assert report["summary"]["do_not_commit_entries"] == 1
    assert report["summary"]["stage_group_count"] == 1
    assert report["summary"]["warning_count"] == 1
    assert report["issues"][0]["scope"] == "local_state"


def test_require_clean_blocks_do_not_commit_entries(tmp_path: Path):
    _write_inventory(tmp_path, _inventory(do_not_commit=1))

    report = cleanliness.build_report(tmp_path, require_clean=True)

    assert report["ok"] is False
    assert report["summary"]["error_count"] == 1
    assert any(item["scope"] == "local_state" for item in report["issues"])


def test_manual_review_entries_always_block_release(tmp_path: Path):
    _write_inventory(tmp_path, _inventory(manual_review=2))

    report = cleanliness.build_report(tmp_path)

    assert report["ok"] is False
    assert report["summary"]["manual_review_entries"] == 2
    assert any(item["scope"] == "manual_review" for item in report["issues"])


def test_missing_validation_commands_block_release_inventory(tmp_path: Path):
    payload = _inventory()
    payload["release_staging_plan"]["validation_commands"] = ["python -m pytest -q"]
    _write_inventory(tmp_path, payload)

    report = cleanliness.build_report(tmp_path)

    assert report["ok"] is False
    assert report["summary"]["missing_validation_command_count"] == 3
    assert any(item["scope"] == "validation_commands" for item in report["issues"])


def test_missing_stage_groups_block_release_inventory(tmp_path: Path):
    payload = _inventory()
    payload["release_staging_plan"]["stage_groups"] = []
    _write_inventory(tmp_path, payload)

    report = cleanliness.build_report(tmp_path)

    assert report["ok"] is False
    assert any(
        item["scope"] == "staging_plan"
        and item["message"] == "release staging plan is missing pathspec staging groups"
        for item in report["issues"]
    )


def test_stage_group_rejects_local_state_paths(tmp_path: Path):
    payload = _inventory()
    payload["release_staging_plan"]["stage_groups"][0]["paths"] = ["bench_state/secrets/token.txt"]
    _write_inventory(tmp_path, payload)

    report = cleanliness.build_report(tmp_path)

    assert report["ok"] is False
    assert any(
        item["scope"] == "staging_plan"
        and item["message"] == "pathspec staging group includes non-release paths"
        for item in report["issues"]
    )


def test_require_release_metadata_reuses_release_metadata_checker(tmp_path: Path, monkeypatch):
    _write_inventory(tmp_path, _inventory())

    def fake_release_report(root=None, require_license=True):
        return {
            "ok": False,
            "summary": {
                "public_release_ready": False,
                "license_present": False,
                "citation_placeholder_author": True,
                "citation_preprint": True,
                "citation_has_public_link": False,
            },
            "next_actions": [{"id": "add_final_license"}],
        }

    monkeypatch.setattr(
        cleanliness.check_release_metadata,
        "build_release_metadata_report",
        fake_release_report,
    )

    report = cleanliness.build_report(tmp_path, require_release_metadata=True)

    assert report["ok"] is False
    assert report["summary"]["release_metadata_checked"] is True
    assert report["summary"]["release_metadata_public_ready"] is False
    assert any(item["scope"] == "release_metadata" for item in report["issues"])
