from __future__ import annotations

import json
from pathlib import Path

from infra.cross_harness.adapters.gemini.attack_only_runner import (
    DEFAULT_CONFORMANCE,
    _safe_case_dir_name,
    _write_json,
    build_attack_readiness,
    execute_attack_batch,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_attack_only_readiness_derives_88_ready_cases_from_capability_evidence() -> None:
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        model="gemini-3.5-flash",
        location="global",
    )
    summary = readiness["summary"]
    assert summary["case_count"] == 328
    assert summary["stage_count"] == 690
    assert summary["attack_ready_stage_count"] == 176
    assert summary["attack_status_counts"] == {
        "ATTACK_READY": 88,
        "NOT_RUN": 240,
    }
    assert "BLOCKED" not in summary["attack_status_counts"]
    assert summary["not_run_blocker_group_counts"][
        "skill_discovery + skill_activation_trace + durable_memory_write + durable_memory_retrieval + session_resume + session_compaction"
    ] == 3
    assert readiness["protocol"]["provider"]["kind"] == "openai-compatible"
    assert readiness["protocol"]["provider"]["api_base_url"] == "https://api.evomap.ai/v1"
    assert readiness["protocol"]["provider"]["upstream_credential_recorded"] is False
    assert readiness["protocol"]["trial_policy"]["controls_required"] is False
    assert readiness["protocol"]["scoring"]["status_during_execution"] == "NOT_PRODUCED"
    assert readiness["protocol"]["completion_gate"]["ATTACK_COMPLETED"]


def test_attack_only_dry_run_never_marks_ready_cases_completed(tmp_path: Path) -> None:
    report_path, report = execute_attack_batch(
        credential_file=None,
        project=None,
        output_root=tmp_path / "attack-only",
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        case_set="ready",
        limit=2,
        dry_run=True,
    )
    assert report_path.is_file()
    assert report["dry_run"] is True
    assert report["selection"]["case_count"] == 2
    assert report["outcome_counts"] == {"NOT_RUN": 2}
    assert report["scoring_status"] == "NOT_PRODUCED"
    readiness = json.loads((tmp_path / "attack-only" / "attack-readiness.json").read_text())
    assert readiness["summary"]["attack_status_counts"]["ATTACK_READY"] == 88


def test_attack_only_selection_supports_case_id_file_and_offset(tmp_path: Path) -> None:
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        model="gemini-3.5-flash",
        location="global",
    )
    ready_ids = [
        row["case_id"]
        for row in readiness["cases"]
        if row["attack_status"] == "ATTACK_READY"
    ]
    case_id_file = tmp_path / "case-ids.json"
    case_id_file.write_text(
        json.dumps({"case_ids": ready_ids[:4]}, indent=2) + "\n",
        encoding="utf-8",
    )

    _, report = execute_attack_batch(
        credential_file=None,
        project=None,
        output_root=tmp_path / "attack-only",
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        case_set="all",
        case_id_file=case_id_file,
        offset=1,
        limit=2,
        dry_run=True,
    )

    assert report["selection"]["case_ids"] == ready_ids[1:3]
    assert report["selection"]["requested_case_count"] == 4
    assert report["selection"]["offset"] == 1


def test_attack_only_pending_only_skips_existing_completed_outcome(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "attack-only"
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        model="gemini-3.5-flash",
        location="global",
    )
    ready_rows = [
        row for row in readiness["cases"] if row["attack_status"] == "ATTACK_READY"
    ]
    completed_row = ready_rows[0]
    completed_dir = (
        output_root
        / "cases"
        / _safe_case_dir_name(
            completed_row["manifest_index"], completed_row["case_id"]
        )
    )
    _write_json(
        completed_dir / "attack-outcome.json",
        {
            "attack_status": "ATTACK_COMPLETED",
            "case_id": completed_row["case_id"],
            "case_meta_sha256": completed_row["case_meta_sha256"],
            "protocol_sha256": readiness["protocol"]["protocol_sha256"],
        },
    )

    _, report = execute_attack_batch(
        credential_file=None,
        project=None,
        output_root=output_root,
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        case_set="ready",
        pending_only=True,
        limit=2,
        dry_run=True,
    )

    assert report["selection"]["case_ids"] == [
        ready_rows[1]["case_id"],
        ready_rows[2]["case_id"],
    ]
    assert report["selection"]["selected_before_pending_count"] == 88
    assert report["selection"]["pending_only"] is True


def test_attack_only_dry_run_does_not_overwrite_formal_batch_report(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "attack-only"
    formal_report = output_root / "attack-only-batch-report.json"
    _write_json(formal_report, {"dry_run": False, "sentinel": "formal"})

    report_path, report = execute_attack_batch(
        credential_file=None,
        project=None,
        output_root=output_root,
        repo_root=REPO_ROOT,
        conformance_path=DEFAULT_CONFORMANCE,
        case_set="ready",
        limit=1,
        dry_run=True,
    )

    assert report_path.name == "attack-only-dry-run-report.json"
    assert report["dry_run"] is True
    assert json.loads(formal_report.read_text()) == {
        "dry_run": False,
        "sentinel": "formal",
    }
