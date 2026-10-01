import json
from pathlib import Path

from infra import plan_paper_experiment_matrix


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_case(root: Path, case_dir: str, *, case_id: str, core: bool, controls: list[str]) -> None:
    _write_json(
        root / "runs" / case_dir / "case_meta.json",
        {
            "case_id": case_id,
            "description": "中性任务说明",
            "main_table_eligible": core,
            "reporting_track": "core_benchmark" if core else "extended_benchmark",
            "paper_priority": "P0" if core else "P1",
            "control_suite": [{"control_type": item} for item in controls],
        },
    )


def _write_fixture(root: Path) -> None:
    _write_json(
        root / "runs/manifest.json",
        {
            "suites": {
                "active_suite": {
                    "status": "active",
                    "cases": [
                        {"case_dir": "active/F2_skill_runtime/F2.01_family/case_a"},
                        {"case_dir": "active/F2_skill_runtime/F2.02_family/case_b"},
                    ],
                }
            }
        },
    )
    _write_case(
        root,
        "active/F2_skill_runtime/F2.01_family/case_a",
        case_id="case_a",
        core=True,
        controls=plan_paper_experiment_matrix.CONTROL_TYPES,
    )
    _write_case(
        root,
        "active/F2_skill_runtime/F2.02_family/case_b",
        case_id="case_b",
        core=False,
        controls=["clean_control"],
    )


def test_plan_paper_experiment_matrix_matches_runner_labels_and_counts(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)

    plan = plan_paper_experiment_matrix.build_plan(root=root, case_set="core")

    assert plan["cases"]["count"] == 2
    assert plan["summary"]["attack_rows"] == 6
    assert plan["summary"]["control_rows"] == 5
    assert plan["summary"]["rows_total"] == 11
    assert plan["baseline"]["name"] == "claude_code_kimi_k2.6"
    assert plan["baseline"]["codex_in_current_scope"] is False
    assert plan["labels"]["attack"][0] == "paper_all_trial01_claude_default"
    assert plan["labels"]["control"][0] == "paper_controls_all_trial01_claude_default_clean_control"
    assert plan["labels"]["control"][1] == "paper_controls_all_trial01_claude_default_no_persist_control"
    assert plan["rows"][0]["runtime_model"] == "kimi-k2.6"
    assert plan["rows"][0]["model_source"] == "Claude Code runtime default"
    assert plan["summary"]["by_kind_harness"] == {
        "attack:claude": 6,
        "control:claude": 5,
    }
    assert plan["queue_seed"] == plan_paper_experiment_matrix.DEFAULT_QUEUE_SEED
    assert plan["plan_status"] == "development_unlocked"
    assert plan["formal_execution_eligible"] is False
    assert plan["execution_contract"]["max_parallel_rows"] == 1
    assert [row["queue_position"] for row in plan["rows"]] == list(range(1, 12))
    assert len({row["expected_row_id"] for row in plan["rows"]}) == 11
    assert len({row["isolated_home_id"] for row in plan["rows"]}) == 11
    assert len({row["canary_token"] for row in plan["rows"]}) == 11
    assert all(
        row["label"].endswith(row["expected_row_id"].removeprefix("expected_"))
        for row in plan["rows"]
    )
    assert all(row["base_label"].startswith(row["label_root"]) for row in plan["rows"])
    assert all(row["requires_skip_completed"] is True for row in plan["rows"])
    assert all(row["case_runtime_input_digest"] for row in plan["rows"])
    assert all(row["case_control_contract_digest"] for row in plan["rows"])
    assert all(row["case_content_digest"] for row in plan["rows"])
    assert all(row["runtime_code_revision_digest"] for row in plan["rows"])
    assert all(row["protocol_revision_digest"] for row in plan["rows"])
    assert all(row["runtime_revision_digest"] for row in plan["rows"])
    assert all(row["suite_content_digest"] for row in plan["rows"])
    assert all(row["case_contract_digest"] for row in plan["rows"])
    assert all(row["control_contract_digest"] for row in plan["rows"])
    assert all(row["source_manifest_digest"] for row in plan["rows"])
    assert all(row["source_manifest_canonical_digest"] for row in plan["rows"])
    assert all(row["runtime_input_policy_digest"] for row in plan["rows"])
    assert {row["attestation_mode"] for row in plan["rows"]} == {"formal_suite_lock"}
    assert len({row["suite_content_digest"] for row in plan["rows"]}) == 1
    assert plan_paper_experiment_matrix.validate_plan(plan, root=root) == []


def test_plan_paper_experiment_matrix_respects_control_availability(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)

    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="all",
        harnesses=["claude"],
        attack_trials=0,
        control_trials=1,
        control_types=["all"],
    )

    assert plan["summary"]["attack_rows"] == 0
    assert plan["summary"]["control_rows"] == 5
    assert plan["summary"]["by_control_type"]["clean_control"] == 2
    assert plan["summary"]["by_control_type"]["cleanup_control"] == 1


def test_plan_paper_experiment_matrix_expands_claude_models(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)

    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="core",
        attack_trials=1,
        control_trials=1,
        control_types=["clean_control"],
        claude_models=["kimi-k2.6", "claude-sonnet-4-5"],
    )

    assert plan["models"]["claude_models"] == ["kimi-k2.6", "claude-sonnet-4-5"]
    assert plan["summary"]["attack_rows"] == 4
    assert plan["summary"]["control_rows"] == 4
    assert plan["labels"]["attack"] == [
        "paper_all_trial01_claude_kimi-k2.6",
        "paper_all_trial01_claude_claude-sonnet-4-5",
    ]
    assert {row["runtime_model"] for row in plan["rows"]} == {"kimi-k2.6", "claude-sonnet-4-5"}
    assert {row["model_source"] for row in plan["rows"]} == {"runner argument"}
    assert "-ClaudeModels kimi-k2.6,claude-sonnet-4-5" in "\n".join(
        plan_paper_experiment_matrix.runner_commands(plan)
    )
    assert plan_paper_experiment_matrix.validate_plan(plan, root=root) == []


def test_plan_paper_experiment_matrix_validation_detects_stale_plan(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)
    plan = plan_paper_experiment_matrix.build_plan(root=root, case_set="core")
    plan["summary"]["rows_total"] = 999

    issues = plan_paper_experiment_matrix.validate_plan(plan, root=root)

    assert any(item["message"] == "experiment plan recorded digest does not match its contents" for item in issues)
    assert any(item["message"] == "experiment plan summary does not match regenerated summary" for item in issues)


def test_plan_paper_experiment_matrix_renders_runner_commands(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)
    plan = plan_paper_experiment_matrix.build_plan(root=root, case_set="core")

    markdown = plan_paper_experiment_matrix.render_markdown(plan)

    assert "run_paper_baseline_matrix.ps1" in markdown
    assert "run_paper_control_matrix.ps1" in markdown
    assert "-Harnesses claude" in markdown
    assert "baseline: `claude_code_kimi_k2.6`" in markdown
    assert "paper_controls_all_trial01_claude_default_clean_control" in markdown
    assert "Formal Serialized Queue Contract" in markdown
    assert "do not preserve the formal case-block ordering" in markdown


def test_plan_uses_deterministic_contiguous_interleaved_case_blocks(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)

    first = plan_paper_experiment_matrix.build_plan(root=root, case_set="all", queue_seed=17)
    second = plan_paper_experiment_matrix.build_plan(root=root, case_set="all", queue_seed=17)
    different_seed = plan_paper_experiment_matrix.build_plan(root=root, case_set="all", queue_seed=18)

    assert [row["expected_row_id"] for row in first["rows"]] == [
        row["expected_row_id"] for row in second["rows"]
    ]
    assert [row["case_dir"] for row in first["rows"]] != [
        row["case_dir"] for row in different_seed["rows"]
    ] or [row["kind"] for row in first["rows"]] != [row["kind"] for row in different_seed["rows"]]

    for case_dir in {row["case_dir"] for row in first["rows"]}:
        block = [row for row in first["rows"] if row["case_dir"] == case_dir]
        positions = [row["queue_position"] for row in block]
        assert positions == list(range(min(positions), max(positions) + 1))
    fully_matched = [row for row in first["rows"] if row["case_id"] == "case_a"]
    kinds = [row["kind"] for row in fully_matched]
    assert all(left != right for left, right in zip(kinds[:5], kinds[1:6]))


def test_case_contract_change_produces_new_expected_row_ids_and_formal_labels(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)
    before = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")
    case_dir = "active/F2_skill_runtime/F2.01_family/case_a"
    case_path = root / "runs" / case_dir / "case_meta.json"
    meta = json.loads(case_path.read_text(encoding="utf-8"))
    meta["contract_revision_for_test"] = 2
    _write_json(case_path, meta)

    after = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")
    before_rows = [row for row in before["rows"] if row["case_dir"] == case_dir]
    after_rows = [row for row in after["rows"] if row["case_dir"] == case_dir]

    assert {row["expected_row_id"] for row in before_rows}.isdisjoint(
        {row["expected_row_id"] for row in after_rows}
    )
    assert {row["label"] for row in before_rows}.isdisjoint({row["label"] for row in after_rows})


def test_runtime_asset_change_produces_new_expected_row_ids_and_formal_labels(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)
    case_dir = "active/F2_skill_runtime/F2.01_family/case_a"
    asset = root / "runs" / case_dir / "workspace" / "clean-source.json"
    asset.parent.mkdir(parents=True, exist_ok=True)
    asset.write_text('{"version": 1}\n', encoding="utf-8")
    before = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")
    asset.write_text('{"version": 2}\n', encoding="utf-8")

    after = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")
    before_rows = [row for row in before["rows"] if row["case_dir"] == case_dir]
    after_rows = [row for row in after["rows"] if row["case_dir"] == case_dir]

    assert {row["expected_row_id"] for row in before_rows}.isdisjoint(
        {row["expected_row_id"] for row in after_rows}
    )
    assert {row["label"] for row in before_rows}.isdisjoint({row["label"] for row in after_rows})
    # Every expected row binds the complete suite-content digest, so a frozen
    # runtime-input change rotates the whole preregistered matrix, not only the
    # rows belonging to the edited case.
    assert {row["expected_row_id"] for row in before["rows"]}.isdisjoint(
        {row["expected_row_id"] for row in after["rows"]}
    )


def test_protocol_revision_change_rotates_every_expected_row_id(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)
    protocol = root / plan_paper_experiment_matrix.check_paper_suite_lock.PROTOCOL_REVISION_PATHS[
        "formal_experiment_execution_policy"
    ]
    protocol.parent.mkdir(parents=True, exist_ok=True)
    protocol.write_text("retry ceiling: 3\n", encoding="utf-8")
    before = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")
    protocol.write_text("retry ceiling: 4\n", encoding="utf-8")

    after = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")

    assert {row["expected_row_id"] for row in before["rows"]}.isdisjoint(
        {row["expected_row_id"] for row in after["rows"]}
    )
    assert {row["label"] for row in before["rows"]}.isdisjoint(
        {row["label"] for row in after["rows"]}
    )


def test_verified_lock_does_not_make_non_normative_plan_formal(tmp_path: Path, monkeypatch):
    root = tmp_path / "bench"
    _write_fixture(root)
    live = plan_paper_experiment_matrix.live_runtime_content_binding(root)
    monkeypatch.setattr(
        plan_paper_experiment_matrix,
        "suite_lock_binding",
        lambda _root: {
            "present": True,
            "parse_valid": True,
            "verified": True,
            "suite_content_sha256": live["suite_content_sha256"],
            "runtime_code_revision_sha256": live["runtime_code_revision_sha256"],
            "protocol_revisions_sha256": live["protocol_revisions_sha256"],
            "file_sha256": "a" * 64,
        },
    )

    plan = plan_paper_experiment_matrix.build_plan(
        root=root,
        case_set="all",
        case_limit=1,
        attack_trials=0,
        control_trials=1,
        control_types=["clean_control"],
        queue_seed=9,
    )

    assert plan["plan_status"] == "development_unlocked"
    assert plan["formal_execution_eligible"] is False
    assert "case_limit_must_be_zero" in plan["formal_protocol_issues"]
    assert "formal_row_count_must_be_2296" in plan["formal_protocol_issues"]
    assert "queue_seed_must_be_20260713" in plan["formal_protocol_issues"]


def test_plan_validation_rejects_duplicate_ids_and_non_serial_contract(tmp_path: Path):
    root = tmp_path / "bench"
    _write_fixture(root)
    plan = plan_paper_experiment_matrix.build_plan(root=root, case_set="all")
    plan["rows"][1]["expected_row_id"] = plan["rows"][0]["expected_row_id"]
    plan["execution_contract"]["max_parallel_rows"] = 2

    issues = plan_paper_experiment_matrix.validate_plan(plan, root=root)

    messages = {item["message"] for item in issues}
    assert "expected_row_id values must be present and unique" in messages
    assert "formal queue must execute exactly one real benchmark row at a time" in messages
