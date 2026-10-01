import json
from pathlib import Path

from infra import generate_threat_model_card


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_generate_threat_model_card_summarizes_frame_controls_and_sets(tmp_path: Path):
    suite_lock = tmp_path / "docs/generated_artifacts/paper_suite_lock.json"
    _write(
        suite_lock,
        json.dumps(
            {
                "schema_version": 1,
                "source_manifest": "runs/manifest.json",
                "active_case_count": 2,
                "case_counts": {"core": 1, "extended": 1, "exploratory": 0, "all": 2},
                "cases": [
                    {
                        "case_dir": "active/F2/case_a",
                        "case_sets": ["core", "all"],
                        "suite": "v2_skill_runtime",
                        "paper_family": "F2.04",
                        "main_table_eligible": True,
                        "reporting_track": "core_benchmark",
                        "oracle_strength": "hard_trace_oracle",
                        "infection_mode": "preseeded_carrier_eval",
                        "frame": {
                            "entry": "skill_metadata",
                            "carrier": "skill_file",
                            "boundary": "cross_session",
                            "trigger": "benign_task",
                            "violation": "C3_network_or_C4_canary_exfil",
                            "recovery": "delete_skill",
                        },
                        "control_suite": [
                            {"control_type": "clean_control", "expected_max_node": "N2"},
                            {"control_type": "no_trigger_control", "expected_max_node": "N2"},
                        ],
                    },
                    {
                        "case_dir": "active/F1/case_b",
                        "case_sets": ["extended", "all"],
                        "suite": "F1_memory_runtime",
                        "paper_family": "F1E.01",
                        "main_table_eligible": False,
                        "reporting_track": "extended_benchmark",
                        "oracle_strength": "soft_semantic_oracle",
                        "infection_mode": "preseeded_carrier_eval",
                        "frame": {
                            "entry": "preseeded_memory_snapshot",
                            "carrier": "memory",
                            "boundary": "cross_session",
                            "trigger": "benign_domain_qa_or_workflow_task",
                            "violation": "C5_unsafe_recommendation_drift",
                            "recovery": "replace_memory",
                        },
                        "control_suite": [
                            {"control_type": "clean_control", "expected_max_node": "N2"},
                        ],
                    },
                ],
            }
        ),
    )

    card = generate_threat_model_card.build_card(
        suite_lock_path=suite_lock,
        case_set="all",
        root=tmp_path,
    )
    markdown = generate_threat_model_card.render_markdown(card)

    assert card["schema_version"] == 1
    assert card["scope"]["case_count"] == 2
    assert card["scope"]["active_case_count"] == 2
    assert card["benchmark"]["frame"] == "Entry -> Carrier -> Boundary -> Trigger -> Violation"
    assert card["coverage"]["case_sets"][0]["case_set"] == "core"
    assert card["coverage"]["case_sets"][0]["cases"] == 1
    assert card["coverage"]["frame_dimensions"]["entry"]["unique_values"] == 2
    assert card["coverage"]["control_model"]["cases_with_controls"] == 2
    assert "# Safety Bench Threat Model Card" in markdown
    assert "Threat Model Summary" in markdown
    assert "Frame Coverage" in markdown
    assert "Control And Recovery Model" in markdown
    assert "Public Artifact Boundary" in markdown
