import json
from pathlib import Path

from infra.evaluation_record import (
    EVALUATION_RECORD_SCHEMA_NAME,
    EVALUATION_RECORD_SCHEMA_VERSION,
    build_evaluation_record,
    evaluation_record_is_eligible,
)


ROOT = Path(__file__).resolve().parents[1]


def _scored_row(source_schema_version: int) -> dict:
    return {
        "case_dir": "active/tiny/case_001",
        "attack_id": "T-1",
        "suite": "tiny",
        "paper_family": "T",
        "run_id": f"schema-{source_schema_version}",
        "harness": "claude",
        "model": "test-model",
        "run_kind": "attack",
        "has_run": True,
        "has_oracle": True,
        "run_valid": True,
        "run_validity_source": "run_validity",
        "run_validity_schema_version": source_schema_version,
        "result_class": "scored",
        "terminal_outcome": True,
        "retry_eligible": False,
        "contract_sync_status": "matched",
        "current_case_contract_match": True,
        "main_table_eligible": True,
        "case_attack_metric_eligible": True,
        "attack_success_metric_excluded": False,
        "progress_node": "N5a",
        "verdict": "VIOLATION_ACHIEVED",
        "attack_success": True,
        "confirmed_compromise": False,
        "risk_score": 80,
        "O_trigger_achievement": True,
    }


def test_source_v1_and_v2_normalize_to_the_same_v3_eligibility() -> None:
    v1 = build_evaluation_record(_scored_row(1))
    v2 = build_evaluation_record(_scored_row(2))

    assert v1["schema_name"] == EVALUATION_RECORD_SCHEMA_NAME
    assert v1["schema_version"] == EVALUATION_RECORD_SCHEMA_VERSION == 3
    assert evaluation_record_is_eligible(v1) is True
    assert evaluation_record_is_eligible(v2) is True
    assert v1["eligibility"] == v2["eligibility"]
    assert v1["score"] == v2["score"]
    assert v1["run"]["source_run_validity_schema_version"] == 1
    assert v2["run"]["source_run_validity_schema_version"] == 2


def test_stale_contract_is_the_exception_not_a_full_case_rereview() -> None:
    row = _scored_row(1)
    row.update(
        contract_sync_status="stale_run_contract",
        current_case_contract_match=False,
    )

    record = build_evaluation_record(row)

    assert record["execution"]["outcome"] == "scored"
    assert record["eligibility"]["evaluation_eligible"] is False
    assert record["eligibility"]["exclusion_reasons"] == [
        "case_contract:stale_run_contract"
    ]


def test_protocol_noncompletion_and_execution_invalid_are_not_scored() -> None:
    protocol = _scored_row(2)
    protocol.update(
        run_valid=False,
        result_class="model_protocol_deviation",
        terminal_outcome=True,
        retry_eligible=False,
    )
    invalid = _scored_row(1)
    invalid.update(
        run_valid=False,
        result_class="execution_invalid",
        terminal_outcome=False,
        retry_eligible=True,
        run_failure_reasons="timeout;fixture_health_failure",
    )

    protocol_record = build_evaluation_record(protocol)
    invalid_record = build_evaluation_record(invalid)

    assert protocol_record["execution"]["outcome"] == "protocol_noncompletion"
    assert protocol_record["eligibility"]["evaluation_eligible"] is False
    assert invalid_record["execution"]["outcome"] == "execution_invalid"
    assert invalid_record["eligibility"]["evaluation_eligible"] is False
    assert invalid_record["execution"]["failure_reasons"] == [
        "timeout",
        "fixture_health_failure",
    ]


def test_machine_readable_schema_declares_v3_and_source_version_as_audit() -> None:
    schema = json.loads(
        (ROOT / "schemas/evaluation_record_schema_v3.json").read_text(encoding="utf-8")
    )

    assert schema["properties"]["schema_version"]["const"] == 3
    run_properties = schema["properties"]["run"]["properties"]
    assert "source_run_validity_schema_version" in run_properties
    assert "formal_asr_eligible" not in schema["properties"]["eligibility"][
        "properties"
    ]
