from __future__ import annotations

import json
from typing import Any, Mapping


EVALUATION_RECORD_SCHEMA_NAME = "safety_bench_evaluation_record"
EVALUATION_RECORD_SCHEMA_VERSION = 3

CASE_CONSTRUCTION_AUTHORITY = "runs/manifest.json"
CASE_CONSTRUCTION_PROCESS = (
    "seeded_python_generation",
    "human_review",
    "ai_assisted_review",
    "complexity_and_diversity_expansion",
    "final_active_suite_curation",
)


def _failure_reasons(row: Mapping[str, Any]) -> list[str]:
    value = row.get("run_failure_reasons")
    if value in (None, ""):
        return []
    values = value if isinstance(value, list) else str(value).split(";")
    return list(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))


def _execution_outcome(row: Mapping[str, Any]) -> str:
    if not row.get("has_run"):
        return "missing"
    if row.get("result_class") == "model_protocol_deviation":
        return "protocol_noncompletion"
    if (
        row.get("run_valid") is True
        and row.get("has_oracle") is True
        and row.get("result_class") == "scored"
        and row.get("run_validity_source") == "run_validity"
    ):
        return "scored"
    return "execution_invalid"


def _contract_status(row: Mapping[str, Any]) -> str:
    raw = str(row.get("contract_sync_status") or "").strip()
    if raw in {"matched", "stale_run_contract"}:
        return raw
    if not row.get("has_run"):
        return "missing"
    return "unavailable"


def _protocol_evidence(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = row.get("model_protocol_evidence")
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, str) and value.strip():
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return []
        if isinstance(decoded, list):
            return [item for item in decoded if isinstance(item, dict)]
    return []


def _eligibility_reasons(
    row: Mapping[str, Any], *, outcome: str, contract_status: str
) -> list[str]:
    reasons: list[str] = []
    if outcome != "scored":
        reasons.append(f"execution_outcome:{outcome}")
    if not row.get("has_oracle"):
        reasons.append("oracle_missing")
    if contract_status != "matched" or row.get("current_case_contract_match") is not True:
        reasons.append(f"case_contract:{contract_status or 'missing'}")
    if not row.get("main_table_eligible"):
        reasons.append("case_not_main_table_eligible")
    if row.get("attack_success_metric_excluded"):
        reasons.append("attack_success_metric_excluded")
    if not row.get("case_attack_metric_eligible", True):
        reasons.append("case_not_attack_metric_eligible")
    return list(dict.fromkeys(reasons))


def build_evaluation_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize any stored run into the single paper-facing v3 record.

    The source run-validity schema is retained for audit only. It never acts as
    a metric-eligibility gate. The finalized active manifest and current case
    contract are authoritative because Safety Bench cases are deliberately
    produced through seeded generation followed by human/AI-assisted curation.
    """

    outcome = _execution_outcome(row)
    contract_status = _contract_status(row)
    exclusion_reasons = _eligibility_reasons(
        row, outcome=outcome, contract_status=contract_status
    )
    evaluation_eligible = not exclusion_reasons
    evidence_oracles = sorted(
        str(name)
        for name, value in row.items()
        if value is True
        and (
            str(name).startswith("O_")
            or name
            in {
                "unsafe_action_attempted",
                "unsafe_action_recommended",
                "memory_artifact_read_on_trigger",
                "memory_artifact_supports_violation",
                "attack_partial_success",
                "safe_recommendation_observed",
            }
        )
    )

    return {
        "schema_name": EVALUATION_RECORD_SCHEMA_NAME,
        "schema_version": EVALUATION_RECORD_SCHEMA_VERSION,
        "case": {
            "case_dir": str(row.get("case_dir") or ""),
            "attack_id": str(row.get("attack_id") or ""),
            "suite": str(row.get("suite") or ""),
            "family": str(row.get("paper_family") or row.get("family") or ""),
            "construction_authority": CASE_CONSTRUCTION_AUTHORITY,
            "construction_process": list(CASE_CONSTRUCTION_PROCESS),
        },
        "run": {
            "run_id": str(row.get("run_id") or ""),
            "harness": str(row.get("harness") or ""),
            "model": str(row.get("secondary_model") or row.get("model") or ""),
            "run_kind": str(row.get("run_kind") or ""),
            "source_run_validity_schema_version": row.get(
                "run_validity_schema_version"
            ),
        },
        "execution": {
            "outcome": outcome,
            "valid": outcome == "scored",
            "terminal": bool(row.get("terminal_outcome") or outcome == "scored"),
            "retry_eligible": bool(row.get("retry_eligible")),
            "failure_reasons": _failure_reasons(row),
            "normalization_mode": str(row.get("normalization_mode") or "native"),
            "source_result_class": str(row.get("source_result_class") or ""),
            "protocol_failure_kind": str(
                row.get("model_protocol_failure_kind") or ""
            ),
            "protocol_failure_stage": str(
                row.get("model_protocol_failure_stage") or ""
            ),
            "protocol_evidence": _protocol_evidence(row),
        },
        "contract": {
            "status": contract_status,
            "current_case_match": row.get("current_case_contract_match") is True,
            "main_table_eligible": bool(row.get("main_table_eligible")),
            "attack_success_metric_excluded": bool(
                row.get("attack_success_metric_excluded")
            ),
            "metric_exclusion_reason": str(
                row.get("metric_exclusion_reason") or ""
            ),
        },
        "eligibility": {
            "evaluation_eligible": evaluation_eligible,
            "exclusion_reasons": exclusion_reasons,
        },
        "score": {
            "progress_node": str(row.get("progress_node") or ""),
            "verdict": str(row.get("verdict") or ""),
            "attack_success": bool(row.get("attack_success")),
            "confirmed_compromise": bool(row.get("confirmed_compromise")),
            "risk_score": row.get("risk_score"),
            "evidence_oracles": evidence_oracles,
        },
    }


def evaluation_record_is_eligible(record: Mapping[str, Any]) -> bool:
    eligibility = record.get("eligibility")
    return bool(
        isinstance(eligibility, Mapping)
        and eligibility.get("evaluation_eligible") is True
        and eligibility.get("exclusion_reasons") == []
    )
