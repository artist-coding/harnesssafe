"""Check paper case-study prose against generated evidence artifacts."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra.check_paper_results import is_scored_row
except ModuleNotFoundError:  # direct `python infra/check_paper_case_studies.py`
    from check_paper_results import is_scored_row  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATES_DOC = "docs/generated_artifacts/paper_case_study_candidates.md"
DEFAULT_DRAFT_DOC = "docs/paper_draft.md"
CONTROL_TYPES = ["clean_control", "no_persist_control", "no_trigger_control", "cleanup_control"]
DISTINCTIVE_ORACLES = [
    "O_mcp_canary_arg",
    "O_skill_invoked",
    "O_skill_effect_observed",
    "O_canary",
    "O_outside_read",
]


def issue(severity: str, scope: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "detail": detail or {},
    }


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def bool_text(value: Any) -> str:
    if isinstance(value, str):
        return "true" if value.strip().lower() in {"1", "true", "yes", "y", "__yes__"} else "false"
    return "true" if bool(value) else "false"


def boolish(value: Any) -> bool:
    return bool_text(value) == "true"


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def rate_matches(value: Any, numerator: int, denominator: int) -> bool:
    if numerator < 0 or denominator < 0 or numerator > denominator:
        return False
    if denominator == 0:
        return numerator == 0 and value is None
    try:
        actual = float(value)
    except (TypeError, ValueError):
        return False
    expected = numerator / denominator
    return abs(actual - expected) <= 1.1e-6


def is_asr_eligible_compact_scored(row: dict[str, Any]) -> bool:
    return bool(
        row.get("scored") is True
        and row.get("accounted_terminal") is True
        and row.get("model_protocol_terminal") is False
        and row.get("asr_eligible_scored") is True
        and is_scored_row(row)
    )


def load_json(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), []
    except FileNotFoundError:
        return None, [issue("error", "inputs", "required JSON file is missing", {"path": str(path)})]
    except json.JSONDecodeError as exc:
        return None, [issue("error", "inputs", "could not parse JSON file", {"path": str(path), "error": str(exc)})]


def control_summary(case: dict[str, Any]) -> str:
    controls = case.get("controls", {})
    parts: list[str] = []
    for control_type in CONTROL_TYPES:
        row = controls.get(control_type, {}) if isinstance(controls, dict) else {}
        parts.append(
            f"{control_type}={row.get('progress_node', '')},"
            f"{bool_text(row.get('attack_success'))},"
            f"{bool_text(row.get('confirmed_compromise'))}"
        )
    return "; ".join(parts)


def evidence_lock_row(case: dict[str, Any]) -> str:
    attack = case.get("attack", {}) if isinstance(case.get("attack"), dict) else {}
    return (
        f"| {case.get('paper_family', '')} | {case.get('case_dir', '')} | "
        f"{bool_text(case.get('recommended_main_paper'))} | "
        f"{attack.get('progress_node', '')} | {attack.get('verdict', '')} | "
        f"{attack.get('risk_score', '')} | {case.get('attack_row_count', '')} | "
        f"{bool_text(attack.get('attack_success'))} | "
        f"{bool_text(attack.get('confirmed_compromise'))} | "
        f"{control_summary(case)} |"
    )


def expected_evidence_lock_table(cases: list[dict[str, Any]]) -> str:
    lines = [
        "| Family | Case | Recommended | Progress | Verdict | Risk | Attack rows | Attack success | Confirmed | Controls |",
        "| --- | --- | --- | --- | --- | ---: | ---: | --- | --- | --- |",
    ]
    lines.extend(evidence_lock_row(case) for case in cases)
    return "\n".join(lines)


def check_candidates_doc(
    *,
    payload: dict[str, Any],
    candidates_doc: Path,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not candidates_doc.is_file():
        return [issue("error", "case_study_doc", "case-study candidates doc is missing", {"path": str(candidates_doc)})]
    text = candidates_doc.read_text(encoding="utf-8-sig")
    compact = normalize_text(text)
    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        return [issue("error", "case_evidence", "case_study_evidence.json cases must be a list")]
    if "## Evidence Lock" not in text:
        issues.append(
            issue(
                "error",
                "case_study_doc",
                "case-study candidates doc is missing the machine-checkable Evidence Lock section",
                {"path": str(candidates_doc)},
            )
        )
    expected_summary = f"case_count={payload.get('case_count', '')}; attack_row_count={payload.get('attack_row_count', '')}; recommended_main_paper_count={payload.get('recommended_main_paper_count', '')}"
    if expected_summary not in text:
        issues.append(
            issue(
                "error",
                "case_study_doc",
                "case-study candidates doc is missing the current evidence summary",
                {"expected": expected_summary},
            )
        )
    for case in cases:
        expected = evidence_lock_row(case)
        if normalize_text(expected) not in compact:
            issues.append(
                issue(
                    "error",
                    "case_study_doc",
                    "case-study evidence-lock row is missing or stale",
                    {
                        "case_dir": case.get("case_dir", ""),
                        "paper_family": case.get("paper_family", ""),
                        "expected": expected,
                    },
                )
            )
    recommended = [case for case in cases if case.get("recommended_main_paper")]
    if len(recommended) != int(payload.get("recommended_main_paper_count") or 0):
        issues.append(
            issue(
                "error",
                "case_evidence",
                "recommended_main_paper_count does not match case records",
                {"expected": len(recommended), "actual": payload.get("recommended_main_paper_count")},
            )
        )
    return issues


def observed_oracles(case: dict[str, Any]) -> list[str]:
    attack = case.get("attack", {}) if isinstance(case.get("attack"), dict) else {}
    raw = attack.get("observed_oracles", [])
    return [str(item) for item in raw] if isinstance(raw, list) else []


def check_result_class_accounting(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Reject N-1 or unvalidated rows masquerading as safety case-study evidence."""

    issues: list[dict[str, Any]] = []
    required_top_level = {
        "accounted_terminal_attack_rows",
        "scored_attack_rows",
        "asr_eligible_scored_attack_rows",
        "asr_ineligible_scored_attack_rows",
        "model_protocol_terminal_attack_rows",
        "excluded_model_protocol_attack_rows",
        "protocol_denominator_attack_rows",
        "attack_success_rows",
        "attack_protocol_completion_rate",
        "attack_model_nonconformance_rate",
        "conditional_attack_success_rate",
        "end_to_end_attack_rate",
        "matched_control_accounted_terminal_rows",
        "matched_control_scored_rows",
        "matched_control_asr_eligible_scored_rows",
        "matched_control_asr_ineligible_scored_rows",
        "matched_control_model_protocol_terminal_rows",
        "matched_control_protocol_denominator_rows",
        "control_protocol_completion_rate",
        "control_model_nonconformance_rate",
    }
    missing = sorted(required_top_level - set(payload))
    if missing:
        return [
            issue(
                "error",
                "case_evidence",
                "case-study evidence pack lacks result-class accounting",
                {"missing_fields": missing},
            )
        ]

    scored = as_int(payload.get("scored_attack_rows"))
    eligible_scored = as_int(payload.get("asr_eligible_scored_attack_rows"))
    ineligible_scored = as_int(payload.get("asr_ineligible_scored_attack_rows"))
    n_minus_one = as_int(payload.get("model_protocol_terminal_attack_rows"))
    accounted = as_int(payload.get("accounted_terminal_attack_rows"))
    protocol_denominator = as_int(payload.get("protocol_denominator_attack_rows"))
    attack_successes = as_int(payload.get("attack_success_rows"))
    excluded = as_int(payload.get("excluded_model_protocol_attack_rows"))
    control_scored = as_int(payload.get("matched_control_scored_rows"))
    control_eligible_scored = as_int(
        payload.get("matched_control_asr_eligible_scored_rows")
    )
    control_ineligible_scored = as_int(
        payload.get("matched_control_asr_ineligible_scored_rows")
    )
    control_n_minus_one = as_int(
        payload.get("matched_control_model_protocol_terminal_rows")
    )
    control_accounted = as_int(payload.get("matched_control_accounted_terminal_rows"))
    control_protocol_denominator = as_int(
        payload.get("matched_control_protocol_denominator_rows")
    )
    attack_counts = (
        scored,
        eligible_scored,
        ineligible_scored,
        n_minus_one,
        accounted,
        protocol_denominator,
        excluded,
        attack_successes,
    )
    if (
        any(count < 0 for count in attack_counts)
        or attack_successes > eligible_scored
        or accounted != scored + n_minus_one
        or scored != eligible_scored + ineligible_scored
        or protocol_denominator != eligible_scored + n_minus_one
        or excluded != n_minus_one
    ):
        issues.append(
            issue(
                "error",
                "case_evidence",
                "attack result-class accounting is inconsistent",
                {
                    "scored": scored,
                    "asr_eligible_scored": eligible_scored,
                    "asr_ineligible_scored": ineligible_scored,
                    "model_protocol_terminal": n_minus_one,
                    "accounted_terminal": accounted,
                    "protocol_denominator": protocol_denominator,
                    "excluded_model_protocol": excluded,
                },
            )
        )
    control_counts = (
        control_scored,
        control_eligible_scored,
        control_ineligible_scored,
        control_n_minus_one,
        control_accounted,
        control_protocol_denominator,
    )
    if (
        any(count < 0 for count in control_counts)
        or control_accounted != control_scored + control_n_minus_one
        or control_scored != control_eligible_scored + control_ineligible_scored
        or control_protocol_denominator
        != control_eligible_scored + control_n_minus_one
    ):
        issues.append(
            issue(
                "error",
                "case_evidence",
                "control result-class accounting is inconsistent",
                {
                    "scored": control_scored,
                    "asr_eligible_scored": control_eligible_scored,
                    "asr_ineligible_scored": control_ineligible_scored,
                    "model_protocol_terminal": control_n_minus_one,
                    "accounted_terminal": control_accounted,
                    "protocol_denominator": control_protocol_denominator,
                },
            )
        )
    for field, numerator, denominator in [
        (
            "attack_protocol_completion_rate",
            eligible_scored,
            protocol_denominator,
        ),
        (
            "attack_model_nonconformance_rate",
            n_minus_one,
            protocol_denominator,
        ),
        (
            "conditional_attack_success_rate",
            attack_successes,
            eligible_scored,
        ),
        (
            "end_to_end_attack_rate",
            attack_successes,
            protocol_denominator,
        ),
        (
            "control_protocol_completion_rate",
            control_eligible_scored,
            control_protocol_denominator,
        ),
        (
            "control_model_nonconformance_rate",
            control_n_minus_one,
            control_protocol_denominator,
        ),
    ]:
        if not rate_matches(payload.get(field), numerator, denominator):
            issues.append(
                issue(
                    "error",
                    "case_evidence",
                    "case-study result-class rate is inconsistent",
                    {
                        "field": field,
                        "value": payload.get(field),
                        "numerator": numerator,
                        "denominator": denominator,
                    },
                )
            )

    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        return issues
    control_rows_seen = 0
    selected_attack_rows_seen = 0
    for case in cases:
        if not isinstance(case, dict):
            continue
        attack = case.get("attack", {})
        attack = attack if isinstance(attack, dict) else {}
        if not is_asr_eligible_compact_scored(attack):
            message = (
                "recommended case-study attack is not an ASR-eligible scored terminal result"
                if case.get("recommended_main_paper")
                else "case-study attack is not an ASR-eligible scored terminal result"
            )
            issues.append(
                issue(
                    "error",
                    "case_evidence",
                    message,
                    {"case_dir": case.get("case_dir", "")},
                )
            )
        attacks = case.get("attacks", [])
        attacks = attacks if isinstance(attacks, list) else []
        declared_attack_rows = as_int(case.get("attack_row_count"))
        selected_attack_rows_seen += len(attacks)
        if declared_attack_rows != len(attacks) or any(
            not isinstance(row, dict) or not is_asr_eligible_compact_scored(row)
            for row in attacks
        ):
            issues.append(
                issue(
                    "error",
                    "case_evidence",
                    "case-study attack-row list is not fully ASR-eligible and scored",
                    {
                        "case_dir": case.get("case_dir", ""),
                        "declared": declared_attack_rows,
                        "observed": len(attacks),
                    },
                )
            )
        controls = case.get("controls", {})
        controls = controls if isinstance(controls, dict) else {}
        for control_type, control in controls.items():
            if not isinstance(control, dict):
                continue
            control_rows_seen += 1
            if not is_asr_eligible_compact_scored(control):
                issues.append(
                    issue(
                        "error",
                        "case_evidence",
                        "case-study control is not an ASR-eligible scorable safety contrast",
                        {
                            "case_dir": case.get("case_dir", ""),
                            "control_type": control_type,
                        },
                    )
                )
        if (
            as_int(case.get("control_asr_eligible_scored_count")) != len(controls)
            or as_int(case.get("control_asr_ineligible_scored_count")) != 0
            or as_int(case.get("control_model_protocol_terminal_count")) != 0
            or as_int(case.get("control_protocol_denominator_count"))
            != len(controls)
        ):
            issues.append(
                issue(
                    "error",
                    "case_evidence",
                    "case-study control accounting is not fully scorable",
                    {"case_dir": case.get("case_dir", "")},
                )
            )
    if (
        control_rows_seen != control_eligible_scored
        or control_ineligible_scored != 0
        or control_n_minus_one != 0
    ):
        issues.append(
            issue(
                "error",
                "case_evidence",
                "N-1 controls cannot serve as safety contrasts",
                {
                    "control_rows_seen": control_rows_seen,
                    "scored_controls": control_scored,
                    "model_protocol_terminal_controls": control_n_minus_one,
                },
            )
        )
    if selected_attack_rows_seen != as_int(payload.get("attack_row_count")):
        issues.append(
            issue(
                "error",
                "case_evidence",
                "case-study selected attack-row accounting is inconsistent",
                {
                    "observed": selected_attack_rows_seen,
                    "declared": payload.get("attack_row_count"),
                },
            )
        )
    return issues


def check_draft_doc(
    *,
    payload: dict[str, Any],
    draft_doc: Path,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not draft_doc.is_file():
        return [issue("error", "case_study_draft", "paper draft is missing", {"path": str(draft_doc)})]
    text = draft_doc.read_text(encoding="utf-8-sig")
    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        return issues
    recommended = [case for case in cases if case.get("recommended_main_paper")]
    for case in recommended:
        attack = case.get("attack", {}) if isinstance(case.get("attack"), dict) else {}
        family = str(case.get("paper_family") or "")
        progress = str(attack.get("progress_node") or "")
        verdict = str(attack.get("verdict") or "")
        if family and family not in text:
            issues.append(
                issue(
                    "error",
                    "case_study_draft",
                    "recommended main-paper case family is missing from paper draft",
                    {"paper_family": family, "case_dir": case.get("case_dir", "")},
                )
            )
        if progress and progress not in text:
            issues.append(
                issue(
                    "error",
                    "case_study_draft",
                    "recommended main-paper case progress node is missing from paper draft",
                    {"paper_family": family, "progress_node": progress},
                )
            )
        if verdict and verdict not in text:
            issues.append(
                issue(
                    "error",
                    "case_study_draft",
                    "recommended main-paper case verdict is missing from paper draft",
                    {"paper_family": family, "verdict": verdict},
                )
            )
        distinctive = [oracle for oracle in observed_oracles(case) if oracle in DISTINCTIVE_ORACLES]
        if distinctive and not any(oracle in text for oracle in distinctive):
            issues.append(
                issue(
                    "error",
                    "case_study_draft",
                    "recommended main-paper case distinctive oracle is missing from paper draft",
                    {"paper_family": family, "oracles": distinctive},
                )
            )
    for phrase in ["T2 memory-to-skill", "attack_success=true", "strict chain criteria"]:
        if phrase not in text:
            issues.append(
                issue(
                    "error",
                    "case_study_draft",
                    "paper draft is missing the T2 contrast framing",
                    {"phrase": phrase},
                )
            )
    return issues


def build_case_study_report(
    *,
    root: Path = ROOT,
    case_evidence_dir: Path,
    candidates_doc: Path | None = None,
    draft_doc: Path | None = None,
) -> dict[str, Any]:
    evidence_path = case_evidence_dir / "case_study_evidence.json"
    payload, issues = load_json(evidence_path)
    if payload is None:
        cases: list[dict[str, Any]] = []
    else:
        cases = payload.get("cases", []) if isinstance(payload.get("cases"), list) else []
        issues.extend(check_result_class_accounting(payload))
        issues.extend(check_candidates_doc(payload=payload, candidates_doc=candidates_doc or root / DEFAULT_CANDIDATES_DOC))
        issues.extend(check_draft_doc(payload=payload, draft_doc=draft_doc or root / DEFAULT_DRAFT_DOC))
    recommended_cases = [case for case in cases if case.get("recommended_main_paper")]
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "case_evidence_file": str(evidence_path),
        "candidates_doc": str(candidates_doc or root / DEFAULT_CANDIDATES_DOC),
        "draft_doc": str(draft_doc or root / DEFAULT_DRAFT_DOC),
        "case_count": payload.get("case_count", 0) if payload else 0,
        "attack_row_count": payload.get("attack_row_count", 0) if payload else 0,
        "recommended_main_paper_count": payload.get("recommended_main_paper_count", 0) if payload else 0,
        "recommended_main_paper_cases": [
            {
                "paper_family": case.get("paper_family", ""),
                "case_dir": case.get("case_dir", ""),
                "progress_node": (case.get("attack", {}) if isinstance(case.get("attack"), dict) else {}).get("progress_node", ""),
                "verdict": (case.get("attack", {}) if isinstance(case.get("attack"), dict) else {}).get("verdict", ""),
            }
            for case in recommended_cases
        ],
        "expected_evidence_lock_table": expected_evidence_lock_table(cases),
        "issues": issues,
        "ok": not any(item.get("severity") == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Case Study Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        f"- case_evidence_file: `{report['case_evidence_file']}`",
        f"- candidates_doc: `{report['candidates_doc']}`",
        f"- draft_doc: `{report['draft_doc']}`",
        f"- case_count: `{report['case_count']}`",
        f"- attack_row_count: `{report['attack_row_count']}`",
        f"- recommended_main_paper_count: `{report['recommended_main_paper_count']}`",
        "",
        "## Expected Evidence Lock",
        "",
        report["expected_evidence_lock_table"],
        "",
        "## Issues",
        "",
    ]
    if report["issues"]:
        lines += ["| Severity | Scope | Message | Detail |", "| --- | --- | --- | --- |"]
        for item in report["issues"]:
            detail = json.dumps(item.get("detail", {}), ensure_ascii=False, sort_keys=True)
            lines.append(f"| {item.get('severity')} | {item.get('scope')} | {item.get('message')} | `{detail}` |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper case-study candidates against evidence pack.")
    parser.add_argument("--case-evidence-dir", required=True)
    parser.add_argument("--candidates-doc", default=DEFAULT_CANDIDATES_DOC)
    parser.add_argument("--draft-doc", default=DEFAULT_DRAFT_DOC)
    parser.add_argument("--out", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_case_study_report(
        root=ROOT,
        case_evidence_dir=Path(args.case_evidence_dir),
        candidates_doc=Path(args.candidates_doc),
        draft_doc=Path(args.draft_doc),
    )
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
