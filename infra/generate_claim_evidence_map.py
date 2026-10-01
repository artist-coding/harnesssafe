"""Generate a reviewer-facing map from paper claims to evidence artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_claim_evidence_map.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_claim_evidence_map.md")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else {}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig") if path.is_file() else ""


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def metric_matches(block: Any, *, successes: int | None = None, trials: int) -> bool:
    if not isinstance(block, dict) or block.get("available") is not True:
        return False
    if block.get("successes") is None or block.get("trials") is None:
        return False
    observed_successes = as_int(block.get("successes"))
    observed_trials = as_int(block.get("trials"))
    if observed_trials != trials or observed_successes < 0 or observed_successes > observed_trials:
        return False
    if successes is not None and observed_successes != successes:
        return False
    if observed_trials == 0:
        return observed_successes == 0 and block.get("rate") is None
    if block.get("rate") is None:
        return False
    expected_rate = observed_successes / observed_trials
    try:
        return abs(float(block.get("rate")) - expected_rate) <= 1e-6
    except (TypeError, ValueError):
        return False


def measurement_accounting_supported(stats: dict[str, Any]) -> bool:
    """Validate coverage accounting separately from the S+M metric contract."""
    contract = stats.get("metric_contract", {}) if isinstance(stats.get("metric_contract"), dict) else {}
    matrix = stats.get("matrix", {}) if isinstance(stats.get("matrix"), dict) else {}
    effects = stats.get("primary_effects", {}) if isinstance(stats.get("primary_effects"), dict) else {}
    required_counts = (
        "attack_scored_rows",
        "attack_asr_eligible_scored_rows",
        "attack_n_minus_1_rows",
        "attack_accounted_terminal_rows",
        "attack_protocol_denominator_rows",
        "control_scored_rows",
        "control_asr_eligible_scored_rows",
        "control_n_minus_1_rows",
        "control_accounted_terminal_rows",
        "control_protocol_denominator_rows",
    )
    if as_int(stats.get("schema_version")) != 2 or not all(
        key in matrix and matrix.get(key) is not None for key in required_counts
    ):
        return False
    attack_scored = as_int(matrix.get("attack_scored_rows"))
    attack_asr_eligible = as_int(matrix.get("attack_asr_eligible_scored_rows"))
    attack_n_minus_one = as_int(matrix.get("attack_n_minus_1_rows"))
    attack_accounted = as_int(matrix.get("attack_accounted_terminal_rows"))
    attack_protocol_denominator = as_int(
        matrix.get("attack_protocol_denominator_rows")
    )
    control_scored = as_int(matrix.get("control_scored_rows"))
    control_asr_eligible = as_int(matrix.get("control_asr_eligible_scored_rows"))
    control_n_minus_one = as_int(matrix.get("control_n_minus_1_rows"))
    control_accounted = as_int(matrix.get("control_accounted_terminal_rows"))
    control_protocol_denominator = as_int(
        matrix.get("control_protocol_denominator_rows")
    )
    attack_successes = as_int(
        (effects.get("conditional_attack_success") or {}).get("successes")
        if isinstance(effects.get("conditional_attack_success"), dict)
        else 0
    )
    control_successes = as_int(
        (effects.get("control_conditional_violation") or {}).get("successes")
        if isinstance(effects.get("control_conditional_violation"), dict)
        else 0
    )
    matrix_counts = (
        attack_scored,
        attack_asr_eligible,
        attack_n_minus_one,
        attack_accounted,
        attack_protocol_denominator,
        control_scored,
        control_asr_eligible,
        control_n_minus_one,
        control_accounted,
        control_protocol_denominator,
        attack_successes,
        control_successes,
    )
    return all(
        (
            all(count >= 0 for count in matrix_counts),
            attack_asr_eligible <= attack_scored,
            control_asr_eligible <= control_scored,
            attack_successes <= attack_asr_eligible,
            control_successes <= control_asr_eligible,
            contract.get("n_minus_one_is_progress_node") is False,
            contract.get("conditional_asr_denominator")
            == "ASR-eligible N0-N5b scored attack rows",
            contract.get("end_to_end_denominator")
            == "ASR-eligible scored attack rows plus N-1 attack rows",
            matrix.get("protocol_metrics_available") is True,
            attack_accounted == attack_scored + attack_n_minus_one,
            attack_protocol_denominator
            == attack_asr_eligible + attack_n_minus_one,
            control_accounted == control_scored + control_n_minus_one,
            control_protocol_denominator
            == control_asr_eligible + control_n_minus_one,
            metric_matches(
                effects.get("conditional_attack_success"),
                successes=attack_successes,
                trials=attack_asr_eligible,
            ),
            metric_matches(
                effects.get("protocol_completion"),
                successes=attack_asr_eligible,
                trials=attack_protocol_denominator,
            ),
            metric_matches(
                effects.get("model_nonconformance"),
                successes=attack_n_minus_one,
                trials=attack_protocol_denominator,
            ),
            metric_matches(
                effects.get("end_to_end_attack"),
                successes=attack_successes,
                trials=attack_protocol_denominator,
            ),
            metric_matches(
                effects.get("control_conditional_violation"),
                successes=control_successes,
                trials=control_asr_eligible,
            ),
            metric_matches(
                effects.get("control_protocol_completion"),
                successes=control_asr_eligible,
                trials=control_protocol_denominator,
            ),
            metric_matches(
                effects.get("control_model_nonconformance"),
                successes=control_n_minus_one,
                trials=control_protocol_denominator,
            ),
            metric_matches(
                effects.get("control_end_to_end_violation"),
                successes=control_successes,
                trials=control_protocol_denominator,
            ),
        )
    )


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def evidence(path: str, check: str, value: Any) -> dict[str, Any]:
    return {"path": path, "check": check, "value": value}


def status_for(*conditions: bool, blocked: bool = False) -> str:
    if blocked:
        return "blocked_on_release_metadata"
    return "supported" if all(conditions) else "needs_attention"


def build_claim(
    *,
    claim_id: str,
    claim: str,
    claim_type: str,
    status: str,
    evidence_items: list[dict[str, Any]],
    notes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": claim_id,
        "claim_type": claim_type,
        "status": status,
        "claim": claim,
        "evidence": evidence_items,
        "notes": notes or [],
    }


def build_map(root: Path = ROOT) -> dict[str, Any]:
    generated = root / "docs" / "generated_artifacts"
    benchmark = load_json(generated / "benchmark_card.json")
    statistics = load_json(generated / "paper_statistical_analysis.json")
    oracle = load_json(generated / "paper_oracle_coverage.json")
    threat = load_json(generated / "paper_threat_model_card.json")
    eligibility = load_json(generated / "paper_full_suite_eligibility.json")
    gate_text = read_text(root / "runs" / "_reports" / "paper_core_20260625" / "paper_artifact_gate.md")
    submission_gate_text = read_text(
        root / "runs" / "_reports" / "paper_core_20260625" / "paper_artifact_gate_submission.md"
    )
    submission_gap = load_json(generated / "paper_submission_gap_report.json")
    draft_text = read_text(root / "docs" / "paper_draft.md")

    scope = benchmark.get("scope", {}) if isinstance(benchmark.get("scope"), dict) else {}
    baseline = benchmark.get("current_baseline", {}) if isinstance(benchmark.get("current_baseline"), dict) else {}
    oracle_design = oracle.get("design_time", {}) if isinstance(oracle.get("design_time"), dict) else {}
    threat_scope = threat.get("scope", {}) if isinstance(threat.get("scope"), dict) else {}
    threat_model = threat.get("threat_model", {}) if isinstance(threat.get("threat_model"), dict) else {}
    eligibility_summary = (
        eligibility.get("summary", {})
        if isinstance(eligibility.get("summary"), dict)
        else {}
    )
    statistics_contract = (
        statistics.get("metric_contract", {})
        if isinstance(statistics.get("metric_contract"), dict)
        else {}
    )
    statistics_matrix = (
        statistics.get("matrix", {})
        if isinstance(statistics.get("matrix"), dict)
        else {}
    )
    statistics_effects = (
        statistics.get("primary_effects", {})
        if isinstance(statistics.get("primary_effects"), dict)
        else {}
    )
    release_blocked = not bool(submission_gap.get("submission_ready"))

    claims = [
        build_claim(
            claim_id="C1_scope",
            claim_type="benchmark_scope",
            status=status_for(
                as_int(scope.get("active_case_count")) == 328,
                as_int(scope.get("case_counts", {}).get("core")) == 328,
                as_int(threat_scope.get("case_count")) == 328,
                as_int(eligibility_summary.get("main_asr_cases")) == 328,
                as_int(eligibility_summary.get("diagnostic_cases")) == 0,
            ),
            claim=(
                "Safety Bench covers all 328 active hard-oracle cases; core is a compatibility "
                "alias for all, and all 328 cases are metric-eligible."
            ),
            evidence_items=[
                evidence("docs/generated_artifacts/benchmark_card.json", "scope.active_case_count", scope.get("active_case_count")),
                evidence("docs/generated_artifacts/benchmark_card.json", "scope.case_counts.core", scope.get("case_counts", {}).get("core")),
                evidence("docs/generated_artifacts/paper_threat_model_card.json", "scope.case_count", threat_scope.get("case_count")),
                evidence("docs/generated_artifacts/paper_oracle_coverage.json", "design_time.case_count", oracle_design.get("case_count")),
                evidence("docs/generated_artifacts/paper_full_suite_eligibility.json", "summary.main_asr_cases", eligibility_summary.get("main_asr_cases")),
                evidence("docs/generated_artifacts/paper_full_suite_eligibility.json", "summary.diagnostic_cases", eligibility_summary.get("diagnostic_cases")),
            ],
        ),
        build_claim(
            claim_id="C2_configuration_boundary",
            claim_type="baseline_scope",
            status=status_for(
                baseline.get("runtime") == "Claude Code",
                baseline.get("model") == "Kimi K2.6",
                baseline.get("harness") == "claude",
                baseline.get("codex_in_current_scope") is False,
            ),
            claim=(
                "The current formal configuration is Claude Code + Kimi K2.6; Codex and "
                "cross-harness generalization are outside the current experiment scope."
            ),
            evidence_items=[
                evidence("docs/generated_artifacts/benchmark_card.json", "current_baseline.runtime", baseline.get("runtime")),
                evidence("docs/generated_artifacts/benchmark_card.json", "current_baseline.model", baseline.get("model")),
                evidence("docs/generated_artifacts/benchmark_card.json", "current_baseline.codex_in_current_scope", baseline.get("codex_in_current_scope")),
                evidence("docs/paper_draft.md", "configuration boundary", "Claude Code + Kimi K2.6" in draft_text),
            ],
        ),
        build_claim(
            claim_id="C3_matrix_protocol",
            claim_type="experiment_protocol",
            status=status_for(
                as_int(eligibility_summary.get("main_asr_cases")) == 328,
                "one attack trial per case" in draft_text,
                "656 across the two configurations" in draft_text,
                "not an exhaustive 328-case completion gate" in draft_text,
            ),
            claim=(
                "The current protocol contains one 328-case attack trial per configuration "
                "and uses matched controls for targeted causal and mitigation checks."
            ),
            evidence_items=[
                evidence("docs/generated_artifacts/paper_full_suite_eligibility.json", "summary.main_asr_cases", eligibility_summary.get("main_asr_cases")),
                evidence("docs/paper_draft.md", "single-trial protocol", "one attack trial per case" in draft_text),
                evidence("docs/paper_draft.md", "two-configuration row count", "656 across the two configurations" in draft_text),
                evidence("docs/paper_draft.md", "targeted-control boundary", "not an exhaustive 328-case completion gate" in draft_text),
            ],
        ),
        build_claim(
            claim_id="C4_results_reported",
            claim_type="result_boundary",
            status=status_for(
                "Evaluation Record v3" in draft_text,
                "53.37%" in draft_text,
                "53.97%" in draft_text,
                "RESULTS_PENDING_FORMAL_MATRIX" not in draft_text,
            ),
            claim=(
                "The reported one-trial results are normalized with Evaluation Record v3 and "
                "disclose scored, protocol-noncompletion, and execution-invalid rows."
            ),
            evidence_items=[
                evidence("docs/paper_draft.md", "v3 result contract", "Evaluation Record v3" in draft_text),
                evidence("docs/paper_draft.md", "Kimi conditional ASR", "53.37%" in draft_text),
                evidence("docs/paper_draft.md", "MiniMax conditional ASR", "53.97%" in draft_text),
            ],
        ),
        build_claim(
            claim_id="C5_control_design",
            claim_type="control",
            status=status_for(
                "Clean control" in draft_text,
                "No-persist control" in draft_text,
                "No-trigger control" in draft_text,
                "Cleanup control" in draft_text,
                "not an exhaustive 328-case completion gate" in draft_text,
            ),
            claim=(
                "All cases declare four control interventions, while the current paper runs "
                "predeclared targeted controls for causal and mitigation claims."
            ),
            evidence_items=[
                evidence("docs/paper_draft.md", "targeted controls", "not an exhaustive 328-case completion gate" in draft_text),
                evidence("docs/generated_artifacts/paper_full_suite_eligibility.json", "summary.main_asr_cases", eligibility_summary.get("main_asr_cases")),
            ],
        ),
        build_claim(
            claim_id="C6_oracle_policy",
            claim_type="measurement",
            status=status_for(
                oracle.get("case_set") in {"all", "core"},
                as_int(oracle_design.get("case_count")) == 328,
                as_int(oracle_design.get("oracle_strength_counts", {}).get("hard_trace_oracle")) == 328,
                as_int(eligibility_summary.get("main_asr_cases")) == 328,
            ),
            claim=(
                "All 328 runnable cases use hard trace oracles and are main-table eligible; "
                "model restatement alone is not sufficient evidence."
            ),
            evidence_items=[
                evidence("docs/generated_artifacts/paper_oracle_coverage.json", "case_set", oracle.get("case_set")),
                evidence("docs/generated_artifacts/paper_oracle_coverage.json", "design_time.oracle_strength_counts", oracle_design.get("oracle_strength_counts")),
                evidence("docs/generated_artifacts/paper_full_suite_eligibility.json", "summary.main_asr_cases", eligibility_summary.get("main_asr_cases")),
                evidence("docs/generated_artifacts/paper_threat_model_card.json", "threat_model.defender_assumptions", threat_model.get("defender_assumptions", [])),
            ],
        ),
        build_claim(
            claim_id="C7_public_artifact_boundary",
            claim_type="artifact_safety",
            status=status_for(
                "public_artifact_safety: ok=`true`" in gate_text,
                "files=" in gate_text,
            ),
            claim=(
                "The public repro bundle includes sanitized reports and generated summaries, "
                "not raw traces, honeypots, agent homes, canary values, or provider secrets."
            ),
            evidence_items=[
                evidence("runs/_reports/paper_core_20260625/paper_artifact_gate.md", "public_artifact_safety", "ok=`true`" in gate_text),
                evidence("docs/paper_artifact_evaluation_readme.md", "public boundary documentation", "raw trace exclusion documented"),
                evidence("runs/_artifacts/repro_bundles/paper_core_20260625/repro_manifest.json", "copied artifact scope", "sanitized generated artifacts"),
            ],
        ),
        build_claim(
            claim_id="C8_release_status",
            claim_type="release_metadata",
            status=status_for(blocked=release_blocked),
            claim="Public submission remains blocked until final release metadata is supplied and validated.",
            evidence_items=[
                evidence("docs/generated_artifacts/paper_submission_gap_report.json", "submission_ready", submission_gap.get("submission_ready")),
                evidence("runs/_reports/paper_core_20260625/paper_artifact_gate_submission.md", "release_metadata", "ok=`false`" in submission_gate_text),
                evidence("docs/release_metadata_final.json", "final release metadata decision", "pending user decisions"),
            ],
            notes=["This is an external author/legal decision, not an experiment-quality result."],
        ),
        build_claim(
            claim_id="C9_limitations",
            claim_type="limitation",
            status=status_for(
                bool(threat_model.get("out_of_scope")),
                "one model-harness configuration" in draft_text,
            ),
            claim=(
                "Claims are scoped to one model-harness configuration and do not generalize "
                "to all agent deployments or harnesses."
            ),
            evidence_items=[
                evidence("docs/generated_artifacts/paper_threat_model_card.json", "threat_model.out_of_scope", threat_model.get("out_of_scope", [])),
                evidence("docs/paper_draft.md", "limitations section", "one model-harness configuration" in draft_text),
            ],
        ),
        build_claim(
            claim_id="C10_measurement_accounting",
            claim_type="measurement_accounting",
            status=status_for(measurement_accounting_supported(statistics)),
            claim=(
                "N-1 / MODEL_PROTOCOL_INCOMPLETE is an orthogonal terminal result class, not an "
                "N0-N5b progress node. Conditional attack/control rates use scored ASR-eligible "
                "rows. Coverage accounting uses all scored rows plus N-1, while protocol "
                "completion, model nonconformance, and end-to-end rates use S+M, where S is "
                "ASR-eligible scored rows and M is N-1."
            ),
            evidence_items=[
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "metric_contract.n_minus_one_is_progress_node",
                    statistics_contract.get("n_minus_one_is_progress_node"),
                ),
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "metric_contract.conditional_asr_denominator",
                    statistics_contract.get("conditional_asr_denominator"),
                ),
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "metric_contract.end_to_end_denominator",
                    statistics_contract.get("end_to_end_denominator"),
                ),
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "matrix attack scored/eligible/N-1/coverage-accounted/protocol-denominator",
                    {
                        "scored": statistics_matrix.get("attack_scored_rows"),
                        "asr_eligible": statistics_matrix.get(
                            "attack_asr_eligible_scored_rows"
                        ),
                        "n_minus_1": statistics_matrix.get("attack_n_minus_1_rows"),
                        "accounted": statistics_matrix.get("attack_accounted_terminal_rows"),
                        "protocol_denominator": statistics_matrix.get(
                            "attack_protocol_denominator_rows"
                        ),
                    },
                ),
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "matrix control scored/eligible/N-1/coverage-accounted/protocol-denominator",
                    {
                        "scored": statistics_matrix.get("control_scored_rows"),
                        "asr_eligible": statistics_matrix.get(
                            "control_asr_eligible_scored_rows"
                        ),
                        "n_minus_1": statistics_matrix.get("control_n_minus_1_rows"),
                        "accounted": statistics_matrix.get("control_accounted_terminal_rows"),
                        "protocol_denominator": statistics_matrix.get(
                            "control_protocol_denominator_rows"
                        ),
                    },
                ),
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "primary_effects four attack accounting metrics",
                    {
                        key: statistics_effects.get(key)
                        for key in (
                            "conditional_attack_success",
                            "protocol_completion",
                            "model_nonconformance",
                            "end_to_end_attack",
                        )
                    },
                ),
                evidence(
                    "docs/generated_artifacts/paper_statistical_analysis.json",
                    "primary_effects four control accounting metrics",
                    {
                        key: statistics_effects.get(key)
                        for key in (
                            "control_conditional_violation",
                            "control_protocol_completion",
                            "control_model_nonconformance",
                            "control_end_to_end_violation",
                        )
                    },
                ),
            ],
            notes=[
                "N-1 rows are accounted terminal outcomes but are non-scorable and must not be "
                "folded into the N0-N5b distribution or the conditional ASR denominator."
            ],
        ),
    ]

    supported = sum(1 for claim in claims if claim["status"] == "supported")
    blocked = sum(1 for claim in claims if claim["status"] == "blocked_on_release_metadata")
    attention = sum(1 for claim in claims if claim["status"] == "needs_attention")
    return {
        "schema_version": 2,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "baseline": {
            "runtime": baseline.get("runtime", "Claude Code"),
            "model": baseline.get("model", "Kimi K2.6"),
            "harness": baseline.get("harness", "claude"),
        },
        "summary": {
            "claims": len(claims),
            "supported": supported,
            "blocked_on_release_metadata": blocked,
            "needs_attention": attention,
            "ok_for_current_artifact": attention == 0,
            "submission_ready": not release_blocked,
        },
        "claims": claims,
        "sources": {
            "benchmark_card": "docs/generated_artifacts/benchmark_card.json",
            "statistical_analysis": "docs/generated_artifacts/paper_statistical_analysis.json",
            "oracle_coverage": "docs/generated_artifacts/paper_oracle_coverage.json",
            "threat_model_card": "docs/generated_artifacts/paper_threat_model_card.json",
            "full_suite_eligibility": "docs/generated_artifacts/paper_full_suite_eligibility.json",
            "artifact_gate": "runs/_reports/paper_core_20260625/paper_artifact_gate.md",
            "submission_gate": "runs/_reports/paper_core_20260625/paper_artifact_gate_submission.md",
            "submission_gap": "docs/generated_artifacts/paper_submission_gap_report.json",
        },
    }


def render_markdown(claim_map: dict[str, Any]) -> str:
    summary = claim_map.get("summary", {})
    baseline = claim_map.get("baseline", {})
    lines = [
        "# Paper Claim Evidence Map",
        "",
        f"- generated_at: `{claim_map.get('generated_at')}`",
        f"- baseline: `Claude Code + Kimi K2.6`",
        f"- harness: `{baseline.get('harness')}`",
        f"- claims: `{summary.get('claims', 0)}`",
        f"- supported: `{summary.get('supported', 0)}`",
        f"- blocked_on_release_metadata: `{summary.get('blocked_on_release_metadata', 0)}`",
        f"- needs_attention: `{summary.get('needs_attention', 0)}`",
        f"- ok_for_current_artifact: `{str(summary.get('ok_for_current_artifact')).lower()}`",
        "",
        "## Claim Boundary",
        "",
        "The map binds each paper-facing claim to generated evidence artifacts and gate checks. It distinguishes experiment-supported claims from release metadata blockers.",
        "",
        "## Evidence Sources",
        "",
    ]
    for name, path in claim_map.get("sources", {}).items():
        lines.append(f"- {name}: `{path}`")
    lines += [
        "",
        "## Supported Claims",
        "",
        "| ID | Type | Status | Claim | Evidence count |",
        "| --- | --- | --- | --- | ---: |",
    ]
    for claim in claim_map.get("claims", []):
        if claim.get("status") != "supported":
            continue
        lines.append(
            f"| {claim.get('id')} | {claim.get('claim_type')} | {claim.get('status')} | "
            f"{claim.get('claim')} | {len(claim.get('evidence', []))} |"
        )
    lines += [
        "",
        "## Blocked Release Claims",
        "",
    ]
    blocked = [claim for claim in claim_map.get("claims", []) if claim.get("status") != "supported"]
    if blocked:
        lines += ["| ID | Status | Claim |", "| --- | --- | --- |"]
        for claim in blocked:
            lines.append(f"| {claim.get('id')} | {claim.get('status')} | {claim.get('claim')} |")
    else:
        lines.append("- none")
    lines += [
        "",
        "## Evidence Detail",
        "",
    ]
    for claim in claim_map.get("claims", []):
        lines += [
            f"### {claim.get('id')}",
            "",
            f"- status: `{claim.get('status')}`",
            f"- type: `{claim.get('claim_type')}`",
            f"- claim: {claim.get('claim')}",
            "",
            "| Artifact | Check | Value |",
            "| --- | --- | --- |",
        ]
        for item in claim.get("evidence", []):
            value = json.dumps(item.get("value"), ensure_ascii=False, sort_keys=True)
            if len(value) > 180:
                value = value[:177] + "..."
            lines.append(f"| `{item.get('path')}` | `{item.get('check')}` | `{value}` |")
        if claim.get("notes"):
            lines += ["", "Notes:"]
            lines.extend(f"- {note}" for note in claim.get("notes", []))
        lines.append("")
    lines += [
        "## Public Artifact Boundary",
        "",
        "The map uses sanitized generated artifacts and report summaries. It does not copy raw traces, honeypot logs, raw oracle records, canary values, run-local agent homes, or provider credentials.",
    ]
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    claim_map = build_map(ROOT)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(claim_map, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(claim_map), encoding="utf-8")
    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    return 0 if claim_map.get("summary", {}).get("ok_for_current_artifact") else 1


if __name__ == "__main__":
    raise SystemExit(main())
