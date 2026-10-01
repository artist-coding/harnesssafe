import json
from pathlib import Path

from infra import generate_paper_figures


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_generate_paper_figures_builds_sanitized_svg_artifacts(tmp_path: Path):
    stats = {
        "schema_version": 2,
        "metric_contract": {
            "n_minus_one_is_progress_node": False,
            "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
            "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
        },
        "matrix": {
            "attack_rows": 171,
            "attack_scored_rows": 171,
            "attack_asr_eligible_scored_rows": 160,
            "attack_n_minus_1_rows": 3,
            "attack_accounted_terminal_rows": 174,
            "attack_protocol_denominator_rows": 163,
            "control_rows": 228,
            "control_scored_rows": 228,
            "control_asr_eligible_scored_rows": 220,
            "control_n_minus_1_rows": 2,
            "control_accounted_terminal_rows": 230,
            "control_protocol_denominator_rows": 222,
            "protocol_metrics_available": True,
        },
        "primary_effects": {
            "attack_success": {"successes": 23, "trials": 171, "rate": 23 / 171},
            "conditional_attack_success": {"available": True, "successes": 23, "trials": 160, "rate": 23 / 160},
            "protocol_completion": {"available": True, "successes": 160, "trials": 163, "rate": 160 / 163},
            "model_nonconformance": {"available": True, "successes": 3, "trials": 163, "rate": 3 / 163},
            "end_to_end_attack": {"available": True, "successes": 23, "trials": 163, "rate": 23 / 163},
            "confirmed_compromise": {"successes": 7, "trials": 160, "rate": 7 / 160},
            "control_attack_success": {"successes": 0, "trials": 228, "rate": 0.0},
            "control_conditional_violation": {"available": True, "successes": 0, "trials": 220, "rate": 0.0},
            "control_protocol_completion": {"available": True, "successes": 220, "trials": 222, "rate": 220 / 222},
            "control_model_nonconformance": {"available": True, "successes": 2, "trials": 222, "rate": 2 / 222},
            "control_end_to_end_violation": {"available": True, "successes": 0, "trials": 222, "rate": 0.0},
            "control_confirmed_compromise": {"successes": 0, "trials": 220, "rate": 0.0},
        },
    }
    control_integrity = {
        "summary": {
            "control_rows": 228,
            "critical_absent_oracle_hit_rows": 5,
            "attack_success_rows": 0,
            "confirmed_rows": 0,
        }
    }
    _write_json(tmp_path / "docs/generated_artifacts/paper_statistical_analysis.json", stats)
    _write_json(tmp_path / "docs/generated_artifacts/paper_control_integrity_report.json", control_integrity)

    payload = generate_paper_figures.build_figures(tmp_path)
    frame_svg = generate_paper_figures.render_frame_svg()
    results_svg = generate_paper_figures.render_results_svg(stats, control_integrity)
    markdown = generate_paper_figures.render_markdown(payload)

    assert payload["ok"] is True
    assert payload["schema_version"] == 2
    assert payload["legacy_fallback"] is False
    assert payload["baseline"] == {"runtime": "Claude Code", "model": "Kimi K2.6", "harness": "claude"}
    assert payload["measurement_contract"]["n_minus_one_is_progress_node"] is False
    assert payload["matrix"]["attack_scored_rows"] == 171
    assert payload["matrix"]["attack_asr_eligible_scored_rows"] == 160
    assert payload["matrix"]["attack_n_minus_1_rows"] == 3
    assert payload["matrix"]["attack_accounted_terminal_rows"] == 174
    assert payload["matrix"]["attack_protocol_denominator_rows"] == 163
    assert payload["matrix"]["control_scored_rows"] == 228
    assert payload["matrix"]["control_asr_eligible_scored_rows"] == 220
    assert payload["matrix"]["control_n_minus_1_rows"] == 2
    assert payload["matrix"]["control_accounted_terminal_rows"] == 230
    assert payload["matrix"]["control_protocol_denominator_rows"] == 222
    assert payload["primary_effects"]["end_to_end_attack"]["trials"] == 163
    assert payload["primary_effects"]["control_end_to_end_violation"]["trials"] == 222
    assert len(payload["figures"]) == 2
    assert payload["figures"][0]["path"] == "docs/figures/figure_1_benchmark_frame.svg"
    assert payload["figures"][1]["path"] == "docs/generated_artifacts/figures/figure_2_core_results.svg"
    assert "Entry" in frame_svg
    assert "Carrier" in frame_svg
    assert "Conditional attack success (scored ASR-eligible)" in results_svg
    assert "Model nonconformance / N-1 (S+M)" in results_svg
    assert "23/160" in results_svg
    assert "3/163" in results_svg
    assert "220/222" in results_svg
    assert "2/222" in results_svg
    assert "0/222" in results_svg
    assert "figure_2_core_results.svg" in markdown
    assert "## Measurement Accounting" in markdown
    assert "Conditional attack success (scored ASR-eligible denominator)" in markdown
    assert "End-to-end control violation (S+M denominator)" in markdown
    assert "N-1 / MODEL_PROTOCOL_INCOMPLETE is an orthogonal terminal result class" in markdown
    for svg in [frame_svg, results_svg]:
        lower_svg = svg.lower()
        assert "<svg" in lower_svg
        assert "<script" not in lower_svg
        assert "http://" not in lower_svg
        assert "https://" not in lower_svg
        assert "<image" not in lower_svg

    forged = json.loads(json.dumps(stats))
    forged["matrix"]["attack_asr_eligible_scored_rows"] = 172
    forged["matrix"]["attack_protocol_denominator_rows"] = 175
    forged["primary_effects"]["conditional_attack_success"].update(
        {"trials": 172, "rate": 23 / 172}
    )
    forged["primary_effects"]["protocol_completion"].update(
        {"successes": 172, "trials": 175, "rate": 172 / 175}
    )
    forged["primary_effects"]["model_nonconformance"].update(
        {"trials": 175, "rate": 3 / 175}
    )
    forged["primary_effects"]["end_to_end_attack"].update(
        {"trials": 175, "rate": 23 / 175}
    )
    assert not generate_paper_figures.measurement_view(forged)["matrix"][
        "protocol_metrics_available"
    ]


def test_generate_paper_figures_marks_protocol_metrics_unavailable_for_legacy_summary(tmp_path: Path):
    stats = {
        "matrix": {"attack_rows": 10, "control_rows": 20},
        "primary_effects": {
            "attack_success": {"successes": 2, "trials": 10, "rate": 0.2},
            "confirmed_compromise": {"successes": 1, "trials": 10, "rate": 0.1},
            "control_attack_success": {"successes": 0, "trials": 20, "rate": 0.0},
        },
    }
    _write_json(tmp_path / "docs/generated_artifacts/paper_statistical_analysis.json", stats)
    _write_json(tmp_path / "docs/generated_artifacts/paper_control_integrity_report.json", {"summary": {}})

    payload = generate_paper_figures.build_figures(tmp_path)
    results_svg = generate_paper_figures.render_results_svg(stats, {"summary": {}})
    markdown = generate_paper_figures.render_markdown(payload)

    assert payload["ok"] is True
    assert payload["legacy_fallback"] is True
    assert payload["matrix"]["attack_n_minus_1_rows"] is None
    assert payload["matrix"]["attack_accounted_terminal_rows"] is None
    assert payload["measurement_contract"]["protocol_metrics_available"] is False
    assert payload["primary_effects"]["protocol_completion"]["available"] is False
    assert "2/10 (20.0%)" in results_svg
    assert "eligible/N-1/denominators=n/a (legacy summary)" in results_svg
    assert "n/a (legacy summary lacks N-1 accounting)" in results_svg
    assert "| Attack | 10 | n/a | n/a |" in markdown


def test_zero_denominator_metric_is_available_but_has_no_rate():
    block = {
        "available": True,
        "successes": 0,
        "trials": 0,
        "rate": None,
        "wilson95": [],
    }

    assert generate_paper_figures.metric_available(block)
    assert generate_paper_figures.metric_matches(block, successes=0, trials=0)
    assert generate_paper_figures.metric_text(block) == "0/0 (n/a)"

    invalid = {**block, "rate": 0.0}
    assert not generate_paper_figures.metric_available(invalid)
    assert not generate_paper_figures.metric_matches(invalid, successes=0, trials=0)
