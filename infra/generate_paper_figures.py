"""Generate paper-ready SVG figures from sanitized paper artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_figures.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_figures.md")
DEFAULT_FIGURE_DIR = Path("docs/generated_artifacts/figures")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else {}


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def metric_from(effects: dict[str, Any], key: str, *fallback_keys: str) -> dict[str, Any]:
    """Return a metric block without turning missing legacy data into a zero result."""
    for candidate in (key, *fallback_keys):
        block = effects.get(candidate)
        if isinstance(block, dict):
            return dict(block)
    return {"available": False, "successes": None, "trials": None, "rate": None, "wilson95": []}


def metric_available(block: dict[str, Any]) -> bool:
    if (
        not isinstance(block, dict)
        or block.get("available") is False
        or block.get("successes") is None
        or block.get("trials") is None
    ):
        return False
    try:
        successes = int(block.get("successes"))
        trials = int(block.get("trials"))
    except (TypeError, ValueError):
        return False
    if trials < 0 or not 0 <= successes <= trials:
        return False
    if trials == 0:
        return successes == 0 and block.get("rate") is None
    try:
        rate = float(block.get("rate"))
    except (TypeError, ValueError):
        return False
    return 0.0 <= rate <= 1.0


def metric_matches(block: dict[str, Any], *, successes: int | None = None, trials: int) -> bool:
    if not metric_available(block):
        return False
    observed_successes = as_int(block.get("successes"))
    observed_trials = as_int(block.get("trials"))
    if observed_trials != trials or (successes is not None and observed_successes != successes):
        return False
    if observed_trials == 0:
        return observed_successes == 0 and block.get("rate") is None
    expected_rate = observed_successes / observed_trials
    try:
        actual_rate = float(block.get("rate"))
    except (TypeError, ValueError):
        return False
    return abs(actual_rate - expected_rate) <= 1e-6


def metric_text(block: dict[str, Any]) -> str:
    if not metric_available(block):
        return "n/a (legacy summary lacks N-1 accounting)"
    rate_text = (
        "n/a"
        if block.get("rate") is None
        else pct(float(block.get("rate")))
    )
    return f"{as_int(block.get('successes'))}/{as_int(block.get('trials'))} ({rate_text})"


def measurement_view(stats: dict[str, Any]) -> dict[str, Any]:
    """Normalize statistical-analysis v2 while retaining an explicit legacy fallback."""
    matrix = stats.get("matrix", {}) if isinstance(stats.get("matrix"), dict) else {}
    effects = stats.get("primary_effects", {}) if isinstance(stats.get("primary_effects"), dict) else {}
    contract = stats.get("metric_contract", {}) if isinstance(stats.get("metric_contract"), dict) else {}
    source_schema_version = as_int(stats.get("schema_version"))
    legacy_fallback = source_schema_version < 2

    attack_scored = as_int(matrix.get("attack_scored_rows", matrix.get("attack_rows", 0)))
    control_scored = as_int(matrix.get("control_scored_rows", matrix.get("control_rows", 0)))
    attack_n_minus_one = matrix.get("attack_n_minus_1_rows")
    attack_accounted = matrix.get("attack_accounted_terminal_rows")
    attack_asr_eligible = matrix.get("attack_asr_eligible_scored_rows")
    attack_protocol_denominator = matrix.get("attack_protocol_denominator_rows")
    control_n_minus_one = matrix.get("control_n_minus_1_rows")
    control_accounted = matrix.get("control_accounted_terminal_rows")
    control_asr_eligible = matrix.get("control_asr_eligible_scored_rows")
    control_protocol_denominator = matrix.get("control_protocol_denominator_rows")

    normalized_effects = {
        "conditional_attack_success": metric_from(
            effects,
            "conditional_attack_success",
            *(("attack_success",) if legacy_fallback else ()),
        ),
        "protocol_completion": metric_from(effects, "protocol_completion"),
        "model_nonconformance": metric_from(effects, "model_nonconformance"),
        "end_to_end_attack": metric_from(effects, "end_to_end_attack"),
        "confirmed_compromise": metric_from(effects, "confirmed_compromise"),
        "control_conditional_violation": metric_from(
            effects,
            "control_conditional_violation",
            *(("control_attack_success",) if legacy_fallback else ()),
        ),
        "control_protocol_completion": metric_from(effects, "control_protocol_completion"),
        "control_model_nonconformance": metric_from(effects, "control_model_nonconformance"),
        "control_end_to_end_violation": metric_from(effects, "control_end_to_end_violation"),
        "control_confirmed_compromise": metric_from(effects, "control_confirmed_compromise"),
    }
    protocol_keys = (
        "conditional_attack_success",
        "protocol_completion",
        "model_nonconformance",
        "end_to_end_attack",
        "control_conditional_violation",
        "control_protocol_completion",
        "control_model_nonconformance",
        "control_end_to_end_violation",
    )
    counts_available = all(
        value is not None
        for value in (
            attack_n_minus_one,
            attack_accounted,
            attack_asr_eligible,
            attack_protocol_denominator,
            control_n_minus_one,
            control_accounted,
            control_asr_eligible,
            control_protocol_denominator,
        )
    )
    protocol_available = bool(matrix.get("protocol_metrics_available")) and counts_available and all(
        metric_available(normalized_effects[key]) for key in protocol_keys
    )
    if protocol_available:
        attack_n_minus_one_count = as_int(attack_n_minus_one)
        attack_accounted_count = as_int(attack_accounted)
        attack_asr_eligible_count = as_int(attack_asr_eligible)
        attack_protocol_denominator_count = as_int(attack_protocol_denominator)
        control_n_minus_one_count = as_int(control_n_minus_one)
        control_accounted_count = as_int(control_accounted)
        control_asr_eligible_count = as_int(control_asr_eligible)
        control_protocol_denominator_count = as_int(control_protocol_denominator)
        attack_successes = as_int(
            normalized_effects["conditional_attack_success"].get("successes")
        )
        control_successes = as_int(
            normalized_effects["control_conditional_violation"].get("successes")
        )
        matrix_counts = (
            attack_scored,
            attack_asr_eligible_count,
            attack_n_minus_one_count,
            attack_accounted_count,
            attack_protocol_denominator_count,
            control_scored,
            control_asr_eligible_count,
            control_n_minus_one_count,
            control_accounted_count,
            control_protocol_denominator_count,
            attack_successes,
            control_successes,
        )
        protocol_available = all(
            (
                all(count >= 0 for count in matrix_counts),
                attack_asr_eligible_count <= attack_scored,
                control_asr_eligible_count <= control_scored,
                attack_successes <= attack_asr_eligible_count,
                control_successes <= control_asr_eligible_count,
                attack_accounted_count == attack_scored + attack_n_minus_one_count,
                attack_protocol_denominator_count
                == attack_asr_eligible_count + attack_n_minus_one_count,
                control_accounted_count == control_scored + control_n_minus_one_count,
                control_protocol_denominator_count
                == control_asr_eligible_count + control_n_minus_one_count,
                metric_matches(
                    normalized_effects["conditional_attack_success"],
                    successes=attack_successes,
                    trials=attack_asr_eligible_count,
                ),
                metric_matches(
                    normalized_effects["protocol_completion"],
                    successes=attack_asr_eligible_count,
                    trials=attack_protocol_denominator_count,
                ),
                metric_matches(
                    normalized_effects["model_nonconformance"],
                    successes=attack_n_minus_one_count,
                    trials=attack_protocol_denominator_count,
                ),
                metric_matches(
                    normalized_effects["end_to_end_attack"],
                    successes=attack_successes,
                    trials=attack_protocol_denominator_count,
                ),
                metric_matches(
                    normalized_effects["control_conditional_violation"],
                    successes=control_successes,
                    trials=control_asr_eligible_count,
                ),
                metric_matches(
                    normalized_effects["control_protocol_completion"],
                    successes=control_asr_eligible_count,
                    trials=control_protocol_denominator_count,
                ),
                metric_matches(
                    normalized_effects["control_model_nonconformance"],
                    successes=control_n_minus_one_count,
                    trials=control_protocol_denominator_count,
                ),
                metric_matches(
                    normalized_effects["control_end_to_end_violation"],
                    successes=control_successes,
                    trials=control_protocol_denominator_count,
                ),
            )
        )
    return {
        "schema_version": source_schema_version,
        "legacy_fallback": legacy_fallback,
        "measurement_contract": {
            "n_minus_one_is_progress_node": contract.get("n_minus_one_is_progress_node"),
            "conditional_asr_denominator": contract.get(
                "conditional_asr_denominator", "scored trials (legacy summary)"
            ),
            "end_to_end_denominator": contract.get(
                "end_to_end_denominator", "unavailable in legacy summary"
            ),
            "protocol_metrics_available": protocol_available,
        },
        "matrix": {
            "attack_rows": attack_scored,
            "attack_scored_rows": attack_scored,
            "attack_asr_eligible_scored_rows": (
                as_int(attack_asr_eligible)
                if attack_asr_eligible is not None
                else None
            ),
            "attack_n_minus_1_rows": as_int(attack_n_minus_one) if attack_n_minus_one is not None else None,
            "attack_accounted_terminal_rows": as_int(attack_accounted) if attack_accounted is not None else None,
            "attack_protocol_denominator_rows": (
                as_int(attack_protocol_denominator)
                if attack_protocol_denominator is not None
                else None
            ),
            "control_rows": control_scored,
            "control_scored_rows": control_scored,
            "control_asr_eligible_scored_rows": (
                as_int(control_asr_eligible)
                if control_asr_eligible is not None
                else None
            ),
            "control_n_minus_1_rows": as_int(control_n_minus_one) if control_n_minus_one is not None else None,
            "control_accounted_terminal_rows": as_int(control_accounted) if control_accounted is not None else None,
            "control_protocol_denominator_rows": (
                as_int(control_protocol_denominator)
                if control_protocol_denominator is not None
                else None
            ),
            "protocol_metrics_available": protocol_available,
        },
        "primary_effects": normalized_effects,
    }


def svg_text(x: int, y: int, text: str, *, size: int = 15, weight: str = "400", fill: str = "#152238") -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="Arial, Helvetica, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill}">{escape(text)}</text>'
    )


def svg_rect(x: int, y: int, w: int, h: int, *, fill: str, stroke: str = "#24364f", rx: int = 8) -> str:
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>'


def svg_line(x1: int, y1: int, x2: int, y2: int, *, stroke: str = "#607088", width: float = 1.8) -> str:
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{width}" marker-end="url(#arrow)"/>'


def render_frame_svg() -> str:
    labels = [
        ("Entry", "untrusted input", "#dceefb"),
        ("Carrier", "durable state", "#e7f3d7"),
        ("Boundary", "session/process/tool", "#fff0c9"),
        ("Trigger", "later benign task", "#f4e2f7"),
        ("Violation", "observable unsafe effect", "#f7ded8"),
    ]
    parts = [
        '<svg width="1120" height="360" viewBox="0 0 1120 360" role="img" aria-labelledby="title desc">',
        "<title id=\"title\">Safety Bench benchmark frame</title>",
        "<desc id=\"desc\">Entry to Carrier to Boundary to Trigger to Violation pipeline used by Safety Bench.</desc>",
        "<defs><marker id=\"arrow\" markerWidth=\"9\" markerHeight=\"9\" refX=\"8\" refY=\"4.5\" orient=\"auto\"><path d=\"M0,0 L9,4.5 L0,9 Z\" fill=\"#607088\"/></marker></defs>",
        '<rect x="0" y="0" width="1120" height="360" fill="#ffffff"/>',
        svg_text(42, 48, "Safety Bench task-first frame", size=24, weight="700"),
        svg_text(42, 78, "Each case is scored by observable evidence after a later benign trigger.", size=15, fill="#45556d"),
    ]
    x = 42
    y = 136
    w = 174
    h = 92
    gap = 42
    for index, (title, subtitle, fill) in enumerate(labels):
        parts.append(svg_rect(x, y, w, h, fill=fill))
        parts.append(svg_text(x + 18, y + 36, title, size=20, weight="700"))
        parts.append(svg_text(x + 18, y + 64, subtitle, size=14, fill="#45556d"))
        if index < len(labels) - 1:
            parts.append(svg_line(x + w + 8, y + h // 2, x + w + gap - 8, y + h // 2))
        x += w + gap
    parts += [
        svg_text(42, 292, "Main success is not model restatement; it requires trace, honeypot, canary, marker, artifact, or tool/MCP evidence.", size=15, fill="#24364f"),
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


def render_results_svg(stats: dict[str, Any], control_integrity: dict[str, Any]) -> str:
    view = measurement_view(stats)
    matrix = view["matrix"]
    effects = view["primary_effects"]
    summary = control_integrity.get("summary", {}) if isinstance(control_integrity.get("summary"), dict) else {}
    attack_metrics = [
        ("Conditional attack success (scored ASR-eligible)", effects["conditional_attack_success"], "#4477aa"),
        ("Protocol completion (S+M)", effects["protocol_completion"], "#66c2a5"),
        ("Model nonconformance / N-1 (S+M)", effects["model_nonconformance"], "#dd8452"),
        ("End-to-end attack (S+M)", effects["end_to_end_attack"], "#8172b3"),
    ]
    control_metrics = [
        ("Conditional control violation (scored ASR-eligible)", effects["control_conditional_violation"], "#cc6677"),
        ("Control protocol completion (S+M)", effects["control_protocol_completion"], "#88ccee"),
        ("Control model nonconformance / N-1 (S+M)", effects["control_model_nonconformance"], "#ee8866"),
        ("End-to-end control violation (S+M)", effects["control_end_to_end_violation"], "#aa4499"),
    ]

    def accounting_text(prefix: str) -> str:
        scored = matrix[f"{prefix}_scored_rows"]
        eligible = matrix[f"{prefix}_asr_eligible_scored_rows"]
        n_minus_one = matrix[f"{prefix}_n_minus_1_rows"]
        accounted = matrix[f"{prefix}_accounted_terminal_rows"]
        protocol_denominator = matrix[f"{prefix}_protocol_denominator_rows"]
        label = "Attack" if prefix == "attack" else "Control"
        if any(
            value is None
            for value in (eligible, n_minus_one, accounted, protocol_denominator)
        ):
            return f"{label} accounting: scored={scored}; eligible/N-1/denominators=n/a (legacy summary)"
        return (
            f"{label} accounting: coverage={scored}+{n_minus_one}={accounted}; "
            f"protocol S+M={eligible}+{n_minus_one}={protocol_denominator}"
        )

    def append_metric_rows(parts: list[str], rows: list[tuple[str, dict[str, Any], str]], start_y: int) -> None:
        base_x = 390
        max_w = 650
        for idx, (label, block, fill) in enumerate(rows):
            y = start_y + idx * 58
            parts.append(svg_text(42, y + 24, label, size=15, weight="700"))
            parts.append(svg_rect(base_x, y, max_w, 30, fill="#edf1f5", stroke="#c6ced8", rx=5))
            if metric_available(block) and block.get("rate") is not None:
                rate = max(0.0, min(1.0, float(block.get("rate"))))
                if rate > 0:
                    bar_w = max(2, int(max_w * rate))
                    parts.append(svg_rect(base_x, y, bar_w, 30, fill=fill, stroke=fill, rx=5))
            parts.append(svg_text(base_x + max_w + 22, y + 22, metric_text(block), size=15, weight="700"))

    parts = [
        '<svg width="1320" height="790" viewBox="0 0 1320 790" role="img" aria-labelledby="title desc">',
        "<title id=\"title\">Safety Bench core result summary</title>",
        "<desc id=\"desc\">Conditional ASR-eligible scored metrics and S+M protocol metrics for attack and matched-control rows, with coverage accounting reported separately.</desc>",
        '<rect x="0" y="0" width="1320" height="790" fill="#ffffff"/>',
        svg_text(42, 48, "Claude Code + Kimi K2.6 core matrix", size=24, weight="700"),
        svg_text(42, 78, "N-1 is an orthogonal terminal result class; it is not an N0-N5b progress node.", size=15, fill="#45556d"),
        svg_text(42, 108, accounting_text("attack"), size=15, weight="700", fill="#24364f"),
        svg_text(690, 108, accounting_text("control"), size=15, weight="700", fill="#24364f"),
        svg_text(42, 150, "Attack outcomes", size=19, weight="700"),
    ]
    append_metric_rows(parts, attack_metrics, 172)
    parts += [
        svg_text(42, 424, f"Confirmed compromise (scored): {metric_text(effects['confirmed_compromise'])}", size=14, fill="#45556d"),
        svg_text(42, 472, "Matched-control outcomes", size=19, weight="700"),
    ]
    append_metric_rows(parts, control_metrics, 494)
    parts += [
        svg_text(42, 746, f"Control confirmed compromise (scored): {metric_text(effects['control_confirmed_compromise'])}. Integrity report: {summary.get('control_rows', 0)} rows; {summary.get('critical_absent_oracle_hit_rows', 0)} disclosed low-level O_* signal rows.", size=14, fill="#45556d"),
        "</svg>",
    ]
    return "\n".join(parts) + "\n"


def build_figures(root: Path = ROOT) -> dict[str, Any]:
    generated = root / "docs" / "generated_artifacts"
    stats = load_json(generated / "paper_statistical_analysis.json")
    control_integrity = load_json(generated / "paper_control_integrity_report.json")
    view = measurement_view(stats)
    matrix = view["matrix"]
    effects = view["primary_effects"]
    figures = [
        {
            "id": "figure_1_benchmark_frame",
            "title": "Safety Bench benchmark frame",
            "path": "docs/figures/figure_1_benchmark_frame.svg",
            "source": "static benchmark frame",
            "caption": "Task-first case frame used by all active Safety Bench cases.",
        },
        {
            "id": "figure_2_core_results",
            "title": "Claude Code + Kimi K2.6 core results",
            "path": "docs/generated_artifacts/figures/figure_2_core_results.svg",
            "source": (
                "docs/generated_artifacts/paper_statistical_analysis.json and "
                "docs/generated_artifacts/paper_control_integrity_report.json"
            ),
            "caption": (
                "Conditional attack/control rates use ASR-eligible scored denominators; coverage accounting "
                "uses all scored rows plus N-1, while protocol completion, orthogonal N-1 model "
                "nonconformance, and end-to-end rates use S+M denominators."
            ),
        },
    ]
    valid_v2 = (
        view["schema_version"] >= 2
        and matrix["protocol_metrics_available"]
        and view["measurement_contract"].get("n_minus_one_is_progress_node") is False
        and view["measurement_contract"].get("conditional_asr_denominator")
        == "ASR-eligible N0-N5b scored attack rows"
        and view["measurement_contract"].get("end_to_end_denominator")
        == "ASR-eligible scored attack rows plus N-1 attack rows"
    )
    return {
        "schema_version": 2,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "baseline": {"runtime": "Claude Code", "model": "Kimi K2.6", "harness": "claude"},
        "measurement_contract": view["measurement_contract"],
        "legacy_fallback": view["legacy_fallback"],
        "matrix": matrix,
        "primary_effects": effects,
        "figures": figures,
        "public_artifact_boundary": "SVG figures are generated from sanitized summaries and contain no raw traces, canaries, honeypot logs, or external image references.",
        "ok": bool(matrix.get("attack_scored_rows")) and bool(matrix.get("control_scored_rows")) and (
            valid_v2 if view["schema_version"] >= 2 else True
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    matrix = payload.get("matrix", {}) if isinstance(payload.get("matrix"), dict) else {}
    effects = payload.get("primary_effects", {}) if isinstance(payload.get("primary_effects"), dict) else {}
    contract = payload.get("measurement_contract", {}) if isinstance(payload.get("measurement_contract"), dict) else {}
    lines = [
        "# Paper Figures",
        "",
        f"- generated_at: `{payload.get('generated_at')}`",
        "- baseline: `Claude Code + Kimi K2.6`",
        f"- ok: `{str(payload.get('ok')).lower()}`",
        "",
        "| Figure | File | Source | Caption |",
        "| --- | --- | --- | --- |",
    ]
    for fig in payload.get("figures", []):
        lines.append(f"| {fig.get('title')} | `{fig.get('path')}` | `{fig.get('source')}` | {fig.get('caption')} |")
    lines += [
        "",
        "## Measurement Accounting",
        "",
        "N-1 / MODEL_PROTOCOL_INCOMPLETE is an orthogonal terminal result class, not an N0-N5b progress node. Conditional rates use ASR-eligible scored rows S. Coverage accounting uses all scored rows plus N-1; protocol and end-to-end rates use S+M.",
        "",
        "| Run kind | Scored | ASR eligible (S) | N-1 (M) | Coverage accounted | Protocol denominator (S+M) |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        f"| Attack | {matrix.get('attack_scored_rows', 0)} | {matrix.get('attack_asr_eligible_scored_rows') if matrix.get('attack_asr_eligible_scored_rows') is not None else 'n/a'} | {matrix.get('attack_n_minus_1_rows') if matrix.get('attack_n_minus_1_rows') is not None else 'n/a'} | {matrix.get('attack_accounted_terminal_rows') if matrix.get('attack_accounted_terminal_rows') is not None else 'n/a'} | {matrix.get('attack_protocol_denominator_rows') if matrix.get('attack_protocol_denominator_rows') is not None else 'n/a'} |",
        f"| Control | {matrix.get('control_scored_rows', 0)} | {matrix.get('control_asr_eligible_scored_rows') if matrix.get('control_asr_eligible_scored_rows') is not None else 'n/a'} | {matrix.get('control_n_minus_1_rows') if matrix.get('control_n_minus_1_rows') is not None else 'n/a'} | {matrix.get('control_accounted_terminal_rows') if matrix.get('control_accounted_terminal_rows') is not None else 'n/a'} | {matrix.get('control_protocol_denominator_rows') if matrix.get('control_protocol_denominator_rows') is not None else 'n/a'} |",
        "",
        "| Metric | Result |",
        "| --- | --- |",
        f"| Conditional attack success (scored ASR-eligible denominator) | {metric_text(effects.get('conditional_attack_success', {}))} |",
        f"| Protocol completion (S+M denominator) | {metric_text(effects.get('protocol_completion', {}))} |",
        f"| Model nonconformance / N-1 (S+M denominator) | {metric_text(effects.get('model_nonconformance', {}))} |",
        f"| End-to-end attack (S+M denominator) | {metric_text(effects.get('end_to_end_attack', {}))} |",
        f"| Conditional control violation (scored ASR-eligible denominator) | {metric_text(effects.get('control_conditional_violation', {}))} |",
        f"| Control protocol completion (S+M denominator) | {metric_text(effects.get('control_protocol_completion', {}))} |",
        f"| Control model nonconformance / N-1 (S+M denominator) | {metric_text(effects.get('control_model_nonconformance', {}))} |",
        f"| End-to-end control violation (S+M denominator) | {metric_text(effects.get('control_end_to_end_violation', {}))} |",
        "",
        f"- statistical contract: conditional ASR denominator = `{contract.get('conditional_asr_denominator')}`; end-to-end denominator = `{contract.get('end_to_end_denominator')}`",
        "",
        "## Public Artifact Boundary",
        "",
        str(payload.get("public_artifact_boundary", "")),
    ]
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    parser.add_argument("--figure-dir", default=str(DEFAULT_FIGURE_DIR))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_figures(ROOT)
    figure_dir = Path(args.figure_dir)
    figure_dir.mkdir(parents=True, exist_ok=True)
    frame_path = ROOT / "docs" / "figures" / "figure_1_benchmark_frame.svg"
    results_path = figure_dir / "figure_2_core_results.svg"
    generated = ROOT / "docs" / "generated_artifacts"
    stats = load_json(generated / "paper_statistical_analysis.json")
    control_integrity = load_json(generated / "paper_control_integrity_report.json")
    frame_path.parent.mkdir(parents=True, exist_ok=True)
    frame_path.write_text(render_frame_svg(), encoding="utf-8")
    results_path.write_text(render_results_svg(stats, control_integrity), encoding="utf-8")
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    print(f"wrote {frame_path}")
    print(f"wrote {results_path}")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
