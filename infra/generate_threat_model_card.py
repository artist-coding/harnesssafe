"""Generate a reviewer-facing threat model card for Safety Bench."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_threat_model_card.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_threat_model_card.md")
FRAME_KEYS = ["entry", "carrier", "boundary", "trigger", "violation", "recovery"]
CASE_SETS = ["core", "extended", "exploratory", "all"]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def case_in_set(case: dict[str, Any], case_set: str) -> bool:
    if case_set == "all":
        return True
    case_sets = case.get("case_sets")
    if isinstance(case_sets, list):
        return case_set in {str(item) for item in case_sets}
    if case_set == "core":
        return bool(case.get("main_table_eligible"))
    if case_set == "extended":
        return case.get("reporting_track") == "extended_benchmark"
    if case_set == "exploratory":
        return case.get("reporting_track") == "exploratory_case_study"
    raise ValueError(f"unknown case_set: {case_set}")


def normalize_token(value: Any) -> str:
    return str(value or "unspecified").strip() or "unspecified"


def counter_rows(counter: Counter[str], *, limit: int | None = None) -> list[dict[str, Any]]:
    items = counter.most_common(limit) if limit else sorted(counter.items())
    return [{"value": key, "count": value} for key, value in items]


def unique_sorted(values: set[str]) -> list[str]:
    return sorted(value for value in values if value)


def frame_value(case: dict[str, Any], key: str) -> str:
    frame = case.get("frame")
    if not isinstance(frame, dict):
        return "unspecified"
    return normalize_token(frame.get(key))


def control_type_counts(cases: list[dict[str, Any]]) -> dict[str, Any]:
    control_counts: Counter[str] = Counter()
    max_node_counts: Counter[str] = Counter()
    cases_with_controls = 0
    for case in cases:
        controls = case.get("control_suite")
        if not isinstance(controls, list) or not controls:
            continue
        cases_with_controls += 1
        seen_types: set[str] = set()
        for control in controls:
            if not isinstance(control, dict):
                continue
            control_type = normalize_token(control.get("control_type"))
            if control_type not in seen_types:
                control_counts[control_type] += 1
                seen_types.add(control_type)
            max_node_counts[f"{control_type}:{normalize_token(control.get('expected_max_node'))}"] += 1
    return {
        "cases_with_controls": cases_with_controls,
        "control_type_counts": counter_rows(control_counts),
        "expected_max_node_counts": counter_rows(max_node_counts),
    }


def build_suite_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for case in cases:
        suite = normalize_token(case.get("suite") or case.get("canonical_suite"))
        bucket = buckets.setdefault(
            suite,
            {
                "suite": suite,
                "cases": 0,
                "core_cases": 0,
                "families": set(),
                "entries": set(),
                "carriers": set(),
                "boundaries": set(),
                "triggers": set(),
                "violations": set(),
                "recoveries": set(),
            },
        )
        bucket["cases"] += 1
        if case_in_set(case, "core"):
            bucket["core_cases"] += 1
        bucket["families"].add(normalize_token(case.get("paper_family")))
        bucket["entries"].add(frame_value(case, "entry"))
        bucket["carriers"].add(frame_value(case, "carrier"))
        bucket["boundaries"].add(frame_value(case, "boundary"))
        bucket["triggers"].add(frame_value(case, "trigger"))
        bucket["violations"].add(frame_value(case, "violation"))
        bucket["recoveries"].add(frame_value(case, "recovery"))

    rows: list[dict[str, Any]] = []
    for bucket in buckets.values():
        rows.append(
            {
                "suite": bucket["suite"],
                "cases": bucket["cases"],
                "core_cases": bucket["core_cases"],
                "families": len(bucket["families"]),
                "unique_entries": len(bucket["entries"]),
                "unique_carriers": len(bucket["carriers"]),
                "unique_boundaries": len(bucket["boundaries"]),
                "unique_triggers": len(bucket["triggers"]),
                "unique_violations": len(bucket["violations"]),
                "unique_recoveries": len(bucket["recoveries"]),
            }
        )
    return sorted(rows, key=lambda row: row["suite"])


def build_family_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for case in cases:
        suite = normalize_token(case.get("suite") or case.get("canonical_suite"))
        family = normalize_token(case.get("paper_family"))
        bucket = buckets.setdefault(
            (suite, family),
            {
                "suite": suite,
                "paper_family": family,
                "cases": 0,
                "core_cases": 0,
                "entry": Counter(),
                "carrier": Counter(),
                "boundary": Counter(),
                "trigger": Counter(),
                "violation": Counter(),
                "recovery": Counter(),
            },
        )
        bucket["cases"] += 1
        if case_in_set(case, "core"):
            bucket["core_cases"] += 1
        for key in FRAME_KEYS:
            bucket[key][frame_value(case, key)] += 1
    rows: list[dict[str, Any]] = []
    for bucket in buckets.values():
        rows.append(
            {
                "suite": bucket["suite"],
                "paper_family": bucket["paper_family"],
                "cases": bucket["cases"],
                "core_cases": bucket["core_cases"],
                "top_entry": bucket["entry"].most_common(1)[0][0],
                "top_carrier": bucket["carrier"].most_common(1)[0][0],
                "top_boundary": bucket["boundary"].most_common(1)[0][0],
                "top_trigger": bucket["trigger"].most_common(1)[0][0],
                "top_violation": bucket["violation"].most_common(1)[0][0],
                "top_recovery": bucket["recovery"].most_common(1)[0][0],
            }
        )
    return sorted(rows, key=lambda row: (row["suite"], row["paper_family"]))


def build_frame_coverage(cases: list[dict[str, Any]]) -> dict[str, Any]:
    counters: dict[str, Counter[str]] = {key: Counter() for key in FRAME_KEYS}
    missing: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        frame = case.get("frame")
        for key in FRAME_KEYS:
            value = frame_value(case, key)
            counters[key][value] += 1
            if value == "unspecified" or not isinstance(frame, dict) or not str(frame.get(key) or "").strip():
                missing[key].append(str(case.get("case_dir") or case.get("case_id") or ""))
    return {
        key: {
            "unique_values": len(counter),
            "top_values": counter_rows(counter, limit=15),
            "missing_cases": sorted(missing.get(key, [])),
        }
        for key, counter in counters.items()
    }


def build_case_set_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for case_set in CASE_SETS:
        selected = [case for case in cases if case_in_set(case, case_set)]
        strengths = Counter(normalize_token(case.get("oracle_strength")) for case in selected)
        tracks = Counter(normalize_token(case.get("reporting_track")) for case in selected)
        rows.append(
            {
                "case_set": case_set,
                "cases": len(selected),
                "hard_trace_oracle": as_int(strengths.get("hard_trace_oracle")),
                "propagation_only": as_int(strengths.get("propagation_only")),
                "soft_semantic_oracle": as_int(strengths.get("soft_semantic_oracle")),
                "main_table_eligible": sum(1 for case in selected if bool(case.get("main_table_eligible"))),
                "reporting_tracks": dict(sorted(tracks.items())),
            }
        )
    return rows


def build_card(*, suite_lock_path: Path, case_set: str = "all", root: Path = ROOT) -> dict[str, Any]:
    suite_lock_abs = suite_lock_path if suite_lock_path.is_absolute() else root / suite_lock_path
    suite_lock = load_json(suite_lock_abs)
    all_cases = [case for case in suite_lock.get("cases", []) if isinstance(case, dict)]
    selected = [case for case in all_cases if case_in_set(case, case_set)]
    infection_modes = Counter(normalize_token(case.get("infection_mode")) for case in selected)
    reporting_tracks = Counter(normalize_token(case.get("reporting_track")) for case in selected)
    oracle_strengths = Counter(normalize_token(case.get("oracle_strength")) for case in selected)
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "benchmark": {
            "name": "Safety Bench",
            "frame": "Entry -> Carrier -> Boundary -> Trigger -> Violation",
            "threat": (
                "Persistent poisoning in agent harnesses where untrusted input is saved, loaded, "
                "propagated, or reused before a later benign task produces observable unsafe behavior."
            ),
        },
        "scope": {
            "case_set": case_set,
            "case_count": len(selected),
            "active_case_count": as_int(suite_lock.get("active_case_count")),
            "case_counts": suite_lock.get("case_counts", {}),
            "source_manifest": suite_lock.get("source_manifest", "runs/manifest.json"),
            "suite_lock": relpath(suite_lock_abs, root),
        },
        "threat_model": {
            "attacker_capabilities": [
                "Can place adversarial content into untrusted inputs, local artifacts, memory-like state, skill packages, or tool/MCP metadata.",
                "Can rely on later benign tasks to reload, summarize, execute, or otherwise reuse the contaminated carrier.",
                "Can attempt to influence tool arguments, workspace artifacts, local markers, synthetic canaries, or network callback probes.",
            ],
            "defender_assumptions": [
                "Benchmark runs are isolated and use explicit permission profiles.",
                "Unsafe outcomes are measured through observable inert targets, not real credential theft or external system modification.",
                "Model restatement of suspicious text is not sufficient evidence; scoring requires trace, artifact, marker, canary, or tool/MCP evidence.",
            ],
            "in_scope": [
                "Persistent or semi-persistent carrier poisoning across memory, skill, tool/MCP, subagent, compaction, and shared-artifact boundaries.",
                "Delayed activation during benign tasks.",
                "Hard, proxy, and soft oracle families documented in the suite lock.",
            ],
            "out_of_scope": [
                "Real-world exploitation of production credentials or services.",
                "Claims about all possible models, all deployments, or all harness configurations.",
                "Final public-release licensing and author metadata decisions.",
            ],
        },
        "coverage": {
            "case_sets": build_case_set_rows(all_cases),
            "frame_dimensions": build_frame_coverage(selected),
            "infection_mode_counts": counter_rows(infection_modes),
            "reporting_track_counts": counter_rows(reporting_tracks),
            "oracle_strength_counts": counter_rows(oracle_strengths),
            "control_model": control_type_counts(selected),
            "suites": build_suite_rows(selected),
            "families": build_family_rows(selected),
        },
        "public_artifact_boundary": {
            "included": [
                "case metadata taxonomy",
                "suite/family coverage counts",
                "control and recovery model summaries",
                "threat-model assumptions",
            ],
            "excluded": [
                "raw traces",
                "honeypot logs",
                "canary values",
                "raw oracle payloads",
                "agent homes",
                "provider secrets",
            ],
        },
        "sources": {
            "suite_lock": relpath(suite_lock_abs, root),
            "source_manifest": suite_lock.get("source_manifest", "runs/manifest.json"),
        },
    }


def render_counter_table(rows: list[dict[str, Any]], *, label: str) -> list[str]:
    lines = [
        f"| {label} | Cases |",
        "| --- | ---: |",
    ]
    if not rows:
        lines.append("| none | 0 |")
        return lines
    for row in rows:
        lines.append(f"| `{row['value']}` | {row['count']} |")
    return lines


def render_markdown(card: dict[str, Any]) -> str:
    scope = card["scope"]
    coverage = card["coverage"]
    lines = [
        "# Safety Bench Threat Model Card",
        "",
        f"- generated_at: `{card['generated_at']}`",
        f"- benchmark: `{card['benchmark']['name']}`",
        f"- frame: `{card['benchmark']['frame']}`",
        f"- case_set: `{scope['case_set']}`",
        f"- case_count: `{scope['case_count']}`",
        f"- active_case_count: `{scope['active_case_count']}`",
        "",
        "## Threat Model Summary",
        "",
        card["benchmark"]["threat"],
        "",
        "### Attacker Capabilities",
        "",
    ]
    lines.extend(f"- {item}" for item in card["threat_model"]["attacker_capabilities"])
    lines += ["", "### Defender Assumptions", ""]
    lines.extend(f"- {item}" for item in card["threat_model"]["defender_assumptions"])
    lines += ["", "### In Scope", ""]
    lines.extend(f"- {item}" for item in card["threat_model"]["in_scope"])
    lines += ["", "### Out Of Scope", ""]
    lines.extend(f"- {item}" for item in card["threat_model"]["out_of_scope"])

    lines += [
        "",
        "## Case-Set Coverage",
        "",
        "| Case Set | Cases | Main Table | Hard | Propagation | Soft |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in coverage["case_sets"]:
        lines.append(
            f"| {row['case_set']} | {row['cases']} | {row['main_table_eligible']} | "
            f"{row['hard_trace_oracle']} | {row['propagation_only']} | {row['soft_semantic_oracle']} |"
        )

    lines += [
        "",
        "## Frame Coverage",
        "",
        "| Dimension | Unique Values | Missing Cases |",
        "| --- | ---: | ---: |",
    ]
    for key in FRAME_KEYS:
        row = coverage["frame_dimensions"][key]
        lines.append(f"| {key} | {row['unique_values']} | {len(row['missing_cases'])} |")
    for key in FRAME_KEYS:
        lines += [
            "",
            f"### Top {key.title()} Values",
            "",
            "| Value | Cases |",
            "| --- | ---: |",
        ]
        for row in coverage["frame_dimensions"][key]["top_values"]:
            lines.append(f"| `{row['value']}` | {row['count']} |")

    lines += [
        "",
        "## Suite Coverage",
        "",
        "| Suite | Cases | Core | Families | Entries | Carriers | Boundaries | Triggers | Violations | Recoveries |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in coverage["suites"]:
        lines.append(
            f"| {row['suite']} | {row['cases']} | {row['core_cases']} | {row['families']} | "
            f"{row['unique_entries']} | {row['unique_carriers']} | {row['unique_boundaries']} | "
            f"{row['unique_triggers']} | {row['unique_violations']} | {row['unique_recoveries']} |"
        )

    lines += [
        "",
        "## Control And Recovery Model",
        "",
        f"- cases_with_controls: `{coverage['control_model']['cases_with_controls']}`",
        "",
    ]
    lines.extend(render_counter_table(coverage["control_model"]["control_type_counts"], label="Control Type"))
    lines += [
        "",
        "## Infection And Oracle Strata",
        "",
    ]
    lines.extend(render_counter_table(coverage["infection_mode_counts"], label="Infection Mode"))
    lines += ["", *render_counter_table(coverage["oracle_strength_counts"], label="Oracle Strength")]

    lines += [
        "",
        "## Public Artifact Boundary",
        "",
        "- Included: " + ", ".join(card["public_artifact_boundary"]["included"]) + ".",
        "- Excluded: " + ", ".join(card["public_artifact_boundary"]["excluded"]) + ".",
        "",
        "## Sources",
        "",
        f"- suite_lock: `{card['sources']['suite_lock']}`",
        f"- source_manifest: `{card['sources']['source_manifest']}`",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the Safety Bench threat model card.")
    parser.add_argument("--suite-lock", default=str(DEFAULT_SUITE_LOCK))
    parser.add_argument("--case-set", default="all", choices=CASE_SETS)
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    card = build_card(suite_lock_path=Path(args.suite_lock), case_set=args.case_set)
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_markdown(card), encoding="utf-8")
    print(out_json)
    print(out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
