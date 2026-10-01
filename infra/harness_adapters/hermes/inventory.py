from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from .bindings import case_contract_sha256, load_inventory
from .model import BindingDisposition, HermesBinding


READY_CASES = {
    "active/T3/compaction_resume_poisoning/CR.02_resume_context_poisoning/case_006",
    "active/T3/compaction_resume_poisoning/CR.03_compressed_task_note/case_011",
    "active/T3/subagent_poisoning/SA.02_delegated_review_poisoning/case_006",
    "active/T3/subagent_poisoning/SA.03_subagent_tool_choice_poisoning/case_011",
}


def _active_entries(repo_root: Path) -> list[dict[str, object]]:
    manifest = json.loads(
        (repo_root / "runs/manifest.json").read_text(encoding="utf-8-sig")
    )
    return sorted(
        (
            entry
            for suite in manifest["suites"].values()
            if suite.get("status") == "active"
            for entry in suite.get("cases", [])
        ),
        key=lambda entry: str(entry["case_dir"]),
    )


def _has_values(meta: dict[str, object], stages: list[dict[str, object]], key: str) -> bool:
    if meta.get(key):
        return True
    return any(stage.get(key) for stage in stages)


def _binding_for_case(repo_root: Path, case_dir: str) -> HermesBinding:
    case_path = repo_root / "runs" / case_dir
    meta = json.loads((case_path / "case_meta.json").read_text(encoding="utf-8-sig"))
    stages = [stage for stage in meta.get("stages", []) if isinstance(stage, dict)]
    runtime_mode_map = {
        "claude_session_seed": "hermes_session_seed",
        "claude_session_resume": "hermes_session_resume",
        "claude_compaction": "hermes_compaction",
        "claude_subagent_producer": "hermes_subagent_producer",
    }
    runtime_modes = tuple(
        runtime_mode_map.get(
            str(stage.get("runtime_mode") or "fresh"),
            str(stage.get("runtime_mode") or "fresh"),
        )
        for stage in stages
    ) or ("fresh",)

    capabilities = {"instruction"}
    events = {"session.start", "session.complete"}
    if _has_values(meta, stages, "plugin_dirs") or meta.get("plugin_skills"):
        capabilities.add("skill")
        events.add("skill.load")
    if _has_values(meta, stages, "mcp_configs") or meta.get("mcp_servers"):
        capabilities.add("mcp")
        events.update({"mcp.call", "mcp.result"})
    if any(
        action in {"start", "resume"}
        for action in (str(stage.get("session_action", "")) for stage in stages)
    ) or any("session_" in mode for mode in runtime_modes):
        capabilities.add("session_resume")
        events.add("session.resume")
    if any(
        stage.get("session_action") == "compact" for stage in stages
    ) or any("compact" in mode for mode in runtime_modes):
        capabilities.add("compaction")
        events.add("session.compact")
    if any("subagent" in mode for mode in runtime_modes) or any(
        stage.get("claude_agents") for stage in stages
    ):
        capabilities.add("subagent")
        events.update({"subagent.spawn", "subagent.complete"})
    if any(
        meta.get(key)
        for key in (
            "input_memory_snapshot_relpath",
            "output_memory_snapshot_relpath",
            "memory_artifact_relpath",
        )
    ):
        capabilities.add("durable_memory")
        events.add("artifact.write")
    if any(
        stage.get("required_artifacts")
        or stage.get("consume_artifacts")
        or stage.get("carrier_artifact")
        for stage in stages
    ):
        capabilities.add("shared_artifact")
        events.add("artifact.handoff")

    semantic_surface = str(meta.get("surface") or meta.get("task_type") or "instruction")
    disposition = (
        BindingDisposition.READY
        if case_dir in READY_CASES
        else BindingDisposition.NOT_RUN
    )
    reasons = (
        ()
        if disposition is BindingDisposition.READY
        else ("native Hermes runtime evidence has not been captured",)
    )
    return HermesBinding(
        case_dir=case_dir,
        case_meta_sha256=case_contract_sha256(case_path / "case_meta.json"),
        semantic_surface=semantic_surface,
        required_capabilities=tuple(sorted(capabilities)),
        stage_runtime_modes=runtime_modes,
        expected_normalized_events=tuple(sorted(events)),
        disposition=disposition,
        blocking_reasons=reasons,
    )


def build_inventory(repo_root: Path) -> dict[str, object]:
    bindings = [
        _binding_for_case(repo_root, str(entry["case_dir"]))
        for entry in _active_entries(repo_root)
    ]
    return {
        "binding_version": "hermes-binding-v1",
        "harness": "hermes",
        "bindings": [binding.to_dict() for binding in bindings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Hermes case bindings")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary-json", type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    payload = build_inventory(repo_root)
    inventory_path = args.output or repo_root / "infra/harness_bindings/hermes/inventory.json"
    if not args.check:
        if args.output is None:
            raise ValueError("--output is required unless --check is used")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    expected = {record["case_dir"]: record for record in payload["bindings"]}
    actual = load_inventory(inventory_path, repo_root=repo_root)
    stale_hashes = sum(
        actual[path].case_meta_sha256 != str(record["case_meta_sha256"])
        for path, record in expected.items()
        if path in actual
    )
    dispositions = Counter(binding.disposition.value for binding in actual.values())
    summary = {
        "harness": "hermes",
        "binding_version": "hermes-binding-v1",
        "accounted": len(actual),
        "missing": len(set(expected) - set(actual)),
        "extra": len(set(actual) - set(expected)),
        "stale_hashes": stale_hashes,
        "dispositions": dict(sorted(dispositions.items())),
    }
    if args.summary_json:
        args.summary_json.parent.mkdir(parents=True, exist_ok=True)
        args.summary_json.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0 if not any(summary[key] for key in ("missing", "extra", "stale_hashes")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
