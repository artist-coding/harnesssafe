from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .bindings import case_contract_sha256, load_inventory
from .model import BindingDisposition, OpenClawBinding


# READY is deliberately case-specific. Each entry below has a provider-backed,
# isolated-home smoke with a valid run contract; adjacent cases remain NOT_RUN.
PROVIDER_SMOKED_READY_CASES = frozenset({
    "active/F1_memory_runtime/F1E.01_customerservice_01_refund_case_overgeneralization/case_001",
    "active/F1_memory_runtime/F1E.02_customerservice_02_complaint_tactic_normalization/case_004",
    "active/F2_skill_runtime/F2.01_perm_claim_spoofing/sk_i_case_101",
    "active/F2_skill_runtime/F2.02_scope_overflow/sk_i_case_201",
    "active/F2_skill_runtime/F2.10_execution_output_ipi/sk_e_case_401",
    "active/F3_tool_mcp_runtime/f301_rii/case_001",
    "active/F3_tool_mcp_runtime/f304_hpae/case_002",
    "active/F3_tool_mcp_runtime/f306_tcs/case_003",
    "active/T2_memory_to_skill/M2S.01_runbook_to_skill_provenance/case_001",
    "active/T2_memory_to_skill/M2S.02_compliance_memory_artifact_leak/case_004",
    "active/T3/subagent_poisoning/SA.01_subagent_output_poisoning/case_001",
    "active/T3/subagent_poisoning/SA.02_delegated_review_poisoning/case_006",
    "active/T3/subagent_poisoning/SA.03_subagent_tool_choice_poisoning/case_011",
    "active/T3/compaction_resume_poisoning/CR.01_session_summary_poisoning/case_001",
    "active/T3/compaction_resume_poisoning/CR.02_resume_context_poisoning/case_006",
    "active/T3/compaction_resume_poisoning/CR.03_compressed_task_note/case_011",
    "active/T3/shared_artifact_supply_chain/SAF.01_shared_decision_artifact/case_001",
    "active/T3/shared_artifact_supply_chain/SAF.01_shared_decision_artifact/case_002",
    "active/T3/shared_artifact_supply_chain/SAF.02_shared_template_artifact/case_004",
})


def _entries(repo_root: Path) -> list[dict[str, object]]:
    manifest = json.loads((repo_root / "runs/manifest.json").read_text(encoding="utf-8-sig"))
    return sorted((entry for suite in manifest["suites"].values() if suite.get("status") == "active" for entry in suite.get("cases", [])), key=lambda item: str(item["case_dir"]))


def _has(meta: dict[str, object], stages: list[dict[str, object]], key: str) -> bool:
    return bool(meta.get(key) or any(stage.get(key) for stage in stages))


def _binding(repo_root: Path, case_dir: str) -> OpenClawBinding:
    root = repo_root / "runs" / case_dir
    meta = json.loads((root / "case_meta.json").read_text(encoding="utf-8-sig"))
    stages = [s for s in meta.get("stages", []) if isinstance(s, dict)]
    mode_map = {
        "claude_session_seed": "openclaw_session_seed",
        "claude_session_resume": "openclaw_session_resume",
        "claude_compaction": "openclaw_compaction",
        "claude_subagent_producer": "openclaw_subagent_producer",
    }
    modes = tuple(mode_map.get(str(s.get("runtime_mode") or "fresh"), str(s.get("runtime_mode") or "fresh")) for s in stages) or ("fresh",)
    caps = {"instruction"}
    events = {"session.start", "session.complete"}
    if _has(meta, stages, "plugin_dirs") or meta.get("plugin_skills"):
        caps.add("skill"); events.add("skill.discovered")
    if _has(meta, stages, "mcp_configs") or meta.get("mcp_servers"):
        caps.add("mcp"); events.update({"mcp.initialize", "tool.request", "tool.result"})
    if any(s.get("session_action") in {"start", "resume"} for s in stages) or any("session_" in m for m in modes):
        caps.add("session_resume"); events.add("session.resume")
    if any(s.get("session_action") == "compact" for s in stages) or any("compact" in m for m in modes):
        caps.add("compaction"); events.add("session.compact")
    if any("subagent" in m for m in modes) or any(s.get("claude_agents") for s in stages):
        caps.add("subagent"); events.update({"subagent.spawn", "subagent.complete"})
    if any(meta.get(k) for k in ("input_memory_snapshot_relpath", "output_memory_snapshot_relpath", "memory_artifact_relpath")):
        caps.add("durable_memory"); events.add("artifact.write")
    if any(s.get("required_artifacts") or s.get("consume_artifacts") or s.get("carrier_artifact") for s in stages):
        caps.add("shared_artifact"); events.add("artifact.handoff")
    provider_smoked = case_dir in PROVIDER_SMOKED_READY_CASES
    return OpenClawBinding(
        case_dir=case_dir,
        case_meta_sha256=case_contract_sha256(root / "case_meta.json"),
        semantic_surface=str(meta.get("surface") or meta.get("task_type") or "instruction"),
        comparison_group="openclaw-native",
        required_capabilities=tuple(sorted(caps)),
        stage_runtime_modes=modes,
        expected_normalized_events=tuple(sorted(events)),
        disposition=(
            BindingDisposition.READY
            if provider_smoked
            else BindingDisposition.NOT_RUN
        ),
        blocking_reasons=(
            ()
            if provider_smoked
            else ("provider-backed OpenClaw runtime evidence has not been captured",)
        ),
    )


def build_inventory(repo_root: Path) -> dict[str, object]:
    bindings = [_binding(repo_root, str(entry["case_dir"])) for entry in _entries(repo_root)]
    return {"binding_version": "openclaw-binding-v1", "harness": "openclaw", "bindings": [b.to_dict() for b in bindings]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--summary-json", type=Path)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    payload = build_inventory(root)
    path = args.output or root / "infra/harness_bindings/openclaw/inventory.json"
    if not args.check:
        if args.output is None:
            raise ValueError("--output is required unless --check is used")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    actual = load_inventory(path, repo_root=root)
    expected = {r["case_dir"]: r for r in payload["bindings"]}
    stale = sum(actual[p].case_meta_sha256 != r["case_meta_sha256"] for p, r in expected.items() if p in actual)
    summary = {"harness": "openclaw", "binding_version": "openclaw-binding-v1", "accounted": len(actual), "missing": len(set(expected) - set(actual)), "extra": len(set(actual) - set(expected)), "stale_hashes": stale, "dispositions": dict(sorted(Counter(b.disposition.value for b in actual.values()).items()))}
    if args.summary_json:
        args.summary_json.parent.mkdir(parents=True, exist_ok=True)
        args.summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if not any(summary[k] for k in ("missing", "extra", "stale_hashes")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
