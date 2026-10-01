"""Generate Gemini binding overlays for all 328 active cases.

The 16 hand-reviewed Contract smoke bindings remain the vertical-slice source
of truth.  This generator expands the same fail-closed shape over the remaining
312 cases from the hash-frozen Gemini inventory and canonical metadata.  These
expanded bindings are mechanically generated and validated, not claims of
per-case runtime conformance.  The generator never edits ``runs/active`` or
``runs/manifest.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

from .generate import SPECS as SMOKE_SPECS


REPO_ROOT = Path(__file__).resolve().parents[4]
INVENTORY_PATH = Path(__file__).with_name("active_328_v1.json")
OUTPUT_DIR = Path(__file__).with_name("active_328_v1")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _relative_skill_sources(case_dir: Path, plugin_dirs: list[str]) -> list[str]:
    result: list[str] = []
    for raw_root in plugin_dirs:
        # Workspace-generated T2 skills are relocated separately so the
        # materializer can add Gemini-required frontmatter before discovery.
        if raw_root.startswith("workspace/.claude-plugin"):
            continue
        root = case_dir / raw_root
        if not root.is_dir():
            raise ValueError(f"declared plugin directory is missing: {root}")
        for skill_file in sorted(root.glob("skills/*/SKILL.md")):
            result.append(skill_file.parent.relative_to(case_dir).as_posix())
    return list(dict.fromkeys(result))


def _prompt_replacements(prompt: str) -> list[dict[str, str]]:
    replacements: list[tuple[str, str]] = []
    for match in re.finditer(r"/\.claude-plugin:([a-z0-9-]+)", prompt):
        replacements.append(
            (match.group(0), f"Use the {match.group(1)} skill")
        )
    candidates = (
        (
            "runtime project-memory directory shown in this session",
            "workspace file `.gemini/safety-bench-memory/MEMORY.md`",
        ),
        (
            "runtime project-memory directory",
            "workspace file `.gemini/safety-bench-memory/MEMORY.md`",
        ),
        ("local Claude plugin skill", "local Gemini agent skill"),
        ("local Claude plugin", "local Gemini agent-skill"),
        ("Claude Code", "Gemini CLI"),
        ("CLAUDE.md", "GEMINI.md"),
        (".claude-plugin/skills/", ".gemini/skills/"),
        ("/compact ", "/compress "),
    )
    for source, target in candidates:
        if any(source in prior_source for prior_source, _ in replacements):
            continue
        if source in prompt and source not in {item[0] for item in replacements}:
            replacements.append((source, target))
    return [{"source": source, "target": target} for source, target in replacements]


def _stage_session_overrides(
    *, row: Mapping[str, Any], stage_index: int
) -> dict[str, str]:
    if (
        row["suite"] == "T2_memory_to_skill"
        and "/M2S.08_summary_compaction_skill_seed/" in row["case_dir"]
    ):
        lifecycle = ("start", "compact", "resume")
        return {
            "session_action": lifecycle[stage_index],
            "session_key": "m2s_summary_compaction_skill_seed",
        }
    return {}


def _stage_documents(
    *, row: Mapping[str, Any], meta: Mapping[str, Any], case_dir: Path
) -> list[dict[str, Any]]:
    raw_stages = meta.get("stages")
    if isinstance(raw_stages, list):
        canonical = raw_stages
    else:
        canonical = [meta]
    if len(canonical) != len(row["stages"]):
        raise ValueError(f"stage count drift for {row['case_id']}")
    result: list[dict[str, Any]] = []
    for frozen, raw in zip(row["stages"], canonical):
        if not isinstance(raw, Mapping):
            raise ValueError(f"invalid stage in {row['case_id']}")
        prompt = raw.get("user_prompt")
        if not isinstance(prompt, str) or not prompt:
            raise ValueError(f"stage prompt missing in {row['case_id']}")
        plugin_dirs = raw.get("plugin_dirs")
        if plugin_dirs is None:
            plugin_dirs = meta.get("plugin_dirs", [])
        mcp_configs = raw.get("mcp_configs")
        if mcp_configs is None:
            mcp_configs = meta.get("mcp_configs", [])
        if not isinstance(plugin_dirs, list) or any(
            not isinstance(value, str) for value in plugin_dirs
        ):
            raise ValueError(f"invalid plugin_dirs in {row['case_id']}")
        if not isinstance(mcp_configs, list) or any(
            not isinstance(value, str) for value in mcp_configs
        ):
            raise ValueError(f"invalid mcp_configs in {row['case_id']}")
        if len(mcp_configs) > 1:
            raise ValueError(f"multiple stage MCP configs in {row['case_id']}")
        stage: dict[str, Any] = {
            "index": frozen["index"],
            "name": frozen["name"],
            "canonical_name": (
                frozen["name"] if isinstance(raw_stages, list) else "attack"
            ),
        }
        skills = _relative_skill_sources(case_dir, plugin_dirs)
        if skills:
            stage["skills"] = skills
        if mcp_configs:
            stage["mcp_config"] = mcp_configs[0]
        replacements = _prompt_replacements(prompt)
        if replacements:
            stage["prompt_replacements"] = replacements
        for key in ("session_action", "runtime_mode", "session_key"):
            value = raw.get(key)
            if isinstance(value, str) and value:
                stage[key] = value
        stage.update(_stage_session_overrides(row=row, stage_index=frozen["index"]))
        result.append(stage)
    return result


def _workspace_relocations(case_dir: Path) -> list[dict[str, Any]]:
    root = case_dir / "workspace" / ".claude-plugin"
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for source in sorted(path for path in root.rglob("*") if path.is_file()):
        relative = source.relative_to(case_dir / "workspace")
        target = Path(".gemini", *relative.parts[1:])
        record: dict[str, Any] = {
            "source": relative.as_posix(),
            "target": target.as_posix(),
            "remove_source": True,
        }
        if target.name == "SKILL.md" and len(target.parts) >= 4:
            record["ensure_skill_frontmatter"] = {
                "name": target.parent.name,
                "description": (
                    f"Workspace helper skill {target.parent.name} materialized for Gemini CLI."
                ),
            }
        records.append(record)
    return records


def _instructions(case_dir: Path) -> list[dict[str, Any]]:
    source = case_dir / "workspace" / "CLAUDE.md"
    if not source.is_file():
        return []
    return [
        {
            "source": "workspace/CLAUDE.md",
            "target": "GEMINI.md",
            "translation": "gemini_project_instruction_v1",
            "remove_source": True,
        }
    ]


def _generated_instructions(
    *, row: Mapping[str, Any], case_dir: Path
) -> list[dict[str, Any]]:
    if "instruction_loading" not in set(row["required_capabilities"]):
        return []
    if (case_dir / "workspace" / "CLAUDE.md").is_file():
        return []
    for stage in row["stages"]:
        if stage.get("name") == "write_claudemd":
            return [
                {
                    "path": "GEMINI.md",
                    "producer_stage_index": stage["index"],
                }
            ]
    return []


def _generated_instruction_skill_rewrites(
    *, row: Mapping[str, Any], case_dir: Path
) -> list[dict[str, str]]:
    if not _generated_instructions(row=row, case_dir=case_dir):
        return []
    return [
        {"source": "CLAUDE.md", "target": "GEMINI.md"},
        {"source": "Claude Code", "target": "Gemini CLI"},
    ]


def _memory_bindings(row: Mapping[str, Any], meta: Mapping[str, Any]) -> list[dict[str, str]]:
    required = set(row["required_capabilities"])
    if not {"durable_memory_write", "durable_memory_retrieval"} <= required:
        return []
    if row["suite"] == "v2_tool_mcp_runtime":
        return [
            {
                "path": "GEMINI.md",
                "store": "gemini_project_context",
                "scope": "project",
                "entry_id": "project_gemini_md",
            }
        ]
    carrier = meta.get("carrier_contract")
    artifact = carrier.get("transduced_artifact") if isinstance(carrier, Mapping) else None
    return [
        {
            "path": ".gemini/safety-bench-memory/MEMORY.md",
            "store": "gemini_auto_memory_candidate",
            "scope": "project",
            "entry_id": str(artifact or row["case_id"]),
        }
    ]


def _agents(meta: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for stage in meta.get("stages", []):
        if not isinstance(stage, Mapping):
            continue
        raw_agents = stage.get("claude_agents", {})
        if not isinstance(raw_agents, Mapping):
            continue
        for name, raw in raw_agents.items():
            if not isinstance(name, str) or not isinstance(raw, Mapping):
                raise ValueError("invalid canonical subagent declaration")
            result[name] = {
                "name": name,
                "description": str(raw.get("description") or name),
                "prompt": str(raw.get("prompt") or "Complete the delegated task."),
                "target": f".gemini/agents/{name}.md",
            }
    return [result[name] for name in sorted(result)]


def _artifact_bindings(meta: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    direct = (
        ("entry", meta.get("entry_artifact")),
        ("result", meta.get("workspace_artifact")),
        ("source", meta.get("boundary_source_path")),
    )
    for key, value in direct:
        if isinstance(value, str) and value:
            result[key] = value.removeprefix("workspace/")
    carrier = meta.get("carrier_contract")
    if isinstance(carrier, Mapping):
        handoff = carrier.get("transduced_artifact")
        if isinstance(handoff, str) and handoff:
            result["handoff"] = handoff.removeprefix("workspace/")
    return result


def _variant_kind(row: Mapping[str, Any]) -> str:
    return "neutral" if row["binding_kind"] == "neutral" else "native"


def build_documents() -> list[dict[str, Any]]:
    inventory = _read_json(INVENTORY_PATH)
    documents: list[dict[str, Any]] = []
    for row in inventory["cases"]:
        if row["case_id"] in SMOKE_SPECS:
            continue
        case_dir = REPO_ROOT / row["case_dir"]
        meta = _read_json(case_dir / "case_meta.json")
        config: dict[str, Any] = {
            "binding_class": row["binding_class"],
            "binding_kind": row["binding_kind"],
            "source_inventory_profile": "active_328_v1",
            "component_surfaces": {
                "semantic_surface": row["semantic_surface"],
                "suite": row["suite"],
            },
            "stages": _stage_documents(row=row, meta=meta, case_dir=case_dir),
            "expected_normalized_events": row["expected_normalized_events"],
            "disposition": row["disposition"],
            "blocking_reasons": row["blocking_reasons"],
        }
        optional = {
            "instructions": _instructions(case_dir),
            "generated_instructions": _generated_instructions(
                row=row, case_dir=case_dir
            ),
            "skill_path_rewrites": _generated_instruction_skill_rewrites(
                row=row, case_dir=case_dir
            ),
            "workspace_relocations": _workspace_relocations(case_dir),
            "memory_bindings": _memory_bindings(row, meta),
            "agents": _agents(meta),
        }
        config.update({key: value for key, value in optional.items() if value})
        native: dict[str, Any] = {
            "adapter": "gemini.adapter_v1",
            "variant_kind": _variant_kind(row),
            "config": config,
            "expected_event_types": row["expected_normalized_events"],
        }
        artifacts = _artifact_bindings(meta)
        if artifacts:
            native["artifact_bindings"] = artifacts
        documents.append(
            {
                "schema_name": "safety_bench_cross_harness_binding",
                "schema_version": 1,
                "case_id": row["case_id"],
                "case_meta_sha256": row["case_meta_sha256"],
                "semantic_surface": row["semantic_surface"],
                "surface_class": row["surface_class"],
                "required_capabilities": row["required_capabilities"],
                "supported_harnesses": row["supported_harnesses"],
                "comparison_group": row["comparison_group"],
                "binding_version": 1,
                "harness_native_binding": {"gemini": native},
                "notes": (
                    "Generated from the hash-frozen active inventory and canonical metadata; "
                    "runtime eligibility remains capability-evidence bound."
                ),
            }
        )
    if len(documents) != 312:
        raise ValueError(f"expected 312 expanded bindings, found {len(documents)}")
    return documents


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    expected: set[str] = set()
    for document in build_documents():
        filename = document["case_id"] + ".json"
        expected.add(filename)
        (OUTPUT_DIR / filename).write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    stale = sorted(path for path in OUTPUT_DIR.glob("*.json") if path.name not in expected)
    if stale:
        raise RuntimeError(
            "refusing to delete stale generated bindings: "
            + ", ".join(path.name for path in stale)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
