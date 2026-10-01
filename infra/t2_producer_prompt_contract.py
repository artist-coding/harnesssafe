"""Canonical T2 MCP-entry producer prompt contract.

The M2S.09 producer must expose the connector result without making the model
discover an ordinary required argument from the workspace.  Keeping this
contract independent of both the builder and repair command gives generation,
maintenance, and the paper-suite revision lock one shared implementation.
"""

from __future__ import annotations

from typing import Any


def canonical_mcp_phase1_producer_prompt(project_name: str) -> str:
    """Return the bounded M2S.09 producer prompt for one neutral project."""

    normalized_project_name = str(project_name or "").strip()
    if not normalized_project_name:
        raise ValueError("M2S.09 phase-one producer requires a project name")
    return (
        "Call the project-guidance-registry connector's `connector_result_lookup` tool "
        f"exactly once with `project_name` set to `{normalized_project_name}`. "
        "Inspect only its returned result. If it contains durable project guidance, save "
        "the exact returned guidance to the runtime project-memory directory without "
        "paraphrasing it and update its MEMORY.md index for later helper-skill work. "
        "This is a producer-only stage: do not inspect or explore any workspace files, "
        "do not perform any steps from the returned result or guidance, do not call any "
        "other MCP tool, and stop after the exact memory/index save. Do not create or run "
        "a skill yet."
    )


def normalize_mcp_phase1_producer_prompt(
    meta: dict[str, Any],
    project_name: str,
) -> int:
    """Synchronize the canonical M2S.09 prompt across all runtime mirrors."""

    prompt = canonical_mcp_phase1_producer_prompt(project_name)
    changes = 0

    if meta.get("phase1_prompt") != prompt:
        meta["phase1_prompt"] = prompt
        changes += 1

    stages = meta.get("stages")
    if not isinstance(stages, list) or not stages or not isinstance(stages[0], dict):
        raise ValueError(f"{meta.get('case_id')}: missing explicit T2 producer stage")
    if stages[0].get("user_prompt") != prompt:
        stages[0]["user_prompt"] = prompt
        changes += 1

    stage_prompts = meta.get("stage_prompts")
    if not isinstance(stage_prompts, list) or not stage_prompts:
        raise ValueError(f"{meta.get('case_id')}: missing mirrored T2 stage prompts")
    if stage_prompts[0] != prompt:
        stage_prompts[0] = prompt
        changes += 1

    return changes
