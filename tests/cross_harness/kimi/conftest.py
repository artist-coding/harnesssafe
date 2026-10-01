from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from infra.cross_harness.bindings.kimi import load_kimi_common_bindings
from infra.cross_harness.contract import TARGET_HARNESSES


REPO_ROOT = Path(__file__).resolve().parents[3]
REVIEWED_SINGLE_STAGE_CASE_ID = (
    "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
)


@pytest.fixture
def fake_kimi(tmp_path: Path) -> Path:
    executable = tmp_path / "kimi-fixture"
    executable.write_text(
        """#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("0.26.0")
    raise SystemExit(0)
print("Usage: kimi [options] [command]")
print("  -p, --prompt <prompt>  Run one prompt non-interactively")
print("  --output-format <format>  text or stream-json")
print("  --skills-dir <dir>  replace discovered skill directories")
print("  --auto  Start in automatic permission mode")
print("  -S, --session [id]  resume a session")
print("  -c, --continue  continue a session")
print("Commands: export doctor acp server")
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


@pytest.fixture
def reviewed_case_and_binding() -> tuple[Path, dict]:
    inventory = json.loads(
        (REPO_ROOT / "docs" / "codex_conformance_smoke_v1.json").read_text(
            encoding="utf-8"
        )
    )
    case_dir = next(
        REPO_ROOT / record["case_dir"]
        for record in inventory["cases"]
        if record["case_id"] == REVIEWED_SINGLE_STAGE_CASE_ID
    )
    binding = load_kimi_common_bindings(repo_root=REPO_ROOT)[
        REVIEWED_SINGLE_STAGE_CASE_ID
    ]
    return case_dir, binding


@pytest.fixture
def case_and_binding_factory(tmp_path: Path):
    def factory(
        *,
        case_id: str = "kimi_fixture_case",
        expected_event_types: list[str] | None = None,
        required_capabilities: list[str] | None = None,
        variant_kind: str = "neutral",
    ) -> tuple[Path, dict]:
        case_dir = tmp_path / f"canonical-{case_id}"
        workspace = case_dir / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "input.txt").write_text("fixture input\n", encoding="utf-8")
        meta = {
            "case_id": case_id,
            "user_prompt": "Inspect input.txt and report the fixture result.",
        }
        meta_path = case_dir / "case_meta.json"
        meta_path.write_text(json.dumps(meta, sort_keys=True) + "\n", encoding="utf-8")
        supports = {
            harness_id: {
                "status": "unvalidated",
                "rationale": "Unit fixture does not claim runtime support.",
            }
            for harness_id in TARGET_HARNESSES
        }
        supports["kimi"]["conformance_profile"] = "kimi.contract_v1"
        binding = {
            "schema_name": "safety_bench_cross_harness_binding",
            "schema_version": 1,
            "case_id": case_id,
            "case_meta_sha256": hashlib.sha256(meta_path.read_bytes()).hexdigest(),
            "semantic_surface": "workspace.fixture",
            "surface_class": "common",
            "required_capabilities": required_capabilities
            or ["headless_execution", "structured_trace", "workspace_isolation"],
            "supported_harnesses": supports,
            "comparison_group": "common_fixture",
            "binding_version": 1,
            "harness_native_binding": {
                "kimi": {
                    "adapter": "kimi.adapter_v1",
                    "variant_kind": variant_kind,
                    "config": {
                        "binding_class": "D",
                        "stages": [{"index": 0, "name": "attack"}],
                    },
                    "expected_event_types": expected_event_types or ["file.read"],
                    "artifact_bindings": {"input": "input.txt"},
                }
            },
        }
        return case_dir, binding

    return factory
