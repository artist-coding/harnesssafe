from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from infra.cross_harness.adapter import CapabilityProbe, HarnessAdapter
from infra.cross_harness.contract import (
    CAPABILITY_STATUSES,
    EXECUTION_OUTCOMES,
    PROGRESS_NODES,
    TARGET_HARNESSES,
    ContractValidationError,
    validate_binding_document,
    validate_event_document,
    validate_smoke_inventory,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = REPO_ROOT / "schemas"
SCHEMA_PATHS = (
    SCHEMAS_DIR / "cross_harness_binding_schema_v1.json",
    SCHEMAS_DIR / "cross_harness_event_ir_schema_v1.json",
    SCHEMAS_DIR / "cross_harness_smoke_inventory_schema_v1.json",
)
INVENTORY_PATH = SCHEMAS_DIR / "codex_conformance_smoke_v1.json"
SHA256_ZERO = "0" * 64


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _binding() -> dict:
    support = {
        harness_id: {
            "status": "unsupported",
            "rationale": "No binding is declared in this contract fixture.",
        }
        for harness_id in TARGET_HARNESSES
    }
    support["codex"] = {
        "status": "supported",
        "rationale": "The fixture declares a concrete neutral Codex binding.",
        "conformance_profile": "codex.contract_v1",
    }
    return {
        "schema_name": "safety_bench_cross_harness_binding",
        "schema_version": 1,
        "case_id": "contract-fixture-001",
        "case_meta_sha256": SHA256_ZERO,
        "semantic_surface": "workspace.artifact_read",
        "surface_class": "common",
        "required_capabilities": [
            "headless_execution",
            "structured_trace",
            "workspace_isolation",
        ],
        "supported_harnesses": support,
        "comparison_group": "common_workspace_artifact",
        "binding_version": 1,
        "harness_native_binding": {
            "codex": {
                "adapter": "codex.adapter_v1",
                "variant_kind": "neutral",
                "config": {"instruction_file": "AGENTS.md"},
                "expected_event_types": ["file.read"],
                "artifact_bindings": {"input": "workspace/input.md"},
            }
        },
    }


def _event(event_type: str = "session.compacted") -> dict:
    event = {
        "schema_name": "safety_bench_cross_harness_event",
        "schema_version": 1,
        "event_id": "run-001:stage-1:0003",
        "event_type": event_type,
        "run_id": "run-001",
        "case_id": "contract-fixture-001",
        "harness": {
            "id": "codex",
            "version": "fixture-1.0",
            "feature_flags": {"structured_trace": True},
        },
        "stage": {"name": "attack", "index": 1},
        "sequence": 3,
        "timestamp": "2026-07-20T10:00:00+08:00",
        "source": {
            "trace_path": "raw/codex-events.jsonl",
            "line": 17,
            "raw_event_type": "context_compacted",
        },
        "attributes": {
            "pre_tokens": 12000,
            "post_tokens": 4500,
            "summary_sha256": SHA256_ZERO,
        },
        "session_id": "session-fixture-001",
    }
    return event


def test_json_schemas_are_valid_draft7_and_accept_contract_fixtures() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schemas = [_load_json(path) for path in SCHEMA_PATHS]
    for schema in schemas:
        jsonschema.Draft7Validator.check_schema(schema)

    jsonschema.validate(_binding(), schemas[0])
    jsonschema.validate(
        _event(),
        schemas[1],
        format_checker=jsonschema.FormatChecker(),
    )
    jsonschema.validate(_load_json(INVENTORY_PATH), schemas[2])


def test_binding_validator_accepts_complete_binding() -> None:
    validate_binding_document(_binding())


def test_conditional_or_supported_harness_requires_native_binding() -> None:
    binding = _binding()
    binding["supported_harnesses"]["gemini"] = {
        "status": "conditional",
        "rationale": "Pending a versioned adapter implementation.",
    }

    with pytest.raises(ContractValidationError, match="gemini status requires"):
        validate_binding_document(binding)


def test_unknown_binding_capability_fails_closed() -> None:
    binding = _binding()
    binding["required_capabilities"].append("implicit_magic_memory")

    with pytest.raises(ContractValidationError, match="unknown value"):
        validate_binding_document(binding)


def test_compaction_event_requires_real_reduction_and_summary_hash() -> None:
    validate_event_document(_event())

    invalid = _event()
    invalid["attributes"]["post_tokens"] = invalid["attributes"]["pre_tokens"]
    with pytest.raises(ContractValidationError, match="must reduce token count"):
        validate_event_document(invalid)


def test_mcp_tool_event_requires_call_correlation() -> None:
    event = _event("mcp.tool_requested")
    event.pop("session_id")
    event["attributes"] = {}
    event["tool"] = {"server": "fixture", "name": "read_record"}

    with pytest.raises(ContractValidationError, match="call_id"):
        validate_event_document(event)


def test_smoke_inventory_is_hash_frozen_against_active_cases() -> None:
    inventory = _load_json(INVENTORY_PATH)
    validate_smoke_inventory(inventory, repo_root=REPO_ROOT)

    assert inventory["target_case_count"] == 16
    assert inventory["summary"] == {
        "total": 16,
        "common": 11,
        "native": 5,
        "selected": 8,
        "conditional": 7,
        "blocked_contract": 1,
    }
    assert {case["suite"] for case in inventory["cases"]} == {
        "F1_memory_runtime",
        "F2_skill_runtime",
        "F3_tool_mcp_runtime",
        "T2_memory_to_skill",
        "T3_compaction_resume_poisoning",
        "T3_shared_artifact_supply_chain",
        "T3_subagent_poisoning",
    }


def test_smoke_inventory_rejects_hash_and_summary_drift() -> None:
    inventory = _load_json(INVENTORY_PATH)

    stale_hash = deepcopy(inventory)
    stale_hash["cases"][0]["case_meta_sha256"] = SHA256_ZERO
    with pytest.raises(ContractValidationError, match="stale digest"):
        validate_smoke_inventory(stale_hash, repo_root=REPO_ROOT)

    stale_summary = deepcopy(inventory)
    stale_summary["summary"]["selected"] += 1
    with pytest.raises(ContractValidationError, match="derived summary"):
        validate_smoke_inventory(stale_summary)


def test_status_layers_cannot_collapse_into_safety_or_progress() -> None:
    assert CAPABILITY_STATUSES == {"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"}
    assert EXECUTION_OUTCOMES == {
        "NOT_RUN",
        "SCORED",
        "EXECUTION_INVALID",
        "MODEL_PROTOCOL_INCOMPLETE",
    }
    assert PROGRESS_NODES == {"N0", "N1", "N2", "N3", "N4", "N5a", "N5b"}
    assert CAPABILITY_STATUSES.isdisjoint(EXECUTION_OUTCOMES)
    assert CAPABILITY_STATUSES.isdisjoint(PROGRESS_NODES)
    assert EXECUTION_OUTCOMES.isdisjoint(PROGRESS_NODES)
    assert "SAFE" not in CAPABILITY_STATUSES | EXECUTION_OUTCOMES | PROGRESS_NODES


def test_capability_probe_fails_closed_without_reasons() -> None:
    CapabilityProbe(
        status="SUPPORTED",
        required_capabilities=("headless_execution",),
        evidence=("codex --version",),
    )

    with pytest.raises(ValueError, match="require reasons"):
        CapabilityProbe(
            status="UNVALIDATED",
            required_capabilities=("session_compaction",),
        )


def test_adapter_is_abstract_and_rejects_unknown_harness_ids() -> None:
    with pytest.raises(TypeError):
        HarnessAdapter()

    with pytest.raises(TypeError, match="unknown adapter harness_id"):

        class InvalidHarnessAdapter(HarnessAdapter):
            harness_id = "fixture_harness"

            def detect_identity(self):
                raise NotImplementedError

            def probe_capabilities(self, required_capabilities):
                raise NotImplementedError

            def materialize_binding(self, **kwargs):
                raise NotImplementedError

            def build_launch_spec(self, **kwargs):
                raise NotImplementedError

            def normalize_trace(self, **kwargs):
                raise NotImplementedError

            def cleanup(self, **kwargs):
                raise NotImplementedError
