from __future__ import annotations

import json
from pathlib import Path

from infra.cross_harness.adapters.gemini import GeminiHarnessAdapter
from infra.cross_harness.bindings.gemini import (
    COMMON_BINDING_DIR,
    NATIVE_BINDING_DIR,
)

from .conftest import write_conformance


QUALIFICATION_PLAN = (
    Path(__file__).with_name("fixtures")
    / "gemini_cli_0_51_0_3_5_flash_16_case_qualification_plan.json"
)


def test_smoke_binding_set_is_hash_frozen_complete_and_unvalidated(gemini_bindings) -> None:
    assert len(gemini_bindings) == 16
    assert len(list(COMMON_BINDING_DIR.glob("*.json"))) == 11
    assert len(list(NATIVE_BINDING_DIR.glob("*.json"))) == 5
    assert {doc["surface_class"] for doc in gemini_bindings.values()} == {
        "common",
        "native",
    }
    for document in gemini_bindings.values():
        assert document["supported_harnesses"]["gemini"]["status"] == "unvalidated"
        native = document["harness_native_binding"]["gemini"]
        assert native["adapter"] == "gemini.adapter_v1"
        config = native["config"]
        assert config["expected_normalized_events"] == native["expected_event_types"]
        assert config["disposition"] in {"NOT_RUN", "BLOCKED"}
        assert config["blocking_reasons"]
        assert config["binding_class"] in {"D", "M", "N/A"}
        assert config["binding_kind"] in {"native", "hybrid", "neutral"}


def test_16_case_qualification_plan_is_individual_fail_closed_review(
    gemini_bindings,
) -> None:
    plan = json.loads(QUALIFICATION_PLAN.read_text(encoding="utf-8"))
    assert plan["review_method"]["individual_review_completed"] is True
    assert plan["review_method"]["mechanical_materializability_alone_is_not_sufficient"] is True
    assert len(plan["cases"]) == 16
    assert {item["case_id"] for item in plan["cases"]} == set(gemini_bindings)
    for item in plan["cases"]:
        binding = gemini_bindings[item["case_id"]]
        native = binding["harness_native_binding"]["gemini"]["config"]
        assert item["case_meta_sha256"] == binding["case_meta_sha256"]
        assert item["canonical_stage_order"] == [
            stage.get("canonical_name", stage["name"]) for stage in native["stages"]
        ]
        if item["disposition"] == "READY_FOR_QUALIFICATION":
            assert item["blocking_capabilities"] == []
            assert len(item["qualification_requirements"]) == 4
        else:
            assert item["disposition"] in {"NOT_RUN", "BLOCKED"}
            assert item["blocking_capabilities"]
    assert plan["summary"] == {
        "case_count": 16,
        "ready_for_qualification": 4,
        "not_run": 11,
        "blocked": 1,
        "binding_class": {"D": 7, "M": 9, "N/A": 0},
        "binding_kind": {"native": 8, "hybrid": 4, "neutral": 4},
        "surface_class": {"common": 11, "native": 5},
    }
    assert plan["execution_policy"]["safe_or_n0_from_qualification_prohibited"] is True


def test_missing_executable_is_unvalidated_not_safe(tmp_path: Path) -> None:
    adapter = GeminiHarnessAdapter(
        run_id="missing-cli",
        run_dir=tmp_path / "run",
        executable="definitely-no-gemini-cli",
        base_environment={"PATH": str(tmp_path)},
    )
    probe = adapter.probe_capabilities(
        ["headless_execution", "structured_trace", "workspace_isolation"]
    )
    assert probe.status == "UNVALIDATED"
    assert probe.reasons
    manifest = json.loads(
        (tmp_path / "run" / "evidence" / "capabilities-gemini-missing-cli.json").read_text()
    )
    assert manifest["scoring_prohibited"] is True
    assert "SAFE" not in json.dumps(manifest)


def test_help_output_without_runtime_conformance_remains_unvalidated(
    tmp_path: Path, fake_gemini: Path
) -> None:
    adapter = GeminiHarnessAdapter(
        run_id="identity-only",
        run_dir=tmp_path / "run",
        executable=str(fake_gemini),
        base_environment={"PATH": str(tmp_path)},
    )
    identity = adapter.detect_identity()
    assert identity.version == "0.41.0"
    assert identity.feature_flags["stream_json"] is True
    probe = adapter.probe_capabilities(["headless_execution", "structured_trace"])
    assert probe.status == "UNVALIDATED"


def test_matching_executed_conformance_can_support_only_declared_capabilities(
    tmp_path: Path, fake_gemini: Path
) -> None:
    evidence = write_conformance(
        tmp_path / "conformance.json",
        fake_gemini,
        ["headless_execution", "structured_trace"],
    )
    adapter = GeminiHarnessAdapter(
        run_id="conformant-fixture",
        run_dir=tmp_path / "run",
        executable=str(fake_gemini),
        conformance_evidence_path=evidence,
        base_environment={"PATH": str(tmp_path)},
    )
    supported = adapter.probe_capabilities(["headless_execution", "structured_trace"])
    assert supported.status == "SUPPORTED"
    missing = adapter.probe_capabilities(["workspace_isolation"])
    assert missing.status == "UNVALIDATED"


def test_conformance_is_bound_to_exact_executable_bytes(
    tmp_path: Path, fake_gemini: Path
) -> None:
    evidence = write_conformance(
        tmp_path / "conformance.json", fake_gemini, ["headless_execution"]
    )
    executable_copy = tmp_path / "gemini-copy"
    executable_copy.write_bytes(fake_gemini.read_bytes() + b"\n")
    executable_copy.chmod(fake_gemini.stat().st_mode)
    adapter = GeminiHarnessAdapter(
        run_id="binary-mismatch",
        run_dir=tmp_path / "run",
        executable=str(executable_copy),
        conformance_evidence_path=evidence,
        base_environment={"PATH": str(tmp_path)},
    )
    assert adapter.probe_capabilities(["headless_execution"]).status == "UNVALIDATED"
