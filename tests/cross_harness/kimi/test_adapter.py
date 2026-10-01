from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from infra.cross_harness.adapters.kimi import (
    CapabilityEvidence,
    KimiExecutableNotFound,
    KimiHarnessAdapter,
    KimiMaterializationError,
    KimiPreflightError,
    KimiTraceNormalizationError,
)
from infra.cross_harness.adapter import CapabilityProbe, HarnessIdentity
from infra.cross_harness.adapters.kimi.capabilities import (
    RUNTIME_EVIDENCE_FIXTURE,
    RUNTIME_EVIDENCE_FIXTURE_SHA256,
    aggregate_required_capabilities,
    default_capability_matrix,
    load_runtime_supported_capabilities,
)
from infra.cross_harness.contract import validate_binding_document


def _raw_locator(tmp_path: Path, name: str) -> str:
    path = tmp_path / f"evidence-{name}.json"
    path.write_text(json.dumps({"evidence": name}), encoding="utf-8")
    return str(path)


def _resign_manifest(document: dict) -> None:
    payload = {
        key: value
        for key, value in document.items()
        if key != "manifest_payload_sha256"
    }
    document["manifest_payload_sha256"] = hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def test_kimi_adapter_harness_id_and_missing_executable(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty-path"
    empty_path.mkdir()
    adapter = KimiHarnessAdapter(
        run_id="missing-001",
        state_root=tmp_path,
        search_path=str(empty_path),
        base_environment={"PATH": str(empty_path)},
    )

    assert adapter.harness_id == "kimi"
    with pytest.raises(KimiExecutableNotFound):
        adapter.detect_identity()

    probe = adapter.probe_capabilities(["headless_execution"])
    assert probe.status == "UNVALIDATED"
    assert probe.reasons
    assert all(Path(locator).is_file() for locator in probe.evidence)


def test_version_and_help_probe_capture_raw_evidence(
    tmp_path: Path, fake_kimi: Path
) -> None:
    adapter = KimiHarnessAdapter(
        run_id="identity-001",
        state_root=tmp_path,
        executable=fake_kimi,
    )

    identity = adapter.detect_identity()

    assert identity.harness_id == "kimi"
    assert identity.version == "0.26.0"
    assert identity.executable == str(fake_kimi)
    assert identity.feature_flags["headless_prompt"] is True
    assert identity.feature_flags["stream_json"] is True
    assert identity.feature_flags["skills_dir"] is True
    assert identity.feature_flags["auto_mode"] is True
    assert {"server_help", "server_run_help"} <= set(adapter.identity_evidence)
    for locator in adapter.identity_evidence.values():
        assert Path(locator).is_file()
    version_evidence = json.loads(
        Path(adapter.identity_evidence["version"]).read_text(encoding="utf-8")
    )
    assert version_evidence["command"] == [str(fake_kimi), "--version"]
    assert version_evidence["exit_code"] == 0
    assert version_evidence["stdout"].strip() == "0.26.0"


def test_capability_probe_preserves_all_three_states(
    tmp_path: Path,
) -> None:
    matrix = {
        "headless_execution": CapabilityEvidence(
            capability="headless_execution",
            status="SUPPORTED",
            evidence=(_raw_locator(tmp_path, "headless"),),
            detail="Fixture execution evidence.",
        ),
        "structured_trace": CapabilityEvidence(
            capability="structured_trace",
            status="UNSUPPORTED",
            evidence=(_raw_locator(tmp_path, "trace"),),
            detail="Fixture proves the required event is absent.",
        ),
        "workspace_isolation": CapabilityEvidence(
            capability="workspace_isolation",
            status="UNVALIDATED",
            evidence=(_raw_locator(tmp_path, "isolation"),),
            detail="Fixture deliberately lacks an isolation run.",
        ),
    }
    assert aggregate_required_capabilities(["headless_execution"], matrix)[0] == "SUPPORTED"
    assert aggregate_required_capabilities(["workspace_isolation"], matrix)[0] == "UNVALIDATED"
    assert aggregate_required_capabilities(
        ["headless_execution", "structured_trace", "workspace_isolation"], matrix
    )[0] == "UNSUPPORTED"


def test_default_detected_matrix_is_complete_and_fail_closed(
    tmp_path: Path, fake_kimi: Path
) -> None:
    adapter = KimiHarnessAdapter(
        run_id="matrix-001", state_root=tmp_path, executable=fake_kimi
    )

    probe = adapter.probe_capabilities(["structured_trace"])

    assert probe.status == "UNVALIDATED"
    assert len(adapter.last_capability_matrix) == 17
    assert {
        capability
        for capability, evidence in adapter.last_capability_matrix.items()
        if evidence.status == "SUPPORTED"
    } == {"fresh_process"}
    assert "binary SHA-256 does not match" in (
        adapter.last_capability_matrix["structured_trace"].detail
    )


def test_reviewed_runtime_evidence_is_exact_version_and_binary_scoped() -> None:
    binary_sha256 = (
        "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
    )
    supported, disposition = load_runtime_supported_capabilities(
        detected_version="0.26.0",
        detected_binary_sha256=binary_sha256,
    )

    assert supported == {
        "headless_execution",
        "structured_trace",
        "instruction_loading",
        "skill_discovery",
        "skill_activation_trace",
        "mcp_configuration",
        "mcp_health_trace",
        "mcp_tool_trace",
        "session_resume",
        "session_compaction",
        "subagent_delegation",
        "artifact_hash_provenance",
    }
    assert "exact version and binary" in disposition
    assert "mcp_health_trace" in supported

    for version, digest in (
        ("0.27.0", binary_sha256),
        ("0.26.0", "0" * 64),
    ):
        mismatched, reason = load_runtime_supported_capabilities(
            detected_version=version,
            detected_binary_sha256=digest,
        )
        assert mismatched == frozenset()
        assert "does not match" in reason


def test_exact_runtime_evidence_upgrades_only_reviewed_capabilities() -> None:
    matrix = default_capability_matrix(
        executable_found=True,
        feature_flags={
            "headless_prompt": True,
            "stream_json": True,
            "skills_dir": True,
        },
        path_lookup_evidence=str(RUNTIME_EVIDENCE_FIXTURE),
        help_evidence=str(RUNTIME_EVIDENCE_FIXTURE),
        isolation_evidence=str(RUNTIME_EVIDENCE_FIXTURE),
        detected_version="0.26.0",
        detected_binary_sha256=(
            "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
        ),
    )

    supported = {
        capability for capability, evidence in matrix.items()
        if evidence.status == "SUPPORTED"
    }
    assert supported == {
        "headless_execution",
        "structured_trace",
        "instruction_loading",
        "skill_discovery",
        "skill_activation_trace",
        "mcp_configuration",
        "mcp_health_trace",
        "mcp_tool_trace",
        "fresh_process",
        "session_resume",
        "session_compaction",
        "subagent_delegation",
        "artifact_hash_provenance",
    }
    assert matrix["mcp_health_trace"].status == "SUPPORTED"
    assert "post-run health evidence validation" in (
        matrix["mcp_health_trace"].detail
    )
    assert "mcp.tools_discovered is never sufficient" in (
        matrix["mcp_health_trace"].detail
    )
    assert matrix["workspace_isolation"].status == "UNVALIDATED"
    assert matrix["artifact_hash_provenance"].status == "SUPPORTED"
    assert "adapter hashes file bytes" in (
        matrix["artifact_hash_provenance"].detail
    )


def test_runtime_evidence_fixture_integrity_drift_fails_closed(tmp_path: Path) -> None:
    drifted = tmp_path / "drifted-runtime-evidence.json"
    document = json.loads(RUNTIME_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
    document["capability_claims"]["mcp_health_trace"] = [
        "mcp_configuration_tool_trace"
    ]
    drifted.write_text(json.dumps(document), encoding="utf-8")

    supported, reason = load_runtime_supported_capabilities(
        detected_version="0.26.0",
        detected_binary_sha256=(
            "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
        ),
        fixture_path=drifted,
        expected_fixture_sha256=RUNTIME_EVIDENCE_FIXTURE_SHA256,
    )

    assert supported == frozenset()
    assert "fixture SHA-256 drifted" in reason


@pytest.mark.parametrize(
    ("proof", "pin_group", "component", "error"),
    [
        (
            "native_instruction_loading",
            "adapter_implementation_pins",
            "direct_evidence_observer",
            "instruction adapter implementation pins direct_evidence_observer bytes drifted",
        ),
        (
            "native_instruction_loading",
            "adapter_implementation_pins",
            "provider_request_observer",
            "instruction adapter implementation pins provider_request_observer bytes drifted",
        ),
        (
            "native_instruction_loading",
            "adapter_implementation_pins",
            "event_ir_normalizer",
            "instruction adapter implementation pins event_ir_normalizer bytes drifted",
        ),
        (
            "adapter_artifact_hash_provenance",
            "adapter_implementation_pins",
            "direct_evidence_observer",
            "artifact adapter implementation pins direct_evidence_observer bytes drifted",
        ),
        (
            "adapter_artifact_hash_provenance",
            "adapter_implementation_pins",
            "event_ir_normalizer",
            "artifact adapter implementation pins event_ir_normalizer bytes drifted",
        ),
        (
            "native_instruction_loading",
            "adapter_test_pins",
            "provider_request_observer",
            "instruction adapter test pins provider_request_observer bytes drifted",
        ),
        (
            "adapter_artifact_hash_provenance",
            "adapter_test_pins",
            "event_ir_normalizer",
            "artifact adapter test pins event_ir_normalizer bytes drifted",
        ),
    ],
)
def test_resigned_runtime_fixture_rejects_composite_adapter_byte_drift(
    tmp_path: Path,
    proof: str,
    pin_group: str,
    component: str,
    error: str,
) -> None:
    document = json.loads(RUNTIME_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
    document["proofs"][proof][pin_group][component]["sha256"] = "0" * 64
    drifted = tmp_path / f"runtime-{proof}-{pin_group}-{component}.json"
    drifted.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    supported, reason = load_runtime_supported_capabilities(
        detected_version="0.26.0",
        detected_binary_sha256=(
            "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
        ),
        fixture_path=drifted,
        expected_fixture_sha256=hashlib.sha256(drifted.read_bytes()).hexdigest(),
    )

    assert supported == frozenset()
    assert error in reason


@pytest.mark.parametrize(
    "proof",
    ["native_instruction_loading", "adapter_artifact_hash_provenance"],
)
def test_resigned_runtime_fixture_rejects_missing_implementation_pin(
    tmp_path: Path, proof: str
) -> None:
    document = json.loads(RUNTIME_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
    document["proofs"][proof]["adapter_implementation_pins"].pop(
        "direct_evidence_observer"
    )
    drifted = tmp_path / f"runtime-{proof}-missing-pin.json"
    drifted.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    supported, reason = load_runtime_supported_capabilities(
        detected_version="0.26.0",
        detected_binary_sha256=(
            "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
        ),
        fixture_path=drifted,
        expected_fixture_sha256=hashlib.sha256(drifted.read_bytes()).hexdigest(),
    )

    assert supported == frozenset()
    label = "instruction" if proof == "native_instruction_loading" else "artifact"
    assert f"{label} adapter implementation pins set drifted" in reason


def test_tools_discovered_cannot_be_promoted_to_health_even_if_resigned(
    tmp_path: Path,
) -> None:
    drifted = tmp_path / "resigned-runtime-evidence.json"
    document = json.loads(RUNTIME_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
    document["proofs"]["mcp_configuration_tool_trace"]["tools_discovered"][
        "health_evidence"
    ] = True
    drifted.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    resigned_sha256 = hashlib.sha256(drifted.read_bytes()).hexdigest()

    supported, reason = load_runtime_supported_capabilities(
        detected_version="0.26.0",
        detected_binary_sha256=(
            "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
        ),
        fixture_path=drifted,
        expected_fixture_sha256=resigned_sha256,
    )

    assert supported == frozenset()
    assert "non-health evidence" in reason


def test_runtime_evidence_fixture_is_redacted_and_not_a_scored_result() -> None:
    raw = RUNTIME_EVIDENCE_FIXTURE.read_text(encoding="utf-8")
    document = json.loads(raw)

    assert document["scored_benchmark_run"] is False
    assert document["external_credentials_used"] is False
    assert document["network_scope"] == "loopback_only"
    assert document["redaction"]["model_text_copied"] is False
    assert document["redaction"]["system_prompt_copied"] is False
    assert document["redaction"]["credential_value_copied"] is False
    manual = document["proofs"]["native_compaction"]["manual_acp"]
    assert manual["launch"]["argv"] == ["/usr/local/bin/kimi", "acp"]
    assert manual["launch"]["resume_method"] == "session/resume"
    assert manual["launch"]["command"].startswith("/compact ")
    assert manual["launch"]["request_sequencing"] == (
        "flush_then_wait_for_matching_response_id"
    )
    assert manual["begin"]["source"] == "manual"
    assert manual["apply"]["tokens_before"] > manual["apply"]["tokens_after"]
    assert manual["provider_request_observer"]["credential_kind"] == (
        "run_local_dummy_token"
    )
    assert manual["provider_request_observer"]["credential_value_retained"] is False
    environment_probe = document["negative_evidence"][
        "tool_process_environment_inheritance"
    ]
    assert environment_probe["tool_result"]["result_classification"] == "PRESENT"
    assert environment_probe["external_credential_used"] is False
    assert environment_probe["credential_value_retained"] is False
    artifact_provenance = document["proofs"]["adapter_artifact_hash_provenance"]
    assert artifact_provenance["per_run_observation_required"] is True
    assert artifact_provenance["native_result_payload_used_as_file_hash"] is False
    assert artifact_provenance["write"]["tool_call"]["content_sha256"] == (
        artifact_provenance["write"]["adapter_hash_observation"]["sha256"]
    )
    for forbidden in (
        "fixture-ok",
        "fixture-resumed",
        "fixture-skill-loaded",
        "fixture-compaction-summary",
        "fixture-parent-received-child",
        "MUST_NOT_REACH_CHILD",
        "KIMI_ARTIFACT_WRITE_PROBE_V1",
    ):
        assert forbidden not in raw


@pytest.mark.parametrize(
    ("drift", "error"),
    [
        ("manual_source", "manual native compaction lifecycle"),
        ("manual_stop_reason", "resume/command/prompt correlation"),
        ("environment_result", "environment inheritance call/result correlation"),
        ("artifact_native_payload", "artifact provenance proof kind"),
        ("artifact_write_hash", "Write content does not match"),
    ],
)
def test_resigned_runtime_fixture_cannot_weaken_manual_or_negative_evidence(
    tmp_path: Path, drift: str, error: str
) -> None:
    document = json.loads(RUNTIME_EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
    if drift == "manual_source":
        document["proofs"]["native_compaction"]["manual_acp"]["begin"][
            "source"
        ] = "auto"
    elif drift == "manual_stop_reason":
        document["proofs"]["native_compaction"]["manual_acp"][
            "prompt_response"
        ]["stop_reason"] = "cancelled"
    elif drift == "environment_result":
        document["negative_evidence"]["tool_process_environment_inheritance"][
            "tool_result"
        ]["result_classification"] = "ABSENT"
    elif drift == "artifact_native_payload":
        document["proofs"]["adapter_artifact_hash_provenance"][
            "native_result_payload_used_as_file_hash"
        ] = True
    else:
        document["proofs"]["adapter_artifact_hash_provenance"]["write"][
            "tool_call"
        ]["content_sha256"] = "0" * 64
    drifted = tmp_path / f"runtime-{drift}.json"
    drifted.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")

    supported, reason = load_runtime_supported_capabilities(
        detected_version="0.26.0",
        detected_binary_sha256=(
            "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
        ),
        fixture_path=drifted,
        expected_fixture_sha256=hashlib.sha256(drifted.read_bytes()).hexdigest(),
    )

    assert supported == frozenset()
    assert error in reason


def test_invalid_version_probe_becomes_unvalidated_capability_evidence(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "kimi-invalid-version"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo unknown-version; exit 0; fi\n"
        "echo 'Usage: kimi --prompt --output-format --skills-dir --auto'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    adapter = KimiHarnessAdapter(
        run_id="bad-version-001", state_root=tmp_path / "state", executable=executable
    )

    probe = adapter.probe_capabilities(["headless_execution"])

    assert probe.status == "UNVALIDATED"
    assert adapter.last_capability_matrix["headless_execution"].status == "UNVALIDATED"
    assert all(Path(locator).is_file() for locator in probe.evidence)


def test_unvalidated_preflight_cannot_build_scored_launch(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
) -> None:
    case_dir, binding = reviewed_case_and_binding
    adapter = KimiHarnessAdapter(
        run_id="blocked-001",
        state_root=tmp_path / "state",
        executable=fake_kimi,
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text(encoding="utf-8")

    with pytest.raises(KimiPreflightError, match="UNVALIDATED") as raised:
        adapter.build_launch_spec(
            materialized=materialized,
            prompt=prompt,
            timeout_seconds=30,
        )

    assert raised.value.execution_outcome == "NOT_RUN"
    assert not Path(manifest["stages"][0]["trace_path"]).exists()
    assert not Path(manifest["stages"][0]["event_ir_path"]).exists()
    assert list(Path(manifest["stages"][0]["result_dir"]).iterdir()) == []
    assert not (
        adapter.evidence_dir / "launch-kimi-blocked-001-stage-000.json"
    ).exists()
    assert "SCORED" not in str(raised.value)


def test_launch_spec_is_run_local_and_drops_other_harness_state(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
) -> None:
    case_dir, binding = reviewed_case_and_binding

    class UnitSupportedAdapter(KimiHarnessAdapter):
        def probe_capabilities(self, required_capabilities):
            return CapabilityProbe(
                status="SUPPORTED",
                required_capabilities=tuple(required_capabilities),
                evidence=(_raw_locator(tmp_path, "runtime-trace"),),
                reasons=(),
            )

    adapter = UnitSupportedAdapter(
        run_id="launch-001",
        state_root=tmp_path / "state",
        executable=fake_kimi,
        base_environment={
            "PATH": "/usr/bin:/bin",
            "ANTHROPIC_API_KEY": "must-not-pass",
            "CLAUDE_CONFIG_DIR": "/tmp/claude-state",
            "CODEX_HOME": "/tmp/codex-state",
        },
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text(encoding="utf-8")

    spec = adapter.build_launch_spec(
        materialized=materialized,
        prompt=prompt,
        timeout_seconds=45,
    )

    assert spec.argv[:3] == (str(fake_kimi), "--prompt", prompt)
    assert "--auto" not in spec.argv
    assert spec.argv[-2] == "--skills-dir"
    assert spec.cwd == Path(manifest["materialized"]["workspace_dir"])
    assert spec.trace_path == Path(manifest["stages"][0]["trace_path"])
    assert spec.timeout_seconds == 45
    assert "ANTHROPIC_API_KEY" not in spec.env
    assert "CLAUDE_CONFIG_DIR" not in spec.env
    assert "CODEX_HOME" not in spec.env
    for key in (
        "HOME",
        "KIMI_CODE_HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "TMPDIR",
    ):
        path = Path(spec.env[key]).resolve()
        assert path.is_relative_to(adapter.run_dir.resolve())
        assert "kimi" in path.as_posix().lower()
        assert adapter.run_id in path.as_posix()


def test_launch_rejects_executable_bytes_changed_after_identity_probe(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
) -> None:
    class UnitSupportedAdapter(KimiHarnessAdapter):
        def probe_capabilities(self, required_capabilities):
            return CapabilityProbe(
                status="SUPPORTED",
                required_capabilities=tuple(required_capabilities),
                evidence=(_raw_locator(tmp_path, "binary-drift-preflight"),),
                reasons=(),
            )

    case_dir, binding = reviewed_case_and_binding
    adapter = UnitSupportedAdapter(
        run_id="binary-drift-001",
        state_root=tmp_path / "state",
        executable=fake_kimi,
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text(encoding="utf-8")
    identity = adapter.detect_identity()
    assert identity.feature_flags["binary_sha256"]
    fake_kimi.write_text(
        fake_kimi.read_text(encoding="utf-8") + "\n# bytes changed after probe\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiPreflightError, match="executable|binary|identity") as raised:
        adapter.build_launch_spec(
            materialized=materialized,
            prompt=prompt,
            timeout_seconds=45,
        )

    assert raised.value.execution_outcome == "NOT_RUN"
    assert not (
        adapter.evidence_dir / "launch-kimi-binary-drift-001-stage-000.json"
    ).exists()


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("required_capabilities", ["headless_execution"], "required capabilities"),
        ("expected_event_types", [], "expected events"),
    ],
)
def test_recomputed_manifest_digest_cannot_weaken_trusted_binding(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
    field: str,
    replacement: list[str],
    error: str,
) -> None:
    case_dir, binding = reviewed_case_and_binding
    adapter = KimiHarnessAdapter(
        run_id=f"binding-anchor-{field}",
        state_root=tmp_path / "state",
        executable=fake_kimi,
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    manifest[field] = replacement
    _resign_manifest(manifest)
    materialized.manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )

    with pytest.raises(KimiMaterializationError, match=error):
        adapter.build_launch_spec(
            materialized=materialized,
            prompt="fixture prompt",
            timeout_seconds=30,
        )


def test_formal_adapter_rejects_schema_valid_unreviewed_binding(
    tmp_path: Path,
    fake_kimi: Path,
    case_and_binding_factory,
) -> None:
    case_dir, binding = case_and_binding_factory(case_id="unreviewed-schema-valid")
    validate_binding_document(binding)
    adapter = KimiHarnessAdapter(
        run_id="unreviewed-001",
        state_root=tmp_path / "state",
        executable=fake_kimi,
    )

    with pytest.raises(
        KimiMaterializationError,
        match="exact reviewed common binding",
    ):
        adapter.materialize_binding(
            case_dir=case_dir,
            binding_document=binding,
            run_dir=adapter.run_dir,
        )


@pytest.mark.parametrize(
    ("relative_path", "run_id"),
    [
        ("workspace/main.py", "canonical-copy-workspace"),
        (
            "plugin/skills/inventory-viewer/SKILL.md",
            "canonical-copy-fixture",
        ),
    ],
)
def test_formal_adapter_rejects_tampered_copy_of_reviewed_canonical_case(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
    relative_path: str,
    run_id: str,
) -> None:
    case_dir, binding = reviewed_case_and_binding
    copied_case = tmp_path / f"copied-{run_id}"
    shutil.copytree(case_dir, copied_case)
    assert (copied_case / "case_meta.json").read_bytes() == (
        case_dir / "case_meta.json"
    ).read_bytes()
    target = copied_case / relative_path
    target.write_text(
        target.read_text(encoding="utf-8") + "\nattacker-controlled-copy\n",
        encoding="utf-8",
    )
    adapter = KimiHarnessAdapter(
        run_id=run_id,
        state_root=tmp_path / "state",
        executable=fake_kimi,
    )

    with pytest.raises(KimiMaterializationError, match="reviewed.*case|case_dir"):
        adapter.materialize_binding(
            case_dir=copied_case,
            binding_document=binding,
            run_dir=adapter.run_dir,
        )


def test_adapter_normalize_rejects_forged_version_identity(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
) -> None:
    fake_kimi.write_text(
        fake_kimi.read_text(encoding="utf-8").replace(
            'print("0.26.0")', 'print("0.27.0")'
        ),
        encoding="utf-8",
    )
    case_dir, binding = reviewed_case_and_binding
    adapter = KimiHarnessAdapter(
        run_id="identity-anchor-001",
        state_root=tmp_path / "state",
        executable=fake_kimi,
    )
    detected = adapter.detect_identity()
    assert detected.version == "0.27.0"
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    trace_path = Path(manifest["stages"][0]["trace_path"])
    trace_path.write_text("\n", encoding="utf-8")
    forged = HarnessIdentity(
        harness_id=detected.harness_id,
        version="0.26.0",
        executable=detected.executable,
        feature_flags=dict(detected.feature_flags),
    )

    with pytest.raises(KimiTraceNormalizationError, match="identity.*detected|cached"):
        adapter.normalize_trace(
            identity=forged,
            materialized=materialized,
            raw_trace_path=trace_path,
        )


def test_new_adapter_process_cannot_trust_run_local_manifest_alone(
    tmp_path: Path,
    fake_kimi: Path,
    reviewed_case_and_binding,
) -> None:
    case_dir, binding = reviewed_case_and_binding
    state_root = tmp_path / "state"
    producer = KimiHarnessAdapter(
        run_id="no-tofu-resume",
        state_root=state_root,
        executable=fake_kimi,
    )
    materialized = producer.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=producer.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text(encoding="utf-8")
    fresh_adapter = KimiHarnessAdapter(
        run_id="no-tofu-resume",
        state_root=state_root,
        executable=fake_kimi,
    )

    with pytest.raises(
        KimiMaterializationError, match="trusted materialization snapshot is unavailable"
    ):
        fresh_adapter.build_launch_spec(
            materialized=materialized,
            prompt=prompt,
            timeout_seconds=30,
        )
