from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from infra.cross_harness.adapter import HarnessIdentity
from infra.cross_harness.adapters.opencode import OpenCodeHarnessAdapter
from infra.cross_harness.adapters.opencode.capabilities import capability_matrix
from infra.cross_harness.adapters.opencode.launcher import (
    build_opencode_bwrap_command,
    build_opencode_launch_spec,
)
from infra.cross_harness.adapters.opencode.materializer import (
    OpenCodeMaterializationError,
    load_materialization_manifest,
    materialize_opencode_binding,
    translate_runtime_project_instruction,
)
from infra.cross_harness.adapters.opencode.provider import (
    OpenCodeProviderError,
    load_provider_profile,
    preflight_provider,
)
from infra.cross_harness.adapters.opencode.trace import normalize_opencode_trace
from infra.cross_harness.bindings.opencode import load_opencode_smoke_bindings
from infra.cross_harness.contract import TARGET_HARNESSES

from .fixtures.openai_fixture_server import OpenAIFixtureServer


REPO_ROOT = Path(__file__).resolve().parents[3]
CASE_DIR = (
    REPO_ROOT
    / "runs/active/F2_skill_runtime/F2.01_perm_claim_spoofing/sk_i_case_101"
)


def _binding(
    case_dir: Path = CASE_DIR,
    *,
    expected_events: list[str] | None = None,
    config: dict | None = None,
) -> dict:
    support = {
        harness: {
            "status": "unsupported",
            "rationale": "Test fixture declares no binding for this harness.",
        }
        for harness in TARGET_HARNESSES
    }
    support["opencode"] = {
        "status": "conditional",
        "rationale": "Version-pinned runtime evidence is required.",
        "conformance_profile": "opencode.contract_v1",
    }
    return {
        "schema_name": "safety_bench_cross_harness_binding",
        "schema_version": 1,
        "case_id": json.loads(
            (case_dir / "case_meta.json").read_text(encoding="utf-8-sig")
        )["case_id"],
        "case_meta_sha256": hashlib.sha256(
            (case_dir / "case_meta.json").read_bytes()
        ).hexdigest(),
        "semantic_surface": "skill.direct_discovery_activation",
        "surface_class": "native",
        "required_capabilities": [
            "headless_execution",
            "structured_trace",
            "workspace_isolation",
            "skill_discovery",
            "skill_activation_trace",
        ],
        "supported_harnesses": support,
        "comparison_group": "native_skill_activation",
        "binding_version": 1,
        "harness_native_binding": {
            "opencode": {
                "adapter": "opencode.adapter_v1",
                "variant_kind": "native",
                "config": config
                or {
                    "stages": [
                        {
                            "index": 0,
                            "name": "attack",
                            "skills": ["plugin/skills/inventory-viewer"],
                        }
                    ]
                },
                "expected_event_types": expected_events
                or ["session.started", "skill.discovered", "skill.activated"],
                "artifact_bindings": {
                    "skill": "plugin/skills/inventory-viewer/SKILL.md"
                },
            }
        },
    }


def _provider(base_url: str = "http://127.0.0.1:1/v1") -> dict:
    return {
        "bench-fixture": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Safety Bench Fixture",
            "options": {"baseURL": base_url, "apiKey": "fixture-key"},
            "models": {"fixture-model": {"name": "Fixture Model"}},
        }
    }


def test_real_executable_identity_probe_is_read_only(tmp_path: Path) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    adapter = OpenCodeHarnessAdapter(
        run_id="opencode-identity-test",
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        executable=executable,
        base_environment={"PATH": os.environ.get("PATH", "")},
    )
    identity = adapter.detect_identity()
    assert identity.harness_id == "opencode"
    assert identity.feature_flags["headless_run"] is True
    assert identity.feature_flags["json_trace"] is True
    assert identity.feature_flags["session_resume"] is True
    assert Path(identity.executable).is_file()


def test_missing_conformance_evidence_fails_closed() -> None:
    identity = HarnessIdentity(
        harness_id="opencode",
        version="1.18.4",
        executable="/fixture/opencode",
        feature_flags={
            "binary_sha256": "a" * 64,
            "headless_run": True,
            "json_trace": True,
            "session_resume": True,
        },
    )
    matrix = capability_matrix(identity=identity, conformance_path=None)
    assert {entry.status for entry in matrix.values()} == {"UNVALIDATED"}


def test_provider_profile_uses_environment_placeholder(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provider.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_opencode_provider_profile",
                "schema_version": 1,
                "profile_id": "test-provider",
                "provider_id": "test-provider",
                "provider_name": "Test Provider",
                "model_id": "test-model",
                "model_name": "Test Model",
                "protocol": "chat_completions",
                "base_url": "https://api.example.invalid/v1",
                "credential_env": "OPENCODE_TEST_API_KEY",
            }
        ),
        encoding="utf-8",
    )
    profile = load_provider_profile(path)
    assert profile.model == "test-provider/test-model"
    assert profile.provider_config()["test-provider"]["options"]["apiKey"] == (
        "{env:OPENCODE_TEST_API_KEY}"
    )
    missing = preflight_provider(profile, environ={}, profile_path=path)
    assert missing.ready is False
    assert missing.reasons == (
        "required credential environment variable is missing: "
        "OPENCODE_TEST_API_KEY",
    )
    ready = preflight_provider(
        profile,
        environ={"OPENCODE_TEST_API_KEY": "not-recorded"},
        profile_path=path,
    )
    assert ready.ready is True
    assert all("not-recorded" not in value for value in ready.evidence)


def test_provider_profile_rejects_insecure_remote_url(
    tmp_path: Path,
) -> None:
    path = tmp_path / "provider.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_opencode_provider_profile",
                "schema_version": 1,
                "profile_id": "test-provider",
                "provider_id": "test-provider",
                "provider_name": "Test Provider",
                "model_id": "test-model",
                "model_name": "Test Model",
                "protocol": "responses",
                "base_url": "http://api.example.invalid/v1",
                "credential_env": "OPENCODE_TEST_API_KEY",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(OpenCodeProviderError, match="must use HTTPS"):
        load_provider_profile(path)


def test_materializer_rejects_literal_provider_secret(
    tmp_path: Path,
) -> None:
    provider = _provider("https://api.example.invalid/v1")
    provider["bench-fixture"]["options"]["apiKey"] = "real-secret"
    with pytest.raises(OpenCodeMaterializationError, match="literal credentials"):
        materialize_opencode_binding(
            run_id="opencode-secret-rejection-test",
            case_dir=CASE_DIR,
            binding_document=_binding(),
            run_dir=tmp_path / "run",
            model="bench-fixture/fixture-model",
            provider_config=provider,
        )


def test_smoke_bindings_freeze_candidates_and_unsupported_surfaces() -> None:
    bindings = load_opencode_smoke_bindings(repo_root=REPO_ROOT)
    candidates = [
        document
        for document in bindings.values()
        if "opencode" in document["harness_native_binding"]
    ]
    unsupported = [
        document
        for document in bindings.values()
        if document["supported_harnesses"]["opencode"]["status"]
        == "unsupported"
    ]
    assert len(bindings) == 16
    assert len(candidates) == 11
    assert len(unsupported) == 5
    assert all(
        document["harness_native_binding"]["opencode"]["config"]["disposition"]
        == "NOT_RUN"
        for document in candidates
    )
    assert all(not document["harness_native_binding"] for document in unsupported)


def test_materializer_translates_skills_and_isolates_config(
    tmp_path: Path,
) -> None:
    materialized = materialize_opencode_binding(
        run_id="opencode-materialize-test",
        case_dir=CASE_DIR,
        binding_document=_binding(),
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)
    workspace = Path(manifest["workspace_dir"])
    skill = workspace / ".opencode/skills/inventory-viewer/SKILL.md"
    assert skill.is_file()
    assert skill.read_text(encoding="utf-8").startswith("---\n")
    assert not (workspace / ".opencode/plugins").exists()
    config = json.loads(
        Path(manifest["stages"][0]["config_path"]).read_text(encoding="utf-8")
    )
    assert config["model"] == "bench-fixture/fixture-model"
    assert config["permission"]["external_directory"] == "deny"
    assert config["provider"]["bench-fixture"]["options"]["apiKey"] == "fixture-key"
    assert not (CASE_DIR / "workspace/.opencode").exists()


def test_materializer_relocates_opencode_skill_metadata(
    tmp_path: Path,
) -> None:
    bindings = load_opencode_smoke_bindings(repo_root=REPO_ROOT)
    case_id = "SK_I_sk_i_case_402_metadata_tampering_v2_hash_forgery_persist"
    row = next(
        value
        for value in json.loads(
            (REPO_ROOT / "docs/codex_conformance_smoke_v1.json").read_text()
        )["cases"]
        if value["case_id"] == case_id
    )
    materialized = materialize_opencode_binding(
        run_id="opencode-relocation-test",
        case_dir=REPO_ROOT / row["case_dir"],
        binding_document=bindings[case_id],
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)
    workspace = Path(manifest["workspace_dir"])
    target = (
        workspace
        / ".opencode/skills/api-client/dependency_lock.json"
    )
    assert target.is_file()
    assert not (
        workspace
        / ".claude-plugin/skills/api-client/dependency_lock.json"
    ).exists()
    assert manifest["workspace_relocations"][0]["target"] == (
        ".opencode/skills/api-client/dependency_lock.json"
    )


@pytest.mark.parametrize(
    ("case_dir", "expected_skills"),
    [
        (
            REPO_ROOT
            / "runs/active/F2_skill_runtime/F2.02_scope_overflow/sk_i_case_203",
            {"test-runner", "env-check"},
        ),
        (
            REPO_ROOT
            / "runs/active/F2_skill_runtime/F2.13_local_memory_state_attack/sk_e_case_705",
            {"config-hydrator", "data-processor"},
        ),
    ],
)
def test_materializer_supports_multi_plugin_skill_topology(
    tmp_path: Path,
    case_dir: Path,
    expected_skills: set[str],
) -> None:
    materialized = materialize_opencode_binding(
        run_id="opencode-multi-plugin-test",
        case_dir=case_dir,
        binding_document=_binding(
            case_dir,
            config={
                "stages": [
                    {
                        "index": 0,
                        "name": "attack",
                    }
                ]
            },
        ),
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)

    assert set(manifest["skills"]) == expected_skills
    assert all(
        (
            Path(manifest["workspace_dir"])
            / ".opencode"
            / "skills"
            / name
            / "SKILL.md"
        ).is_file()
        for name in expected_skills
    )


def test_runtime_instruction_translation_preserves_source(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "CLAUDE.md"
    source.write_text(
        "Run this at the start of every Claude Code session.\n",
        encoding="utf-8",
    )

    result = translate_runtime_project_instruction(workspace)

    assert result is not None
    assert source.is_file()
    assert (workspace / "AGENTS.md").read_text(encoding="utf-8") == (
        "Run this at the start of every OpenCode session.\n"
    )
    assert result["source"] == "CLAUDE.md"
    assert result["target"] == "AGENTS.md"


def test_launcher_uses_run_local_state_and_json_trace(tmp_path: Path) -> None:
    materialized = materialize_opencode_binding(
        run_id="opencode-launch-test",
        case_dir=CASE_DIR,
        binding_document=_binding(),
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text(
        encoding="utf-8"
    )
    spec = build_opencode_launch_spec(
        materialized=materialized,
        executable="/fixture/opencode",
        prompt=prompt,
        timeout_seconds=30,
        stage_index=0,
        session_id=None,
        base_environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    assert spec.argv[:4] == (
        "/fixture/opencode",
        "run",
        "--format",
        "json",
    )
    assert "--session" not in spec.argv
    assert spec.env["OPENCODE_DISABLE_CLAUDE_CODE"] == "1"
    assert spec.env["OPENCODE_CONFIG_DIR"].endswith(".opencode")
    assert spec.env["TAR_OPTIONS"] == "--no-same-owner"
    assert Path(spec.env["HOME"]).is_relative_to(tmp_path)
    assert spec.trace_path.name == "stage-00-opencode.jsonl"


def test_bwrap_command_exposes_only_runtime_and_run_tree(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "opencode"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    run_dir = tmp_path / "run"
    materialized = materialize_opencode_binding(
        run_id="opencode-bwrap-test",
        case_dir=CASE_DIR,
        binding_document=_binding(),
        run_dir=run_dir,
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text()
    spec = build_opencode_launch_spec(
        materialized=materialized,
        executable=str(executable),
        prompt=prompt,
        timeout_seconds=30,
        stage_index=0,
        session_id=None,
        base_environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    command = build_opencode_bwrap_command(
        launch_spec=spec,
        run_dir=run_dir,
        executable=executable,
    )
    assert "--unshare-user" in command
    assert "--clearenv" in command
    assert str(run_dir.resolve()) in command
    assert command[-1] == prompt
    separator = command.index("--")
    assert command[separator + 1] == "/opt/safety-bench/opencode"
    assert spec.argv[0] not in command[separator + 1 :]
    path_index = next(
        index
        for index, value in enumerate(command)
        if value == "--setenv" and command[index + 1] == "PATH"
    )
    sandbox_path = command[path_index + 2].split(":")
    host_rg = shutil.which("rg", path=os.environ.get("PATH", ""))
    if host_rg is not None:
        rg_parent = Path(host_rg).resolve().parent
        if rg_parent.is_relative_to(Path("/usr")):
            assert str(rg_parent) in sandbox_path


def test_bwrap_command_keeps_credentials_out_of_process_arguments(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "opencode"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    run_dir = tmp_path / "run"
    materialized = materialize_opencode_binding(
        run_id="opencode-bwrap-secret-test",
        case_dir=CASE_DIR,
        binding_document=_binding(),
        run_dir=run_dir,
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)
    prompt = Path(manifest["stages"][0]["prompt_path"]).read_text()
    secret_value = "fixture-secret-should-not-appear-in-argv"
    spec = build_opencode_launch_spec(
        materialized=materialized,
        executable=str(executable),
        prompt=prompt,
        timeout_seconds=30,
        stage_index=0,
        session_id=None,
        base_environment={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "OPENCODE_BENCH_API_KEY": secret_value,
        },
        credential_environment_names=("OPENCODE_BENCH_API_KEY",),
    )
    command = build_opencode_bwrap_command(
        launch_spec=spec,
        run_dir=run_dir,
        executable=executable,
    )
    assert secret_value not in command
    assert not any(
        value == "--setenv" and command[index + 1] == "OPENCODE_BENCH_API_KEY"
        for index, value in enumerate(command[:-2])
    )
    separator = command.index("--")
    assert command[separator + 1] == "/bin/sh"
    assert command[separator + 4] == "opencode-secret-loader"
    secret_loader = Path(command[separator + 5])
    assert secret_loader.is_relative_to(run_dir.resolve())
    assert secret_loader.is_file()
    assert secret_value in secret_loader.read_text(encoding="utf-8")


def test_trace_normalizer_maps_native_skill_tool(tmp_path: Path) -> None:
    materialized = materialize_opencode_binding(
        run_id="opencode-trace-test",
        case_dir=CASE_DIR,
        binding_document=_binding(),
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    raw_trace = tmp_path / "run/raw/stage-00-opencode.jsonl"
    raw_trace.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "type": "step_start",
            "timestamp": 1784880000000,
            "sessionID": "ses_fixture",
            "part": {
                "type": "step-start",
                "sessionID": "ses_fixture",
                "id": "part_start",
            },
        },
        {
            "type": "tool_use",
            "timestamp": 1784880001000,
            "sessionID": "ses_fixture",
            "part": {
                "type": "tool",
                "sessionID": "ses_fixture",
                "id": "part_skill",
                "callID": "call_skill",
                "tool": "skill",
                "state": {
                    "status": "completed",
                    "input": {"name": "inventory-viewer"},
                    "output": "loaded",
                },
            },
        },
    ]
    raw_trace.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    identity = HarnessIdentity(
        harness_id="opencode",
        version="1.18.4",
        executable="/fixture/opencode",
        feature_flags={"structured_trace": True},
    )
    events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=raw_trace,
            stage_index=0,
            run_id="opencode-trace-test",
        )
    )
    assert [event["event_type"] for event in events] == [
        "session.started",
        "skill.discovered",
        "skill.activated",
    ]
    assert events[-1]["attributes"]["skill_name"] == "inventory-viewer"


def test_trace_normalizer_keeps_recoverable_tool_errors_as_raw_evidence(
    tmp_path: Path,
) -> None:
    materialized = materialize_opencode_binding(
        run_id="opencode-trace-tool-error-test",
        case_dir=CASE_DIR,
        binding_document=_binding(),
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    raw_trace = tmp_path / "run/raw/stage-00-opencode.jsonl"
    raw_trace.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "type": "step_start",
            "timestamp": 1784880000000,
            "sessionID": "ses_fixture",
            "part": {"type": "step-start", "sessionID": "ses_fixture"},
        },
        {
            "type": "tool_use",
            "timestamp": 1784880001000,
            "sessionID": "ses_fixture",
            "part": {
                "type": "tool",
                "tool": "read",
                "state": {
                    "status": "error",
                    "input": {"filePath": "missing.md"},
                    "error": "File not found: missing.md",
                },
            },
        },
        {
            "type": "step_finish",
            "timestamp": 1784880002000,
            "sessionID": "ses_fixture",
            "part": {"type": "step-finish", "reason": "stop"},
        },
    ]
    raw_trace.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    identity = HarnessIdentity(
        harness_id="opencode",
        version="1.18.4",
        executable="/fixture/opencode",
        feature_flags={"structured_trace": True},
    )

    events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=raw_trace,
            stage_index=0,
            run_id="opencode-trace-tool-error-test",
        )
    )

    assert [event["event_type"] for event in events] == ["session.started"]


def test_trace_normalizer_attests_nested_handoff_artifact_diff(
    tmp_path: Path,
) -> None:
    binding = _binding(
        config={
            "stages": [{"index": 0, "name": "attack"}],
            "handoff_paths": ["handoff/produced_context.md"],
        }
    )
    binding["harness_native_binding"]["opencode"]["artifact_bindings"] = {
        "handoff": "handoff/produced_context.md"
    }
    materialized = materialize_opencode_binding(
        run_id="opencode-trace-handoff-test",
        case_dir=CASE_DIR,
        binding_document=binding,
        run_dir=tmp_path / "run",
        model="bench-fixture/fixture-model",
        provider_config=_provider(),
    )
    manifest = load_materialization_manifest(materialized)
    handoff = (
        Path(manifest["workspace_dir"]) / "handoff/produced_context.md"
    )
    handoff.parent.mkdir(parents=True)
    handoff.write_text("subagent output\n", encoding="utf-8")
    raw_trace = tmp_path / "run/raw/stage-00-opencode.jsonl"
    raw_trace.parent.mkdir(parents=True, exist_ok=True)
    raw_trace.write_text(
        json.dumps(
            {
                "type": "step_start",
                "timestamp": 1784880000000,
                "sessionID": "ses_fixture",
                "part": {"type": "step-start", "sessionID": "ses_fixture"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    identity = HarnessIdentity(
        harness_id="opencode",
        version="1.18.4",
        executable="/fixture/opencode",
        feature_flags={"structured_trace": True},
    )

    events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=raw_trace,
            stage_index=0,
            run_id="opencode-trace-handoff-test",
            artifact_snapshot_before={"handoff/produced_context.md": None},
        )
    )

    assert [event["event_type"] for event in events] == [
        "session.started",
        "file.write",
        "artifact.handoff",
    ]
    assert events[-1]["attributes"]["evidence"] == (
        "post_stage_artifact_diff"
    )


def test_real_opencode_json_stream_with_local_fixture(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("fixture\n", encoding="utf-8")
    config_dir = workspace / ".opencode"
    config_dir.mkdir()
    config_path = tmp_path / "opencode.json"
    state = tmp_path / "state"
    with OpenAIFixtureServer(request_log=tmp_path / "requests.jsonl") as server:
        config_path.write_text(
            json.dumps(
                {
                    "$schema": "https://opencode.ai/config.json",
                    "model": "bench-fixture/fixture-model",
                    "provider": _provider(server.base_url),
                    "permission": {
                        "read": "allow",
                        "question": "deny",
                        "external_directory": "deny",
                    },
                }
            ),
            encoding="utf-8",
        )
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(state / "home"),
            "XDG_CONFIG_HOME": str(state / "config"),
            "XDG_DATA_HOME": str(state / "data"),
            "XDG_CACHE_HOME": str(state / "cache"),
            "OPENCODE_CONFIG": str(config_path),
            "OPENCODE_CONFIG_DIR": str(config_dir),
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
            "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "CI": "1",
            "NO_COLOR": "1",
        }
        for path in (
            state / "home",
            state / "config",
            state / "data",
            state / "cache",
        ):
            path.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [
                executable,
                "run",
                "--format",
                "json",
                "--model",
                "bench-fixture/fixture-model",
                "--dir",
                str(workspace),
                "[fixture:read README.md]",
            ],
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
            env=environment,
        )
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines() if line]
    tools = [row for row in rows if row.get("type") == "tool_use"]
    assert tools
    assert tools[0]["part"]["tool"] == "read"
    assert tools[0]["part"]["state"]["status"] == "completed"
    assert any(row.get("type") == "text" for row in rows)
    assert len(server.requests) >= 2


def test_real_opencode_materialized_skill(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    run_dir = tmp_path / "run"
    with OpenAIFixtureServer(request_log=tmp_path / "requests.jsonl") as server:
        materialized = materialize_opencode_binding(
            run_id="opencode-real-skill-test",
            case_dir=CASE_DIR,
            binding_document=_binding(),
            run_dir=run_dir,
            model="bench-fixture/fixture-model",
            provider_config=_provider(server.base_url),
            permissions={"skill": "allow"},
        )
        spec = build_opencode_launch_spec(
            materialized=materialized,
            executable=executable,
            prompt="[fixture:skill inventory-viewer]",
            timeout_seconds=45,
            stage_index=0,
            session_id=None,
            base_environment={"PATH": os.environ.get("PATH", "")},
        )
        result = subprocess.run(
            spec.argv,
            cwd=spec.cwd,
            env=spec.env,
            text=True,
            capture_output=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    spec.trace_path.parent.mkdir(parents=True, exist_ok=True)
    spec.trace_path.write_text(result.stdout, encoding="utf-8")
    manifest = load_materialization_manifest(materialized)
    identity = HarnessIdentity(
        harness_id="opencode",
        version=subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip(),
        executable=executable,
        feature_flags={"structured_trace": True},
    )
    events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=spec.trace_path,
            stage_index=0,
            run_id="opencode-real-skill-test",
        )
    )
    event_types = [event["event_type"] for event in events]
    assert "skill.discovered" in event_types
    assert "skill.activated" in event_types


def test_real_opencode_runs_inside_bubblewrap(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    run_dir = tmp_path / "run"
    with OpenAIFixtureServer(request_log=tmp_path / "requests.jsonl") as server:
        materialized = materialize_opencode_binding(
            run_id="opencode-real-bwrap-test",
            case_dir=CASE_DIR,
            binding_document=_binding(),
            run_dir=run_dir,
            model="bench-fixture/fixture-model",
            provider_config=_provider(server.base_url),
            permissions={"read": "allow"},
        )
        spec = build_opencode_launch_spec(
            materialized=materialized,
            executable=executable,
            prompt="[fixture:read README.md]",
            timeout_seconds=45,
            stage_index=0,
            session_id=None,
            base_environment={"PATH": os.environ.get("PATH", "")},
        )
        command = build_opencode_bwrap_command(
            launch_spec=spec,
            run_dir=run_dir,
            executable=Path(executable),
        )
        result = subprocess.run(
            command,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line)
        for line in result.stdout.splitlines()
        if line
    ]
    assert any(
        row.get("type") == "tool_use"
        and row["part"]["tool"] == "read"
        and row["part"]["state"]["status"] == "completed"
        for row in rows
    )


def test_real_opencode_allows_bwrap_run_local_external_fixture(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    run_dir = tmp_path / "run"
    fixture_path = (
        run_dir.resolve()
        / "materialized_case"
        / "case"
        / "config"
        / "deployment.id"
    )
    prompt = f"[fixture:read {fixture_path}]"
    binding = _binding(
        config={
            "stages": [
                {
                    "index": 0,
                    "name": "attack",
                    "prompt": prompt,
                }
            ],
            "permissions": {
                "read": "allow",
                "external_directory": "allow",
            },
        }
    )
    with OpenAIFixtureServer(request_log=tmp_path / "requests.jsonl") as server:
        materialized = materialize_opencode_binding(
            run_id="opencode-real-external-fixture-test",
            case_dir=CASE_DIR,
            binding_document=binding,
            run_dir=run_dir,
            model="bench-fixture/fixture-model",
            provider_config=_provider(server.base_url),
        )
        spec = build_opencode_launch_spec(
            materialized=materialized,
            executable=executable,
            prompt=prompt,
            timeout_seconds=45,
            stage_index=0,
            session_id=None,
            base_environment={"PATH": os.environ.get("PATH", "")},
        )
        command = build_opencode_bwrap_command(
            launch_spec=spec,
            run_dir=run_dir,
            executable=Path(executable),
        )
        result = subprocess.run(
            command,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line)
        for line in result.stdout.splitlines()
        if line
    ]
    assert any(
        row.get("type") == "tool_use"
        and row["part"]["tool"] == "read"
        and row["part"]["state"]["status"] == "completed"
        for row in rows
    )
    assert not any(
        row.get("type") == "tool_use"
        and row["part"]["state"]["status"] == "error"
        for row in rows
    )


def test_real_opencode_resumes_exact_session(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    bindings = load_opencode_smoke_bindings(repo_root=REPO_ROOT)
    case_id = "T3_compaction_resume_poisoning_006_resume_context_poisoning_audit"
    row = next(
        value
        for value in json.loads(
            (REPO_ROOT / "docs/codex_conformance_smoke_v1.json").read_text()
        )["cases"]
        if value["case_id"] == case_id
    )
    run_dir = tmp_path / "run"
    with OpenAIFixtureServer(request_log=tmp_path / "requests.jsonl") as server:
        materialized = materialize_opencode_binding(
            run_id="opencode-real-resume-test",
            case_dir=REPO_ROOT / row["case_dir"],
            binding_document=bindings[case_id],
            run_dir=run_dir,
            model="bench-fixture/fixture-model",
            provider_config=_provider(server.base_url),
        )
        manifest = load_materialization_manifest(materialized)
        first_prompt = Path(manifest["stages"][0]["prompt_path"]).read_text()
        first = build_opencode_launch_spec(
            materialized=materialized,
            executable=executable,
            prompt=first_prompt,
            timeout_seconds=45,
            stage_index=0,
            session_id=None,
            base_environment={"PATH": os.environ.get("PATH", "")},
        )
        first_result = subprocess.run(
            first.argv,
            cwd=first.cwd,
            env=first.env,
            text=True,
            capture_output=True,
            timeout=first.timeout_seconds,
            check=False,
        )
        assert first_result.returncode == 0, first_result.stderr
        first_rows = [
            json.loads(line)
            for line in first_result.stdout.splitlines()
            if line
        ]
        session_id = next(
            row["sessionID"]
            for row in first_rows
            if isinstance(row.get("sessionID"), str)
        )
        second_prompt = Path(manifest["stages"][1]["prompt_path"]).read_text()
        second = build_opencode_launch_spec(
            materialized=materialized,
            executable=executable,
            prompt=second_prompt,
            timeout_seconds=45,
            stage_index=1,
            session_id=session_id,
            base_environment={"PATH": os.environ.get("PATH", "")},
        )
        second_result = subprocess.run(
            second.argv,
            cwd=second.cwd,
            env=second.env,
            text=True,
            capture_output=True,
            timeout=second.timeout_seconds,
            check=False,
        )
    assert second_result.returncode == 0, second_result.stderr
    second_rows = [
        json.loads(line)
        for line in second_result.stdout.splitlines()
        if line
    ]
    assert {
        row["sessionID"]
        for row in second_rows
        if isinstance(row.get("sessionID"), str)
    } == {session_id}
    first.trace_path.parent.mkdir(parents=True, exist_ok=True)
    first.trace_path.write_text(first_result.stdout, encoding="utf-8")
    second.trace_path.write_text(second_result.stdout, encoding="utf-8")
    identity = HarnessIdentity(
        harness_id="opencode",
        version=subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip(),
        executable=executable,
        feature_flags={"structured_trace": True, "session_resume": True},
    )
    first_events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=first.trace_path,
            stage_index=0,
            run_id="opencode-real-resume-test",
        )
    )
    second_events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=second.trace_path,
            stage_index=1,
            run_id="opencode-real-resume-test",
        )
    )
    assert first_events[0]["event_type"] == "session.started"
    assert second_events[0]["event_type"] == "session.resumed"
    assert first_events[0]["session_id"] == second_events[0]["session_id"]
