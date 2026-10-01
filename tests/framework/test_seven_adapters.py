"""Offline contract tests. No real provider/model calls."""
import json
import os
import sys
import types
from pathlib import Path
import pytest
from harnesssafe.common import ExperimentError, file_hash, read_json, write_json
from harnesssafe.config import validate_config, load_config, input_inventory
from harnesssafe.registry import ADAPTERS
from harnesssafe.runtime import adapter_environment, adapter_preflight, command_for, runtime_snapshot
from harnesssafe.engine import create_plan, run_plan, read_rows, empty_row, normalize_native
from harnesssafe.reporting import make_report
from harnesssafe.linux_worker import capture_row, execute_native, snapshot_tree, validate_gemini_evidence

def config(harness, tmp_path):
    provider = {
        "codex": {}, "claude": {},
        "hermes": {"base_url": "https://example.invalid/v1", "provider_id": "test",
                   "api_key_env": "TEST_API_KEY", "api_mode": "chat_completions"},
        "openclaw": {"base_url": "https://example.invalid/v1", "provider_id": "test",
                     "api_key_env": "TEST_API_KEY", "api": "openai-completions"},
        "gemini": {"api_base_url": "https://example.invalid/v1", "api_key_env": "TEST_API_KEY",
                   "provider_kind": "openai-compatible", "project": "test", "location": "global"},
        "opencode": {"profile": str(tmp_path / "profile.json")},
        "kimi": {"provider_url": "https://example.invalid/v1", "credential_env": "TEST_API_KEY"},
    }[harness]
    runtime = {
        "hermes": {"source_root": str(tmp_path / "hermes"), "python_executable": sys.executable,
                   "git_bash": str(tmp_path / "bash.exe")},
        "openclaw": {"node_executable": str(tmp_path / "node.exe"), "expected_node_version": "v1.2.3"},
        "gemini": {"conformance": str(tmp_path / "conformance.json")},
        "opencode": {"conformance": str(tmp_path / "conformance.json")},
    }.get(harness, {})
    write_json(tmp_path / "conformance.json", {"offline_test": True})
    write_json(tmp_path / "profile.json", {"schema_name": "safety_bench_opencode_provider_profile",
        "schema_version": 1, "profile_id": "test", "provider_id": "test", "provider_name": "Test",
        "model_id": "model", "model_name": "Model", "protocol": "chat_completions",
        "base_url": "https://example.invalid/v1", "credential_env": "TEST_API_KEY"})
    return validate_config({"name": "test-" + harness, "harness": harness,
        "model": "test/model", "executable": harness, "expected_version": "1.2.3",
        "provider": provider, "runtime": runtime})

@pytest.mark.parametrize("harness", ADAPTERS)
def test_all_seven_configs_roundtrip_and_init_offline(harness, tmp_path, monkeypatch):
    from harnesssafe.__main__ import main
    cfg = config(harness, tmp_path)
    assert cfg["permission_profile"] == ADAPTERS[harness]["profiles"][0]
    write_json(tmp_path / "provider.json", cfg["provider"])
    write_json(tmp_path / "runtime.json", cfg["runtime"])
    monkeypatch.setattr("harnesssafe.__main__.probe", lambda *a, **kw: pytest.fail("Offline init probed a CLI"))
    output = tmp_path / "experiment.json"
    assert main(["init", "--harness", harness, "--model", cfg["model"], "--name", cfg["name"],
                 "--expected-version", "1.2.3", "--provider-config", str(tmp_path / "provider.json"),
                 "--runtime-config", str(tmp_path / "runtime.json"), "--output", str(output)]) == 0
    assert load_config(output) == cfg

@pytest.mark.parametrize("harness", ["gemini", "opencode", "kimi"])
def test_linux_controls_are_rejected_at_config_time(harness, tmp_path):
    cfg = config(harness, tmp_path)
    with pytest.raises(ExperimentError, match="attack-only"):
        validate_config({**cfg, "arms": ["attack", "clean_control"]})

@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_windows_additions_use_declared_provider_and_runtime(harness, tmp_path):
    cfg = config(harness, tmp_path)
    cfg["arms"] = ["cleanup_control"]
    args = command_for(cfg, {"case_dir": "active/test"}, {"arm": "cleanup_control"},
                       tmp_path / "raw", "test", tmp_path, "pwsh")
    assert args[args.index("-ControlType") + 1] == "cleanup_control"
    prefix = "Hermes" if harness == "hermes" else "OpenClaw"
    assert args[args.index("-" + prefix + "ApiKeyEnv") + 1] == "TEST_API_KEY"
    assert args[args.index("-" + prefix + "BaseUrl") + 1] == cfg["provider"]["base_url"]
    env = adapter_environment(cfg)
    assert ("HERMES_AGENT_ROOT" if harness == "hermes" else "OPENCLAW_NODE_BIN") in env
    with pytest.raises(ExperimentError, match="profiles"):
        validate_config({**cfg, "permission_profile": "default_permission"})

@pytest.mark.parametrize("harness", ADAPTERS)
def test_wrong_platform_fails_before_executable_probe(harness, tmp_path, monkeypatch):
    cfg = config(harness, tmp_path)
    monkeypatch.setattr("harnesssafe.runtime.sys.platform", "linux" if ADAPTERS[harness]["platform"] == "win32" else "win32")
    monkeypatch.setattr("harnesssafe.runtime.resolve_executable", lambda *a: pytest.fail("Probe before platform gate"))
    with pytest.raises(ExperimentError, match="native execution requires"):
        runtime_snapshot(cfg)

@pytest.mark.parametrize("harness", ["hermes", "openclaw", "gemini", "kimi"])
def test_credential_values_never_accepted(harness, tmp_path):
    cfg = config(harness, tmp_path)
    key = "credential_env" if harness == "kimi" else "api_key_env"
    cfg["provider"][key] = "sk-example-secret-value"
    with pytest.raises(ExperimentError, match="environment-variable"):
        validate_config(cfg)
    cfg = config(harness, tmp_path)
    cfg["provider"]["api_key"] = "secret"
    with pytest.raises(ExperimentError, match="credential values"):
        validate_config(cfg)

def mini_project(tmp_path):
    root = tmp_path / "repo"
    write_json(root / "runs/manifest.json", {"suites": {"F1_memory_runtime": {"status": "active",
        "cases": [{"case_dir": "active/f1/" + name} for name in ("a", "b")]}}})
    (root / "requirements.txt").write_text("")
    for name in ("a", "b"):
        write_json(root / "runs/active/f1" / name / "case_meta.json",
                   {"case_id": name, "checkpoint_contract": {"test": True}, "main_table_eligible": True})
    return root

@pytest.mark.parametrize("harness", ["gemini", "opencode", "kimi"])
def test_linux_end_to_end_plan_resume_receipts_and_unscored_report(harness, tmp_path):
    cfg = config(harness, tmp_path)
    root = mini_project(tmp_path)
    config_path = tmp_path / "config.json"
    write_json(config_path, cfg)
    out = tmp_path / "experiment"
    plan = create_plan(config_path, out, root)
    def inspect(cfg, root):
        return {"executable": harness, "powershell": None}
    def execute(args, cfg, exe, log, root):
        assert args[:3] == [sys.executable, "-m", "harnesssafe.linux_worker"]
        request = read_json(Path(args[-1]))
        native = Path(request["raw_root"]) / "native"
        row = capture_row(request, {"case_id": request["case"]["case_id"], "attack_status": "ATTACK_COMPLETED"})
        write_json(native / "managed-result.json", {"case_id": request["case"]["case_id"], "job": request["job"], "row": row})
        return 0
    assert run_plan(out, root=root, inspect_runtime=inspect, execute=execute, limit=1)["launched"] == 1
    assert run_plan(out, root=root, inspect_runtime=inspect, execute=execute, resume=True)["launched"] == 1
    rows = read_rows(plan, out)
    assert len(rows) == 2
    assert all(r["execution_outcome"] == "capture_complete_unscored" for r in rows)
    summary = make_report(out)["summaries"]["attack"]
    assert summary["asr"] is None and summary["eligible_trials"] == 0
    assert summary["inventory_trials"] == 2

def test_external_inputs_cannot_drift_after_planning(tmp_path):
    cfg = config("opencode", tmp_path)
    root = mini_project(tmp_path)
    path = tmp_path / "config.json"
    write_json(path, cfg)
    output = tmp_path / "experiment"
    plan = create_plan(path, output, root)
    assert len(plan["external_inputs"]) == 2
    assert (output / "inputs/provider.profile.json").is_file()
    write_json(tmp_path / "conformance.json", {"edited": True})
    with pytest.raises(ExperimentError, match="changed after planning"):
        run_plan(output, root=root, inspect_runtime=lambda *a: pytest.fail("No launch after input drift"))

def test_opencode_model_must_match_native_provider_profile(tmp_path):
    cfg = config("opencode", tmp_path)
    cfg["model"] = "different/model"
    with pytest.raises(ExperimentError, match="model must match"):
        input_inventory(cfg)

@pytest.mark.parametrize("harness", ["gemini", "opencode"])
def test_conformance_is_bound_to_executable_bytes_and_version(harness, tmp_path, monkeypatch):
    cfg = config(harness, tmp_path)
    exe = tmp_path / "cli"
    exe.write_text("synthetic executable")
    doc = {"schema_name": f"safety_bench_{harness}_capability_conformance", "schema_version": 1,
           "harness_id": harness, "harness_version": "1.2.3", "executable_sha256": file_hash(exe),
           "generated_at": "2026-10-01T00:00:00Z", "capabilities": {}}
    write_json(Path(cfg["runtime"]["conformance"]), doc)
    # Only bwrap file availability is mocked; schema and identity checks are real.
    original_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: True if str(p).replace("\\", "/") == "/usr/bin/bwrap" else original_is_file(p))
    monkeypatch.setattr("harnesssafe.runtime.file_hash", lambda p: "b" * 64 if p.name == "bwrap" else file_hash(p))
    details = adapter_preflight(cfg, exe, "1.2.3", tmp_path)
    assert details["conformance_sha256"] == file_hash(Path(cfg["runtime"]["conformance"]))
    with pytest.raises(ExperimentError, match="stale"):
        adapter_preflight(cfg, exe, "1.2.4", tmp_path)
    exe.write_text("changed CLI")
    with pytest.raises(ExperimentError, match="stale"):
        adapter_preflight(cfg, exe, "1.2.3", tmp_path)

@pytest.mark.parametrize("status,expected", [
    ("ATTACK_COMPLETED", "capture_complete_unscored"),
    ("NOT_RUN", "not_experimentable"), ("FAILED", "execution_invalid"),
    ("MODEL_PROTOCOL_INCOMPLETE", "model_protocol_incomplete")])
def test_native_outcomes_do_not_manufacture_n0_or_scores(status, expected):
    request = {"case": {"case_id": "a", "case_dir": "active/a", "family": "F1", "suite": "f1"},
               "job": {"trial": 1, "arm": "attack", "job_id": "abc"}}
    row = capture_row(request, {"case_id": "a", "attack_status": status})
    assert row["execution_outcome"] == expected
    assert row["progress_node"] is None and row["attack_success"] is None and not row["evaluation_eligible"]
    with pytest.raises(ExperimentError, match="identity"):
        capture_row(request, {"case_id": "other", "attack_status": status})

def test_gemini_stage_completion_and_hashes_are_checked(tmp_path):
    event = tmp_path / "stages/01/raw/event-ir.jsonl"
    event.parent.mkdir(parents=True)
    event.write_text("{}")
    trace = event.with_name("gemini-stream.jsonl")
    trace.write_text("{}")
    outcome = {"stage_count_total": 1, "stage_count_completed": 1, "stages": [{
        "process_exit_code": 0, "event_ir_schema_valid": True, "event_ir_path": str(event),
        "event_ir_sha256": file_hash(event), "raw_stream_sha256": file_hash(trace)}]}
    validate_gemini_evidence(tmp_path, outcome)
    trace.write_text("tampered")
    with pytest.raises(ExperimentError, match="hash mismatch"):
        validate_gemini_evidence(tmp_path, outcome)
    outcome["stage_count_completed"] = 0
    with pytest.raises(ExperimentError, match="complete stage"):
        validate_gemini_evidence(tmp_path, outcome)

def test_linux_result_identity_and_process_failure_are_not_eligible(tmp_path):
    case = {"case_id": "a", "case_dir": "active/a", "family": "F1", "suite": "f1"}
    job = {"trial": 1, "arm": "attack", "job_id": "abc"}
    row = empty_row(case, job, "capture_complete_unscored")
    write_json(tmp_path / "managed-result.json", {"case_id": "a", "job": job, "row": row})
    assert normalize_native(case, job, {"harness": "opencode"}, tmp_path, 1)["execution_outcome"] == "execution_invalid"
    with pytest.raises(ExperimentError, match="identity"):
        normalize_native(case, {**job, "trial": 2}, {"harness": "opencode"}, tmp_path, 0)

@pytest.mark.skipif(sys.platform != "linux", reason="Linux FD and Unix socket contract")
def test_kimi_passes_sealed_fd_not_secret_in_argv_or_environment(tmp_path, monkeypatch):
    from harnesssafe.linux_worker import execute_kimi
    import fcntl
    cfg = config("kimi", tmp_path)
    request = {"config": cfg, "root": str(tmp_path), "case": {"case_id": "a", "case_dir": "a", "family": "F1", "suite": "f1"},
               "job": {"trial": 1, "arm": "attack", "job_id": "abc"}}
    observed = {}
    def native_main(args):
        assert "--execute" in args and "--authorize-external-model-execution" in args
        assert "fixture-secret" not in " ".join(args)
        assert "TEST_API_KEY" not in os.environ
        fd = int(args[args.index("--credential-fd") + 1])
        assert os.read(fd, 1000) == b"fixture-secret"
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE
        observed["fd"] = fd
        print(json.dumps({"results": [{"case_id": "a", "outcome": "COMPLETED"}]}))
        return 0
    monkeypatch.setenv("TEST_API_KEY", "fixture-secret")
    monkeypatch.setitem(sys.modules, "infra.cross_harness.adapters.kimi.cli", types.SimpleNamespace(main=native_main))
    row = execute_kimi(request, tmp_path)
    assert not row["evaluation_eligible"] and row["scoring_status"] == "DIAGNOSTIC_ONLY"
    with pytest.raises(OSError):
        os.fstat(observed["fd"])

@pytest.mark.skipif(sys.platform != "linux", reason="Native symlink/socket behavior")
def test_snapshot_preserves_regular_evidence_without_following_links(tmp_path):
    import socket
    source, target = tmp_path / "source", tmp_path / "snapshot"
    source.mkdir()
    (source / "evidence.json").write_text("{}")
    outside = tmp_path / "private"
    outside.write_text("not evidence")
    (source / "link").symlink_to(outside)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(source / "socket"))
    try:
        snapshot_tree(source, target)
    finally:
        sock.close()
    assert (target / "evidence.json").read_text() == "{}"
    assert not (target / "link").exists() and not (target / "socket").exists()
