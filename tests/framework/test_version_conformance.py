import importlib
import inspect
import json
import subprocess
from pathlib import Path
import pytest
from harnesssafe.common import ROOT, ExperimentError, read_json, write_json
from harnesssafe.linux_worker import execute_native

def native_fixture(harness, tmp_path):
    model = importlib.import_module(f"infra.harness_adapters.{harness}.model")
    probe = importlib.import_module(f"infra.harness_adapters.{harness}.probe")
    caps_type = model.HermesCapabilities if harness == "hermes" else model.OpenClawCapabilities
    identity = model.HarnessIdentity(True, "9.9.9" if harness == "hermes" else "2099.1.1",
                                     "a" * 64, "b" * (40 if harness == "hermes" else 64), tmp_path / "cli")
    document = {"schema_name": "harnesssafe_native_version_conformance", "schema_version": 1,
        "harness_id": harness, "harness_version": identity.version, "launcher_sha256": identity.launcher_sha256,
        "source_commit" if harness == "hermes" else "package_sha256": "b" * (40 if harness == "hermes" else 64),
        "generated_at": "2026-10-01T00:00:00Z",
        "capabilities": {name: {"status": "SUPPORTED", "executed": True,
                         "evidence": ["synthetic-test-only:" + name], "reason": ""}
                         for name in caps_type.__dataclass_fields__}}
    path = tmp_path / "conformance.json"
    write_json(path, document)
    def run(argv):
        return subprocess.CompletedProcess(argv, 0,
            stdout="--query --ignore-user-config --source --skills --resume --port --session-key --json sessions compact mcp")
    return identity, probe, path, document, run

@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_new_versions_require_evidence_and_do_not_claim_old_pins(harness, tmp_path, monkeypatch):
    identity, probe, path, document, run = native_fixture(harness, tmp_path)
    monkeypatch.delenv(harness.upper() + "_CONFORMANCE", raising=False)
    assert not identity.pinned
    assert not probe.probe_capabilities(identity, run).subagent.supported
    caps = probe.probe_capabilities(identity, run, conformance_path=path)
    assert caps.subagent.supported
    assert caps.subagent.evidence_kind == "version_conformance"
    assert str(path) in caps.subagent.evidence_ref
    # The native runner receives this same proof via its explicit child env.
    monkeypatch.setenv(harness.upper() + "_CONFORMANCE", str(path))
    assert probe.probe_capabilities(identity, run).subagent.supported

@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
@pytest.mark.parametrize("change", ["version", "bytes", "unexecuted", "unvalidated"])
def test_conformance_cannot_promote_wrong_or_unvalidated_capabilities(harness, change, tmp_path, monkeypatch):
    identity, probe, path, doc, run = native_fixture(harness, tmp_path)
    if change == "version":
        doc["harness_version"] = "other"
    elif change == "bytes":
        doc["launcher_sha256"] = "c" * 64
    elif change == "unexecuted":
        doc["capabilities"]["subagent"]["executed"] = False
    else:
        doc["capabilities"]["subagent"] = {"status": "UNVALIDATED", "executed": False,
                                         "evidence": [], "reason": "not yet exercised"}
    write_json(path, doc)
    assert not probe.probe_capabilities(identity, run, conformance_path=path).subagent.supported

@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_version_proof_does_not_override_missing_cli_flags(harness, tmp_path):
    identity, probe, path, doc, run = native_fixture(harness, tmp_path)
    caps = probe.probe_capabilities(identity, lambda argv: subprocess.CompletedProcess(argv, 0, stdout=""),
                                    conformance_path=path)
    assert not caps.instruction.supported

@pytest.mark.parametrize("harness", ["gemini", "opencode"])
def test_linux_dispatch_matches_real_native_function_contract(harness, tmp_path, monkeypatch):
    from tests.framework.test_seven_adapters import config
    cfg = config(harness, tmp_path)
    module_name = "attack_only_runner" if harness == "gemini" else "active_attack_runner"
    module = importlib.import_module(f"infra.cross_harness.adapters.{harness}.{module_name}")
    function_name = "execute_attack_batch" if harness == "gemini" else "execute_active_batch"
    signature = inspect.signature(getattr(module, function_name))
    work = tmp_path / "work"
    captured = {}
    def native(**kwargs):
        signature.bind(**kwargs)
        captured.update(kwargs)
        write_json(work / "cases/one/attack-outcome.json", {"case_id": "a", "attack_status": "NOT_RUN"})
    monkeypatch.setattr(module, function_name, native)
    request = {"config": cfg, "root": str(ROOT),
        "case": {"case_id": "a", "case_dir": "active/a", "suite": "f1", "family": "F1"},
        "job": {"trial": 1, "arm": "attack", "job_id": "abc"}}
    row = execute_native(request, work)
    assert captured["case_ids"] == ["a"]
    assert captured["executable"] == harness
    assert row["execution_outcome"] == "not_experimentable"
    if harness == "gemini":
        assert captured["enable_honeypot"] is True and captured["model"] == cfg["model"]
    else:
        assert captured["provider_profile_path"] == Path(cfg["provider"]["profile"])

def test_gemini_protocol_uses_conformance_version_not_paper_constant(tmp_path):
    from infra.cross_harness.adapters.gemini.attack_only_runner import attack_only_protocol
    path = tmp_path / "conformance.json"
    write_json(path, {"harness_version": "8.9.10", "executable_sha256": "a" * 64})
    protocol = attack_only_protocol(repo_root=ROOT, conformance_path=path)
    assert protocol["gemini_cli_version"] == "8.9.10"
