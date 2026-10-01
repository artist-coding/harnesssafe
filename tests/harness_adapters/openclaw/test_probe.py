import hashlib
import subprocess
from pathlib import Path

from infra.harness_adapters.openclaw.model import HarnessIdentity
from infra.harness_adapters.openclaw.probe import (
    detect_identity,
    probe_capabilities,
    resolve_openclaw,
)


def completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def test_resolver_prefers_explicit_binary(tmp_path: Path, monkeypatch) -> None:
    explicit = tmp_path / "openclaw.cmd"
    explicit.write_bytes(b"launcher")
    monkeypatch.setenv("OPENCLAW_BIN", str(explicit))
    assert resolve_openclaw(repo_root=tmp_path) == explicit


def test_detect_identity_records_exact_version_and_hashes(tmp_path: Path) -> None:
    launcher = tmp_path / "openclaw.cmd"
    package = tmp_path / "package.json"
    launcher.write_bytes(b"launcher")
    package.write_bytes(b'{"version":"2026.7.1-2"}')
    identity = detect_identity(
        launcher, lambda _: completed("2026.7.1-2\n"), package_json=package
    )
    assert identity.pinned is True
    assert identity.launcher_sha256 == hashlib.sha256(b"launcher").hexdigest()
    assert identity.package_sha256 == hashlib.sha256(package.read_bytes()).hexdigest()


def test_unknown_version_keeps_native_capabilities_unvalidated() -> None:
    identity = HarnessIdentity(True, "2099.1.1", "", "", Path("openclaw"))
    caps = probe_capabilities(identity, lambda _: completed("sessions compact subagent"))
    assert caps.session_resume.supported is False
    assert caps.compaction.supported is False
    assert caps.subagent.supported is False


def test_pinned_capabilities_are_source_addressable() -> None:
    identity = HarnessIdentity(True, "2026.7.1-2", "a" * 64, "b" * 64, Path("openclaw"))
    outputs = {
        ("gateway", "--help"): "gateway --port",
        ("agent", "--help"): "agent --session-key --message --json",
        ("sessions", "--help"): "sessions compact",
        ("mcp", "--help"): "mcp",
    }
    caps = probe_capabilities(
        identity,
        lambda argv: completed(outputs.get(tuple(argv[1:]), "")),
    )
    assert caps.gateway.evidence_ref.startswith("openclaw@2026.7.1-2")
    assert caps.instruction.supported is True
    assert caps.session_resume.supported is True
    assert caps.compaction.supported is True
    assert caps.subagent.evidence_kind == "pinned_package_contract"
