import hashlib
import subprocess
from pathlib import Path

from infra.harness_adapters.hermes.model import HarnessIdentity
from infra.harness_adapters.hermes.probe import detect_identity, probe_capabilities


FIXTURES = Path(__file__).parent / "fixtures"
PINNED_COMMIT = "3c231eb3979ab9c57d5cd6d02f1d577a3b718b43"


def completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def test_detect_identity_requires_exact_version(tmp_path: Path) -> None:
    launcher = tmp_path / "hermes"
    launcher.write_bytes(b"launcher")
    version = (FIXTURES / "hermes_version.txt").read_text(encoding="utf-8")

    identity = detect_identity(
        launcher,
        lambda _argv: completed(version),
        source_commit=PINNED_COMMIT,
    )

    assert identity.version == "0.16.0"
    assert identity.available is True
    assert identity.pinned is True
    assert identity.launcher_sha256 == hashlib.sha256(b"launcher").hexdigest()


def test_unknown_version_has_no_native_promotions() -> None:
    identity = HarnessIdentity(True, "9.9.9", "", "", Path("hermes"))

    caps = probe_capabilities(identity, lambda _argv: completed("--resume --skills"))

    assert caps.session_resume.supported is False
    assert caps.subagent.supported is False
    assert caps.compaction.supported is False


def test_pinned_help_produces_evidence_bearing_capabilities() -> None:
    help_text = (FIXTURES / "hermes_help.txt").read_text(encoding="utf-8")
    identity = HarnessIdentity(
        True,
        "0.16.0",
        "a" * 64,
        PINNED_COMMIT,
        Path("hermes"),
    )

    caps = probe_capabilities(identity, lambda _argv: completed(help_text))

    assert caps.instruction.supported is True
    assert caps.skill.evidence_kind == "cli_help"
    assert caps.session_resume.evidence_ref == "hermes chat --help:--resume"
    assert caps.compaction.evidence_kind == "pinned_source"
    assert caps.subagent.evidence_kind == "pinned_source"


def test_failed_version_command_is_unavailable(tmp_path: Path) -> None:
    launcher = tmp_path / "hermes"
    launcher.write_bytes(b"launcher")

    identity = detect_identity(launcher, lambda _argv: completed(returncode=1))

    assert identity.available is False
    assert identity.pinned is False


def test_detect_identity_reads_source_commit_from_checkout(tmp_path: Path) -> None:
    launcher = tmp_path / "hermes.exe"
    launcher.write_bytes(b"launcher")
    version = (FIXTURES / "hermes_version.txt").read_text(encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def fake_git(argv):
        commands.append(tuple(argv))
        return completed(PINNED_COMMIT + "\n")

    identity = detect_identity(
        launcher,
        lambda _argv: completed(version),
        source_root=tmp_path,
        git_run=fake_git,
    )

    assert identity.pinned is True
    assert commands == [("git", "-C", str(tmp_path), "rev-parse", "HEAD")]


def test_instruction_capability_requires_isolation_flags() -> None:
    identity = HarnessIdentity(
        True,
        "0.16.0",
        "a" * 64,
        PINNED_COMMIT,
        Path("hermes"),
    )

    caps = probe_capabilities(
        identity,
        lambda _argv: completed("--query --skills --resume"),
    )

    assert caps.instruction.supported is False
    assert "--ignore-user-config" in caps.instruction.reason
