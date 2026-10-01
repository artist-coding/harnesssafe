from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .model import CapabilityEvidence, HarnessIdentity, HermesCapabilities
from ..version_conformance import load_version_conformance, apply_version_conformance


PINNED_VERSION = "0.16.0"
PINNED_SOURCE_COMMIT = "3c231eb3979ab9c57d5cd6d02f1d577a3b718b43"
_VERSION_RE = re.compile(r"Hermes Agent v(?P<version>\d+\.\d+\.\d+)")


class CompletedCommand(Protocol):
    returncode: int
    stdout: str


CommandRunner = Callable[[Sequence[str]], CompletedCommand]


def detect_identity(
    executable: Path,
    run: CommandRunner,
    *,
    source_commit: str = "",
    source_root: Path | None = None,
    git_run: CommandRunner | None = None,
) -> HarnessIdentity:
    executable = Path(executable)
    launcher_sha256 = (
        hashlib.sha256(executable.read_bytes()).hexdigest()
        if executable.is_file()
        else ""
    )
    try:
        result = run((str(executable), "--version"))
    except OSError:
        result = None
    match = (
        _VERSION_RE.search(str(result.stdout))
        if result is not None and result.returncode == 0
        else None
    )
    if source_root is not None and git_run is not None:
        try:
            git_result = git_run(
                ("git", "-C", str(Path(source_root)), "rev-parse", "HEAD")
            )
        except OSError:
            git_result = None
        if git_result is not None and git_result.returncode == 0:
            source_commit = str(git_result.stdout).strip()
    return HarnessIdentity(
        available=match is not None,
        version=match.group("version") if match else "",
        launcher_sha256=launcher_sha256,
        source_commit=source_commit,
        executable=executable,
    )


def _unsupported(reason: str) -> CapabilityEvidence:
    return CapabilityEvidence(False, "identity", "", reason)


def _help_flag(help_text: str, flag: str) -> CapabilityEvidence:
    supported = flag in help_text
    return CapabilityEvidence(
        supported,
        "cli_help",
        f"hermes chat --help:{flag}" if supported else "",
        "" if supported else f"missing required CLI flag {flag}",
    )


def _instruction_capability(help_text: str) -> CapabilityEvidence:
    required = ("--query", "--ignore-user-config", "--source")
    missing = tuple(flag for flag in required if flag not in help_text)
    return CapabilityEvidence(
        not missing,
        "cli_help",
        "hermes chat --help:" + ",".join(required) if not missing else "",
        "" if not missing else f"missing required CLI flags: {', '.join(missing)}",
    )


def probe_capabilities(
    identity: HarnessIdentity,
    run: CommandRunner,
    *, conformance_path: Path | None = None, use_environment: bool = True,
) -> HermesCapabilities:
    conformance_path = conformance_path or (Path(os.environ["HERMES_CONFORMANCE"]) if use_environment and os.environ.get("HERMES_CONFORMANCE") else None)
    reviewed = None
    if conformance_path:
        try:
            reviewed = load_version_conformance(conformance_path, harness="hermes", identity=identity,
                                                capability_names=tuple(HermesCapabilities.__dataclass_fields__))
        except (ValueError, OSError, TypeError, AttributeError) as exc:
            unsupported = _unsupported(f"invalid version conformance: {type(exc).__name__}")
            return HermesCapabilities(*([unsupported] * 7))
    if not identity.pinned and reviewed is None:
        reason = (
            f"unrecognized Hermes identity version={identity.version!r} "
            f"source_commit={identity.source_commit!r}"
        )
        unsupported = _unsupported(reason)
        return HermesCapabilities(*([unsupported] * 7))

    try:
        result = run((str(identity.executable), "chat", "--help"))
    except OSError:
        result = None
    help_text = (
        str(result.stdout)
        if result is not None and result.returncode == 0
        else ""
    )
    instruction = _instruction_capability(help_text)
    skill = _help_flag(help_text, "--skills")
    session_resume = _help_flag(help_text, "--resume")
    source_ref = f"hermes-agent@{PINNED_SOURCE_COMMIT}"
    mcp = CapabilityEvidence(True, "pinned_source", f"{source_ref}:MCP config loader")
    compaction = CapabilityEvidence(
        True, "pinned_source", f"{source_ref}:session compression lineage"
    )
    subagent = CapabilityEvidence(
        True, "pinned_source", f"{source_ref}:delegate_task toolset"
    )
    durable_memory = CapabilityEvidence(
        True, "pinned_source", f"{source_ref}:run-local Hermes state"
    )
    capabilities = HermesCapabilities(
        instruction=instruction,
        skill=skill,
        mcp=mcp,
        session_resume=session_resume,
        compaction=compaction,
        subagent=subagent,
        durable_memory=durable_memory,
    )

    if reviewed is not None:
        return apply_version_conformance(capabilities, reviewed, CapabilityEvidence, conformance_path,
                                         help_capabilities=('instruction', 'skill', 'session_resume'))
    return capabilities
