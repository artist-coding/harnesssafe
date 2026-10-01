from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .model import CapabilityEvidence, HarnessIdentity, OpenClawCapabilities
from ..version_conformance import load_version_conformance, apply_version_conformance


PINNED_VERSION = "2026.7.1-2"
_VERSION_RE = re.compile(r"(?P<version>\d{4}\.\d+\.\d+(?:-\d+)?)")


class CompletedCommand(Protocol):
    returncode: int
    stdout: str


CommandRunner = Callable[[Sequence[str]], CompletedCommand]


def resolve_openclaw(*, repo_root: Path) -> Path:
    explicit = os.environ.get("OPENCLAW_BIN", "").strip()
    candidates = [
        Path(explicit) if explicit else None,
        repo_root / "bench_state/tools/openclaw/node_modules/.bin/openclaw.cmd",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    discovered = shutil.which("openclaw")
    if discovered:
        return Path(discovered).resolve()
    raise FileNotFoundError("OpenClaw executable not found; install pinned worktree runtime")


def detect_identity(
    executable: Path,
    run: CommandRunner,
    *,
    package_json: Path | None = None,
) -> HarnessIdentity:
    executable = Path(executable)
    launcher_hash = hashlib.sha256(executable.read_bytes()).hexdigest() if executable.is_file() else ""
    if package_json is None:
        package_json = executable.parent.parent / "openclaw/package.json"
    package_hash = hashlib.sha256(package_json.read_bytes()).hexdigest() if package_json.is_file() else ""
    package_version = ""
    if package_json.is_file():
        try:
            package_version = str(json.loads(package_json.read_text(encoding="utf-8"))["version"])
        except (KeyError, ValueError, TypeError):
            pass
    try:
        result = run((str(executable), "--version"))
    except OSError:
        result = None
    match = _VERSION_RE.search(str(result.stdout)) if result is not None and result.returncode == 0 else None
    version = match.group("version") if match else ""
    available = bool(match and (not package_version or package_version == version))
    return HarnessIdentity(available, version, launcher_hash, package_hash, executable)


def _unsupported(reason: str) -> CapabilityEvidence:
    return CapabilityEvidence(False, "identity", "", reason)


def _help(run: CommandRunner, executable: Path, command: str) -> str:
    try:
        result = run((str(executable), command, "--help"))
    except OSError:
        return ""
    return str(result.stdout) if result.returncode == 0 else ""


def _cli_evidence(ok: bool, command: str, requirement: str) -> CapabilityEvidence:
    return CapabilityEvidence(
        ok,
        "cli_help",
        f"openclaw@{PINNED_VERSION}:{command} --help:{requirement}" if ok else "",
        "" if ok else f"missing {requirement} from {command} help",
    )


def probe_capabilities(identity: HarnessIdentity, run: CommandRunner, *, conformance_path: Path | None = None, use_environment: bool = True) -> OpenClawCapabilities:
    conformance_path = conformance_path or (Path(os.environ["OPENCLAW_CONFORMANCE"]) if use_environment and os.environ.get("OPENCLAW_CONFORMANCE") else None)
    reviewed = None
    if conformance_path:
        try:
            reviewed = load_version_conformance(conformance_path, harness="openclaw", identity=identity,
                                                capability_names=tuple(OpenClawCapabilities.__dataclass_fields__))
        except (ValueError, OSError, TypeError, AttributeError) as exc:
            unsupported = _unsupported(f"invalid version conformance: {type(exc).__name__}")
            return OpenClawCapabilities(*([unsupported] * 8))
    if not identity.pinned and reviewed is None:
        unsupported = _unsupported(f"unrecognized OpenClaw identity version={identity.version!r}")
        return OpenClawCapabilities(*([unsupported] * 8))
    gateway_help = _help(run, identity.executable, "gateway")
    agent_help = _help(run, identity.executable, "agent")
    sessions_help = _help(run, identity.executable, "sessions")
    mcp_help = _help(run, identity.executable, "mcp")
    gateway = _cli_evidence("--port" in gateway_help, "gateway", "--port")
    required_agent = ("--session-key", "--json")
    instruction = _cli_evidence(all(x in agent_help for x in required_agent), "agent", ",".join(required_agent))
    session_resume = _cli_evidence("--session-key" in agent_help, "agent", "--session-key")
    compaction = _cli_evidence("compact" in sessions_help, "sessions", "compact")
    mcp = _cli_evidence(bool(mcp_help.strip()), "mcp", "command")
    source = f"openclaw@{PINNED_VERSION}"
    capabilities = OpenClawCapabilities(
        gateway=gateway,
        instruction=instruction,
        skill=CapabilityEvidence(True, "pinned_package_contract", f"{source}:workspace skills"),
        mcp=mcp,
        session_resume=session_resume,
        compaction=compaction,
        subagent=CapabilityEvidence(True, "pinned_package_contract", f"{source}:sessions_spawn runtime=subagent"),
        durable_memory=CapabilityEvidence(True, "pinned_package_contract", f"{source}:OPENCLAW_STATE_DIR"),
    )

    if reviewed is not None:
        return apply_version_conformance(capabilities, reviewed, CapabilityEvidence, conformance_path,
                                         help_capabilities=('gateway', 'instruction', 'mcp', 'session_resume', 'compaction'))
    return capabilities
