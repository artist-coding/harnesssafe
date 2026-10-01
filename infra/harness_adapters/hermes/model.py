from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class BindingDisposition(str, Enum):
    """Engineering state for a harness binding, never a benchmark score."""

    READY = "READY"
    NOT_RUN = "NOT_RUN"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class HermesBinding:
    case_dir: str
    case_meta_sha256: str
    semantic_surface: str
    required_capabilities: tuple[str, ...]
    stage_runtime_modes: tuple[str, ...]
    expected_normalized_events: tuple[str, ...]
    disposition: BindingDisposition
    blocking_reasons: tuple[str, ...]
    binding_version: str = "hermes-binding-v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "binding_version": self.binding_version,
            "case_dir": self.case_dir,
            "case_meta_sha256": self.case_meta_sha256,
            "semantic_surface": self.semantic_surface,
            "required_capabilities": list(self.required_capabilities),
            "stage_runtime_modes": list(self.stage_runtime_modes),
            "expected_normalized_events": list(self.expected_normalized_events),
            "disposition": self.disposition.value,
            "blocking_reasons": list(self.blocking_reasons),
        }


@dataclass(frozen=True)
class HarnessIdentity:
    available: bool
    version: str
    launcher_sha256: str
    source_commit: str
    executable: Path

    @property
    def pinned(self) -> bool:
        return (
            self.available
            and self.version == "0.16.0"
            and self.source_commit
            == "3c231eb3979ab9c57d5cd6d02f1d577a3b718b43"
        )


@dataclass(frozen=True)
class CapabilityEvidence:
    supported: bool
    evidence_kind: str
    evidence_ref: str
    reason: str = ""


@dataclass(frozen=True)
class HermesCapabilities:
    instruction: CapabilityEvidence
    skill: CapabilityEvidence
    mcp: CapabilityEvidence
    session_resume: CapabilityEvidence
    compaction: CapabilityEvidence
    subagent: CapabilityEvidence
    durable_memory: CapabilityEvidence
