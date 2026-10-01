"""Abstract adapter interface for Cross-Harness Contract v1."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .contract import (
    CAPABILITIES,
    CAPABILITY_STATUSES,
    TARGET_HARNESSES,
    validate_binding_document,
    validate_event_document,
)


def _require_nonempty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


@dataclass(frozen=True)
class HarnessIdentity:
    """Version and feature evidence captured before a run."""

    harness_id: str
    version: str
    executable: str
    feature_flags: Mapping[str, bool | str | int | float] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if self.harness_id not in TARGET_HARNESSES:
            raise ValueError(f"unknown harness_id: {self.harness_id!r}")
        _require_nonempty(self.version, "version")
        _require_nonempty(self.executable, "executable")


@dataclass(frozen=True)
class CapabilityProbe:
    """Fail-closed capability disposition with raw evidence locators."""

    status: str
    required_capabilities: tuple[str, ...]
    evidence: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in CAPABILITY_STATUSES:
            raise ValueError(f"unknown capability status: {self.status!r}")
        unknown = sorted(set(self.required_capabilities) - CAPABILITIES)
        if unknown:
            raise ValueError(f"unknown capabilities: {unknown}")
        if len(set(self.required_capabilities)) != len(self.required_capabilities):
            raise ValueError("required_capabilities must be unique")
        if self.status == "SUPPORTED" and self.reasons:
            raise ValueError("SUPPORTED capability probes cannot have failure reasons")
        if self.status != "SUPPORTED" and not self.reasons:
            raise ValueError(f"{self.status} capability probes require reasons")


@dataclass(frozen=True)
class MaterializedBinding:
    """One immutable run-local binding produced from a canonical case."""

    harness_id: str
    case_id: str
    case_dir: Path
    run_dir: Path
    binding_version: int
    manifest_path: Path

    def __post_init__(self) -> None:
        if self.harness_id not in TARGET_HARNESSES:
            raise ValueError(f"unknown harness_id: {self.harness_id!r}")
        _require_nonempty(self.case_id, "case_id")
        if self.binding_version < 1:
            raise ValueError("binding_version must be >= 1")


@dataclass(frozen=True)
class LaunchSpec:
    """Non-interactive process launch specification."""

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    trace_path: Path
    timeout_seconds: int
    secret_env_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.argv or any(
            not isinstance(item, str) or not item for item in self.argv
        ):
            raise ValueError("argv must contain non-empty strings")
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.env.items()
        ):
            raise ValueError("env must map strings to strings")
        if any(
            not isinstance(name, str) or not name
            for name in self.secret_env_names
        ):
            raise ValueError("secret_env_names must contain non-empty strings")
        if len(set(self.secret_env_names)) != len(self.secret_env_names):
            raise ValueError("secret_env_names must be unique")
        if any(name not in self.env for name in self.secret_env_names):
            raise ValueError("secret_env_names must be present in env")


class HarnessAdapter(ABC):
    """Required lifecycle for every harness-specific implementation.

    Concrete adapters may not score attacks. They materialize native bindings,
    run capability preflight, build a process launch, and normalize raw evidence
    into the shared event IR. The analyzer/scoring layer remains the sole owner
    of N0-N5b.
    """

    harness_id: str

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        harness_id = getattr(cls, "harness_id", "")
        if harness_id and harness_id not in TARGET_HARNESSES:
            raise TypeError(f"unknown adapter harness_id: {harness_id!r}")

    @abstractmethod
    def detect_identity(self) -> HarnessIdentity:
        """Capture executable version and feature flags."""

    @abstractmethod
    def probe_capabilities(
        self,
        required_capabilities: Sequence[str],
    ) -> CapabilityProbe:
        """Prove or reject all required capabilities before model execution."""

    @abstractmethod
    def materialize_binding(
        self,
        *,
        case_dir: Path,
        binding_document: Mapping[str, Any],
        run_dir: Path,
    ) -> MaterializedBinding:
        """Create an isolated, run-local native binding."""

    @abstractmethod
    def build_launch_spec(
        self,
        *,
        materialized: MaterializedBinding,
        prompt: str,
        timeout_seconds: int,
    ) -> LaunchSpec:
        """Build the non-interactive harness process invocation."""

    @abstractmethod
    def normalize_trace(
        self,
        *,
        identity: HarnessIdentity,
        materialized: MaterializedBinding,
        raw_trace_path: Path,
    ) -> Iterable[Mapping[str, Any]]:
        """Yield ordered Cross-Harness Event IR v1 records."""

    @abstractmethod
    def cleanup(self, *, materialized: MaterializedBinding) -> None:
        """Release only run-local processes and resources owned by the adapter."""

    @staticmethod
    def validate_binding(binding_document: Mapping[str, Any]) -> None:
        validate_binding_document(binding_document)

    @staticmethod
    def validate_event(event_document: Mapping[str, Any]) -> None:
        validate_event_document(event_document)
