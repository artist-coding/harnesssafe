"""Fail-closed, version-pinned OpenCode capability evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...adapter import HarnessIdentity
from ...contract import CAPABILITIES


class OpenCodeCapabilityEvidenceError(ValueError):
    """Capability evidence is malformed or does not match the detected binary."""


@dataclass(frozen=True)
class CapabilityEvidence:
    status: str
    evidence: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evidence": list(self.evidence),
            "reasons": list(self.reasons),
        }


def _unvalidated(reason: str, *evidence: str) -> CapabilityEvidence:
    return CapabilityEvidence(
        status="UNVALIDATED",
        evidence=tuple(value for value in evidence if value),
        reasons=(reason,),
    )


def _read_document(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeCapabilityEvidenceError(
            f"cannot read OpenCode conformance evidence {path}: {exc}"
        ) from exc
    if not isinstance(document, Mapping):
        raise OpenCodeCapabilityEvidenceError(
            "OpenCode conformance evidence must be an object"
        )
    return document


def _validate_timestamp(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise OpenCodeCapabilityEvidenceError(
            "generated_at must be a non-empty timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OpenCodeCapabilityEvidenceError(
            "generated_at must be RFC3339-compatible"
        ) from exc
    if parsed.tzinfo is None:
        raise OpenCodeCapabilityEvidenceError(
            "generated_at must include a timezone"
        )


def _validated_entries(
    document: Mapping[str, Any], *, evidence_path: Path
) -> dict[str, CapabilityEvidence]:
    expected = {
        "schema_name",
        "schema_version",
        "harness_id",
        "harness_version",
        "executable_sha256",
        "generated_at",
        "capabilities",
    }
    if set(document) != expected:
        raise OpenCodeCapabilityEvidenceError(
            "OpenCode conformance evidence has missing or unknown top-level fields"
        )
    if document["schema_name"] != "safety_bench_opencode_capability_conformance":
        raise OpenCodeCapabilityEvidenceError("invalid OpenCode conformance schema_name")
    if document["schema_version"] != 1:
        raise OpenCodeCapabilityEvidenceError(
            "OpenCode conformance schema_version must equal 1"
        )
    if document["harness_id"] != "opencode":
        raise OpenCodeCapabilityEvidenceError(
            "OpenCode conformance harness_id must be opencode"
        )
    for key in ("harness_version", "executable_sha256"):
        if not isinstance(document[key], str) or not document[key].strip():
            raise OpenCodeCapabilityEvidenceError(f"{key} must be non-empty")
    digest = document["executable_sha256"]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise OpenCodeCapabilityEvidenceError(
            "executable_sha256 must be lowercase SHA-256"
        )
    _validate_timestamp(document["generated_at"])

    raw_capabilities = document["capabilities"]
    if not isinstance(raw_capabilities, Mapping):
        raise OpenCodeCapabilityEvidenceError("capabilities must be an object")
    unknown = sorted(set(raw_capabilities) - CAPABILITIES)
    if unknown:
        raise OpenCodeCapabilityEvidenceError(
            f"unknown OpenCode capabilities: {unknown}"
        )

    result: dict[str, CapabilityEvidence] = {}
    for capability, raw in raw_capabilities.items():
        if not isinstance(raw, Mapping) or set(raw) != {
            "status",
            "executed",
            "evidence",
            "reason",
        }:
            raise OpenCodeCapabilityEvidenceError(
                f"capability {capability} must declare "
                "status/executed/evidence/reason"
            )
        status = raw["status"]
        if status not in {"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"}:
            raise OpenCodeCapabilityEvidenceError(
                f"capability {capability} has invalid status {status!r}"
            )
        if not isinstance(raw["executed"], bool):
            raise OpenCodeCapabilityEvidenceError(
                f"capability {capability} executed must be boolean"
            )
        evidence = raw["evidence"]
        if (
            not isinstance(evidence, list)
            or any(not isinstance(item, str) or not item.strip() for item in evidence)
            or len(set(evidence)) != len(evidence)
        ):
            raise OpenCodeCapabilityEvidenceError(
                f"capability {capability} evidence must contain "
                "unique non-empty strings"
            )
        reason = raw["reason"]
        if not isinstance(reason, str):
            raise OpenCodeCapabilityEvidenceError(
                f"capability {capability} reason must be a string"
            )
        if status == "SUPPORTED":
            if not raw["executed"] or not evidence or reason:
                raise OpenCodeCapabilityEvidenceError(
                    f"SUPPORTED capability {capability} needs executed evidence "
                    "and no failure reason"
                )
            reasons: tuple[str, ...] = ()
        else:
            if not reason.strip():
                raise OpenCodeCapabilityEvidenceError(
                    f"{status} capability {capability} needs a reason"
                )
            if status == "UNSUPPORTED" and (
                not raw["executed"] or not evidence
            ):
                raise OpenCodeCapabilityEvidenceError(
                    f"UNSUPPORTED capability {capability} needs executed evidence"
                )
            reasons = (reason,)
        result[capability] = CapabilityEvidence(
            status=status,
            evidence=(str(evidence_path), *tuple(evidence)),
            reasons=reasons,
        )
    return result


def capability_matrix(
    *,
    identity: HarnessIdentity | None,
    conformance_path: Path | None,
) -> dict[str, CapabilityEvidence]:
    """Return every Contract v1 capability without inferring runtime support."""

    if identity is None:
        return {
            capability: _unvalidated("OpenCode executable identity is unavailable")
            for capability in CAPABILITIES
        }
    identity_locator = f"identity:{identity.executable}@{identity.version}"
    if conformance_path is None or not conformance_path.is_file():
        return {
            capability: _unvalidated(
                "No version-pinned OpenCode runtime conformance evidence is available",
                identity_locator,
            )
            for capability in CAPABILITIES
        }
    try:
        document = _read_document(conformance_path)
        entries = _validated_entries(document, evidence_path=conformance_path)
    except OpenCodeCapabilityEvidenceError as exc:
        return {
            capability: _unvalidated(
                f"OpenCode conformance evidence is invalid: {exc}",
                str(conformance_path),
            )
            for capability in CAPABILITIES
        }

    if (
        document["harness_version"] != identity.version
        or document["executable_sha256"]
        != identity.feature_flags.get("binary_sha256")
    ):
        return {
            capability: _unvalidated(
                "OpenCode conformance evidence does not match the detected binary",
                str(conformance_path),
            )
            for capability in CAPABILITIES
        }

    matrix: dict[str, CapabilityEvidence] = {}
    for capability in CAPABILITIES:
        entry = entries.get(capability)
        if entry is None:
            matrix[capability] = _unvalidated(
                "Capability is absent from version-pinned OpenCode evidence",
                str(conformance_path),
            )
            continue
        if capability == "headless_execution" and not identity.feature_flags.get(
            "headless_run"
        ):
            matrix[capability] = _unvalidated(
                "Detected OpenCode help does not expose the run command",
                str(conformance_path),
            )
            continue
        if capability == "structured_trace" and not identity.feature_flags.get(
            "json_trace"
        ):
            matrix[capability] = _unvalidated(
                "Detected OpenCode run help does not expose JSON output",
                str(conformance_path),
            )
            continue
        if capability == "session_resume" and not identity.feature_flags.get(
            "session_resume"
        ):
            matrix[capability] = _unvalidated(
                "Detected OpenCode run help does not expose --session",
                str(conformance_path),
            )
            continue
        matrix[capability] = entry
    return matrix


def aggregate_required_capabilities(
    required: Sequence[str], matrix: Mapping[str, CapabilityEvidence]
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if not required:
        raise ValueError("required_capabilities must not be empty")
    unknown = sorted(set(required) - CAPABILITIES)
    if unknown:
        raise ValueError(f"unknown capabilities: {unknown}")
    if len(set(required)) != len(required):
        raise ValueError("required_capabilities must be unique")
    statuses: list[str] = []
    evidence: list[str] = []
    reasons: list[str] = []
    for capability in required:
        entry = matrix[capability]
        statuses.append(entry.status)
        evidence.extend(entry.evidence)
        reasons.extend(f"{capability}: {reason}" for reason in entry.reasons)
    if "UNSUPPORTED" in statuses:
        status = "UNSUPPORTED"
    elif "UNVALIDATED" in statuses:
        status = "UNVALIDATED"
    else:
        status = "SUPPORTED"
        reasons = []
    return (
        status,
        tuple(dict.fromkeys(evidence)),
        tuple(dict.fromkeys(reasons)),
    )


__all__ = [
    "CapabilityEvidence",
    "OpenCodeCapabilityEvidenceError",
    "aggregate_required_capabilities",
    "capability_matrix",
]
