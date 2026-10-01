"""Version-pinned, fail-closed Gemini CLI capability conformance."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...adapter import HarnessIdentity
from ...contract import CAPABILITIES


class GeminiCapabilityEvidenceError(ValueError):
    """A capability evidence document is malformed or not identity-bound."""


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
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GeminiCapabilityEvidenceError(
            f"cannot read Gemini conformance evidence {path}: {exc}"
        ) from exc
    if not isinstance(value, Mapping):
        raise GeminiCapabilityEvidenceError("Gemini conformance evidence must be an object")
    return value


def _validate_timestamp(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise GeminiCapabilityEvidenceError("generated_at must be a non-empty timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GeminiCapabilityEvidenceError("generated_at must be RFC3339-compatible") from exc
    if parsed.tzinfo is None:
        raise GeminiCapabilityEvidenceError("generated_at must include a timezone")


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
        raise GeminiCapabilityEvidenceError(
            "Gemini conformance evidence has missing or unknown top-level fields"
        )
    if document["schema_name"] != "safety_bench_gemini_capability_conformance":
        raise GeminiCapabilityEvidenceError("invalid Gemini conformance schema_name")
    if document["schema_version"] != 1:
        raise GeminiCapabilityEvidenceError("Gemini conformance schema_version must equal 1")
    if document["harness_id"] != "gemini":
        raise GeminiCapabilityEvidenceError("Gemini conformance harness_id must be gemini")
    for key in ("harness_version", "executable_sha256"):
        if not isinstance(document[key], str) or not document[key].strip():
            raise GeminiCapabilityEvidenceError(f"{key} must be a non-empty string")
    digest = document["executable_sha256"]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise GeminiCapabilityEvidenceError("executable_sha256 must be lowercase SHA-256")
    _validate_timestamp(document["generated_at"])
    raw_capabilities = document["capabilities"]
    if not isinstance(raw_capabilities, Mapping):
        raise GeminiCapabilityEvidenceError("capabilities must be an object")
    unknown = sorted(set(raw_capabilities) - CAPABILITIES)
    if unknown:
        raise GeminiCapabilityEvidenceError(f"unknown Gemini capabilities: {unknown}")

    result: dict[str, CapabilityEvidence] = {}
    for capability, raw in raw_capabilities.items():
        if not isinstance(raw, Mapping) or set(raw) != {
            "status",
            "executed",
            "evidence",
            "reason",
        }:
            raise GeminiCapabilityEvidenceError(
                f"capability {capability} must declare status/executed/evidence/reason"
            )
        status = raw["status"]
        if status not in {"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"}:
            raise GeminiCapabilityEvidenceError(
                f"capability {capability} has invalid status {status!r}"
            )
        if not isinstance(raw["executed"], bool):
            raise GeminiCapabilityEvidenceError(
                f"capability {capability} executed must be boolean"
            )
        evidence = raw["evidence"]
        if (
            not isinstance(evidence, list)
            or any(not isinstance(item, str) or not item.strip() for item in evidence)
            or len(set(evidence)) != len(evidence)
        ):
            raise GeminiCapabilityEvidenceError(
                f"capability {capability} evidence must contain unique non-empty strings"
            )
        reason = raw["reason"]
        if not isinstance(reason, str):
            raise GeminiCapabilityEvidenceError(
                f"capability {capability} reason must be a string"
            )
        if status == "SUPPORTED":
            if not raw["executed"] or not evidence or reason:
                raise GeminiCapabilityEvidenceError(
                    f"SUPPORTED capability {capability} needs executed runtime evidence "
                    "and no failure reason"
                )
            reasons: tuple[str, ...] = ()
        elif status == "UNSUPPORTED":
            if not raw["executed"] or not evidence:
                raise GeminiCapabilityEvidenceError(
                    f"UNSUPPORTED capability {capability} needs executed runtime "
                    "evidence proving the absence"
                )
            if not reason.strip():
                raise GeminiCapabilityEvidenceError(
                    f"{status} capability {capability} needs a reason"
                )
            reasons = (reason,)
        else:
            if not reason.strip():
                raise GeminiCapabilityEvidenceError(
                    f"{status} capability {capability} needs a reason"
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
    """Return every Contract v1 capability without inferring support from docs/help."""

    if identity is None:
        return {
            capability: _unvalidated("Gemini CLI executable identity is unavailable")
            for capability in CAPABILITIES
        }
    if conformance_path is None or not conformance_path.is_file():
        return {
            capability: _unvalidated(
                "No version-pinned Gemini runtime conformance evidence is available",
                f"identity:{identity.executable}@{identity.version}",
            )
            for capability in CAPABILITIES
        }

    try:
        document = _read_document(conformance_path)
        entries = _validated_entries(document, evidence_path=conformance_path)
    except GeminiCapabilityEvidenceError as exc:
        return {
            capability: _unvalidated(
                f"Gemini conformance evidence is invalid: {exc}", str(conformance_path)
            )
            for capability in CAPABILITIES
        }

    observed_digest = identity.feature_flags.get("binary_sha256")
    if (
        document["harness_version"] != identity.version
        or document["executable_sha256"] != observed_digest
    ):
        return {
            capability: _unvalidated(
                "Gemini conformance evidence does not match the detected version/binary",
                str(conformance_path),
            )
            for capability in CAPABILITIES
        }

    matrix: dict[str, CapabilityEvidence] = {}
    for capability in CAPABILITIES:
        entry = entries.get(capability)
        if entry is None:
            matrix[capability] = _unvalidated(
                "Capability is absent from the version-pinned Gemini conformance evidence",
                str(conformance_path),
            )
            continue
        if capability == "headless_execution" and (
            identity.feature_flags.get("headless_prompt") is not True
        ):
            matrix[capability] = _unvalidated(
                "Detected Gemini help does not expose --prompt", str(conformance_path)
            )
            continue
        if capability == "structured_trace" and (
            identity.feature_flags.get("stream_json") is not True
        ):
            matrix[capability] = _unvalidated(
                "Detected Gemini help does not expose stream-json output",
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
    evidence: list[str] = []
    reasons: list[str] = []
    statuses: list[str] = []
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
    return status, tuple(dict.fromkeys(evidence)), tuple(dict.fromkeys(reasons))


__all__ = [
    "CapabilityEvidence",
    "GeminiCapabilityEvidenceError",
    "aggregate_required_capabilities",
    "capability_matrix",
]
