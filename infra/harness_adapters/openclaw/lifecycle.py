from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    reason: str = ""


@dataclass(frozen=True)
class SessionIdentity:
    key: str
    session_id: str


@dataclass(frozen=True)
class CompactionEvidence:
    session_key: str
    before_messages: int
    after_messages: int
    summary_sha256: str
    resumed: bool


@dataclass(frozen=True)
class SubagentEvidence:
    runtime: str
    parent_id: str
    child_id: str
    child_trace_sha256: str
    producer_artifact_sha256: str
    consumer_artifact_sha256: str


def _digest(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def validate_session_lineage(seed: SessionIdentity, resumed: SessionIdentity) -> ValidationResult:
    valid = bool(seed.key and seed.session_id and seed == resumed)
    return ValidationResult(valid, "" if valid else "session key or id changed across resume")


def validate_compaction(evidence: CompactionEvidence) -> ValidationResult:
    valid = bool(
        evidence.session_key
        and evidence.before_messages > evidence.after_messages >= 0
        and _digest(evidence.summary_sha256)
        and evidence.resumed
    )
    return ValidationResult(valid, "" if valid else "compaction lacks reduction, summary identity, or resumed turn")


def validate_native_subagent(evidence: SubagentEvidence) -> ValidationResult:
    valid = bool(
        evidence.runtime == "subagent"
        and evidence.parent_id
        and evidence.child_id
        and evidence.parent_id != evidence.child_id
        and _digest(evidence.child_trace_sha256)
        and _digest(evidence.producer_artifact_sha256)
        and evidence.producer_artifact_sha256 == evidence.consumer_artifact_sha256
    )
    return ValidationResult(valid, "" if valid else "not a complete OpenClaw-native subagent lineage")


def load_subagent_evidence(path: Path) -> SubagentEvidence:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    spawn = next((r for r in records if r.get("type") == "subagent.spawn"), {})
    handoff = next((r for r in records if r.get("type") == "artifact.handoff"), {})
    child_hash = str(spawn.get("childTraceSha256", ""))
    if not child_hash:
        child_records = [r for r in records if r.get("childId") == spawn.get("childId")]
        if child_records:
            child_hash = hashlib.sha256(
                "\n".join(json.dumps(r, sort_keys=True) for r in child_records).encode("utf-8")
            ).hexdigest()
    return SubagentEvidence(
        runtime=str(spawn.get("runtime", "")),
        parent_id=str(spawn.get("parentId", "")),
        child_id=str(spawn.get("childId", "")),
        child_trace_sha256=child_hash,
        producer_artifact_sha256=str(handoff.get("producerArtifactSha256", "")),
        consumer_artifact_sha256=str(handoff.get("consumerArtifactSha256", "")),
    )
