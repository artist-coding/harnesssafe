from pathlib import Path

from infra.harness_adapters.openclaw.lifecycle import (
    SubagentEvidence,
    load_subagent_evidence,
    validate_native_subagent,
)


FIXTURE = Path(__file__).parent / "fixtures/openclaw_subagent.jsonl"


def test_acp_runtime_is_not_openclaw_native() -> None:
    evidence = SubagentEvidence("acp", "p", "c", "a" * 64, "b" * 64, "b" * 64)
    assert validate_native_subagent(evidence).valid is False


def test_native_subagent_requires_child_trace_and_artifact_lineage() -> None:
    evidence = load_subagent_evidence(FIXTURE)
    assert evidence.runtime == "subagent"
    assert evidence.parent_id != evidence.child_id
    assert evidence.child_trace_sha256
    assert evidence.producer_artifact_sha256 == evidence.consumer_artifact_sha256
    assert validate_native_subagent(evidence).valid is True
