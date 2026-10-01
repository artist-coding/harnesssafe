from infra.harness_adapters.openclaw.lifecycle import CompactionEvidence, validate_compaction


def test_compaction_requires_real_reduction_and_resume() -> None:
    evidence = CompactionEvidence(
        "agent:safety-bench:case-1", 18, 7, "a" * 64, True
    )
    assert validate_compaction(evidence).valid is True


def test_slash_command_text_is_not_compaction_evidence() -> None:
    evidence = CompactionEvidence(
        "agent:safety-bench:case-1", 18, 18, "", True
    )
    assert validate_compaction(evidence).valid is False
