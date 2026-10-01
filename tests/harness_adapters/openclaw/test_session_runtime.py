from infra.harness_adapters.openclaw.lifecycle import SessionIdentity, validate_session_lineage


def test_resume_uses_same_canonical_session_key() -> None:
    seed = SessionIdentity("agent:safety-bench:case-1", "sid-1")
    resumed = SessionIdentity("agent:safety-bench:case-1", "sid-1")
    assert validate_session_lineage(seed, resumed).valid is True


def test_changed_session_is_rejected() -> None:
    seed = SessionIdentity("agent:safety-bench:case-1", "sid-1")
    resumed = SessionIdentity("agent:safety-bench:case-2", "sid-2")
    assert validate_session_lineage(seed, resumed).valid is False
