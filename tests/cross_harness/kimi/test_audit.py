from __future__ import annotations

import json
from pathlib import Path

import pytest

from infra.cross_harness.adapters.kimi import audit


def _fake_inventory(case_dir: Path) -> dict:
    return {
        "inventory_content_sha256": "a" * 64,
        "cases": [
            {
                "case_id": "fixture_case",
                "suite": "fixture_suite",
                "case_dir": case_dir.as_posix(),
            }
        ],
    }


def _install_one_case_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    repo: Path,
) -> Path:
    relative = Path("runs/active/fixture_suite/fixture_case")
    canonical = repo / relative
    (canonical / "workspace").mkdir(parents=True)
    (canonical / "case_meta.json").write_text(
        '{"case_id":"fixture_case","user_prompt":"fixture"}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(audit, "EXPECTED_CASE_COUNT", 1)
    monkeypatch.setattr(audit, "EXPECTED_STAGE_COUNT", 1)
    monkeypatch.setattr(
        audit,
        "load_frozen_inventory",
        lambda _repo, verify_live: _fake_inventory(relative),
    )
    def materialize(**kwargs: object) -> dict:
        assert kwargs["case_dir"] == canonical.resolve()
        assert kwargs["capability_states"]
        run_dir = Path(str(kwargs["run_dir"]))
        run_dir.mkdir(parents=True)
        artifact = run_dir / "materialized.txt"
        artifact.write_text("fixture\n", encoding="utf-8")
        manifest = run_dir / f"manifest-kimi-{kwargs['run_id']}.json"
        manifest.write_text('{"fixture":true}\n', encoding="utf-8")
        return {
            "disposition": "READY",
            "disposition_reasons": [],
            "stages": [{"index": 0, "name": "fixture"}],
            "manifest_path": str(manifest),
            "materialized": {"tree_sha256": audit.tree_sha256(run_dir)},
            "semantic_binding": None,
        }

    monkeypatch.setattr(audit, "materialize_bench_case", materialize)
    return canonical


def test_static_audit_is_hash_bound_and_never_claims_runtime_or_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    _install_one_case_fakes(monkeypatch, repo=repo)
    result = audit.run_static_materialization_audit(
        repo_root=repo,
        result_root=tmp_path / "results",
        run_id="audit-001",
    )

    assert result["valid"] is True
    assert result["case_count_succeeded"] == 1
    assert result["stage_count_materialized"] == 1
    assert result["plan_dispositions"] == {"READY": 1}
    assert result["canonical_hashes_unchanged"] is True
    assert result["formal_runtime_readiness_claimed"] is False
    assert result["scoring_status"] == "NOT_PRODUCED"
    assert result["external_model_started"] is False
    assert result["credentials_used"] is False
    assert result["network_request_made"] is False
    assert result["network_service_started"] is False
    assert result["callback_url_is_materialization_placeholder_only"] is True
    loaded = audit.load_static_materialization_audit(Path(result["summary_path"]))
    assert loaded["audit_payload_sha256"] == result["audit_payload_sha256"]


def test_static_audit_rejects_summary_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    _install_one_case_fakes(monkeypatch, repo=repo)
    result = audit.run_static_materialization_audit(
        repo_root=repo,
        result_root=tmp_path / "results",
        run_id="audit-002",
    )
    path = Path(result["summary_path"])
    document = json.loads(path.read_text(encoding="utf-8"))
    document["valid"] = False
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(audit.KimiStaticAuditError, match="self-hash"):
        audit.load_static_materialization_audit(path)


def test_static_audit_refuses_nonempty_run_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    _install_one_case_fakes(monkeypatch, repo=repo)
    result_root = tmp_path / "results"
    run_dir = result_root / "kimi-audit-003"
    run_dir.mkdir(parents=True)
    (run_dir / "preexisting-kimi-audit-003.txt").write_text(
        "owned by another attempt\n", encoding="utf-8"
    )
    with pytest.raises(audit.KimiStaticAuditError, match="non-empty"):
        audit.run_static_materialization_audit(
            repo_root=repo,
            result_root=result_root,
            run_id="audit-003",
        )


def test_cli_exposes_credential_free_materialization_audit() -> None:
    from infra.cross_harness.adapters.kimi.cli import build_parser

    args = build_parser().parse_args(
        ["audit-materialization", "--run-id", "audit-cli-001"]
    )
    assert args.command == "audit-materialization"
    assert args.run_id == "audit-cli-001"
