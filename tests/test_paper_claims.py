from pathlib import Path

from infra import check_paper_claims


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_current_claim_docs(root: Path) -> None:
    _write(
        root / "docs/paper_draft.md",
        "\n".join(
            [
                "# Safety Bench: Persistent Agent-Harness Poisoning",
                "The benchmark contains 328 active hard-oracle cases.",
                "The protocol uses one attack trial per case and Evaluation Record v3.",
                "Protocol noncompletion is outside N0-N5b.",
                "Report conditional ASR and end-to-end attack rate.",
                "## 6. 328-Case Attack Results",
                "The completed results are reported here.",
            ]
        ),
    )
    _write(
        root / "docs/paper_artifact_evaluation_readme.md",
        "\n".join(
            [
                "The artifact contains 328 active hard-oracle cases and uses one attack trial per case.",
                "Use CaseSet=all.",
                "Evaluation Record v3 reports protocol-noncompletion and execution-invalid rows separately.",
            ]
        ),
    )
    _write(
        root / "docs/paper_current_status.md",
        "\n".join(
            [
                "The trial budget is one attack trial per case.",
                "Evaluation Record v3 is the result contract.",
                "Both configurations attempted all 328 cases.",
                "Protocol-noncompletion and execution invalid rows are disclosed separately.",
            ]
        ),
    )


def _write_finalized_claim_docs(root: Path) -> None:
    _write_current_claim_docs(root)


def test_current_claim_profile_accepts_reported_v3_boundary(tmp_path: Path):
    _write_current_claim_docs(tmp_path)

    report = check_paper_claims.build_claim_report(tmp_path, profile="current_claude")

    assert report["ok"] is True
    assert report["issues"] == []


def test_current_claim_profile_rejects_missing_v3_contract(tmp_path: Path):
    _write_current_claim_docs(tmp_path)
    draft = tmp_path / "docs/paper_draft.md"
    draft.write_text(
        draft.read_text(encoding="utf-8").replace("Evaluation Record v3", "legacy report"),
        encoding="utf-8",
    )

    report = check_paper_claims.build_claim_report(tmp_path, profile="current_claude")

    assert report["ok"] is False
    assert any(
        item["message"] == "required claim-boundary phrase is missing"
        and item["detail"].get("phrase") == "Evaluation Record v3"
        for item in report["issues"]
    )


def test_current_claim_profile_rejects_legacy_matrix_language(tmp_path: Path):
    _write_current_claim_docs(tmp_path)
    draft = tmp_path / "docs/paper_draft.md"
    draft.write_text(
        draft.read_text(encoding="utf-8") + "\n| planned rows | 399 |\n",
        encoding="utf-8",
    )

    report = check_paper_claims.build_claim_report(tmp_path, profile="current_claude")

    assert report["ok"] is False
    assert any(
        item["message"] == "submission profile still contains current/preliminary claim language"
        and item["detail"].get("phrase") == "| planned rows | 399 |"
        for item in report["issues"]
    )


def test_submission_claim_profile_rejects_pending_formal_matrix(tmp_path: Path):
    _write_current_claim_docs(tmp_path)
    draft = tmp_path / "docs/paper_draft.md"
    draft.write_text(
        draft.read_text(encoding="utf-8") + "\nRESULTS_PENDING_FORMAL_MATRIX\n",
        encoding="utf-8",
    )
    readme = tmp_path / "docs/paper_artifact_evaluation_readme.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nThe formal result matrix has not yet been executed.\n",
        encoding="utf-8",
    )

    report = check_paper_claims.build_claim_report(tmp_path, profile="submission")

    assert report["ok"] is False
    phrases = {item["detail"].get("phrase") for item in report["issues"]}
    assert "RESULTS_PENDING_FORMAL_MATRIX" in phrases
    assert "formal result matrix has not yet been executed" in phrases


def test_submission_claim_profile_accepts_finalized_language(tmp_path: Path):
    _write_finalized_claim_docs(tmp_path)

    report = check_paper_claims.build_claim_report(tmp_path, profile="submission")

    assert report["ok"] is True
    assert report["issues"] == []


def test_current_claim_profile_accepts_case_design_freeze_language(tmp_path: Path):
    _write_current_claim_docs(tmp_path)
    _write(tmp_path / "runs/manifest.json", '{"description":"Active frozen-scope 328-case suite"}\n')

    report = check_paper_claims.build_claim_report(tmp_path, profile="current_claude")

    assert report["ok"] is True


def test_stale_scope_gate_rejects_unlabeled_former_denominator(tmp_path: Path):
    _write(tmp_path / "docs/current_scope.md", "The formal suite contains 358 active cases.\n")

    issues = check_paper_claims.check_stale_scope_references(tmp_path)

    assert len(issues) == 1
    assert issues[0]["message"] == "stale former formal-scope reference is not labeled as provenance"


def test_stale_scope_gate_scans_root_operational_docs(tmp_path: Path):
    _write(tmp_path / "README.md", "The formal suite contains 358 active cases.\n")

    issues = check_paper_claims.check_stale_scope_references(tmp_path)

    assert len(issues) == 1
    assert issues[0]["path"] == "README.md"


def test_stale_scope_gate_allows_explicit_historical_provenance(tmp_path: Path):
    _write(
        tmp_path / "docs/history.md",
        "# History\n\nHistorical former scope: 358 active cases.\n",
    )

    assert check_paper_claims.check_stale_scope_references(tmp_path) == []


def test_stale_scope_gate_does_not_parse_sha256_substrings_as_counts(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir(parents=True)
    (docs / "content_lock.json").write_text(
        '{"sha256":"53ec5ac519e5d36f5fcdc172f1a6e4de16b358c106e2c6445ba84874eb6e0fe9"}',
        encoding="utf-8",
    )

    assert check_paper_claims.check_stale_scope_references(tmp_path) == []


def test_prefreeze_claim_gate_rejects_positive_claim_but_allows_explicit_negation(
    tmp_path: Path,
):
    _write(
        tmp_path / "runs/manifest.json",
        '{"description":"Active frozen-scope 328-case suite"}\n',
    )
    _write(
        tmp_path / "docs/paper_current_status.md",
        'We cannot declare "328-case benchmark design is frozen" yet.\n',
    )

    issues = check_paper_claims.check_premature_freeze_claims(tmp_path)

    assert len(issues) == 1
    assert issues[0]["path"] == "runs/manifest.json"
    assert issues[0]["detail"]["phrase"] == "frozen-scope"


def test_prefreeze_claim_gate_rejects_positive_matrix_completion(tmp_path: Path):
    _write(
        tmp_path / "docs/paper_current_status.md",
        "The formal 328-case experiment matrix is complete.\n",
    )

    issues = check_paper_claims.check_premature_freeze_claims(tmp_path)

    assert len(issues) == 1
    assert "premature freeze/completion claim" in issues[0]["message"]


def test_formal_serial_command_gate_rejects_harness_filtered_execute(tmp_path: Path):
    _write(
        tmp_path / "README.md",
        "python infra\\run_paper_queue.py --queue plan.json --queue-mode serial "
        "--harness claude --execute\n",
    )

    issues = check_paper_claims.check_formal_serial_execution_commands(tmp_path)

    assert len(issues) == 1
    assert issues[0]["path"] == "README.md"
    assert issues[0]["detail"]["switches"] == ["--harness"]


def test_formal_serial_command_gate_allows_unfiltered_execute_and_post_run_filter(
    tmp_path: Path,
):
    _write(
        tmp_path / "docs/execution.md",
        "\n".join(
            [
                "python infra\\run_paper_queue.py --queue plan.json --queue-mode serial --execute",
                "python infra\\run_paper_queue.py --queue plan.json --queue-mode post-run "
                "--harness claude --execute",
            ]
        ),
    )

    assert check_paper_claims.check_formal_serial_execution_commands(tmp_path) == []
