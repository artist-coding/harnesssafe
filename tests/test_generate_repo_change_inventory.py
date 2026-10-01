from infra import generate_repo_change_inventory as inventory


def test_parse_status_lines_handles_untracked_modified_and_renamed():
    entries = inventory.parse_status_lines(
        [
            " M .gitignore",
            " M docs/paper_draft.md",
            "?? docs/generated_artifacts/paper_full_suite_eligibility.md",
            "R  old/path.md -> docs/new_path.md",
        ]
    )

    assert entries == [
        {"status": " M", "status_text": "worktree:M", "path": ".gitignore"},
        {"status": " M", "status_text": "worktree:M", "path": "docs/paper_draft.md"},
        {"status": "??", "status_text": "untracked", "path": "docs/generated_artifacts/paper_full_suite_eligibility.md"},
        {"status": "R ", "status_text": "index:R", "path": "docs/new_path.md"},
    ]


def test_classify_path_groups_release_paper_cases_and_local_state():
    assert inventory.classify_path(".gitignore") == "entrypoint_docs"
    assert inventory.classify_path("CITATION.cff") == "release_metadata"
    assert inventory.classify_path("LICENSE") == "release_metadata"
    assert inventory.classify_path("LICENSES.md") == "release_metadata"
    assert inventory.classify_path("NOTICE") == "release_metadata"
    assert inventory.classify_path("docs/release_metadata_final.json") == "release_metadata"
    assert inventory.classify_path("docs/paper_draft.md") == "paper_artifacts"
    assert inventory.classify_path("docs/generated_artifacts/paper_full_suite_eligibility.md") == "paper_artifacts"
    assert inventory.classify_path("docs/generated_artifacts/repo_change_inventory.md") == "repo_cleanup"
    assert inventory.classify_path("infra/apply_release_metadata_decisions.py") == "paper_infra"
    assert inventory.classify_path("infra/check_paper_artifact_gate.py") == "paper_infra"
    assert inventory.classify_path("infra/plan_external_validity_calibration.py") == "paper_infra"
    assert inventory.classify_path("tests/test_apply_release_metadata_decisions.py") == "paper_tests"
    assert inventory.classify_path("tests/test_paper_artifact_gate.py") == "paper_tests"
    assert inventory.classify_path("tests/test_plan_external_validity_calibration.py") == "paper_tests"
    assert inventory.classify_path("runs/active/F2_skill_runtime/case/config/deployment.id") == "active_cases"
    assert inventory.classify_path("bench_state/secrets/local.env") == "local_state_exclude"


def test_build_inventory_adds_logical_commit_and_policy():
    report = inventory.build_inventory(
        [
            "?? CITATION.cff",
            "?? docs/release_metadata_final.json",
            "?? docs/paper_draft.md",
            "?? bench_state/secrets/token.txt",
        ]
    )

    assert report["summary"]["changed_entries"] == 4
    assert report["summary"]["do_not_commit_entries"] == 1
    assert report["summary"]["manual_review_entries"] == 0
    entries_by_path = {entry["path"]: entry for entry in report["entries"]}
    assert entries_by_path["CITATION.cff"]["logical_commit"] == "release-metadata-handoff"
    assert entries_by_path["docs/release_metadata_final.json"]["logical_commit"] == "release-metadata-handoff"
    assert entries_by_path["docs/paper_draft.md"]["logical_commit"] == "paper-docs-and-evidence"
    assert entries_by_path["bench_state/secrets/token.txt"]["include_policy"] == "do_not_commit"
    staging = report["release_staging_plan"]
    assert staging["do_not_commit_entries"] == 1
    assert staging["manual_review_entries"] == 0
    assert staging["pathspec_dir"] == "docs/generated_artifacts/repo_release_stage_pathspecs"
    assert "python infra\\check_repo_release_cleanliness.py --require-clean --require-release-metadata" in staging["validation_commands"]
    assert ".\\infra\\run_paper_preflight.ps1 -Profile submission" in staging["validation_commands"]
    assert "public repository, artifact URL, or DOI" in staging["release_blockers"]
    assert "clean handling of do-not-commit local state" in staging["release_blockers"]
    assert [item["logical_commit"] for item in staging["ordered_logical_commits"]] == [
        "paper-docs-and-evidence",
        "release-metadata-handoff",
    ]
    assert [item["logical_commit"] for item in staging["stage_groups"]] == [
        "paper-docs-and-evidence",
        "release-metadata-handoff",
    ]
    assert all("bench_state/secrets/token.txt" not in item["paths"] for item in staging["stage_groups"])


def test_release_blockers_omit_local_state_when_inventory_is_clean():
    report = inventory.build_inventory(
        [
            "?? docs/paper_draft.md",
            "?? CITATION.cff",
        ]
    )

    blockers = report["release_staging_plan"]["release_blockers"]

    assert "final root LICENSE and CITATION metadata" in blockers
    assert "public repository, artifact URL, or DOI" in blockers
    assert "passing submission preflight" in blockers
    assert "clean handling of do-not-commit local state" not in blockers
    assert "manual review bucket resolved" not in blockers


def test_render_markdown_calls_out_do_not_commit_entries():
    report = inventory.build_inventory(
        [
            "?? docs/paper_draft.md",
            "?? bench_state/secrets/token.txt",
        ]
    )

    markdown = inventory.render_markdown(report)

    assert "Repo Change Inventory" in markdown
    assert "Recommended Logical Commits" in markdown
    assert "Release Staging Procedure" in markdown
    assert "Pathspec staging commands" in markdown
    assert "do_not_commit_entries: `1`" in markdown
    assert "`bench_state/secrets/token.txt`" in markdown
    assert "git add --pathspec-from-file docs/generated_artifacts/repo_release_stage_pathspecs/paper-docs-and-evidence.txt" in markdown
    assert "check_repo_release_cleanliness.py --require-clean --require-release-metadata" in markdown
    assert ".\\infra\\run_paper_preflight.ps1 -Profile submission" in markdown
    assert "tag the release and mint the public artifact DOI/URL" in markdown


def test_write_outputs_writes_stage_pathspec_files(tmp_path):
    report = inventory.build_inventory(
        [
            "?? docs/paper_draft.md",
            "?? tests/test_paper_docs.py",
            "?? bench_state/secrets/token.txt",
        ],
        root=tmp_path,
        stage_dir=tmp_path / "stage-pathspecs",
    )

    inventory.write_outputs(
        report,
        tmp_path / "docs/generated_artifacts/repo_change_inventory.json",
        tmp_path / "docs/generated_artifacts/repo_change_inventory.md",
        tmp_path / "stage-pathspecs",
    )

    paper_docs = (tmp_path / "stage-pathspecs/paper-docs-and-evidence.txt").read_text(encoding="utf-8")
    paper_infra = (tmp_path / "stage-pathspecs/paper-infra-and-gates.txt").read_text(encoding="utf-8")
    assert "docs/paper_draft.md\n" == paper_docs
    assert "tests/test_paper_docs.py\n" == paper_infra
    assert not (tmp_path / "stage-pathspecs/do-not-commit.txt").exists()
