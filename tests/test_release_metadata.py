from pathlib import Path

from infra import check_release_metadata


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_release_docs(root: Path, *, license_text: str | None = None) -> None:
    _write(
        root / "CITATION.cff",
        "\n".join(
            [
                "cff-version: 1.2.0",
                'message: "cite Safety Bench"',
                'title: "Safety Bench"',
                "authors:",
                '  - name: "Safety Bench Authors"',
                'version: "0.1.0-preprint"',
                'date-released: "2026-06-26"',
            ]
        ),
    )
    release_refs = "\n".join(
        [
            "CITATION.cff",
            "LICENSE",
            "docs/release_metadata_final.json",
            "infra/apply_release_metadata_decisions.py",
            "check_release_metadata.py",
            "run_paper_preflight.ps1",
        ]
    )
    for rel in ["README.md", "docs/README.md"]:
        _write(root / rel, release_refs + "\n")
    _write(
        root / "docs/paper_artifact_evaluation_readme.md",
        "\n".join(
            [
                "docs/release_metadata_final.json",
                "infra/apply_release_metadata_decisions.py",
                "python infra\\check_release_metadata.py --require-license",
            ]
        )
        + "\n",
    )
    _write(root / "docs/release_metadata_final.json", '{"schema_version": 1}\n')
    if license_text is not None:
        _write(root / "LICENSE", license_text)


def _write_final_citation(root: Path) -> None:
    _write(
        root / "CITATION.cff",
        "\n".join(
            [
                "cff-version: 1.2.0",
                'message: "cite Safety Bench"',
                'title: "Safety Bench"',
                "authors:",
                '  - family-names: "Example"',
                '    given-names: "Alice"',
                'version: "1.0.0"',
                'date-released: "2026-06-26"',
                'repository-code: "https://example.com/safety-bench"',
            ]
        ),
    )


def test_release_metadata_allows_missing_license_for_current_artifact(tmp_path: Path):
    _write_release_docs(tmp_path)

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=False)

    assert report["ok"] is True
    assert report["summary"]["license_present"] is False
    assert report["summary"]["public_release_ready"] is False
    assert any(item["scope"] == "license" and item["severity"] == "warning" for item in report["issues"])
    assert any(item["id"] == "add_final_license" and item["blocks_current_check"] is False for item in report["next_actions"])
    license_action = next(item for item in report["next_actions"] if item["id"] == "add_final_license")
    assert "docs/release_metadata_final.json" in license_action["action"]
    assert "apply_release_metadata_decisions.py" in license_action["action"]


def test_release_metadata_requires_license_for_submission(tmp_path: Path):
    _write_release_docs(tmp_path)

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(item["scope"] == "license" and item["severity"] == "error" for item in report["issues"])
    assert any(item["id"] == "add_final_license" and item["blocks_current_check"] is True for item in report["next_actions"])


def test_release_metadata_warns_on_placeholder_citation_metadata(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is True
    messages = {item["message"] for item in report["issues"] if item["scope"] == "citation"}
    assert "CITATION.cff uses placeholder author metadata" in messages
    assert "CITATION.cff is still marked as preprint" in messages
    assert "CITATION.cff does not include repository URL or DOI" in messages
    assert report["summary"]["citation_placeholder_author"] is True
    assert report["summary"]["citation_preprint"] is True
    assert report["summary"]["citation_has_public_link"] is False
    action_ids = {item["id"] for item in report["next_actions"]}
    assert {"finalize_citation_authors", "finalize_version_date", "add_public_url_or_doi"} <= action_ids
    markdown = check_release_metadata.render_markdown(report)
    assert "## Finalization Commands" in markdown
    assert "apply_release_metadata_decisions.py --decision docs\\release_metadata_final.json --require-license" in markdown
    assert "apply_release_metadata_decisions.py --decision docs\\release_metadata_final.json --require-license --write" in markdown


def test_release_metadata_accepts_final_license(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is True
    assert not any(item["scope"] == "license" for item in report["issues"])


def test_release_metadata_has_no_next_actions_when_metadata_is_final(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write_final_citation(tmp_path)

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)
    markdown = check_release_metadata.render_markdown(report)

    assert report["ok"] is True
    assert report["summary"]["public_release_ready"] is True
    assert report["next_actions"] == []
    assert "public_release_ready: `true`" in markdown
    assert "## Next Actions" in markdown
    assert "- none" in markdown


def test_release_metadata_reports_optional_split_license_mapping(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write_final_citation(tmp_path)
    _write(tmp_path / "LICENSES.md", "# License Mapping\n\nAll paths use root LICENSE.\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)
    markdown = check_release_metadata.render_markdown(report)

    assert report["ok"] is True
    assert report["split_license_mapping_file"] == "LICENSES.md"
    assert report["summary"]["split_license_mapping_present"] is True
    assert report["summary"]["split_license_mapping_file"] == "LICENSES.md"
    assert report["summary"]["accepted_split_license_mapping_files"] == ["LICENSES.md", "NOTICE"]
    assert "split_license_mapping_file: `LICENSES.md`" in markdown
    assert "split_license_mapping_present: `true`" in markdown


def test_release_metadata_reports_optional_notice_mapping(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write_final_citation(tmp_path)
    _write(tmp_path / "NOTICE", "Path-specific license notices.\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is True
    assert report["split_license_mapping_file"] == "NOTICE"
    assert report["summary"]["split_license_mapping_present"] is True


def test_release_metadata_rejects_missing_citation(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    (tmp_path / "CITATION.cff").unlink()

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(item["message"] == "missing CITATION.cff" for item in report["issues"])
    assert any(item["id"] == "add_citation_file" for item in report["next_actions"])


def test_release_metadata_warns_on_missing_final_decision_file(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    (tmp_path / "docs/release_metadata_final.json").unlink()

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is True
    assert any(
        item["message"] == "missing final release metadata decision file"
        and item["detail"].get("path") == "docs/release_metadata_final.json"
        for item in report["issues"]
    )


def test_release_metadata_rejects_non_utf8_release_text(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    (tmp_path / "README.md").write_bytes(b"\xff\xfe\x00")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "text_encoding"
        and item["message"] == "release-facing text file is not UTF-8 readable"
        and item["detail"]["path"] == "README.md"
        for item in report["issues"]
    )


def test_release_metadata_rejects_likely_mojibake_release_text(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write(tmp_path / "docs/paper_current_status.md", "Safety Bench 鏄 broken\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "text_encoding"
        and item["message"] == "release-facing text file contains likely mojibake"
        and item["detail"]["path"] == "docs/paper_current_status.md"
        for item in report["issues"]
    )


def test_release_metadata_scans_canonical_manuscript_for_mojibake(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write(tmp_path / "docs/paper_draft.md", "Safety Bench 鏄 broken\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "text_encoding"
        and item["message"] == "release-facing text file contains likely mojibake"
        and item["detail"]["path"] == "docs/paper_draft.md"
        for item in report["issues"]
    )


def test_release_metadata_rejects_common_mojibake_fragments(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write(tmp_path / "docs/README.md", "# Safety Bench 鏂囨。鍏ュ彛\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "text_encoding"
        and item["message"] == "release-facing text file contains likely mojibake"
        and item["detail"]["path"] == "docs/README.md"
        for item in report["issues"]
    )


def test_release_metadata_scans_canonical_manuscript_for_replacement_character(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write(tmp_path / "docs/paper_draft.md", "Safety Bench \ufffdbroken\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "text_encoding"
        and item["message"] == "release-facing text file contains likely mojibake"
        and item["detail"]["path"] == "docs/paper_draft.md"
        for item in report["issues"]
    )


def test_release_metadata_scans_optional_notice_for_mojibake(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    _write(tmp_path / "NOTICE", "Safety Bench \ufffdbroken\n")

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "text_encoding"
        and item["message"] == "release-facing text file contains likely mojibake"
        and item["detail"]["path"] == "NOTICE"
        for item in report["issues"]
    )


def test_release_metadata_rejects_unexpanded_env_var_root_directory(tmp_path: Path):
    _write_release_docs(tmp_path, license_text="Permission is hereby granted.\n")
    (tmp_path / "%SystemDrive%" / "ProgramData").mkdir(parents=True)

    report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is False
    assert any(
        item["scope"] == "workspace_hygiene"
        and item["message"] == "repository root contains a likely unexpanded environment-variable path"
        and item["detail"]["path"] == "%SystemDrive%"
        for item in report["issues"]
    )
