from pathlib import Path

from infra import check_paper_manuscript


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _valid_draft() -> str:
    sections = "\n\n".join(check_paper_manuscript.REQUIRED_SECTIONS)
    phrases = "\n".join(check_paper_manuscript.REQUIRED_PHRASES)
    tables = "\n".join(
        [
            "| A | B |",
            "| --- | --- |",
            "| 1 | 2 |",
            "| C | D |",
            "| --- | --- |",
            "| 3 | 4 |",
        ]
    )
    return f"{sections}\n\n{phrases}\n\n{tables}\n"


def test_manuscript_check_accepts_complete_fixture(tmp_path: Path):
    draft = tmp_path / "docs/paper_draft.md"
    _write(draft, _valid_draft())

    report = check_paper_manuscript.build_manuscript_report(tmp_path, draft=draft)

    assert report["ok"] is True, report["issues"]
    assert report["issues"] == []


def test_repository_canonical_manuscript_passes():
    draft = Path("docs/paper_draft.md")

    report = check_paper_manuscript.build_manuscript_report(draft=draft)

    assert draft.is_file()
    assert report["ok"] is True, report["issues"]
    assert report["issues"] == []


def test_manuscript_check_rejects_missing_v3_result_contract(tmp_path: Path):
    draft = tmp_path / "docs/paper_draft.md"
    _write(
        draft,
        _valid_draft().replace(
            "Evaluation Record v3", "legacy result contract"
        ),
    )

    report = check_paper_manuscript.build_manuscript_report(tmp_path, draft=draft)

    assert report["ok"] is False
    assert any(
        item["message"] == "required manuscript support phrase is missing"
        and item["detail"]["phrase"] == "Evaluation Record v3"
        for item in report["issues"]
    )


def test_manuscript_check_rejects_forbidden_placeholder(tmp_path: Path):
    draft = tmp_path / "docs/paper_draft.md"
    _write(draft, _valid_draft() + "\nTODO: finish this later\n")

    report = check_paper_manuscript.build_manuscript_report(tmp_path, draft=draft)

    assert report["ok"] is False
    assert any(
        item["message"] == "manuscript contains unresolved or obsolete language"
        and item["detail"]["phrase"] == "TODO"
        for item in report["issues"]
    )


def test_manuscript_check_rejects_analysis_draft_status(tmp_path: Path):
    draft = tmp_path / "docs/paper_draft.md"
    _write(draft, _valid_draft() + "\nManuscript status: analysis draft\n")

    report = check_paper_manuscript.build_manuscript_report(tmp_path, draft=draft)

    assert report["ok"] is False
    assert any(
        item["message"] == "manuscript contains unresolved or obsolete language"
        and item["detail"]["phrase"] == "analysis draft"
        for item in report["issues"]
    )
