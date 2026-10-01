from pathlib import Path

from infra import check_paper_bibliography


CLOSEST_NOVELTY_KEYS = {
    "chen2024agentpoison",
    "dong2025minja",
    "xie2026memevobench",
    "pulipaka2026hiddenmemory",
    "karamchandani2026farma",
    "louck2026memoryauthority",
    "dai2026statefulbackdoor",
    "li2026plantpersisttrigger",
    "schmotz2026skillinject",
    "qu2026skillsupplychain",
    "xie2026scrbench",
    "jamshidi2025mcpsemantic",
    "huang2026mcptoolpoisoning",
    "liu2026sharelock",
    "lee2024promptinfection",
    "deng2026openclaw",
    "zhang2024asb",
}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_valid_bibliography_fixture(root: Path) -> None:
    entries = []
    for key in check_paper_bibliography.REQUIRED_BIB_KEYS:
        entries.append(f"@misc{{{key},\n  title = {{{key}}}\n}}\n")
    _write(root / "docs/paper_bibliography.bib", "\n".join(entries))
    citations = " ".join(
        f"`{key}`" for key in check_paper_bibliography.REQUIRED_BIB_KEYS
    )
    _write(root / "docs/paper_draft.md", f"# Canonical manuscript\n\n{citations}\n")


def test_closest_novelty_comparators_are_mandatory():
    assert CLOSEST_NOVELTY_KEYS <= set(check_paper_bibliography.REQUIRED_BIB_KEYS)


def test_bibliography_check_accepts_citations_in_canonical_draft(tmp_path: Path):
    _write_valid_bibliography_fixture(tmp_path)

    report = check_paper_bibliography.build_bibliography_report(tmp_path)

    assert report["ok"] is True
    assert report["missing_required_bib_keys"] == []
    assert report["missing_related_work_keys"] == []
    assert report["unknown_cited_keys"] == []
    assert report["unused_required_keys"] == []
    assert [item["path"] for item in report["source_docs"]] == [
        "docs/paper_draft.md"
    ]


def test_bibliography_check_rejects_missing_required_bib_key(tmp_path: Path):
    _write_valid_bibliography_fixture(tmp_path)
    bib = (tmp_path / "docs/paper_bibliography.bib").read_text(encoding="utf-8")
    (tmp_path / "docs/paper_bibliography.bib").write_text(
        bib.replace("@misc{greshake2023indirect,", "@misc{missingkey2026,"),
        encoding="utf-8",
    )

    report = check_paper_bibliography.build_bibliography_report(tmp_path)

    assert report["ok"] is False
    assert "greshake2023indirect" in report["missing_required_bib_keys"]
    assert any(
        item["message"] == "required BibTeX key is missing"
        for item in report["issues"]
    )


def test_bibliography_check_rejects_unknown_key_in_canonical_draft(tmp_path: Path):
    _write_valid_bibliography_fixture(tmp_path)
    draft = tmp_path / "docs/paper_draft.md"
    draft.write_text(
        draft.read_text(encoding="utf-8") + "\n`unknown2026work`\n",
        encoding="utf-8",
    )

    report = check_paper_bibliography.build_bibliography_report(tmp_path)

    assert report["ok"] is False
    assert report["unknown_cited_keys"] == ["unknown2026work"]
    assert any(
        item["message"] == "cited key is missing from BibTeX bibliography"
        for item in report["issues"]
    )


def test_bibliography_check_rejects_placeholder_in_canonical_draft(tmp_path: Path):
    _write_valid_bibliography_fixture(tmp_path)
    draft = tmp_path / "docs/paper_draft.md"
    draft.write_text(
        draft.read_text(encoding="utf-8") + "\n[CITE]\n",
        encoding="utf-8",
    )

    report = check_paper_bibliography.build_bibliography_report(tmp_path)

    assert report["ok"] is False
    assert any(
        item["message"] == "citation source contains unresolved placeholder"
        and item["detail"]["path"] == "docs/paper_draft.md"
        for item in report["issues"]
    )
