import json
from pathlib import Path

from infra import apply_release_metadata_decisions as apply_release
from infra import check_release_metadata


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _release_docs(root: Path) -> None:
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
        )
        + "\n",
    )
    release_refs = (
        "CITATION.cff\n"
        "LICENSE\n"
        "docs/release_metadata_final.json\n"
        "infra/apply_release_metadata_decisions.py\n"
        "check_release_metadata.py\n"
        "run_paper_preflight.ps1\n"
    )
    _write(root / "README.md", release_refs)
    _write(root / "docs/README.md", release_refs)
    _write(
        root / "docs/paper_artifact_evaluation_readme.md",
        "docs/release_metadata_final.json\n"
        "infra/apply_release_metadata_decisions.py\n"
        "python infra\\check_release_metadata.py --require-license\n",
    )
    _write(root / "docs/release_metadata_final.json", '{"schema_version": 1}\n')


def _decision() -> dict:
    return {
        "citation": {
            "title": "Safety Bench: A Persistent-Poisoning Benchmark for Agent Harnesses",
            "authors": [
                {
                    "family-names": "Example",
                    "given-names": "Alice",
                    "orcid": "https://orcid.org/0000-0000-0000-0000",
                },
                {
                    "family-names": "Example",
                    "given-names": "Bob",
                },
            ],
            "version": "1.0.0",
            "date-released": "2026-06-27",
            "repository-code": "https://example.com/safety-bench",
            "doi": "10.0000/example.safetybench",
        },
        "license": {
            "path": "LICENSE",
            "text": "Permission is hereby granted, free of charge, to any person obtaining a copy.",
        },
        "split_license_mapping": {
            "path": "LICENSES.md",
            "text": "# License Mapping\n\nAll paths use the root LICENSE unless stated otherwise.",
        },
    }


def test_apply_release_metadata_decisions_dry_run_does_not_write(tmp_path: Path):
    _release_docs(tmp_path)
    decision_path = tmp_path / "release_decision.json"
    _write(decision_path, json.dumps(_decision()))
    original_citation = (tmp_path / "CITATION.cff").read_text(encoding="utf-8")

    report = apply_release.build_report(tmp_path, decision_path, require_license=True)

    assert report["ok"] is True
    assert report["written"] is False
    assert [item["path"] for item in report["changes"]] == ["CITATION.cff", "LICENSE", "LICENSES.md"]
    assert (tmp_path / "CITATION.cff").read_text(encoding="utf-8") == original_citation
    assert not (tmp_path / "LICENSE").exists()


def test_apply_release_metadata_decisions_write_produces_final_release_metadata(tmp_path: Path):
    _release_docs(tmp_path)
    decision_path = tmp_path / "release_decision.json"
    _write(decision_path, json.dumps(_decision()))

    report = apply_release.build_report(tmp_path, decision_path, write=True, require_license=True)
    release_report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)
    citation_text = (tmp_path / "CITATION.cff").read_text(encoding="utf-8")

    assert report["ok"] is True
    assert report["written"] is True
    assert 'family-names: "Example"' in citation_text
    assert 'version: "1.0.0"' in citation_text
    assert 'repository-code: "https://example.com/safety-bench"' in citation_text
    assert (tmp_path / "LICENSE").is_file()
    assert (tmp_path / "LICENSES.md").is_file()
    assert release_report["ok"] is True
    assert release_report["summary"]["public_release_ready"] is True
    assert release_report["summary"]["split_license_mapping_present"] is True
    assert release_report["summary"]["split_license_mapping_file"] == "LICENSES.md"


def test_apply_release_metadata_decisions_accepts_notice_mapping(tmp_path: Path):
    _release_docs(tmp_path)
    decision = _decision()
    decision["split_license_mapping"] = {
        "path": "NOTICE",
        "text": "Path-specific license notices.",
    }
    decision_path = tmp_path / "release_decision.json"
    _write(decision_path, json.dumps(decision))

    report = apply_release.build_report(tmp_path, decision_path, write=True, require_license=True)
    release_report = check_release_metadata.build_release_metadata_report(tmp_path, require_license=True)

    assert report["ok"] is True
    assert (tmp_path / "NOTICE").is_file()
    assert release_report["ok"] is True
    assert release_report["summary"]["split_license_mapping_file"] == "NOTICE"


def test_apply_release_metadata_decisions_requires_public_link_and_final_version(tmp_path: Path):
    _release_docs(tmp_path)
    bad = _decision()
    bad["citation"].pop("doi")
    bad["citation"].pop("repository-code")
    bad["citation"]["version"] = "0.1.0-preprint"
    decision_path = tmp_path / "release_decision.json"
    _write(decision_path, json.dumps(bad))

    report = apply_release.build_report(tmp_path, decision_path, require_license=True)

    assert report["ok"] is False
    messages = {item["message"] for item in report["issues"]}
    assert "citation version must be finalized and non-preprint" in messages
    assert "citation must include at least one public repository, artifact URL, or DOI field" in messages


def test_apply_release_metadata_decisions_rejects_unsafe_paths(tmp_path: Path):
    _release_docs(tmp_path)
    bad = _decision()
    bad["license"]["path"] = "docs/LICENSE"
    bad["split_license_mapping"]["path"] = "../NOTICE"
    decision_path = tmp_path / "release_decision.json"
    _write(decision_path, json.dumps(bad))

    report = apply_release.build_report(tmp_path, decision_path, require_license=True)

    assert report["ok"] is False
    assert any(item["scope"] == "license" for item in report["issues"])
    assert any(item["scope"] == "split_license_mapping" for item in report["issues"])


def test_apply_release_metadata_decisions_rejects_example_only_decision(tmp_path: Path):
    _release_docs(tmp_path)
    decision = _decision()
    decision["example_only"] = True
    decision_path = tmp_path / "release_decision.json"
    _write(decision_path, json.dumps(decision))

    report = apply_release.build_report(tmp_path, decision_path, require_license=True)

    assert report["ok"] is False
    assert report["changes"] == []
    assert any(item["scope"] == "inputs" and "example_only" in item["message"] for item in report["issues"])


def test_release_metadata_example_json_is_not_directly_applicable(tmp_path: Path):
    _release_docs(tmp_path)
    decision = _decision()
    decision["example_only"] = True
    decision_path = tmp_path / "release_metadata_final.example.json"
    _write(decision_path, json.dumps(decision))

    report = apply_release.build_report(
        tmp_path,
        decision_path,
        require_license=True,
    )

    assert report["ok"] is False
    assert report["changes"] == []
    messages = {item["message"] for item in report["issues"]}
    assert any("example_only" in message for message in messages)
