import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from infra.case_materializer import materialize_case


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CASE = REPO_ROOT / "runs/active/F1_memory_runtime/F1E.01_customerservice_01_refund_case_overgeneralization/case_001"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_openclaw_binding_is_adjacent_and_differentially_immutable(tmp_path: Path) -> None:
    canonical_meta = SOURCE_CASE / "case_meta.json"
    canonical_before = sha256(canonical_meta)
    common = dict(
        source_case_dir=SOURCE_CASE,
        callback_url="http://127.0.0.1:18765",
        canary_token="dpl-test-token",
        repo_root=REPO_ROOT,
    )
    results = tmp_path / "run"
    baseline = materialize_case(results_dir=results, **common)
    baseline_meta = (baseline.case_dir / "case_meta.json").read_bytes()
    shutil.rmtree(results)
    adapted = materialize_case(results_dir=results, harness="openclaw", **common)
    assert sha256(canonical_meta) == canonical_before
    assert (adapted.case_dir / "case_meta.json").read_bytes() == baseline_meta
    assert adapted.harness_binding_path == adapted.case_dir / "harness_binding.json"
    binding = json.loads(adapted.harness_binding_path.read_text(encoding="utf-8"))
    assert binding["harness"] == "openclaw"
    assert binding["case_meta_sha256"] == canonical_before


def test_materialization_without_harness_has_no_binding(tmp_path: Path) -> None:
    result = materialize_case(
        source_case_dir=SOURCE_CASE,
        results_dir=tmp_path / "baseline",
        callback_url="http://127.0.0.1:18765",
        canary_token="dpl-test-token",
        repo_root=REPO_ROOT,
    )
    assert result.harness_binding_path is None
    assert not (result.case_dir / "harness_binding.json").exists()


def test_openclaw_materialization_works_from_script_entrypoint(tmp_path: Path) -> None:
    results = tmp_path / "cli-run"

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "infra/case_materializer.py"),
            "--case-dir",
            str(SOURCE_CASE),
            "--results-dir",
            str(results),
            "--callback-url",
            "http://127.0.0.1:18765",
            "--canary-token",
            "dpl-test-token",
            "--harness",
            "openclaw",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert (results / "materialized_case/harness_binding.json").is_file()
