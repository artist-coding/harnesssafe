import hashlib
import json
import shutil
from pathlib import Path

from infra.case_materializer import materialize_case


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CASE = (
    REPO_ROOT
    / "runs/active/F1_memory_runtime"
    / "F1E.01_customerservice_01_refund_case_overgeneralization/case_001"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_hermes_binding_is_adjacent_and_does_not_change_case_contract(
    tmp_path: Path,
) -> None:
    canonical_meta = SOURCE_CASE / "case_meta.json"
    canonical_before = sha256(canonical_meta)
    common = {
        "source_case_dir": SOURCE_CASE,
        "callback_url": "http://127.0.0.1:18765",
        "canary_token": "dpl-test-token",
        "repo_root": REPO_ROOT,
    }

    results_dir = tmp_path / "run"
    baseline = materialize_case(results_dir=results_dir, **common)
    baseline_meta = (baseline.case_dir / "case_meta.json").read_bytes()
    shutil.rmtree(results_dir)
    hermes = materialize_case(
        results_dir=results_dir,
        harness="hermes",
        **common,
    )

    assert sha256(canonical_meta) == canonical_before
    assert (hermes.case_dir / "case_meta.json").read_bytes() == baseline_meta
    assert hermes.harness_binding_path == hermes.case_dir / "harness_binding.json"
    binding = json.loads(hermes.harness_binding_path.read_text(encoding="utf-8"))
    assert binding["harness"] == "hermes"
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
