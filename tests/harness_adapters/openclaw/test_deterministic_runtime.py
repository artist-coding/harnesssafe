from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from fake_openclaw import run_fake_openclaw_case


def test_deterministic_openclaw_pipeline_never_scores(tmp_path: Path) -> None:
    result = run_fake_openclaw_case(tmp_path)
    assert result.run_validity["valid"] is True
    assert result.adapter_record["scoring_status"] == "NOT_PRODUCED"
    assert result.cleanup["live_owned_processes"] == []
    assert result.canonical_hash_before == result.canonical_hash_after
