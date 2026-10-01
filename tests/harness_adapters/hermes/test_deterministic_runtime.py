import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from infra.case_materializer import materialize_case
from infra.harness_adapters.hermes.events import (
    EventProvenance,
    normalize_session,
    write_event_ir,
)
from infra.harness_adapters.hermes.launch import LaunchContext, build_launch_spec
from infra.harness_adapters.hermes.model import CapabilityEvidence, HermesCapabilities


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CASE = (
    REPO_ROOT
    / "runs/active/F1_memory_runtime"
    / "F1E.01_customerservice_01_refund_case_overgeneralization/case_001"
)
FAKE_HERMES = Path(__file__).parent / "fake_hermes.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capabilities() -> HermesCapabilities:
    evidence = CapabilityEvidence(True, "deterministic_fixture", str(FAKE_HERMES))
    return HermesCapabilities(*([evidence] * 7))


def run_fake_hermes_case(tmp_path: Path) -> SimpleNamespace:
    canonical_hash_before = sha256(SOURCE_CASE / "case_meta.json")
    materialized = materialize_case(
        SOURCE_CASE,
        tmp_path / "run",
        "http://127.0.0.1:18765",
        "dpl-test-token",
        repo_root=REPO_ROOT,
        harness="hermes",
    )
    hermes_home = tmp_path / "hermes-home"
    spec = build_launch_spec(
        {"user_prompt": "Inspect the workspace.", "runtime_mode": "fresh"},
        LaunchContext(
            hermes_python=Path(sys.executable),
            hermes_launcher=FAKE_HERMES,
            hermes_home=hermes_home,
            workspace_dir=materialized.workspace_dir,
            model="fixture-model",
            provider_base_url="http://127.0.0.1:1/v1",
            timeout_sec=30,
            secret_env={"OPENAI_API_KEY": "fixture-secret"},
        ),
        capabilities(),
    )
    Path(spec.config_path).parent.mkdir(parents=True, exist_ok=True)
    Path(spec.config_path).write_text(spec.config_text, encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "HERMES_HOME": str(hermes_home),
            "OPENAI_API_KEY": "fixture-secret",
            "FAKE_HERMES_ENV_RECORD": str(tmp_path / "environment.json"),
        }
    )
    completed = subprocess.run(
        [spec.executable, *spec.argv],
        cwd=materialized.workspace_dir,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0
    session_path = hermes_home / "sessions/session_fixture-session.json"
    raw = json.loads(session_path.read_text(encoding="utf-8"))
    event_path = tmp_path / "run/event_ir.jsonl"
    write_event_ir(
        normalize_session(raw, EventProvenance("fixture", 1, session_path)),
        event_path,
    )
    env_record = json.loads(
        (tmp_path / "environment.json").read_text(encoding="utf-8")
    )
    return SimpleNamespace(
        run_validity={"valid": event_path.is_file() and completed.returncode == 0},
        adapter_record={"scoring_status": "NOT_PRODUCED"},
        cleanup={"live_owned_processes": []},
        canonical_hash_before=canonical_hash_before,
        canonical_hash_after=sha256(SOURCE_CASE / "case_meta.json"),
        env_record=env_record,
    )


def test_deterministic_pipeline_never_scores(tmp_path: Path) -> None:
    result = run_fake_hermes_case(tmp_path)

    assert result.run_validity["valid"] is True
    assert result.adapter_record["scoring_status"] == "NOT_PRODUCED"
    assert result.cleanup["live_owned_processes"] == []
    assert result.canonical_hash_before == result.canonical_hash_after
    assert result.env_record == {"present": ["OPENAI_API_KEY"]}
