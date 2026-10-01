from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from infra.case_materializer import materialize_case
from infra.harness_adapters.openclaw.config import build_paths, render_config, write_config
from infra.harness_adapters.openclaw.events import normalize_openclaw_run
from infra.harness_adapters.openclaw.gateway import (
    OwnershipManifest,
    ProcessIdentity,
    cleanup_owned_processes,
)
from infra.harness_adapters.openclaw.launch import build_agent_launch


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CASE = REPO_ROOT / "runs/active/F1_memory_runtime/F1E.01_customerservice_01_refund_case_overgeneralization/case_001"
AGENT_FIXTURE = Path(__file__).parent / "fixtures/openclaw_agent.json"


@dataclass(frozen=True)
class FakeRunResult:
    run_validity: dict[str, object]
    adapter_record: dict[str, object]
    cleanup: dict[str, object]
    canonical_hash_before: str
    canonical_hash_after: str


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_fake_openclaw_case(tmp_path: Path) -> FakeRunResult:
    canonical = SOURCE_CASE / "case_meta.json"
    before = _hash(canonical)
    materialized = materialize_case(
        SOURCE_CASE,
        tmp_path / "result",
        "http://127.0.0.1:18765",
        "dpl-fake-token",
        repo_root=REPO_ROOT,
        harness="openclaw",
    )
    paths = build_paths(tmp_path / "adapter", "fake-case", workspace_dir=materialized.workspace_dir)
    write_config(paths, render_config(paths, model="fake-model"))
    launch = build_agent_launch(
        Path("openclaw"), paths, "deterministic task", "fake-model", 10,
        secret_env={"OPENAI_API_KEY": "not-a-real-secret"},
    )
    raw = AGENT_FIXTURE.read_text(encoding="utf-8")
    events = normalize_openclaw_run(
        raw, source_path=AGENT_FIXTURE, run_id=paths.run_nonce,
        agent_id=paths.agent_id, session_id=paths.session_key,
    )
    ownership = OwnershipManifest(4242, paths.run_nonce, tmp_path / "ownership.json")
    observed = ProcessIdentity(4242, paths.run_nonce)
    cleanup_result = cleanup_owned_processes(
        ownership, observed, terminate=lambda pid: pid == 4242
    )
    return FakeRunResult(
        run_validity={"valid": bool(events and launch.prompt_path.is_file())},
        adapter_record={
            "scoring_status": "NOT_PRODUCED",
            "event_count": len(events),
            "binding_path": str(materialized.harness_binding_path),
        },
        cleanup={
            "terminated": list(cleanup_result.terminated),
            "live_owned_processes": [],
        },
        canonical_hash_before=before,
        canonical_hash_after=_hash(canonical),
    )
