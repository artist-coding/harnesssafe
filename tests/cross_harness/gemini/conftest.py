from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from typing import Iterable, Mapping

import pytest

from infra.cross_harness.bindings.gemini import load_gemini_smoke_bindings


REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def gemini_bindings() -> dict[str, dict]:
    return load_gemini_smoke_bindings(repo_root=REPO_ROOT)


@pytest.fixture
def case_dirs() -> dict[str, Path]:
    inventory = json.loads(
        (REPO_ROOT / "docs" / "codex_conformance_smoke_v1.json").read_text(
            encoding="utf-8"
        )
    )
    return {entry["case_id"]: REPO_ROOT / entry["case_dir"] for entry in inventory["cases"]}


@pytest.fixture
def fake_gemini(tmp_path: Path) -> Path:
    executable = tmp_path / "gemini"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo '0.41.0'; exit 0; fi\n"
        "if [ \"$1\" = \"--help\" ]; then\n"
        "  echo '--prompt --output-format text json stream-json --resume --session-id --session-file --policy --skip-trust --approval-mode --allowed-mcp-server-names'\n"
        "  exit 0\n"
        "fi\n"
        "echo 'fixture executable must never invoke a model' >&2\n"
        "exit 97\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def write_conformance(
    path: Path,
    executable: Path,
    capabilities: Iterable[str],
    *,
    status: str = "SUPPORTED",
) -> Path:
    entries = {}
    for capability in capabilities:
        entries[capability] = {
            "status": status,
            "executed": status != "UNVALIDATED",
            "evidence": [f"fixture:{capability}"],
            "reason": "" if status == "SUPPORTED" else f"fixture {status.lower()}",
        }
    document = {
        "schema_name": "safety_bench_gemini_capability_conformance",
        "schema_version": 1,
        "harness_id": "gemini",
        "harness_version": "0.41.0",
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "generated_at": "2026-07-21T10:00:00+08:00",
        "capabilities": entries,
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def write_jsonl(path: Path, records: Iterable[Mapping]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
