from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NODES = {"N0": 100, "N1": 80, "N2": 60, "N3": 40, "N4": 20, "N5a": 10, "N5b": 0}
ARMS = ("attack", "clean_control", "no_persist_control", "no_trigger_control", "cleanup_control")
FAMILIES = {
    "F1_memory_runtime": "F1", "v2_skill_runtime": "F2", "v2_tool_mcp_runtime": "F3",
    "T2_memory_to_skill": "T2", "T3_subagent_poisoning": "T3-S",
    "T3_compaction_resume_poisoning": "T3-C", "T3_shared_artifact_supply_chain": "T3-A",
}

class ExperimentError(ValueError):
    pass

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def long_path(path: Path) -> Path:
    value = str(path.absolute())
    if os.name == "nt" and not value.startswith("\\\\?\\"):
        value = "\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value
    return Path(value)

def read_json(path: Path) -> Any:
    return json.loads(long_path(path).read_text(encoding="utf-8-sig"))

def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with long_path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def write_json(path: Path, value: Any) -> None:
    path = long_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)

def within(base: Path, relative: str) -> Path:
    path = (base / relative).resolve()
    if not path.is_relative_to(base.resolve()):
        raise ExperimentError(f"Path is outside its declared root: {relative}")
    return path

def case_catalog(root: Path = ROOT) -> list[dict]:
    result = []
    manifest = read_json(root / "runs/manifest.json")
    for suite, obj in manifest["suites"].items():
        if obj.get("status") != "active":
            continue
        for entry in obj["cases"]:
            meta = read_json(within(root / "runs", entry["case_dir"]) / "case_meta.json")
            case_id = meta.get("case_id") or entry.get("case_id")
            if not case_id or not meta.get("checkpoint_contract"):
                raise ExperimentError(f"Missing case identity or checkpoint contract: {entry['case_dir']}")
            result.append({**entry, "case_id": case_id, "suite": suite,
                           "family": FAMILIES.get(suite, suite),
                           "main_table_eligible": bool(meta.get("main_table_eligible")),
                           "attack_success_metric_excluded": bool(meta.get("attack_success_metric_excluded"))})
    if len({r["case_id"] for r in result}) != len(result):
        raise ExperimentError("Duplicate case IDs in manifest")
    return result

def source_inventory(root: Path = ROOT) -> dict[str, str]:
    """Hash membership and contents; runtime results are separate from fixtures."""
    paths = [root / "runs/manifest.json", root / "requirements.txt"]
    for folder in ("harnesssafe", "infra", "schemas", "runs/active"):
        for path in (root / folder).rglob("*"):
            if path.is_file() and not any(p in {"__pycache__", "results", ".pytest_cache"} for p in path.relative_to(root).parts) and path.suffix != ".pyc":
                paths.append(path)
    return {p.relative_to(root).as_posix(): file_hash(p) for p in sorted(set(paths))}

def split_inventory(files: dict[str, str]) -> dict[str, str]:
    return {
        "benchmark_sha256": digest({k: v for k, v in files.items() if k.startswith("runs/")}),
        "implementation_sha256": digest({k: v for k, v in files.items() if not k.startswith("runs/")}),
    }
