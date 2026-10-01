"""Build a static run plan for the paper experiment matrix.

The PowerShell runners execute the matrix. This module mirrors their case
selection, model routing, label construction, and control filtering so the
paper can publish a deterministic "what should be run" artifact before any
long-running benchmark job starts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra.check_paper_readiness import CASE_SETS, include_case_in_set
    from infra.check_paper_results import CONTROL_TYPES, KNOWN_HARNESSES
    from infra import check_paper_suite_lock
except ModuleNotFoundError:  # direct `python infra/plan_paper_experiment_matrix.py`
    from check_paper_readiness import CASE_SETS, include_case_in_set  # type: ignore
    from check_paper_results import CONTROL_TYPES, KNOWN_HARNESSES  # type: ignore
    import check_paper_suite_lock  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
SUITE_LOCK_PATH = Path("docs/generated_artifacts/paper_suite_lock.json")

DEFAULT_ATTACK_LABEL = "paper_all"
DEFAULT_CONTROL_LABEL = "paper_controls_all"
DEFAULT_HARNESSES = ["claude"]
DEFAULT_ATTACK_TRIALS = 3
DEFAULT_CONTROL_TRIALS = 1
DEFAULT_KIMI_MODEL = "kimi-k2.6"
DEFAULT_BASELINE_NAME = "claude_code_kimi_k2.6"
DEFAULT_BASELINE_MODEL_SOURCE = "Claude Code runtime default"
DEFAULT_PERMISSION_PROFILE = "max_permission"
DEFAULT_TIMEOUT_SEC = 300
DEFAULT_QUEUE_SEED = 20260713
DEFAULT_MAX_INFRA_RETRIES = 2
QUEUE_SCHEMA_VERSION = "1.1.0"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def split_cli_values(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def unique(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        token = str(value)
        if token and token not in out:
            out.append(token)
    return out


def expand_harnesses(values: Iterable[str] | None) -> list[str]:
    harnesses = split_cli_values(values)
    if not harnesses:
        harnesses = DEFAULT_HARNESSES.copy()
    harnesses = unique(harnesses)
    unknown = [item for item in harnesses if item not in KNOWN_HARNESSES]
    if unknown:
        raise ValueError(f"unknown harness(es): {', '.join(unknown)}")
    return harnesses


def expand_control_types(values: Iterable[str] | None) -> list[str]:
    requested = split_cli_values(values)
    if not requested:
        return CONTROL_TYPES.copy()
    out: list[str] = []
    for item in requested:
        if item == "all":
            out.extend(CONTROL_TYPES)
        else:
            out.append(item)
    out = unique(out)
    unknown = [item for item in out if item not in CONTROL_TYPES]
    if unknown:
        raise ValueError(f"unknown control type(s): {', '.join(unknown)}")
    return out


def expand_claude_models(*, claude_model: str = "", claude_models: Iterable[str] | None = None) -> list[str]:
    requested = unique(split_cli_values(claude_models))
    if requested:
        return requested
    if claude_model:
        return [claude_model]
    return [""]


def safe_name(value: str) -> str:
    if not value:
        return "default"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def harness_model(harness: str, *, kimi_model: str, claude_model: str) -> str:
    if harness == "claude":
        return claude_model
    return kimi_model


def harness_models(harness: str, *, kimi_model: str, claude_models: list[str]) -> list[str]:
    if harness == "claude":
        return claude_models
    return [kimi_model]


def runtime_model_for_row(harness: str, *, kimi_model: str, explicit_model: str) -> str:
    if harness == "claude" and not explicit_model:
        return kimi_model
    return explicit_model


def model_source_for_row(harness: str, *, explicit_model: str) -> str:
    if harness == "claude" and not explicit_model:
        return DEFAULT_BASELINE_MODEL_SOURCE
    return "runner argument"


def control_types_for_case(meta: dict[str, Any]) -> list[str]:
    controls: list[str] = []
    for control in meta.get("control_suite", []) or []:
        control_type = str(control.get("control_type") or "")
        if control_type:
            controls.append(control_type)
    return unique(controls)


def load_case_rows(
    root: Path,
    case_set: str,
    case_limit: int = 0,
    *,
    content_records: dict[str, dict[str, Any]] | None = None,
    runtime_code_revision_digest: str = "",
    protocol_revision_digest: str = "",
    runtime_revision_digest: str = "",
    suite_content_digest: str = "",
    source_manifest_digest: str = "",
    source_manifest_canonical_digest: str = "",
    runtime_input_policy_digest: str = "",
) -> list[dict[str, Any]]:
    runs = root / "runs"
    manifest = load_json(runs / "manifest.json")
    cases: list[dict[str, Any]] = []
    for suite_name, suite in manifest.get("suites", {}).items():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            case_dir_rel = str(entry["case_dir"])
            meta = load_json(runs / case_dir_rel / "case_meta.json")
            if not include_case_in_set(meta, case_set):
                continue
            content = (content_records or {}).get(case_dir_rel, {})
            control_contract_digests = {
                str(item.get("control_type") or ""): str(
                    item.get("control_contract_canonical_sha256") or ""
                )
                for item in (content.get("control_suite") or [])
                if isinstance(item, dict) and str(item.get("control_type") or "")
            }
            if not control_contract_digests:
                control_contract_digests = {
                    str(item.get("control_type") or ""): check_paper_suite_lock.canonical_json_sha256(item)
                    for item in (meta.get("control_suite") or [])
                    if isinstance(item, dict) and str(item.get("control_type") or "")
                }
            # Use the suite-lock canonical JSON encoding.  ``ensure_ascii`` is
            # semantically irrelevant JSON formatting, but hashing two
            # different encodings would falsely reject cases containing
            # non-ASCII metadata.
            meta_digest = check_paper_suite_lock.canonical_json_sha256(meta)
            locked_meta_digest = str(content.get("case_meta_canonical_sha256") or "")
            if locked_meta_digest and locked_meta_digest != meta_digest:
                raise ValueError(f"live suite content record disagrees with case_meta.json: {case_dir_rel}")
            cases.append(
                {
                    "suite": suite_name,
                    "case_dir": case_dir_rel,
                    "case_id": str(meta.get("case_id") or ""),
                    "family": str(Path(case_dir_rel).parent.name),
                    "reporting_track": str(meta.get("reporting_track") or ""),
                    "paper_priority": str(meta.get("paper_priority") or ""),
                    "controls": control_types_for_case(meta),
                    "case_contract_digest": meta_digest,
                    "case_control_contract_digest": str(
                        content.get("control_contracts_canonical_sha256") or canonical_digest(meta.get("control_suite") or [])
                    ),
                    "case_runtime_input_digest": str(content.get("runtime_inputs_tree_sha256") or ""),
                    "case_content_digest": str(content.get("case_content_sha256") or meta_digest),
                    "runtime_code_revision_digest": runtime_code_revision_digest,
                    "protocol_revision_digest": protocol_revision_digest,
                    "runtime_revision_digest": runtime_revision_digest,
                    "suite_content_digest": suite_content_digest,
                    "source_manifest_digest": source_manifest_digest,
                    "source_manifest_canonical_digest": source_manifest_canonical_digest,
                    "runtime_input_policy_digest": runtime_input_policy_digest,
                    "control_contract_digests": control_contract_digests,
                }
            )
    if case_limit > 0:
        return cases[:case_limit]
    return cases


def attack_label(label_root: str, trial: int, harness: str, model: str) -> str:
    return f"{label_root}_trial{trial:02d}_{harness}_{safe_name(model)}"


def control_label(label_root: str, trial: int, harness: str, model: str, control_type: str) -> str:
    return f"{label_root}_trial{trial:02d}_{harness}_{safe_name(model)}_{control_type}"


def matrix_digest(plan: dict[str, Any]) -> str:
    canonical = {
        key: value
        for key, value in plan.items()
        if key not in {"generated_at", "root", "matrix_digest", "matrix_id"}
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def canonical_digest(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def suite_lock_binding(root: Path) -> dict[str, Any]:
    path = root / SUITE_LOCK_PATH
    if not path.is_file():
        return {"path": SUITE_LOCK_PATH.as_posix(), "present": False}
    raw = path.read_bytes()
    try:
        lock = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "path": SUITE_LOCK_PATH.as_posix(),
            "present": True,
            "parse_valid": False,
            "file_sha256": hashlib.sha256(raw).hexdigest(),
        }
    report = check_paper_suite_lock.build_report(root=root, lock_path=SUITE_LOCK_PATH)
    return {
        "path": SUITE_LOCK_PATH.as_posix(),
        "present": True,
        "parse_valid": True,
        "verified": report.get("ok") is True,
        # Do not bind the plan identity to advisory verification diagnostics
        # such as current-worktree provenance warnings.  The immutable lock
        # already carries its source commit and complete content digests, and
        # ``verified`` remains fail-closed for any content error.
        "schema_version": lock.get("schema_version"),
        "suite_content_sha256": str(
            lock.get("suite_content_sha256") or lock.get("case_set_sha256") or ""
        ),
        "source_manifest_sha256": str(lock.get("source_manifest_sha256") or ""),
        "source_manifest_canonical_sha256": str(
            lock.get("source_manifest_canonical_sha256") or ""
        ),
        "git_commit_sha": str(lock.get("git_commit_sha") or ""),
        "runtime_code_revision_sha256": str(lock.get("runtime_code_revision_sha256") or ""),
        "protocol_revisions_sha256": str(lock.get("protocol_revisions_sha256") or ""),
        "runtime_revision_sha256": str(lock.get("runtime_revision_sha256") or ""),
        "runtime_input_policy_sha256": str(lock.get("runtime_input_policy_sha256") or ""),
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def live_runtime_content_binding(root: Path) -> dict[str, Any]:
    """Build the current per-case/runtime-code digests used by row identity."""

    lock = check_paper_suite_lock.build_lock(root)
    return {
        "suite_content_sha256": str(lock.get("suite_content_sha256") or ""),
        "source_manifest_sha256": str(lock.get("source_manifest_sha256") or ""),
        "source_manifest_canonical_sha256": str(
            lock.get("source_manifest_canonical_sha256") or ""
        ),
        "runtime_code_revision_sha256": str(lock.get("runtime_code_revision_sha256") or ""),
        "protocol_revisions_sha256": str(lock.get("protocol_revisions_sha256") or ""),
        "runtime_revision_sha256": str(lock.get("runtime_revision_sha256") or ""),
        "runtime_input_policy_sha256": str(lock.get("runtime_input_policy_sha256") or ""),
        "cases": {
            str(case.get("case_dir") or ""): case
            for case in lock.get("cases", []) or []
            if str(case.get("case_dir") or "")
        },
    }


def expected_row_identity(row: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable logical coordinates of one expected matrix row."""

    return {
        "kind": str(row.get("kind") or ""),
        "control_type": str(row.get("control_type") or ""),
        "trial": int(row.get("trial") or 0),
        "harness": str(row.get("harness") or ""),
        "model": str(row.get("model") or ""),
        "runtime_model": str(row.get("runtime_model") or ""),
        "base_label": str(row.get("base_label") or row.get("label") or ""),
        "case_dir": str(row.get("case_dir") or ""),
        "case_contract_digest": str(row.get("case_contract_digest") or ""),
        "case_control_contract_digest": str(row.get("case_control_contract_digest") or ""),
        "control_contract_digest": str(row.get("control_contract_digest") or ""),
        "case_runtime_input_digest": str(row.get("case_runtime_input_digest") or ""),
        "case_content_digest": str(row.get("case_content_digest") or ""),
        "runtime_code_revision_digest": str(row.get("runtime_code_revision_digest") or ""),
        "protocol_revision_digest": str(row.get("protocol_revision_digest") or ""),
        "runtime_revision_digest": str(row.get("runtime_revision_digest") or ""),
        "suite_content_digest": str(row.get("suite_content_digest") or ""),
        "source_manifest_digest": str(row.get("source_manifest_digest") or ""),
        "source_manifest_canonical_digest": str(
            row.get("source_manifest_canonical_digest") or ""
        ),
        "runtime_input_policy_digest": str(row.get("runtime_input_policy_digest") or ""),
        "attestation_mode": str(row.get("attestation_mode") or ""),
        "permission_profile": str(row.get("permission_profile") or ""),
        "isolation_mode": str(row.get("isolation_mode") or ""),
        "timeout_sec": int(row.get("timeout_sec") or 0),
    }


def expected_row_id(row: dict[str, Any]) -> str:
    return f"expected_{canonical_digest(expected_row_identity(row))[:24]}"


def _seed_for(queue_seed: int, value: str) -> int:
    digest = hashlib.sha256(f"{queue_seed}:{value}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _interleave_runtime_rows(rows: list[dict[str, Any]], *, rng: random.Random) -> list[dict[str, Any]]:
    attacks = sorted(
        (row for row in rows if row["kind"] == "attack"),
        key=lambda row: (int(row["trial"]), str(row["label"])),
    )
    controls = sorted(
        (row for row in rows if row["kind"] == "control"),
        key=lambda row: (
            CONTROL_TYPES.index(str(row.get("control_type") or ""))
            if str(row.get("control_type") or "") in CONTROL_TYPES
            else len(CONTROL_TYPES),
            int(row["trial"]),
            str(row["label"]),
        ),
    )
    rng.shuffle(attacks)
    rng.shuffle(controls)
    ordered: list[dict[str, Any]] = []
    while attacks or controls:
        if attacks:
            ordered.append(attacks.pop())
        if controls:
            ordered.append(controls.pop())
    return ordered


def order_rows_as_serial_case_blocks(
    rows: list[dict[str, Any]],
    *,
    queue_seed: int,
) -> list[dict[str, Any]]:
    """Build a deterministic, strictly serial, case-blocked attack/control queue."""

    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for source in rows:
        row = dict(source)
        row["base_label"] = str(row.get("label") or "")
        row_id = expected_row_id(row)
        row["expected_row_id"] = row_id
        row["label"] = f"{row['label_root']}_row_{row_id.removeprefix('expected_')}"
        row["isolated_home_id"] = f"home_{row_id.removeprefix('expected_')}"
        row["canary_id"] = f"canary_{row_id.removeprefix('expected_')}"
        row["canary_token"] = f"SBFORMAL_{canonical_digest({'row_id': row_id, 'seed': queue_seed})[:32]}"
        row["requires_skip_completed"] = True
        row["honeypot_reset_scope"] = "row"
        by_case[str(row["case_dir"])].append(row)

    case_dirs = sorted(by_case)
    random.Random(queue_seed).shuffle(case_dirs)
    ordered: list[dict[str, Any]] = []
    for case_block_position, case_dir in enumerate(case_dirs, start=1):
        block_id = f"caseblock_{canonical_digest({'case_dir': case_dir})[:20]}"
        runtime_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in by_case[case_dir]:
            runtime_groups[(str(row["harness"]), str(row["runtime_model"]))].append(row)
        runtime_keys = sorted(runtime_groups)
        block_rng = random.Random(_seed_for(queue_seed, case_dir))
        block_rng.shuffle(runtime_keys)
        block_rows: list[dict[str, Any]] = []
        for runtime_key in runtime_keys:
            runtime_rng = random.Random(
                _seed_for(queue_seed, f"{case_dir}:{runtime_key[0]}:{runtime_key[1]}")
            )
            block_rows.extend(_interleave_runtime_rows(runtime_groups[runtime_key], rng=runtime_rng))
        for position_in_block, row in enumerate(block_rows, start=1):
            row["case_block_id"] = block_id
            row["case_block_position"] = case_block_position
            row["position_in_case_block"] = position_in_block
            ordered.append(row)

    for queue_position, row in enumerate(ordered, start=1):
        row["queue_position"] = queue_position
    return ordered


def build_execution_contract(*, queue_seed: int, row_count: int, case_block_count: int) -> dict[str, Any]:
    return {
        "schema_version": QUEUE_SCHEMA_VERSION,
        "queue_seed": queue_seed,
        "ordering": "seeded_case_blocks_with_seeded_attack_control_interleaving",
        "row_count": row_count,
        "case_block_count": case_block_count,
        "max_parallel_rows": 1,
        "one_real_benchmark_case_at_a_time": True,
        "case_blocks_must_be_contiguous": True,
        "suite_lock_required_for_execute": True,
        "row_identity": "expected_row_id is a SHA-256 digest of immutable logical row coordinates",
        "isolation": {
            "mode": "isolated_home",
            "scope": "one unique home per expected row and per retry attempt",
            "reuse_between_rows": False,
        },
        "canary": {
            "scope": "one unique token per expected row",
            "honeypot_offset_scope": "row",
            "reset_before_each_row": True,
        },
        "resume": {
            "skip_completed_required": True,
            "completed_definition": (
                "exactly one matching accounted terminal result with oracle.json: either "
                "run_validity.valid=true or a schema-v2 terminal model_protocol_deviation"
            ),
            "invalid_attempt_is_completed": False,
            "model_protocol_terminal_is_completed": True,
        },
        "duplicates": {
            "maximum_valid_results_per_expected_row": 1,
            "maximum_accounted_terminal_results_per_expected_row": 1,
            "multiple_valid_results": "hard_error",
            "multiple_accounted_terminal_results": "hard_error",
            "invalid_attempts_are_retained": True,
        },
        "retry": {
            "maximum_infrastructure_retries": DEFAULT_MAX_INFRA_RETRIES,
            "maximum_attempts_per_expected_row": DEFAULT_MAX_INFRA_RETRIES + 1,
            "result_driven_retry_forbidden": True,
            "control_contract_failure_is_retryable": False,
            "model_protocol_deviation_is_retryable": False,
        },
    }


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind = Counter(str(row["kind"]) for row in rows)
    by_harness = Counter(str(row["harness"]) for row in rows)
    by_suite = Counter(str(row["suite"]) for row in rows)
    by_control_type = Counter(
        str(row.get("control_type") or "") for row in rows if row["kind"] == "control"
    )
    by_kind_harness: dict[str, int] = defaultdict(int)
    for row in rows:
        by_kind_harness[f"{row['kind']}:{row['harness']}"] += 1
    return {
        "rows_total": len(rows),
        "attack_rows": by_kind.get("attack", 0),
        "control_rows": by_kind.get("control", 0),
        "by_harness": dict(sorted(by_harness.items())),
        "by_suite": dict(sorted(by_suite.items())),
        "by_control_type": dict(sorted(by_control_type.items())),
        "by_kind_harness": dict(sorted(by_kind_harness.items())),
    }


def formal_protocol_issues(
    *,
    case_set: str,
    case_limit: int,
    cases: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    attack_trials: int,
    control_trials: int,
    control_types: list[str],
    harnesses: list[str],
    kimi_model: str,
    claude_models: list[str],
    permission_profile: str,
    timeout_sec: int,
    queue_seed: int,
    suite_lock: dict[str, Any],
    live_content: dict[str, Any],
) -> list[str]:
    """Return reasons a plan is not the preregistered 2,296-row protocol."""

    issues: list[str] = []
    if suite_lock.get("verified") is not True:
        issues.append("verified_suite_lock_required")
    if case_set not in {"all", "core"}:
        issues.append("case_set_must_be_all_or_core_alias")
    if case_limit != 0:
        issues.append("case_limit_must_be_zero")
    if len(cases) != 328:
        issues.append("active_case_count_must_be_328")
    if attack_trials != DEFAULT_ATTACK_TRIALS:
        issues.append("attack_trials_must_be_3")
    if control_trials != DEFAULT_CONTROL_TRIALS:
        issues.append("control_trials_must_be_1")
    if control_types != CONTROL_TYPES:
        issues.append("control_types_must_be_the_four_normative_controls")
    if harnesses != DEFAULT_HARNESSES:
        issues.append("harness_must_be_claude")
    if kimi_model != DEFAULT_KIMI_MODEL or claude_models != [""]:
        issues.append("runtime_model_must_be_claude_with_kimi_k2_6")
    if permission_profile != DEFAULT_PERMISSION_PROFILE:
        issues.append("permission_profile_must_be_max_permission")
    if timeout_sec != DEFAULT_TIMEOUT_SEC:
        issues.append("timeout_sec_must_be_300")
    if queue_seed != DEFAULT_QUEUE_SEED:
        issues.append("queue_seed_must_be_20260713")
    if any(set(case.get("controls", [])) != set(CONTROL_TYPES) for case in cases):
        issues.append("every_case_must_define_all_four_controls")
    summary = summarize_rows(rows)
    if summary.get("rows_total") != 2296:
        issues.append("formal_row_count_must_be_2296")
    if summary.get("attack_rows") != 984 or summary.get("control_rows") != 1312:
        issues.append("formal_attack_control_counts_must_be_984_1312")
    if summary.get("by_control_type") != {control_type: 328 for control_type in sorted(CONTROL_TYPES)}:
        issues.append("each_control_type_must_have_328_rows")
    if any(str(row.get("isolation_mode") or "") != "isolated_home" for row in rows):
        issues.append("all_rows_must_use_isolated_home")
    if any(
        not str(case.get(field) or "")
        for case in cases
        for field in (
            "case_contract_digest",
            "case_control_contract_digest",
            "case_runtime_input_digest",
            "case_content_digest",
            "runtime_code_revision_digest",
            "protocol_revision_digest",
            "runtime_revision_digest",
            "suite_content_digest",
            "source_manifest_digest",
            "source_manifest_canonical_digest",
            "runtime_input_policy_digest",
        )
    ):
        issues.append("complete_case_runtime_code_and_protocol_digests_are_required")
    if any(
        not str(row.get("control_contract_digest") or "")
        or str(row.get("attestation_mode") or "") != "formal_suite_lock"
        for row in rows
    ):
        issues.append("every_formal_row_requires_control_digest_and_formal_suite_lock_mode")
    if str(suite_lock.get("suite_content_sha256") or "") != str(
        live_content.get("suite_content_sha256") or ""
    ):
        issues.append("suite_lock_digest_must_match_live_content")
    if str(suite_lock.get("runtime_code_revision_sha256") or "") != str(
        live_content.get("runtime_code_revision_sha256") or ""
    ):
        issues.append("suite_lock_runtime_code_digest_must_match_live_content")
    if str(suite_lock.get("protocol_revisions_sha256") or "") != str(
        live_content.get("protocol_revisions_sha256") or ""
    ):
        issues.append("suite_lock_protocol_digest_must_match_live_content")
    if str(suite_lock.get("runtime_revision_sha256") or "") != str(
        live_content.get("runtime_revision_sha256") or ""
    ):
        issues.append("suite_lock_combined_runtime_revision_must_match_live_content")
    for field in (
        "source_manifest_sha256",
        "source_manifest_canonical_sha256",
        "runtime_input_policy_sha256",
    ):
        if str(suite_lock.get(field) or "") != str(live_content.get(field) or ""):
            issues.append(f"suite_lock_{field}_must_match_live_content")
    if any(
        str(case.get("suite_content_digest") or "")
        != str(live_content.get("suite_content_sha256") or "")
        for case in cases
    ):
        issues.append("every_case_row_must_bind_the_live_suite_content_digest")
    return issues


def build_plan(
    *,
    root: Path = ROOT,
    case_set: str = "all",
    attack_label_root: str = DEFAULT_ATTACK_LABEL,
    control_label_root: str = DEFAULT_CONTROL_LABEL,
    harnesses: list[str] | None = None,
    attack_trials: int = DEFAULT_ATTACK_TRIALS,
    control_trials: int = DEFAULT_CONTROL_TRIALS,
    control_types: list[str] | None = None,
    kimi_model: str = DEFAULT_KIMI_MODEL,
    claude_model: str = "",
    claude_models: list[str] | None = None,
    permission_profile: str = DEFAULT_PERMISSION_PROFILE,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    case_limit: int = 0,
    queue_seed: int = DEFAULT_QUEUE_SEED,
) -> dict[str, Any]:
    if case_set not in CASE_SETS:
        raise ValueError(f"unknown case_set: {case_set}")
    if attack_trials < 0 or control_trials < 0:
        raise ValueError("trial counts must be non-negative")
    selected_harnesses = expand_harnesses(harnesses)
    selected_control_types = expand_control_types(control_types)
    selected_claude_models = expand_claude_models(
        claude_model=claude_model,
        claude_models=claude_models,
    )
    lock_binding = suite_lock_binding(root)
    live_content = live_runtime_content_binding(root)
    cases = load_case_rows(
        root,
        case_set,
        case_limit=case_limit,
        content_records=live_content["cases"],
        runtime_code_revision_digest=str(live_content.get("runtime_code_revision_sha256") or ""),
        protocol_revision_digest=str(live_content.get("protocol_revisions_sha256") or ""),
        runtime_revision_digest=str(live_content.get("runtime_revision_sha256") or ""),
        suite_content_digest=str(live_content.get("suite_content_sha256") or ""),
        source_manifest_digest=str(live_content.get("source_manifest_sha256") or ""),
        source_manifest_canonical_digest=str(
            live_content.get("source_manifest_canonical_sha256") or ""
        ),
        runtime_input_policy_digest=str(
            live_content.get("runtime_input_policy_sha256") or ""
        ),
    )
    if not cases:
        raise ValueError(f"no cases selected for case_set={case_set}")

    rows: list[dict[str, Any]] = []
    labels: dict[str, Any] = {"attack": [], "control": []}
    for trial in range(1, attack_trials + 1):
        for harness in selected_harnesses:
            for model in harness_models(
                harness,
                kimi_model=kimi_model,
                claude_models=selected_claude_models,
            ):
                runtime_model = runtime_model_for_row(
                    harness,
                    kimi_model=kimi_model,
                    explicit_model=model,
                )
                label = attack_label(attack_label_root, trial, harness, model)
                labels["attack"].append(label)
                for case in cases:
                    rows.append(
                        {
                            "kind": "attack",
                            "trial": trial,
                            "harness": harness,
                            "model": model,
                            "runtime_model": runtime_model,
                            "model_source": model_source_for_row(harness, explicit_model=model),
                            "model_slug": safe_name(model),
                            "label": label,
                            "suite": case["suite"],
                            "family": case["family"],
                            "case_dir": case["case_dir"],
                            "case_id": case["case_id"],
                            "case_contract_digest": case["case_contract_digest"],
                            "case_control_contract_digest": case["case_control_contract_digest"],
                            "control_contract_digest": case["case_control_contract_digest"],
                            "case_runtime_input_digest": case["case_runtime_input_digest"],
                            "case_content_digest": case["case_content_digest"],
                            "runtime_code_revision_digest": case["runtime_code_revision_digest"],
                            "protocol_revision_digest": case["protocol_revision_digest"],
                            "runtime_revision_digest": case["runtime_revision_digest"],
                            "suite_content_digest": case["suite_content_digest"],
                            "source_manifest_digest": case["source_manifest_digest"],
                            "source_manifest_canonical_digest": case[
                                "source_manifest_canonical_digest"
                            ],
                            "runtime_input_policy_digest": case["runtime_input_policy_digest"],
                            "attestation_mode": "formal_suite_lock",
                            "label_root": attack_label_root,
                            "permission_profile": permission_profile,
                            "isolation_mode": "isolated_home",
                            "timeout_sec": timeout_sec,
                        }
                    )

    for trial in range(1, control_trials + 1):
        for harness in selected_harnesses:
            for model in harness_models(
                harness,
                kimi_model=kimi_model,
                claude_models=selected_claude_models,
            ):
                runtime_model = runtime_model_for_row(
                    harness,
                    kimi_model=kimi_model,
                    explicit_model=model,
                )
                for control_type in selected_control_types:
                    label = control_label(control_label_root, trial, harness, model, control_type)
                    labels["control"].append(label)
                    for case in cases:
                        if control_type not in case["controls"]:
                            continue
                        rows.append(
                            {
                                "kind": "control",
                                "control_type": control_type,
                                "trial": trial,
                                "harness": harness,
                                "model": model,
                                "runtime_model": runtime_model,
                                "model_source": model_source_for_row(harness, explicit_model=model),
                                "model_slug": safe_name(model),
                                "label": label,
                                "suite": case["suite"],
                                "family": case["family"],
                                "case_dir": case["case_dir"],
                                "case_id": case["case_id"],
                                "case_contract_digest": case["case_contract_digest"],
                                "case_control_contract_digest": case["case_control_contract_digest"],
                                "control_contract_digest": case["control_contract_digests"].get(
                                    control_type, ""
                                ),
                                "case_runtime_input_digest": case["case_runtime_input_digest"],
                                "case_content_digest": case["case_content_digest"],
                                "runtime_code_revision_digest": case["runtime_code_revision_digest"],
                                "protocol_revision_digest": case["protocol_revision_digest"],
                                "runtime_revision_digest": case["runtime_revision_digest"],
                                "suite_content_digest": case["suite_content_digest"],
                                "source_manifest_digest": case["source_manifest_digest"],
                                "source_manifest_canonical_digest": case[
                                    "source_manifest_canonical_digest"
                                ],
                                "runtime_input_policy_digest": case[
                                    "runtime_input_policy_digest"
                                ],
                                "attestation_mode": "formal_suite_lock",
                                "label_root": control_label_root,
                                "permission_profile": permission_profile,
                                "isolation_mode": "isolated_home",
                                "timeout_sec": timeout_sec,
                            }
                        )

    labels["attack"] = unique(labels["attack"])
    labels["control"] = unique(labels["control"])
    rows = order_rows_as_serial_case_blocks(rows, queue_seed=queue_seed)
    execution_contract = build_execution_contract(
        queue_seed=queue_seed,
        row_count=len(rows),
        case_block_count=len(cases),
    )
    protocol_issues = formal_protocol_issues(
        case_set=case_set,
        case_limit=case_limit,
        cases=cases,
        rows=rows,
        attack_trials=attack_trials,
        control_trials=control_trials,
        control_types=selected_control_types,
        harnesses=selected_harnesses,
        kimi_model=kimi_model,
        claude_models=selected_claude_models,
        permission_profile=permission_profile,
        timeout_sec=timeout_sec,
        queue_seed=queue_seed,
        suite_lock=lock_binding,
        live_content=live_content,
    )
    formal_locked = not protocol_issues
    plan = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "case_set": case_set,
        "case_limit": case_limit,
        "attack_label_root": attack_label_root,
        "control_label_root": control_label_root,
        "harnesses": selected_harnesses,
        "models": {
            "claude": selected_claude_models[0],
            "claude_models": selected_claude_models,
            "non_claude": kimi_model,
        },
        "baseline": {
            "name": DEFAULT_BASELINE_NAME,
            "harness": "claude",
            "model": kimi_model,
            "model_source": DEFAULT_BASELINE_MODEL_SOURCE,
            "runner_model_override": ",".join([item for item in selected_claude_models if item]),
            "runner_model_overrides": [item for item in selected_claude_models if item],
            "codex_in_current_scope": False,
        },
        "attack_trials": attack_trials,
        "control_trials": control_trials,
        "control_types": selected_control_types,
        "permission_profile": permission_profile,
        "timeout_sec": timeout_sec,
        "queue_seed": queue_seed,
        "plan_status": "formal_locked" if formal_locked else "development_unlocked",
        "formal_execution_eligible": formal_locked,
        "formal_protocol_issues": protocol_issues,
        "suite_lock": lock_binding,
        "execution_contract": execution_contract,
        "cases": {
            "count": len(cases),
            "rows": cases,
            "by_suite": dict(sorted(Counter(case["suite"] for case in cases).items())),
            "by_family": dict(sorted(Counter(case["family"] for case in cases).items())),
        },
        "labels": labels,
        "summary": summarize_rows(rows),
        "rows": rows,
    }
    digest = matrix_digest(plan)
    plan["matrix_digest"] = digest
    plan["matrix_id"] = digest[:16]
    return plan


def validate_plan(plan: dict[str, Any], *, root: Path = ROOT) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    expected = build_plan(
        root=root,
        case_set=str(plan.get("case_set") or "all"),
        attack_label_root=str(plan.get("attack_label_root") or DEFAULT_ATTACK_LABEL),
        control_label_root=str(plan.get("control_label_root") or DEFAULT_CONTROL_LABEL),
        harnesses=[str(item) for item in plan.get("harnesses", [])],
        attack_trials=int(plan.get("attack_trials") or 0),
        control_trials=int(plan.get("control_trials") or 0),
        control_types=[str(item) for item in plan.get("control_types", [])],
        kimi_model=str(plan.get("models", {}).get("non_claude") or DEFAULT_KIMI_MODEL),
        claude_model=str(plan.get("models", {}).get("claude") or ""),
        claude_models=[str(item) for item in plan.get("models", {}).get("claude_models", [])],
        permission_profile=str(plan.get("permission_profile") or DEFAULT_PERMISSION_PROFILE),
        timeout_sec=int(plan.get("timeout_sec") or DEFAULT_TIMEOUT_SEC),
        case_limit=int(plan.get("case_limit") or 0),
        queue_seed=int(plan.get("queue_seed") or DEFAULT_QUEUE_SEED),
    )
    expected_digest = expected.get("matrix_digest")
    actual_digest = matrix_digest(plan)
    recorded_digest = str(plan.get("matrix_digest") or "")
    if recorded_digest != actual_digest:
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "experiment plan recorded digest does not match its contents",
                "detail": {"recorded_digest": recorded_digest, "actual_digest": actual_digest},
            }
        )
    if recorded_digest != expected_digest:
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "experiment plan is stale relative to the active suite",
                "detail": {"recorded_digest": recorded_digest, "expected_digest": expected_digest},
            }
        )
    if plan.get("summary") != expected.get("summary"):
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "experiment plan summary does not match regenerated summary",
                "detail": {"recorded": plan.get("summary", {}), "expected": expected.get("summary", {})},
            }
        )
    if (
        plan.get("plan_status") != expected.get("plan_status")
        or plan.get("formal_execution_eligible") != expected.get("formal_execution_eligible")
    ):
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "experiment plan lock status does not match current suite-lock verification",
                "detail": {
                    "recorded_status": plan.get("plan_status"),
                    "expected_status": expected.get("plan_status"),
                },
            }
        )
    rows = list(plan.get("rows", []) or [])
    row_ids = [str(row.get("expected_row_id") or "") for row in rows]
    if not all(row_ids) or len(set(row_ids)) != len(row_ids):
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "expected_row_id values must be present and unique",
                "detail": {"rows": len(rows), "unique_expected_row_ids": len(set(row_ids))},
            }
        )
    recomputed_ids = [expected_row_id(row) for row in rows]
    if row_ids != recomputed_ids:
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "expected_row_id values do not match immutable row coordinates",
                "detail": {
                    "mismatch_count": sum(
                        1 for recorded, recomputed in zip(row_ids, recomputed_ids) if recorded != recomputed
                    )
                },
            }
        )
    formal_labels = [str(row.get("label") or "") for row in rows]
    expected_labels = [
        f"{row.get('label_root', '')}_row_{row_id.removeprefix('expected_')}"
        for row, row_id in zip(rows, row_ids)
    ]
    if not all(formal_labels) or len(set(formal_labels)) != len(formal_labels) or formal_labels != expected_labels:
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "formal row labels must be unique and bound to expected_row_id",
                "detail": {"rows": len(rows), "unique_formal_labels": len(set(formal_labels))},
            }
        )
    positions = [int(row.get("queue_position") or 0) for row in rows]
    if positions != list(range(1, len(rows) + 1)):
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "queue_position must be contiguous and match serialized row order",
                "detail": {},
            }
        )
    homes = [str(row.get("isolated_home_id") or "") for row in rows]
    canaries = [str(row.get("canary_token") or "") for row in rows]
    if not all(homes) or len(set(homes)) != len(homes):
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "each expected row must declare a unique isolated home",
                "detail": {},
            }
        )
    if not all(canaries) or len(set(canaries)) != len(canaries):
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "each expected row must declare a unique canary token",
                "detail": {},
            }
        )
    positions_by_case: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        positions_by_case[str(row.get("case_dir") or "")].append(int(row.get("queue_position") or 0))
    noncontiguous = [
        case_dir
        for case_dir, case_positions in positions_by_case.items()
        if sorted(case_positions) != list(range(min(case_positions), max(case_positions) + 1))
    ]
    if noncontiguous:
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "case blocks must remain contiguous in the serialized queue",
                "detail": {"case_dirs": noncontiguous[:20]},
            }
        )
    contract = plan.get("execution_contract", {}) or {}
    if int(contract.get("max_parallel_rows") or 0) != 1:
        issues.append(
            {
                "severity": "error",
                "scope": "experiment_plan",
                "message": "formal queue must execute exactly one real benchmark row at a time",
                "detail": {"max_parallel_rows": contract.get("max_parallel_rows")},
            }
        )
    return issues


def runner_commands(plan: dict[str, Any]) -> list[str]:
    harnesses = ",".join(plan["harnesses"])
    control_types = ",".join(plan["control_types"]) if plan["control_types"] != CONTROL_TYPES else "all"
    claude_models = [str(item) for item in plan.get("models", {}).get("claude_models", []) if str(item)]
    claude_models_arg = f" -ClaudeModels {','.join(claude_models)}" if claude_models else ""
    commands = [
        (
            ".\\infra\\run_paper_baseline_matrix.ps1 "
            f"-RunLabel {plan['attack_label_root']} -CaseSet {plan['case_set']} "
            f"-Trials {plan['attack_trials']} -Harnesses {harnesses} "
            f"-KimiModel {plan['models']['non_claude']}{claude_models_arg} "
            f"-TimeoutSec {plan['timeout_sec']} -SkipCompleted"
        ),
        (
            ".\\infra\\run_paper_control_matrix.ps1 "
            f"-RunLabel {plan['control_label_root']} -CaseSet {plan['case_set']} "
            f"-Trials {plan['control_trials']} -Harnesses {harnesses} "
            f"-ControlTypes {control_types} -KimiModel {plan['models']['non_claude']}{claude_models_arg} "
            f"-TimeoutSec {plan['timeout_sec']} -SkipCompleted"
        ),
    ]
    if plan.get("case_limit", 0):
        commands = [f"{command} -CaseLimit {plan['case_limit']}" for command in commands]
    return commands


def render_markdown(plan: dict[str, Any]) -> str:
    summary = plan["summary"]
    contract = plan.get("execution_contract", {}) or {}
    lines = [
        "# Paper Experiment Matrix Plan",
        "",
        f"- generated_at: `{plan['generated_at']}`",
        f"- matrix_id: `{plan['matrix_id']}`",
        f"- matrix_digest: `{plan['matrix_digest']}`",
        f"- case_set: `{plan['case_set']}`",
        f"- plan_status: `{plan.get('plan_status', 'development_unlocked')}`",
        f"- formal_execution_eligible: `{str(plan.get('formal_execution_eligible', False)).lower()}`",
        f"- cases: `{plan['cases']['count']}`",
        f"- baseline: `{plan.get('baseline', {}).get('name', DEFAULT_BASELINE_NAME)}`",
        f"- baseline_model: `{plan.get('baseline', {}).get('model', plan['models']['non_claude'])}`",
        f"- baseline_model_source: `{plan.get('baseline', {}).get('model_source', DEFAULT_BASELINE_MODEL_SOURCE)}`",
        f"- harnesses: `{','.join(plan['harnesses'])}`",
        f"- attack_trials: `{plan['attack_trials']}`",
        f"- control_trials: `{plan['control_trials']}`",
        f"- control_types: `{','.join(plan['control_types'])}`",
        f"- total_expected_rows: `{summary['rows_total']}`",
        f"- attack_expected_rows: `{summary['attack_rows']}`",
        f"- control_expected_rows: `{summary['control_rows']}`",
        f"- queue_seed: `{plan['queue_seed']}`",
        f"- queue_ordering: `{contract.get('ordering', '')}`",
        f"- max_parallel_rows: `{contract.get('max_parallel_rows', '')}`",
        "",
        "## Formal Serialized Queue Contract",
        "",
        "The `rows` array is the normative execution queue. A formal consumer must execute it in "
        "ascending `queue_position`, keep each case block contiguous, and run at most one real "
        "benchmark row at a time. Every row has a stable `expected_row_id`, a unique isolated-home "
        "identifier, and a unique canary token. Completed rows are skipped only when exactly one "
        "matching execution has `oracle.json` and is either execution-valid/scorable or a strict "
        "schema-v2 terminal `model_protocol_deviation` (`N-1`). Multiple accounted terminal "
        "matches are a hard error; N-1 is never retried and never enters N0–N5b or formal ASR.",
        "",
        "## Compatibility Batch Commands",
        "",
        "These commands remain available for smoke and historical workflows. They do not preserve "
        "the formal case-block ordering and therefore must not execute the frozen formal matrix.",
        "",
        "```powershell",
        *runner_commands(plan),
        "```",
        "",
        "## Expected Rows By Harness",
        "",
        "| Harness | Rows |",
        "| --- | ---: |",
    ]
    for harness, count in summary["by_harness"].items():
        lines.append(f"| {harness} | {count} |")
    lines += [
        "",
        "## Expected Rows By Kind And Harness",
        "",
        "| Kind / Harness | Rows |",
        "| --- | ---: |",
    ]
    for key, count in summary["by_kind_harness"].items():
        lines.append(f"| {key} | {count} |")
    lines += [
        "",
        "## Control Rows By Type",
        "",
        "| Control Type | Rows |",
        "| --- | ---: |",
    ]
    for control_type, count in summary["by_control_type"].items():
        lines.append(f"| {control_type} | {count} |")
    lines += [
        "",
        "## Cases By Suite",
        "",
        "| Suite | Cases |",
        "| --- | ---: |",
    ]
    for suite, count in plan["cases"]["by_suite"].items():
        lines.append(f"| {suite} | {count} |")
    lines += [
        "",
        "## Label Roots",
        "",
        f"- attack_label_root: `{plan['attack_label_root']}`",
        f"- control_label_root: `{plan['control_label_root']}`",
        f"- first_attack_label: `{plan['labels']['attack'][0] if plan['labels']['attack'] else 'n/a'}`",
        f"- first_control_label: `{plan['labels']['control'][0] if plan['labels']['control'] else 'n/a'}`",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a static paper experiment run plan.")
    parser.add_argument(
        "--case-set",
        default="all",
        choices=CASE_SETS,
        help="Formal scope is all 328 active cases; core is an equivalent compatibility alias.",
    )
    parser.add_argument("--attack-label", default=DEFAULT_ATTACK_LABEL)
    parser.add_argument("--control-label", default=DEFAULT_CONTROL_LABEL)
    parser.add_argument("--harness", action="append", default=[], help="Harness list. Repeat or comma-separate.")
    parser.add_argument("--attack-trials", type=int, default=DEFAULT_ATTACK_TRIALS)
    parser.add_argument("--control-trials", type=int, default=DEFAULT_CONTROL_TRIALS)
    parser.add_argument("--control-type", action="append", default=[], help="Control type list, or all.")
    parser.add_argument("--kimi-model", default=DEFAULT_KIMI_MODEL)
    parser.add_argument(
        "--claude-model",
        dest="claude_models",
        action="append",
        default=[],
        help="Claude Code model list. Repeat or comma-separate. Omit to use runtime default.",
    )
    parser.add_argument(
        "--claude-models",
        dest="claude_models",
        action="append",
        help="Alias for --claude-model.",
    )
    parser.add_argument("--permission-profile", default=DEFAULT_PERMISSION_PROFILE)
    parser.add_argument("--timeout-sec", type=int, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--case-limit", type=int, default=0)
    parser.add_argument(
        "--queue-seed",
        type=int,
        default=DEFAULT_QUEUE_SEED,
        help="Fixed seed for deterministic case-block and within-block ordering.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown.")
    parser.add_argument(
        "--allow-unlocked-preview",
        action="store_true",
        help="Explicitly allow a development preview when no verified suite lock exists.",
    )
    parser.add_argument("--out-json", default="", help="Optional JSON output path.")
    parser.add_argument("--out-md", default="", help="Optional Markdown output path.")
    args = parser.parse_args()

    plan = build_plan(
        case_set=args.case_set,
        attack_label_root=args.attack_label,
        control_label_root=args.control_label,
        harnesses=expand_harnesses(args.harness),
        attack_trials=args.attack_trials,
        control_trials=args.control_trials,
        control_types=expand_control_types(args.control_type),
        kimi_model=args.kimi_model,
        claude_models=split_cli_values(args.claude_models),
        permission_profile=args.permission_profile,
        timeout_sec=args.timeout_sec,
        case_limit=args.case_limit,
        queue_seed=args.queue_seed,
    )
    if plan.get("formal_execution_eligible") is not True and not args.allow_unlocked_preview:
        print(
            "refusing to emit a formal experiment plan without a verified paper suite lock; "
            "use --allow-unlocked-preview only for a non-formal development preview",
            file=sys.stderr,
        )
        return 2
    if args.out_json:
        path = Path(args.out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.out_md:
        path = Path(args.out_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(plan), encoding="utf-8")
    text = json.dumps(plan, indent=2, ensure_ascii=False) if args.json else render_markdown(plan)
    if not args.out_json and not args.out_md:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
