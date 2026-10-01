"""Export runnable batches for the remaining paper experiment matrix rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra import (
        check_paper_matrix_progress,
        plan_paper_experiment_matrix,
        result_classification,
    )
except ModuleNotFoundError:  # direct `python infra/export_paper_run_queue.py`
    import check_paper_matrix_progress  # type: ignore
    import plan_paper_experiment_matrix  # type: ignore
    import result_classification  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PLAN = ROOT / "docs" / "generated_artifacts" / "paper_experiment_matrix_plan.json"
DEFAULT_OUT_JSON = ROOT / "docs" / "generated_artifacts" / "paper_run_queue.json"
DEFAULT_OUT_MD = ROOT / "docs" / "generated_artifacts" / "paper_run_queue.md"

CURRENT_CLAUDE_ATTACK_LABEL = "paper_all"
CURRENT_CLAUDE_CONTROL_LABEL = "paper_controls_all"
CURRENT_CLAUDE_ATTACK_REPORT_DIR = r"runs\_reports\paper_all"
CURRENT_CLAUDE_CONTROL_REPORT_DIR = r"runs\_reports\paper_controls_all"
CURRENT_CLAUDE_MAX_TIMEOUTS = 3
CURRENT_CLAUDE_TABLE_DIR = r"runs\_reports\paper_all\paper_tables"
CURRENT_CLAUDE_CASE_EVIDENCE_DIR = r"runs\_reports\paper_all\case_study_evidence"
CURRENT_CLAUDE_BUNDLE_DIR = r"runs\_artifacts\repro_bundles\paper_all"
CURRENT_CLAUDE_ARTIFACT_GATE = r"runs\_reports\paper_all\paper_artifact_gate_submission.md"
QUEUE_SCHEMA_VERSION = "1.1.0"
FORMAL_MAX_ATTEMPTS = plan_paper_experiment_matrix.DEFAULT_MAX_INFRA_RETRIES + 1
FORMAL_LEDGER_SCHEMA_VERSION = 1


def formal_attempt_ledger_path(root: Path, matrix_id: str) -> Path:
    """Return the only ledger path accepted for one frozen matrix."""

    if not re.fullmatch(r"[0-9a-f]{16}", str(matrix_id or "")):
        raise ValueError("formal matrix_id must be 16 lowercase hex characters")
    return root / "runs" / "_artifacts" / "paper_queue_attempts" / f"{matrix_id}.jsonl"


def formal_launch_event_digest(event: dict[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key != "event_sha256"}
    return plan_paper_experiment_matrix.canonical_digest(payload)


def new_formal_launch_nonce() -> str:
    return secrets.token_hex(32)


def load_formal_launch_events(
    path: Path,
    *,
    expected_matrix_id: str = "",
) -> list[dict[str, Any]]:
    """Load and fully validate the append-only, hash-chained launch ledger.

    Attempts must start at one, remain contiguous for a row, and advance through
    queue positions without gaps or backwards movement.  This makes the ledger
    an executable record of the preregistered serial order rather than a loose
    retry counter.
    """

    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    previous_digest = ""
    previous_position = 0
    previous_row_id = ""
    attempts_by_row: dict[str, int] = {}
    row_by_position: dict[int, str] = {}
    seen_nonces: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed formal attempt ledger at line {line_number}: {exc}") from exc
        if not isinstance(event, dict) or event.get("event") != "launch":
            raise ValueError(f"formal attempt ledger has a non-launch record at line {line_number}")
        if event.get("schema_version") != FORMAL_LEDGER_SCHEMA_VERSION:
            raise ValueError(f"formal attempt ledger schema mismatch at line {line_number}")
        if int(event.get("ledger_sequence") or 0) != len(events) + 1:
            raise ValueError(f"formal attempt ledger sequence is not contiguous at line {line_number}")
        if str(event.get("previous_event_sha256") or "") != previous_digest:
            raise ValueError(f"formal attempt ledger hash chain is broken at line {line_number}")
        digest = str(event.get("event_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != formal_launch_event_digest(event):
            raise ValueError(f"formal attempt ledger event digest is invalid at line {line_number}")
        matrix_id = str(event.get("matrix_id") or "")
        if not re.fullmatch(r"[0-9a-f]{16}", matrix_id):
            raise ValueError(f"formal attempt ledger matrix_id is invalid at line {line_number}")
        if expected_matrix_id and matrix_id != expected_matrix_id:
            raise ValueError(f"formal attempt ledger matrix_id mismatch at line {line_number}")
        row_id = str(event.get("expected_row_id") or "")
        home_id = str(event.get("isolated_home_id") or "")
        nonce = str(event.get("launch_nonce") or "")
        command_digest = str(event.get("command_sha256") or "")
        try:
            position = int(event.get("queue_position") or 0)
            attempt = int(event.get("attempt_number") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"formal attempt ledger numeric binding is invalid at line {line_number}") from exc
        if not row_id or not home_id or position < 1:
            raise ValueError(f"formal attempt ledger row binding is incomplete at line {line_number}")
        if not 1 <= attempt <= FORMAL_MAX_ATTEMPTS:
            raise ValueError(f"formal attempt ledger attempt is outside [1, {FORMAL_MAX_ATTEMPTS}] at line {line_number}")
        if not re.fullmatch(r"[0-9a-f]{64}", nonce) or nonce in seen_nonces:
            raise ValueError(f"formal attempt ledger launch nonce is invalid or duplicated at line {line_number}")
        if not re.fullmatch(r"[0-9a-f]{64}", command_digest):
            raise ValueError(f"formal attempt ledger command digest is invalid at line {line_number}")
        expected_attempt = attempts_by_row.get(row_id, 0) + 1
        if attempt != expected_attempt:
            raise ValueError(f"formal attempt ledger attempts are not contiguous at line {line_number}")
        bound_row = row_by_position.get(position)
        if bound_row and bound_row != row_id:
            raise ValueError(f"formal attempt ledger reuses a queue position at line {line_number}")
        if previous_position:
            if position == previous_position:
                if row_id != previous_row_id:
                    raise ValueError(f"formal attempt ledger changes row within a queue position at line {line_number}")
            elif position != previous_position + 1 or attempt != 1:
                raise ValueError(f"formal attempt ledger queue order is not contiguous at line {line_number}")
        elif position != 1 or attempt != 1:
            raise ValueError("formal attempt ledger must begin with queue position 1 attempt 1")
        attempts_by_row[row_id] = attempt
        row_by_position[position] = row_id
        seen_nonces.add(nonce)
        previous_position = position
        previous_row_id = row_id
        previous_digest = digest
        events.append(event)
    return events


def append_formal_launch_event(
    path: Path,
    *,
    matrix_id: str,
    expected_row_id: str,
    isolated_home_id: str,
    queue_position: int,
    attempt_number: int,
    command_sha256: str,
    launch_nonce: str,
) -> dict[str, Any]:
    """Append one fsync'd launch after validating all preceding provenance."""

    events = load_formal_launch_events(path, expected_matrix_id=matrix_id)
    if not re.fullmatch(r"[0-9a-f]{16}", matrix_id):
        raise ValueError("formal launch matrix_id must be 16 lowercase hex characters")
    if not expected_row_id or not isolated_home_id or int(queue_position) < 1:
        raise ValueError("formal launch row binding is incomplete")
    prior_attempts = [
        item for item in events if str(item.get("expected_row_id") or "") == expected_row_id
    ]
    if int(attempt_number) != len(prior_attempts) + 1:
        raise ValueError("formal launch attempt is not contiguous for expected_row_id")
    if any(
        int(item.get("queue_position") or 0) == int(queue_position)
        and str(item.get("expected_row_id") or "") != expected_row_id
        for item in events
    ):
        raise ValueError("formal launch queue position is already bound to another row")
    if prior_attempts and any(
        int(item.get("queue_position") or 0) != int(queue_position) for item in prior_attempts
    ):
        raise ValueError("formal launch expected_row_id is already bound to another queue position")
    event: dict[str, Any] = {
        "schema_version": FORMAL_LEDGER_SCHEMA_VERSION,
        "event": "launch",
        "ledger_sequence": len(events) + 1,
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
        "matrix_id": matrix_id,
        "expected_row_id": expected_row_id,
        "isolated_home_id": isolated_home_id,
        "queue_position": int(queue_position),
        "attempt_number": int(attempt_number),
        "command_sha256": command_sha256,
        "launch_nonce": launch_nonce,
        "previous_event_sha256": str(events[-1].get("event_sha256") or "") if events else "",
    }
    event["event_sha256"] = formal_launch_event_digest(event)
    # Validate the candidate together with the existing chain before mutating
    # the durable file.  A temporary in-memory round-trip keeps one canonical
    # validator authoritative for both append and consumption.
    prior = events[-1] if events else None
    if prior:
        if int(event["queue_position"]) == int(prior["queue_position"]):
            if event["expected_row_id"] != prior["expected_row_id"]:
                raise ValueError("formal launch changes row within a queue position")
            if int(event["attempt_number"]) != int(prior["attempt_number"]) + 1:
                raise ValueError("formal launch retry attempt is not contiguous")
        elif int(event["queue_position"]) != int(prior["queue_position"]) + 1 or int(
            event["attempt_number"]
        ) != 1:
            raise ValueError("formal launch queue order is not contiguous")
    elif int(event["queue_position"]) != 1 or int(event["attempt_number"]) != 1:
        raise ValueError("formal launch ledger must begin with queue position 1 attempt 1")
    if not 1 <= int(attempt_number) <= FORMAL_MAX_ATTEMPTS:
        raise ValueError(f"formal launch attempt must be in [1, {FORMAL_MAX_ATTEMPTS}]")
    if not re.fullmatch(r"[0-9a-f]{64}", launch_nonce):
        raise ValueError("formal launch nonce must be 64 lowercase hex characters")
    if any(str(item.get("launch_nonce") or "") == launch_nonce for item in events):
        raise ValueError("formal launch nonce is duplicated")
    if not re.fullmatch(r"[0-9a-f]{64}", command_sha256):
        raise ValueError("formal launch command digest must be 64 lowercase hex characters")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    verified = load_formal_launch_events(path, expected_matrix_id=matrix_id)
    if not verified or verified[-1] != event:
        raise RuntimeError("formal launch ledger append could not be verified")
    return event


def queue_digest(queue: dict[str, Any]) -> str:
    canonical = {
        key: value
        for key, value in queue.items()
        if key not in {"generated_at", "queue_digest"}
    }
    return plan_paper_experiment_matrix.canonical_digest(canonical)


def split_control_types(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def powershell_list(values: list[str]) -> str:
    return ",".join(values)


def powershell_quote(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def formal_row_command(row: dict[str, Any]) -> str:
    case_dir = ".\\runs\\" + str(row["case_dir"]).replace("/", "\\")
    parts = [
        ".\\infra\\run_harness_case.ps1",
        "-Harness",
        powershell_quote(row["harness"]),
        "-CaseDir",
        powershell_quote(case_dir),
        "-PermissionProfile",
        powershell_quote(row["permission_profile"]),
        "-IsolationMode",
        "isolated_home",
        "-RunLabel",
        powershell_quote(row["label"]),
        "-TimeoutSec",
        str(int(row["timeout_sec"])),
        "-CanaryToken",
        powershell_quote(row["canary_token"]),
        "-FormalCaseContentSha256",
        powershell_quote(row["case_content_digest"]),
        "-FormalCaseContractSha256",
        powershell_quote(row["case_contract_digest"]),
        "-FormalControlContractSha256",
        powershell_quote(row["control_contract_digest"]),
        "-FormalRuntimeInputsSha256",
        powershell_quote(row["case_runtime_input_digest"]),
        "-FormalSourceManifestSha256",
        powershell_quote(row["source_manifest_digest"]),
        "-FormalSourceManifestCanonicalSha256",
        powershell_quote(row["source_manifest_canonical_digest"]),
        "-FormalRuntimeCodeSha256",
        powershell_quote(row["runtime_code_revision_digest"]),
        "-FormalProtocolSha256",
        powershell_quote(row["protocol_revision_digest"]),
        "-FormalRuntimeInputPolicySha256",
        powershell_quote(row["runtime_input_policy_digest"]),
        "-FormalRuntimeRevisionSha256",
        powershell_quote(row["runtime_revision_digest"]),
        "-FormalSuiteContentSha256",
        powershell_quote(row["suite_content_digest"]),
        "-FormalRowId",
        powershell_quote(row["expected_row_id"]),
        "-FormalAttestationMode",
        "formal_suite_lock",
        "-FormalIsolatedHomeId",
        powershell_quote(row["isolated_home_id"]),
        "-OutputMode",
        "minimal",
    ]
    runtime_model = str(row.get("runtime_model") or "")
    if runtime_model:
        parts.extend(["-Model", powershell_quote(runtime_model)])
    control_type = str(row.get("control_type") or "")
    if control_type:
        parts.extend(["-ControlType", powershell_quote(control_type)])
    return " ".join(parts)


def _run_validity_is_valid(run_dir: Path) -> bool:
    validity_path = run_dir / "run_validity.json"
    oracle_path = run_dir / "oracle.json"
    if not validity_path.is_file() or not oracle_path.is_file():
        return False
    try:
        validity = check_paper_matrix_progress.load_json(validity_path)
    except Exception:
        return False
    return result_classification.is_scored_run_validity(validity)


def _run_validity_is_terminal_model_protocol(run_dir: Path) -> bool:
    validity_path = run_dir / "run_validity.json"
    oracle_path = run_dir / "oracle.json"
    if not validity_path.is_file() or not oracle_path.is_file():
        return False
    try:
        validity = check_paper_matrix_progress.load_json(validity_path)
    except Exception:
        return False
    return result_classification.is_terminal_model_protocol_deviation(validity)


def formal_launch_binding_matches(
    run_dir: Path,
    row: dict[str, Any],
    case_meta: dict[str, Any],
    attestation: dict[str, Any],
) -> bool:
    """Bind a result to exactly one valid launch in the frozen serial ledger."""

    matrix_id = str(row.get("matrix_id") or "")
    if not re.fullmatch(r"[0-9a-f]{16}", matrix_id):
        return False
    try:
        queue_position = int(row.get("queue_position") or 0)
        formal_attempt = int(case_meta.get("formal_attempt") or 0)
    except (TypeError, ValueError):
        return False
    if queue_position < 1 or not 1 <= formal_attempt <= FORMAL_MAX_ATTEMPTS:
        return False
    launch_fields = {
        "formal_matrix_id": matrix_id,
        "formal_queue_position": queue_position,
        "formal_launch_nonce": str(case_meta.get("formal_launch_nonce") or ""),
        "formal_launch_command_sha256": str(
            case_meta.get("formal_launch_command_sha256") or ""
        ),
        "formal_launch_event_sha256": str(case_meta.get("formal_launch_event_sha256") or ""),
    }
    if str(case_meta.get("formal_matrix_id") or "") != matrix_id:
        return False
    try:
        if int(case_meta.get("formal_queue_position") or 0) != queue_position:
            return False
    except (TypeError, ValueError):
        return False
    if any(
        not re.fullmatch(r"[0-9a-f]{64}", str(value or ""))
        for field, value in launch_fields.items()
        if field not in {"formal_matrix_id", "formal_queue_position"}
    ):
        return False
    for field, expected in launch_fields.items():
        if attestation.get(field) != expected:
            return False
    paths = attestation.get("paths") or {}
    try:
        root = Path(str(paths.get("repo_root") or "")).resolve(strict=True)
        expected_results_root = (
            root / "runs" / str(row.get("case_dir") or "") / "results"
        ).resolve(strict=True)
        if run_dir.resolve(strict=True).parent != expected_results_root:
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    try:
        ledger_path = formal_attempt_ledger_path(root, matrix_id)
        events = load_formal_launch_events(ledger_path, expected_matrix_id=matrix_id)
    except (OSError, ValueError):
        return False
    matching = [
        event
        for event in events
        if str(event.get("expected_row_id") or "") == str(row.get("expected_row_id") or "")
        and str(event.get("isolated_home_id") or "") == str(row.get("isolated_home_id") or "")
        and int(event.get("queue_position") or 0) == queue_position
        and int(event.get("attempt_number") or 0) == formal_attempt
        and str(event.get("launch_nonce") or "") == launch_fields["formal_launch_nonce"]
        and str(event.get("command_sha256") or "")
        == launch_fields["formal_launch_command_sha256"]
        and str(event.get("event_sha256") or "")
        == launch_fields["formal_launch_event_sha256"]
    ]
    return len(matching) == 1


def formal_result_provenance_matches(run_dir: Path, row: dict[str, Any]) -> bool:
    """Require the materialization/runtime digests on every formal result.

    ``matching_runs`` still performs the normal logical-row match.  This
    additional gate intentionally makes pre-attestation/legacy rows
    non-matching and verifies the out-of-workspace materialization artifact.
    A missing ``run_validity.json`` is permitted only so a freshly launched,
    exactly bound row can be classified as in progress.
    """

    expected = {
        "formal_case_content_sha256": str(row.get("case_content_digest") or ""),
        "formal_case_contract_sha256": str(row.get("case_contract_digest") or ""),
        "formal_control_contract_sha256": str(row.get("control_contract_digest") or ""),
        "formal_runtime_inputs_sha256": str(row.get("case_runtime_input_digest") or ""),
        "formal_source_manifest_sha256": str(row.get("source_manifest_digest") or ""),
        "formal_source_manifest_canonical_sha256": str(
            row.get("source_manifest_canonical_digest") or ""
        ),
        "formal_runtime_code_sha256": str(row.get("runtime_code_revision_digest") or ""),
        "formal_protocol_sha256": str(row.get("protocol_revision_digest") or ""),
        "formal_runtime_input_policy_sha256": str(row.get("runtime_input_policy_digest") or ""),
        "formal_runtime_revision_sha256": str(row.get("runtime_revision_digest") or ""),
        "formal_suite_content_sha256": str(row.get("suite_content_digest") or ""),
    }
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in expected.values()):
        return False
    try:
        case_meta = check_paper_matrix_progress.load_json(run_dir / "case.json")
    except Exception:
        return False
    if any(str(case_meta.get(field) or "") != value for field, value in expected.items()):
        return False
    if str(case_meta.get("formal_attestation_mode") or "") != "formal_suite_lock":
        return False
    attestation_path = run_dir / "materialization_attestation.json"
    if str(case_meta.get("materialization_attestation_path") or "") != str(attestation_path.resolve()):
        return False
    try:
        attestation = check_paper_matrix_progress.load_json(attestation_path)
    except Exception:
        return False
    if (
        attestation.get("all_verified") is not True
        or str(attestation.get("formal_row_id") or "") != str(row.get("expected_row_id") or "")
    ):
        return False
    stored_attestation_digest = str(attestation.get("attestation_sha256") or "")
    digest_payload = {
        key: value for key, value in attestation.items() if key != "attestation_sha256"
    }
    if stored_attestation_digest != plan_paper_experiment_matrix.check_paper_suite_lock.canonical_json_sha256(
        digest_payload
    ):
        return False
    attestation_file_digest = hashlib.sha256(attestation_path.read_bytes()).hexdigest()
    if (
        str(case_meta.get("materialization_attestation_sha256") or "")
        != stored_attestation_digest
        or str(case_meta.get("materialization_attestation_initial_file_sha256") or "")
        != attestation_file_digest
        or str(case_meta.get("materialization_attestation_final_file_sha256") or "")
        != attestation_file_digest
        or case_meta.get("materialization_attestation_untampered") is not True
    ):
        return False
    attestation_expected = attestation.get("expected") or {}
    expected_attestation = {
        "case_content_sha256": expected["formal_case_content_sha256"],
        "case_contract_digest": expected["formal_case_contract_sha256"],
        "control_contract_digest": expected["formal_control_contract_sha256"],
        "runtime_inputs_sha256": expected["formal_runtime_inputs_sha256"],
        "source_manifest_sha256": expected["formal_source_manifest_sha256"],
        "source_manifest_canonical_sha256": expected[
            "formal_source_manifest_canonical_sha256"
        ],
        "runtime_code_sha256": expected["formal_runtime_code_sha256"],
        "protocol_sha256": expected["formal_protocol_sha256"],
        "runtime_input_policy_sha256": expected[
            "formal_runtime_input_policy_sha256"
        ],
        "runtime_revision_sha256": expected["formal_runtime_revision_sha256"],
        "suite_content_sha256": expected["formal_suite_content_sha256"],
    }
    if attestation_expected != expected_attestation:
        return False
    if attestation.get("attestation_mode") != "formal_suite_lock":
        return False
    paths = attestation.get("paths") or {}
    if str(paths.get("attestation") or "") != str(attestation_path.resolve()):
        return False
    observed = attestation.get("observed") or {}
    source_before = observed.get("source_before") or {}
    copied = observed.get("copied_pre_injection") or {}
    source_after = observed.get("source_after") or {}
    for field in (
        "case_meta_canonical_sha256",
        "control_contracts_canonical_sha256",
        "runtime_inputs_tree_sha256",
        "case_content_sha256",
    ):
        values = [str(item.get(field) or "") for item in (source_before, copied, source_after)]
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in values) or len(set(values)) != 1:
            return False
    if source_before.get("case_content_sha256") != expected_attestation["case_content_sha256"]:
        return False
    if source_before.get("runtime_inputs_tree_sha256") != expected_attestation["runtime_inputs_sha256"]:
        return False
    runtime_before = observed.get("runtime_before") or {}
    runtime_after = observed.get("runtime_after") or {}
    for field in (
        "runtime_code_sha256",
        "protocol_sha256",
        "runtime_input_policy_sha256",
        "runtime_revision_sha256",
    ):
        if (
            str(runtime_before.get(field) or "") != expected_attestation[field]
            or str(runtime_after.get(field) or "") != expected_attestation[field]
        ):
            return False
    if str(observed.get("suite_lock_content_sha256") or "") != expected_attestation[
        "suite_content_sha256"
    ]:
        return False
    if not formal_launch_binding_matches(run_dir, row, case_meta, attestation):
        return False
    validity_path = run_dir / "run_validity.json"
    if validity_path.is_file():
        try:
            validity = check_paper_matrix_progress.load_json(validity_path)
        except Exception:
            return False
        schema_version = validity.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version < result_classification.RUN_VALIDITY_SCHEMA_VERSION
        ):
            return False
        if any(str(validity.get(field) or "") != value for field, value in expected.items()):
            return False
        for field in (
            "formal_matrix_id",
            "formal_launch_nonce",
            "formal_launch_command_sha256",
            "formal_launch_event_sha256",
        ):
            if str(validity.get(field) or "") != str(case_meta.get(field) or ""):
                return False
        try:
            if int(validity.get("formal_queue_position") or 0) != int(
                case_meta.get("formal_queue_position") or 0
            ) or int(validity.get("formal_attempt") or 0) != int(
                case_meta.get("formal_attempt") or 0
            ):
                return False
        except (TypeError, ValueError):
            return False
        if validity.get("materialization_all_verified") is not True:
            return False
        if validity.get("materialization_attestation_untampered") is not True:
            return False
        if (
            str(validity.get("materialization_attestation_sha256") or "")
            != stored_attestation_digest
            or str(validity.get("materialization_attestation_initial_file_sha256") or "")
            != attestation_file_digest
            or str(validity.get("materialization_attestation_final_file_sha256") or "")
            != attestation_file_digest
        ):
            return False
    return True


def serial_row_state(
    root: Path,
    row: dict[str, Any],
    *,
    in_progress_grace_sec: int = check_paper_matrix_progress.DEFAULT_IN_PROGRESS_GRACE_SEC,
) -> dict[str, Any]:
    matches = [
        path
        for path in check_paper_matrix_progress.matching_runs(root, row)
        if formal_result_provenance_matches(path, row)
    ]
    valid = [path for path in matches if _run_validity_is_valid(path)]
    model_protocol_terminal = [
        path for path in matches if _run_validity_is_terminal_model_protocol(path)
    ]
    accounted = valid + model_protocol_terminal
    now = time.time()
    in_progress: list[Path] = []
    invalid: list[Path] = []
    for path in matches:
        if path in accounted:
            continue
        try:
            recent = now - check_paper_matrix_progress.newest_mtime(path) <= in_progress_grace_sec
        except OSError:
            recent = False
        if recent and not (path / "run_validity.json").is_file():
            in_progress.append(path)
        else:
            invalid.append(path)
    return {
        "matching_attempts": len(matches),
        "valid_result_count": len(valid),
        "model_protocol_terminal_count": len(model_protocol_terminal),
        "accounted_result_count": len(accounted),
        "invalid_attempt_count": len(invalid),
        "in_progress_attempt_count": len(in_progress),
        "valid_result_dirs": [check_paper_matrix_progress.norm_path(path, root) for path in valid],
        "model_protocol_terminal_dirs": [
            check_paper_matrix_progress.norm_path(path, root)
            for path in model_protocol_terminal
        ],
        "invalid_attempt_dirs": [check_paper_matrix_progress.norm_path(path, root) for path in invalid],
        "in_progress_attempt_dirs": [
            check_paper_matrix_progress.norm_path(path, root) for path in in_progress
        ],
    }


def serial_row_record(root: Path, row: dict[str, Any], *, max_attempts: int) -> dict[str, Any]:
    state = serial_row_state(root, row)
    completed = state["accounted_result_count"] == 1 and state["in_progress_attempt_count"] == 0
    return {
        **row,
        "batch_id": str(row["expected_row_id"]),
        "control_types": [str(row.get("control_type") or "")] if row.get("control_type") else [],
        "missing_rows": 0 if completed else 1,
        "command": formal_row_command(row),
        "skip_completed": True,
        "max_attempts": max_attempts,
        "attempts_remaining": max(0, max_attempts - int(state["matching_attempts"])),
        "completed": completed,
        **state,
    }


def claude_models_arg(plan: dict[str, Any], harness: str) -> str:
    if harness != "claude":
        return ""
    models = [str(item) for item in plan.get("models", {}).get("claude_models", []) if str(item)]
    if not models:
        legacy_model = str(plan.get("models", {}).get("claude") or "")
        models = [legacy_model] if legacy_model else []
    return f" -ClaudeModels {powershell_list(models)}" if models else ""


def attack_command(plan: dict[str, Any], harness: str) -> str:
    model = plan.get("models", {}).get("non_claude") or plan_paper_experiment_matrix.DEFAULT_KIMI_MODEL
    return (
        ".\\infra\\run_paper_baseline_matrix.ps1 "
        f"-RunLabel {plan['attack_label_root']} "
        f"-CaseSet {plan['case_set']} "
        f"-Trials {plan['attack_trials']} "
        f"-Harnesses {harness} "
        f"-KimiModel {model}{claude_models_arg(plan, harness)} "
        f"-TimeoutSec {plan['timeout_sec']} "
        "-SkipCompleted -NoReport"
    )


def control_command(plan: dict[str, Any], harness: str, control_types: list[str]) -> str:
    model = plan.get("models", {}).get("non_claude") or plan_paper_experiment_matrix.DEFAULT_KIMI_MODEL
    return (
        ".\\infra\\run_paper_control_matrix.ps1 "
        f"-RunLabel {plan['control_label_root']} "
        f"-CaseSet {plan['case_set']} "
        f"-Trials {plan['control_trials']} "
        f"-Harnesses {harness} "
        f"-ControlTypes {powershell_list(control_types)} "
        f"-KimiModel {model}{claude_models_arg(plan, harness)} "
        f"-TimeoutSec {plan['timeout_sec']} "
        "-SkipCompleted -NoReport"
    )


def is_current_claude_scope(harnesses: list[str]) -> bool:
    return [str(item).lower() for item in harnesses] == ["claude"]


def current_claude_artifact_commands() -> list[str]:
    return [
        (
            "python infra\\report_active_run.py "
            f"--label {CURRENT_CLAUDE_ATTACK_LABEL} --case-set all "
            "--all-matching-runs --run-kind attack --harness claude"
        ),
        (
            "python infra\\report_active_run.py "
            f"--label {CURRENT_CLAUDE_CONTROL_LABEL} --case-set all "
            "--all-matching-runs --run-kind control --control-type all --harness claude"
        ),
        (
            "python infra\\check_paper_results.py "
            f"--attack-label {CURRENT_CLAUDE_ATTACK_LABEL} --control-label {CURRENT_CLAUDE_CONTROL_LABEL} "
            "--case-set all --min-attack-trials 3 --min-control-trials 1 "
            f"--control-type all --expected-harness claude --max-timeouts {CURRENT_CLAUDE_MAX_TIMEOUTS} "
            f"--out {CURRENT_CLAUDE_ATTACK_REPORT_DIR}\\paper_result_quality_gate.md"
        ),
        (
            "python infra\\export_paper_tables.py "
            f"--attack-label {CURRENT_CLAUDE_ATTACK_LABEL} --control-label {CURRENT_CLAUDE_CONTROL_LABEL} "
            f"--out-dir {CURRENT_CLAUDE_TABLE_DIR}"
        ),
        (
            "python infra\\export_case_study_evidence.py "
            f"--attack-label {CURRENT_CLAUDE_ATTACK_LABEL} --control-label {CURRENT_CLAUDE_CONTROL_LABEL} "
            f"--out-dir {CURRENT_CLAUDE_CASE_EVIDENCE_DIR}"
        ),
        "python infra\\check_paper_matrix_progress.py --out docs\\generated_artifacts\\paper_experiment_matrix_progress.md",
        "python infra\\check_paper_matrix_progress.py --harness claude --out docs\\generated_artifacts\\paper_experiment_matrix_progress_claude.md",
        "python infra\\export_paper_run_queue.py --out-json docs\\generated_artifacts\\paper_run_queue.json --out-md docs\\generated_artifacts\\paper_run_queue.md",
        (
            "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json "
            "--queue-mode serial --out-json docs\\generated_artifacts\\paper_run_execution_plan.json "
            "--out-md docs\\generated_artifacts\\paper_run_execution_plan.md"
        ),
        (
            "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json "
            "--queue-mode serial --harness claude "
            "--out-json docs\\generated_artifacts\\paper_run_execution_claude_dry_run.json "
            "--out-md docs\\generated_artifacts\\paper_run_execution_claude_dry_run.md"
        ),
        (
            "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json "
            "--queue-mode post-run --harness claude "
            "--out-json docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.json "
            "--out-md docs\\generated_artifacts\\paper_run_execution_claude_post_run_dry_run.md"
        ),
        "python infra\\estimate_paper_run_budget.py --out-json docs\\generated_artifacts\\paper_run_budget.json --out-md docs\\generated_artifacts\\paper_run_budget.md",
        (
            "python infra\\report_paper_submission_gaps.py "
            "--out docs\\generated_artifacts\\paper_submission_gap_report.md "
            "--json-out docs\\generated_artifacts\\paper_submission_gap_report.json"
        ),
        (
            "python infra\\build_repro_bundle.py "
            f"--attack-label {CURRENT_CLAUDE_ATTACK_LABEL} --control-label {CURRENT_CLAUDE_CONTROL_LABEL} "
            f"--table-dir {CURRENT_CLAUDE_TABLE_DIR} "
            f"--case-evidence-dir {CURRENT_CLAUDE_CASE_EVIDENCE_DIR} "
            f"--out-dir {CURRENT_CLAUDE_BUNDLE_DIR} --copy-artifacts"
        ),
        f"python infra\\check_public_artifact_safety.py --bundle-dir {CURRENT_CLAUDE_BUNDLE_DIR}",
        (
            "python infra\\check_paper_artifact_gate.py "
            f"--attack-label {CURRENT_CLAUDE_ATTACK_LABEL} --control-label {CURRENT_CLAUDE_CONTROL_LABEL} "
            f"--table-dir {CURRENT_CLAUDE_TABLE_DIR} "
            f"--bundle-dir {CURRENT_CLAUDE_BUNDLE_DIR} "
            f"--case-evidence-dir {CURRENT_CLAUDE_CASE_EVIDENCE_DIR} "
            "--case-set all --min-attack-trials 3 --min-control-trials 1 "
            f"--control-type all --expected-harness claude --max-timeouts {CURRENT_CLAUDE_MAX_TIMEOUTS} "
            f"--submission-profile --out {CURRENT_CLAUDE_ARTIFACT_GATE}"
        ),
        (
            "python infra\\report_paper_submission_gaps.py --require-ready "
            "--out docs\\generated_artifacts\\paper_submission_gap_report.md "
            "--json-out docs\\generated_artifacts\\paper_submission_gap_report.json"
        ),
    ]


def post_run_commands_for_harnesses(
    plan: dict[str, Any],
    harnesses: list[str],
    *,
    suffix: str = "",
    require_complete: bool = False,
    include_preflight: bool = False,
    include_current_claude_artifact: bool = False,
) -> list[str]:
    harness_args = " ".join(f"--harness {harness}" for harness in harnesses)
    progress_harness_args = " ".join(f"--harness {harness}" for harness in harnesses) if suffix else ""
    out_suffix = f"_{suffix}" if suffix else ""
    progress_args = "--require-complete " if require_complete else ""
    progress_command_parts = [
        "python infra\\check_paper_matrix_progress.py",
        progress_args.strip(),
        progress_harness_args,
        "--out",
        f"runs\\_reports\\{plan['attack_label_root']}\\paper_matrix_progress{out_suffix}.md",
    ]
    progress_command = " ".join(part for part in progress_command_parts if part)
    commands = [
        (
            "python infra\\report_active_run.py "
            f"--label {plan['attack_label_root']} --case-set {plan['case_set']} "
            f"--all-matching-runs --run-kind attack {harness_args}"
        ),
        (
            "python infra\\report_active_run.py "
            f"--label {plan['control_label_root']} --case-set {plan['case_set']} "
            f"--all-matching-runs --run-kind control --control-type all {harness_args}"
        ),
        progress_command,
        (
            "python infra\\check_paper_results.py "
            f"--attack-label {plan['attack_label_root']} "
            f"--control-label {plan['control_label_root']} "
            f"--case-set {plan['case_set']} --min-attack-trials {plan['attack_trials']} "
            f"--min-control-trials {plan['control_trials']} --control-type all "
            + " ".join(f"--expected-harness {harness}" for harness in harnesses)
            + f" --max-timeouts {CURRENT_CLAUDE_MAX_TIMEOUTS}"
            + f" --out runs\\_reports\\{plan['attack_label_root']}\\paper_result_quality_gate{out_suffix}.md"
        ),
        (
            "python infra\\export_paper_tables.py "
            f"--attack-label {plan['attack_label_root']} "
            f"--control-label {plan['control_label_root']} "
            f"--out-dir runs\\_reports\\{plan['attack_label_root']}\\paper_tables{out_suffix}"
        ),
        (
            "python infra\\export_case_study_evidence.py "
            f"--attack-label {plan['attack_label_root']} "
            f"--control-label {plan['control_label_root']} "
            f"--out-dir runs\\_reports\\{plan['attack_label_root']}\\case_study_evidence{out_suffix}"
        ),
    ]
    if include_current_claude_artifact and is_current_claude_scope(harnesses):
        commands.extend(current_claude_artifact_commands())
    if include_preflight:
        commands.append(".\\infra\\run_paper_preflight.ps1 -Profile submission")
    return commands


def post_run_commands(plan: dict[str, Any]) -> list[str]:
    harnesses = list(plan["harnesses"])
    return post_run_commands_for_harnesses(
        plan,
        harnesses,
        require_complete=True,
        include_preflight=True,
        include_current_claude_artifact=is_current_claude_scope(harnesses),
    )


def post_run_batches(plan: dict[str, Any]) -> list[dict[str, Any]]:
    batches: list[dict[str, Any]] = []
    for harness in plan["harnesses"]:
        suffix = f"{harness}_partial"
        commands = post_run_commands_for_harnesses(
            plan,
            [harness],
            suffix=suffix,
            require_complete=True,
            include_current_claude_artifact=is_current_claude_scope(list(plan["harnesses"])) and harness == "claude",
        )
        for index, command in enumerate(commands, start=1):
            batches.append(
                {
                    "batch_id": f"post_run_{harness}_{index:02d}",
                    "kind": "post_run",
                    "harness": harness,
                    "control_types": [],
                    "missing_rows": 0,
                    "trials": [],
                    "requires_kimi": False,
                    "command": command,
                }
            )
    return batches


def build_queue(
    root: Path = ROOT,
    plan_path: Path = DEFAULT_PLAN,
    preview_limit: int = 50,
    *,
    allow_unlocked_preview: bool = False,
) -> dict[str, Any]:
    plan = plan_paper_experiment_matrix.load_json(plan_path)
    plan_issues = plan_paper_experiment_matrix.validate_plan(plan, root=root)
    plan_errors = [item for item in plan_issues if item.get("severity") == "error"]
    if plan_errors:
        raise ValueError(
            "refusing to export a stale or invalid experiment plan: "
            + "; ".join(str(item.get("message") or "plan error") for item in plan_errors[:5])
        )
    formal_plan = bool(
        plan.get("plan_status") == "formal_locked"
        and plan.get("formal_execution_eligible") is True
        and (plan.get("suite_lock", {}) or {}).get("verified") is True
    )
    if not formal_plan and not allow_unlocked_preview:
        raise ValueError(
            "refusing to export a formal queue from an unlocked development plan; "
            "use --allow-unlocked-preview only for a non-executable preview"
        )
    progress = check_paper_matrix_progress.build_progress_report(root=root, plan_path=plan_path, preview_limit=preview_limit)
    retry_contract = plan.get("execution_contract", {}).get("retry", {}) or {}
    max_attempts = int(
        retry_contract.get("maximum_attempts_per_expected_row")
        or plan_paper_experiment_matrix.DEFAULT_MAX_INFRA_RETRIES + 1
    )
    matrix_id = str(plan.get("matrix_id") or "unbound")
    serial_rows = [
        serial_row_record(root, {**row, "matrix_id": matrix_id}, max_attempts=max_attempts)
        for row in sorted(plan.get("rows", []) or [], key=lambda item: int(item["queue_position"]))
    ]
    serial_completed = sum(1 for row in serial_rows if row["completed"])
    serial_valid_completed = sum(
        1
        for row in serial_rows
        if int(row["valid_result_count"]) == 1
        and int(row["accounted_result_count"]) == 1
        and int(row["in_progress_attempt_count"]) == 0
    )
    duplicate_valid_rows = sum(1 for row in serial_rows if int(row["valid_result_count"]) > 1)
    duplicate_accounted_rows = sum(
        1 for row in serial_rows if int(row["accounted_result_count"]) > 1
    )
    model_protocol_terminal_rows = sum(
        1 for row in serial_rows if int(row["model_protocol_terminal_count"]) == 1
    )
    retry_exhausted_rows = sum(
        1
        for row in serial_rows
        if not row["completed"]
        and int(row["matching_attempts"]) >= max_attempts
        and int(row["in_progress_attempt_count"]) == 0
    )
    in_progress_rows = sum(1 for row in serial_rows if int(row["in_progress_attempt_count"]) > 0)
    missing = [row for row in progress["rows"] if not row["completed"]]
    attack_by_harness: dict[str, list[dict[str, Any]]] = defaultdict(list)
    controls_by_harness: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for row in missing:
        if row["kind"] == "attack":
            attack_by_harness[row["harness"]].append(row)
        elif row["kind"] == "control":
            controls_by_harness[row["harness"]][row["control_type"]].append(row)

    batches: list[dict[str, Any]] = []
    for harness in plan["harnesses"]:
        rows = attack_by_harness.get(harness, [])
        if rows:
            batches.append(
                {
                    "batch_id": f"attack_{harness}",
                    "kind": "attack",
                    "harness": harness,
                    "control_types": [],
                    "missing_rows": len(rows),
                    "trials": sorted({int(row["trial"]) for row in rows}),
                    "command": attack_command(plan, harness),
                }
            )
    for harness in plan["harnesses"]:
        by_control = controls_by_harness.get(harness, {})
        for control_type in plan["control_types"]:
            rows = by_control.get(control_type, [])
            if rows:
                batches.append(
                    {
                        "batch_id": f"control_{harness}_{control_type}",
                        "kind": "control",
                        "harness": harness,
                        "control_types": [control_type],
                        "missing_rows": len(rows),
                        "trials": sorted({int(row["trial"]) for row in rows}),
                        "command": control_command(plan, harness, [control_type]),
                    }
                )

    all_control_batches: list[dict[str, Any]] = []
    for harness in plan["harnesses"]:
        control_types = [ctype for ctype in plan["control_types"] if controls_by_harness.get(harness, {}).get(ctype)]
        row_count = sum(len(controls_by_harness.get(harness, {}).get(ctype, [])) for ctype in control_types)
        if control_types:
            all_control_batches.append(
                {
                    "batch_id": f"control_{harness}_all_missing_types",
                    "kind": "control",
                    "harness": harness,
                    "control_types": control_types,
                    "missing_rows": row_count,
                    "trials": sorted({int(row["trial"]) for ctype in control_types for row in controls_by_harness[harness][ctype]}),
                    "command": control_command(plan, harness, control_types),
                }
            )

    queue = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "queue_schema_version": QUEUE_SCHEMA_VERSION,
        "root": str(root),
        "plan_path": str(plan_path),
        "plan_file_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "matrix_id": plan.get("matrix_id", ""),
        "matrix_digest": plan.get("matrix_digest", ""),
        "case_set": plan.get("case_set", ""),
        "queue_status": "formal_locked" if formal_plan else "development_unlocked",
        "formal_execution_eligible": formal_plan,
        "suite_lock": plan.get("suite_lock", {}),
        "summary": {
            "expected_rows": progress["summary"]["expected_rows"],
            "completed_rows": progress["summary"]["completed_rows"],
            "missing_rows": len(missing),
            "formal_serial_rows": len(serial_rows),
            "formal_valid_completed_rows": serial_valid_completed,
            "formal_accounted_completed_rows": serial_completed,
            "formal_pending_rows": len(serial_rows) - serial_completed,
            "duplicate_valid_rows": duplicate_valid_rows,
            "duplicate_accounted_rows": duplicate_accounted_rows,
            "model_protocol_terminal_rows": model_protocol_terminal_rows,
            "retry_exhausted_rows": retry_exhausted_rows,
            "in_progress_rows": in_progress_rows,
            "batch_count": len(batches),
            "coalesced_batch_count": len(attack_by_harness) + len(all_control_batches),
        },
        "progress_summary": progress["summary"],
        "execution_contract": plan.get("execution_contract", {}),
        "attempt_ledger": f"runs/_artifacts/paper_queue_attempts/{matrix_id}.jsonl",
        "execution_lock": f"runs/_artifacts/paper_queue_attempts/{matrix_id}.lock",
        "serial_rows": serial_rows,
        "batches": batches,
        "coalesced_batches": [
            *[
                {
                    "batch_id": f"attack_{harness}",
                    "kind": "attack",
                    "harness": harness,
                    "control_types": [],
                    "missing_rows": len(rows),
                    "trials": sorted({int(row["trial"]) for row in rows}),
                    "command": attack_command(plan, harness),
                }
                for harness, rows in sorted(attack_by_harness.items())
                if rows
            ],
            *all_control_batches,
        ],
        "post_run_commands": post_run_commands(plan),
        "post_run_batches": post_run_batches(plan),
        "missing_rows_preview": missing[:preview_limit],
    }
    queue["queue_digest"] = queue_digest(queue)
    return queue


def render_markdown(queue: dict[str, Any]) -> str:
    summary = queue["summary"]
    formal_queue = queue.get("formal_execution_eligible") is True
    lines = [
        "# Paper Run Queue",
        "",
        f"- generated_at: `{queue['generated_at']}`",
        f"- matrix_id: `{queue['matrix_id']}`",
        f"- case_set: `{queue['case_set']}`",
        f"- queue_status: `{queue.get('queue_status', 'development_unlocked')}`",
        f"- formal_execution_eligible: `{str(queue.get('formal_execution_eligible', False)).lower()}`",
        f"- expected_rows: `{summary['expected_rows']}`",
        f"- completed_rows: `{summary['completed_rows']}`",
        f"- missing_rows: `{summary['missing_rows']}`",
        f"- formal_serial_rows: `{summary.get('formal_serial_rows', 0)}`",
        f"- formal_valid_completed_rows: `{summary.get('formal_valid_completed_rows', 0)}`",
        f"- formal_accounted_completed_rows: `{summary.get('formal_accounted_completed_rows', 0)}`",
        f"- model_protocol_terminal_rows: `{summary.get('model_protocol_terminal_rows', 0)}`",
        f"- formal_pending_rows: `{summary.get('formal_pending_rows', 0)}`",
        f"- duplicate_valid_rows: `{summary.get('duplicate_valid_rows', 0)}`",
        f"- duplicate_accounted_rows: `{summary.get('duplicate_accounted_rows', 0)}`",
        f"- retry_exhausted_rows: `{summary.get('retry_exhausted_rows', 0)}`",
        f"- in_progress_rows: `{summary.get('in_progress_rows', 0)}`",
        f"- batch_count: `{summary['batch_count']}`",
        f"- coalesced_batch_count: `{summary['coalesced_batch_count']}`",
        "",
        "## Normative Formal Command" if formal_queue else "## Development Preview Command",
        "",
        (
            "The locked serial consumer re-checks each expected row immediately before launch, skips exactly "
            "one valid completed result, and refuses duplicate valid results or an exhausted retry budget."
            if formal_queue
            else "This queue is an unlocked development preview. It may be dry-run for inspection, but serial "
            "execution refuses it until a verified suite lock is bound and the plan/queue are regenerated."
        ),
        "",
        "```powershell",
        (
            "python infra\\run_paper_queue.py --queue docs\\generated_artifacts\\paper_run_queue.json "
            "--queue-mode serial --execute"
            if formal_queue
            else "python infra\\run_paper_queue.py --queue <development-preview-queue.json> --queue-mode serial"
        ),
        "```",
        "",
        "## Compatibility Coalesced Commands",
        "",
        "These commands are retained for smoke and historical workflows. They do not preserve the "
        "formal case-block queue and must not run the frozen formal matrix.",
        "",
        "```powershell",
    ]
    lines.extend(batch["command"] for batch in queue["coalesced_batches"])
    lines.append("```")

    lines += [
        "",
        "## Fine-Grained Batches",
        "",
        "| Batch | Kind | Harness | Controls | Missing Rows | Trials |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for batch in queue["batches"]:
        lines.append(
            f"| {batch['batch_id']} | {batch['kind']} | {batch['harness']} | "
            f"{','.join(batch['control_types']) or 'n/a'} | {batch['missing_rows']} | "
            f"{','.join(str(item) for item in batch['trials'])} |"
        )

    lines += [
        "",
        "## Post-Run Commands",
        "",
        "```powershell",
        *queue["post_run_commands"],
        "```",
        "",
        "## Harness-Specific Post-Run Batches",
        "",
        "| Batch | Harness | Command |",
        "| --- | --- | --- |",
    ]
    for batch in queue.get("post_run_batches", []) or []:
        lines.append(
            f"| {batch['batch_id']} | {batch['harness']} | `{batch['command']}` |"
        )
    lines += [
        "",
        "## Missing Rows Preview",
        "",
    ]
    if queue["missing_rows_preview"]:
        lines += ["| Kind | Harness | Trial | Control | Case | Label |", "| --- | --- | ---: | --- | --- | --- |"]
        for row in queue["missing_rows_preview"]:
            lines.append(
                f"| {row.get('kind', '')} | {row.get('harness', '')} | {row.get('trial', '')} | "
                f"{row.get('control_type', '') or 'n/a'} | {row.get('case_dir', '')} | {row.get('label', '')} |"
            )
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a resumable paper run queue from plan/progress.")
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--preview-limit", type=int, default=50)
    parser.add_argument(
        "--allow-unlocked-preview",
        action="store_true",
        help="Explicitly export a non-executable development queue from an unlocked preview plan.",
    )
    args = parser.parse_args()

    try:
        queue = build_queue(
            plan_path=Path(args.plan),
            preview_limit=args.preview_limit,
            allow_unlocked_preview=args.allow_unlocked_preview,
        )
    except ValueError as exc:
        parser.error(str(exc))
    if args.out_json:
        path = Path(args.out_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(queue, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.out_md:
        path = Path(args.out_md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(queue), encoding="utf-8")
    if args.json:
        print(json.dumps(queue, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
