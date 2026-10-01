"""Dry-run or execute commands from the paper run queue."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

try:
    from infra import (
        check_paper_readiness,
        check_paper_suite_lock,
        export_paper_run_queue,
        plan_paper_experiment_matrix,
    )
except ModuleNotFoundError:  # direct `python infra/run_paper_queue.py`
    import check_paper_readiness
    import check_paper_suite_lock  # type: ignore
    import export_paper_run_queue  # type: ignore
    import plan_paper_experiment_matrix  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_QUEUE = ROOT / "docs" / "generated_artifacts" / "paper_run_queue.json"
DEFAULT_OUT_JSON = ROOT / "docs" / "generated_artifacts" / "paper_run_execution_plan.json"
DEFAULT_OUT_MD = ROOT / "docs" / "generated_artifacts" / "paper_run_execution_plan.md"

Runner = Callable[[str], tuple[int, str, str]]
ReadinessBuilder = Callable[[bool], dict[str, Any]]
CheckpointWriter = Callable[[dict[str, Any]], None]
RowStateReader = Callable[[dict[str, Any]], dict[str, Any]]
AttemptRecorder = Callable[[dict[str, Any], int], str]
PrelaunchValidator = Callable[[dict[str, Any]], list[str]]

_POWERSHELL_SWITCH_VALUE = r"'(?:[^']|'')*'|\"[^\"]*\"|[^\s]+"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def powershell_switch_values(command: str, switch: str) -> list[str]:
    pattern = re.compile(
        rf"(?<!\S)-{re.escape(switch)}\s+(?P<value>{_POWERSHELL_SWITCH_VALUE})",
        re.IGNORECASE,
    )
    values: list[str] = []
    for match in pattern.finditer(command):
        value = match.group("value")
        if len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1].replace("''", "'")
        elif len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        values.append(value)
    return values


def bind_formal_attempt(command: str, *, expected_row_id: str, attempt_number: int) -> str:
    if not 1 <= attempt_number <= export_paper_run_queue.FORMAL_MAX_ATTEMPTS:
        raise ValueError(
            f"formal attempt must be in [1, {export_paper_run_queue.FORMAL_MAX_ATTEMPTS}], "
            f"got {attempt_number}"
        )
    row_bindings = powershell_switch_values(command, "FormalRowId")
    if row_bindings != [expected_row_id]:
        raise ValueError(
            "formal command must bind exactly one -FormalRowId equal to expected_row_id"
        )
    attempt_pattern = re.compile(
        rf"(?<!\S)-FormalAttempt\s+(?P<value>{_POWERSHELL_SWITCH_VALUE})",
        re.IGNORECASE,
    )
    matches = list(attempt_pattern.finditer(command))
    if len(matches) > 1:
        raise ValueError("formal command contains duplicate -FormalAttempt bindings")
    binding = f"-FormalAttempt {attempt_number}"
    if not matches:
        return f"{command.rstrip()} {binding}"
    match = matches[0]
    return command[: match.start()] + binding + command[match.end() :]


def bind_new_formal_switch(command: str, switch: str, value: str | int) -> str:
    if powershell_switch_values(command, switch):
        raise ValueError(f"formal command already contains a -{switch} binding")
    token = str(value) if isinstance(value, int) else "'" + str(value).replace("'", "''") + "'"
    return f"{command.rstrip()} -{switch} {token}"


def command_record(source: str, index: int, command: str, batch: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = batch or {}
    record = {
        **payload,
        "index": index,
        "source": source,
        "batch_id": payload.get("batch_id", f"{source}_{index:02d}"),
        "kind": payload.get("kind", ""),
        "harness": payload.get("harness", ""),
        "control_types": payload.get("control_types", []),
        "missing_rows": payload.get("missing_rows", 0),
        "command": command,
    }
    if "requires_kimi" in payload:
        record["requires_kimi"] = bool(payload.get("requires_kimi"))
    return record


def validate_serial_queue_structure(queue: dict[str, Any]) -> list[str]:
    rows = list(queue.get("serial_rows", []) or [])
    issues: list[str] = []
    if not rows:
        return ["formal serial queue is missing serial_rows"]
    positions = [int(row.get("queue_position") or 0) for row in rows]
    if positions != list(range(1, len(rows) + 1)):
        issues.append("serial queue positions are not contiguous and ordered")
    row_ids = [str(row.get("expected_row_id") or "") for row in rows]
    if not all(row_ids) or len(set(row_ids)) != len(row_ids):
        issues.append("serial queue expected_row_id values are missing or duplicated")
    contract = queue.get("execution_contract", {}) or {}
    digest_required = contract.get("suite_lock_required_for_execute") is True
    recorded_digest = str(queue.get("queue_digest") or "")
    if recorded_digest:
        actual_digest = export_paper_run_queue.queue_digest(queue)
        if recorded_digest != actual_digest:
            issues.append("formal serial queue digest does not match its contents")
    elif digest_required:
        issues.append("formal serial queue is missing queue_digest")
    if int(contract.get("max_parallel_rows") or 0) != 1:
        issues.append("formal serial queue must set max_parallel_rows=1")
    if any(row.get("skip_completed") is not True for row in rows):
        issues.append("every formal serial row must require SkipCompleted semantics")
    strict_formal = bool(
        queue.get("queue_status") == "formal_locked"
        and queue.get("formal_execution_eligible") is True
    )
    labels = [str(row.get("label") or "") for row in rows]
    homes = [str(row.get("isolated_home_id") or "") for row in rows]
    canaries = [str(row.get("canary_token") or "") for row in rows]
    formal_digest_switches = (
        ("case_content_digest", "FormalCaseContentSha256"),
        ("case_contract_digest", "FormalCaseContractSha256"),
        ("control_contract_digest", "FormalControlContractSha256"),
        ("case_runtime_input_digest", "FormalRuntimeInputsSha256"),
        ("source_manifest_digest", "FormalSourceManifestSha256"),
        ("source_manifest_canonical_digest", "FormalSourceManifestCanonicalSha256"),
        ("runtime_code_revision_digest", "FormalRuntimeCodeSha256"),
        ("protocol_revision_digest", "FormalProtocolSha256"),
        ("runtime_input_policy_digest", "FormalRuntimeInputPolicySha256"),
        ("runtime_revision_digest", "FormalRuntimeRevisionSha256"),
        ("suite_content_digest", "FormalSuiteContentSha256"),
    )
    if strict_formal:
        if len(rows) != 2296 or int(contract.get("row_count") or 0) != 2296:
            issues.append("formal serial queue must contain exactly 2,296 rows")
        if int(contract.get("case_block_count") or 0) != 328:
            issues.append("formal serial queue must declare exactly 328 case blocks")
        if int(contract.get("queue_seed") or 0) != plan_paper_experiment_matrix.DEFAULT_QUEUE_SEED:
            issues.append("formal serial queue must use queue_seed=20260713")
        if not all(labels) or len(set(labels)) != len(labels):
            issues.append("formal serial row labels are missing or duplicated")
        if not all(homes) or len(set(homes)) != len(homes):
            issues.append("formal serial isolated_home_id values are missing or duplicated")
        if not all(canaries) or len(set(canaries)) != len(canaries):
            issues.append("formal serial canary tokens are missing or duplicated")
        for field, _switch in formal_digest_switches:
            invalid_count = sum(
                1
                for row in rows
                if not re.fullmatch(r"[0-9a-f]{64}", str(row.get(field) or ""))
            )
            if invalid_count:
                issues.append(
                    f"formal serial rows require a lowercase 64-hex {field} ({invalid_count} invalid)"
                )
        bound_suite_digest = str((queue.get("suite_lock") or {}).get("suite_content_sha256") or "")
        if any(str(row.get("suite_content_digest") or "") != bound_suite_digest for row in rows):
            issues.append("formal serial row suite-content digests differ from the queue suite-lock binding")
        if any(str(row.get("attestation_mode") or "") != "formal_suite_lock" for row in rows):
            issues.append("formal serial rows must use attestation_mode=formal_suite_lock")
        kinds = collections.Counter(str(row.get("kind") or "") for row in rows)
        if kinds != collections.Counter({"attack": 984, "control": 1312}):
            issues.append("formal serial queue must contain 984 attack and 1,312 control rows")
        controls = collections.Counter(
            str(row.get("control_type") or "")
            for row in rows
            if str(row.get("kind") or "") == "control"
        )
        if controls != collections.Counter(
            {control_type: 328 for control_type in plan_paper_experiment_matrix.CONTROL_TYPES}
        ):
            issues.append("formal serial queue must contain 328 rows of each control type")

        by_case: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        for row in rows:
            by_case[str(row.get("case_dir") or "")].append(row)
        if len(by_case) != 328:
            issues.append("formal serial queue must contain exactly 328 distinct cases")
        for case_dir, block in by_case.items():
            block_positions = [int(row.get("queue_position") or 0) for row in block]
            if len(block) != 7 or block_positions != list(
                range(min(block_positions, default=0), max(block_positions, default=-1) + 1)
            ):
                issues.append(f"formal case block is not one contiguous seven-row block: {case_dir}")
                continue
            attack_trials = sorted(
                int(row.get("trial") or 0) for row in block if row.get("kind") == "attack"
            )
            control_types = sorted(
                str(row.get("control_type") or "") for row in block if row.get("kind") == "control"
            )
            if attack_trials != [1, 2, 3] or control_types != sorted(
                plan_paper_experiment_matrix.CONTROL_TYPES
            ):
                issues.append(f"formal case block does not contain the normative 3+4 rows: {case_dir}")

    def require_switch(command: str, switch: str, expected: list[str], row_id: str) -> None:
        actual = powershell_switch_values(command, switch)
        if actual != expected:
            issues.append(
                f"serial row {row_id or '<missing>'} command switch -{switch} does not match row fields"
            )

    for row in rows:
        row_id = str(row.get("expected_row_id") or "")
        home_id = str(row.get("isolated_home_id") or "")
        command = str(row.get("command") or "")
        if powershell_switch_values(command, "FormalRowId") != [row_id]:
            issues.append(
                f"serial row {row_id or '<missing>'} command does not bind its expected_row_id via -FormalRowId"
            )
        if not home_id or powershell_switch_values(command, "FormalIsolatedHomeId") != [home_id]:
            issues.append(
                f"serial row {row_id or '<missing>'} command does not bind its planned isolated_home_id"
            )
        attempt_bindings = powershell_switch_values(command, "FormalAttempt")
        if len(attempt_bindings) > 1:
            issues.append(f"serial row {row_id or '<missing>'} command has duplicate -FormalAttempt bindings")
        elif attempt_bindings:
            try:
                attempt = int(attempt_bindings[0])
            except ValueError:
                attempt = 0
            if not 1 <= attempt <= export_paper_run_queue.FORMAL_MAX_ATTEMPTS:
                issues.append(f"serial row {row_id or '<missing>'} command has an invalid -FormalAttempt")
        if strict_formal:
            if plan_paper_experiment_matrix.expected_row_id(row) != row_id:
                issues.append(f"serial row {row_id or '<missing>'} expected_row_id does not match row coordinates")
            if str(row.get("batch_id") or "") != row_id:
                issues.append(f"serial row {row_id or '<missing>'} batch_id must equal expected_row_id")
            if int(row.get("max_attempts") or 0) != 3:
                issues.append(f"serial row {row_id or '<missing>'} must declare exactly three attempts")
            if str(row.get("matrix_id") or "") != str(queue.get("matrix_id") or ""):
                issues.append(f"serial row {row_id or '<missing>'} matrix_id does not match its queue")
            case_arg = ".\\runs\\" + str(row.get("case_dir") or "").replace("/", "\\")
            require_switch(command, "Harness", [str(row.get("harness") or "")], row_id)
            require_switch(command, "CaseDir", [case_arg], row_id)
            require_switch(command, "PermissionProfile", [str(row.get("permission_profile") or "")], row_id)
            require_switch(command, "IsolationMode", [str(row.get("isolation_mode") or "")], row_id)
            require_switch(command, "RunLabel", [str(row.get("label") or "")], row_id)
            require_switch(command, "TimeoutSec", [str(int(row.get("timeout_sec") or 0))], row_id)
            require_switch(command, "CanaryToken", [str(row.get("canary_token") or "")], row_id)
            require_switch(command, "FormalRowId", [row_id], row_id)
            require_switch(command, "FormalIsolatedHomeId", [home_id], row_id)
            require_switch(command, "FormalAttestationMode", ["formal_suite_lock"], row_id)
            for field, switch in formal_digest_switches:
                require_switch(command, switch, [str(row.get(field) or "")], row_id)
            require_switch(command, "OutputMode", ["minimal"], row_id)
            runtime_model = str(row.get("runtime_model") or "")
            require_switch(command, "Model", [runtime_model] if runtime_model else [], row_id)
            control_type = str(row.get("control_type") or "")
            require_switch(command, "ControlType", [control_type] if control_type else [], row_id)
            require_switch(command, "FormalAttempt", [], row_id)
            for launch_switch in (
                "FormalMatrixId",
                "FormalQueuePosition",
                "FormalLaunchNonce",
                "FormalLaunchCommandSha256",
                "FormalLaunchEventSha256",
            ):
                require_switch(command, launch_switch, [], row_id)
    return issues


def serial_suite_lock_issues(queue: dict[str, Any], root: Path) -> list[str]:
    contract = queue.get("execution_contract", {}) or {}
    if contract.get("suite_lock_required_for_execute") is not True:
        return ["formal serial execution requires suite_lock_required_for_execute=true"]
    if queue.get("queue_status") != "formal_locked" or queue.get("formal_execution_eligible") is not True:
        return ["formal serial execution refuses a development_unlocked queue"]
    binding = queue.get("suite_lock", {}) or {}
    if binding.get("present") is not True or binding.get("parse_valid") is not True:
        return ["formal serial queue is not bound to a valid paper_suite_lock.json"]
    report = check_paper_suite_lock.build_report(root=root)
    issues: list[str] = []
    if not str(queue.get("attempt_ledger") or ""):
        issues.append("formal serial queue is missing its persistent attempt ledger path")
    if not str(queue.get("execution_lock") or ""):
        issues.append("formal serial queue is missing its single-consumer execution lock path")
    if report.get("ok") is not True:
        issues.append("paper suite content lock verification failed")
    bound_digest = str(binding.get("suite_content_sha256") or "")
    current_digest = str(report.get("expected_digest") or "")
    if not bound_digest or bound_digest != current_digest:
        issues.append("formal serial queue suite-lock digest does not match the verified lock")
    lock_path = root / str(binding.get("path") or check_paper_suite_lock.DEFAULT_LOCK)
    if not lock_path.is_file():
        issues.append("paper suite lock file is missing at execution time")
    else:
        current_file_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        if current_file_digest != str(binding.get("file_sha256") or ""):
            issues.append("formal serial queue was generated from a different suite-lock attestation")
    return issues


def serial_plan_binding_issues(
    queue: dict[str, Any],
    root: Path,
    *,
    validate_live_plan: bool = True,
) -> list[str]:
    """Verify that a formal queue is an exact executable projection of its plan."""

    if queue.get("queue_status") != "formal_locked" or queue.get("formal_execution_eligible") is not True:
        return ["formal serial queue is not bound to a formal_locked experiment plan"]
    plan_path = queue_artifact_path(root, queue.get("plan_path"))
    if plan_path is None or not plan_path.is_file():
        return ["formal serial queue experiment plan file is missing"]
    raw = plan_path.read_bytes()
    issues: list[str] = []
    if hashlib.sha256(raw).hexdigest() != str(queue.get("plan_file_sha256") or ""):
        issues.append("formal serial queue experiment plan file digest drifted")
    try:
        plan = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return issues + ["formal serial queue experiment plan is not valid JSON"]
    if plan.get("plan_status") != "formal_locked" or plan.get("formal_execution_eligible") is not True:
        issues.append("bound experiment plan is not formal execution eligible")
    if str(plan.get("matrix_id") or "") != str(queue.get("matrix_id") or ""):
        issues.append("formal serial queue matrix_id does not match its experiment plan")
    if str(plan.get("matrix_digest") or "") != str(queue.get("matrix_digest") or ""):
        issues.append("formal serial queue matrix digest does not match its experiment plan")
    if plan.get("suite_lock") != queue.get("suite_lock"):
        issues.append("formal serial queue suite-lock binding differs from its experiment plan")
    if validate_live_plan:
        issues.extend(
            str(item.get("message") or "experiment plan validation failed")
            for item in plan_paper_experiment_matrix.validate_plan(plan, root=root)
            if item.get("severity") == "error"
        )
    plan_rows = list(plan.get("rows", []) or [])
    queue_rows = list(queue.get("serial_rows", []) or [])
    if len(plan_rows) != len(queue_rows):
        issues.append("formal serial queue row count differs from its experiment plan")
        return issues
    for plan_row, queue_row in zip(plan_rows, queue_rows):
        if any(queue_row.get(key) != value for key, value in plan_row.items()):
            issues.append(
                f"formal serial row differs from its experiment plan: {queue_row.get('expected_row_id') or '<missing>'}"
            )
            break
        if str(queue_row.get("command") or "") != export_paper_run_queue.formal_row_command(plan_row):
            issues.append(
                f"formal serial row command differs from its experiment plan: {queue_row.get('expected_row_id') or '<missing>'}"
            )
            break
    return issues


def serial_execution_artifact_issues(
    queue: dict[str, Any],
    *,
    queue_path: Path,
    root: Path,
    expected_queue_file_sha256: str,
) -> list[str]:
    """Recheck the immutable queue->plan binding immediately before a row."""

    issues: list[str] = []
    try:
        queue_raw = queue_path.read_bytes()
    except OSError as exc:
        return [f"formal queue file is unavailable before launch: {exc}"]
    if hashlib.sha256(queue_raw).hexdigest() != expected_queue_file_sha256:
        issues.append("formal queue file changed after execution planning")
    try:
        live_queue = json.loads(queue_raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return issues + ["formal queue file is not valid JSON before launch"]
    if str(live_queue.get("queue_digest") or "") != str(queue.get("queue_digest") or ""):
        issues.append("formal queue digest binding changed before launch")
    if str(live_queue.get("matrix_id") or "") != str(queue.get("matrix_id") or ""):
        issues.append("formal queue matrix_id changed before launch")
    plan_path = queue_artifact_path(root, queue.get("plan_path"))
    if plan_path is None or not plan_path.is_file():
        issues.append("formal experiment plan file is unavailable before launch")
        return issues
    try:
        plan_raw = plan_path.read_bytes()
    except OSError as exc:
        issues.append(f"formal experiment plan file is unreadable before launch: {exc}")
        return issues
    if hashlib.sha256(plan_raw).hexdigest() != str(queue.get("plan_file_sha256") or ""):
        issues.append("formal experiment plan file changed before launch")
        return issues
    try:
        live_plan = json.loads(plan_raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        issues.append("formal experiment plan is not valid JSON before launch")
        return issues
    if (
        str(live_plan.get("matrix_id") or "") != str(queue.get("matrix_id") or "")
        or str(live_plan.get("matrix_digest") or "") != str(queue.get("matrix_digest") or "")
        or live_plan.get("suite_lock") != queue.get("suite_lock")
    ):
        issues.append("formal queue no longer matches its frozen experiment plan")
    return issues


def serial_prelaunch_issues(queue: dict[str, Any], root: Path, record: dict[str, Any]) -> list[str]:
    """Revalidate immutable formal inputs immediately before one real launch."""

    # Queue structure and exact queue-to-plan projection are checked once
    # before the serial consumer acquires its execution lock.  The immutable
    # queue is already resident in this process; repeating all 2,296 command
    # parses for each of 2,296 launches would add quadratic overhead.  What can
    # drift externally while the consumer is running is re-attested here.
    issues: list[str] = []
    binding = queue.get("suite_lock", {}) or {}
    lock_path = Path(str(binding.get("path") or check_paper_suite_lock.DEFAULT_LOCK))
    report = check_paper_suite_lock.build_prelaunch_case_report(
        root,
        str(record.get("case_dir") or ""),
        lock_path=lock_path,
    )
    issues.extend(str(item.get("message") or "suite lock verification failed") for item in report.get("issues", []))
    if str(report.get("suite_content_sha256") or "") != str(binding.get("suite_content_sha256") or ""):
        issues.append("prelaunch suite-content digest differs from the queue binding")
    if str(report.get("runtime_code_revision_sha256") or "") != str(
        record.get("runtime_code_revision_digest") or ""
    ):
        issues.append("prelaunch runtime-code digest differs from the expected row")
    if str(report.get("protocol_revisions_sha256") or "") != str(
        record.get("protocol_revision_digest") or ""
    ):
        issues.append("prelaunch protocol digest differs from the expected row")
    if str(report.get("runtime_revision_sha256") or "") != str(
        record.get("runtime_revision_digest") or ""
    ):
        issues.append("prelaunch combined runtime revision differs from the expected row")
    if str(report.get("case_content_sha256") or "") != str(record.get("case_content_digest") or ""):
        issues.append("prelaunch case-content digest differs from the expected row")
    if str(report.get("case_meta_canonical_sha256") or "") != str(
        record.get("case_contract_digest") or ""
    ):
        issues.append("prelaunch case-contract digest differs from the expected row")
    control_type = str(record.get("control_type") or "")
    observed_control_digest = (
        str((report.get("control_contract_digests") or {}).get(control_type) or "")
        if control_type
        else str(report.get("control_contracts_canonical_sha256") or "")
    )
    if observed_control_digest != str(record.get("control_contract_digest") or ""):
        issues.append("prelaunch control-contract digest differs from the expected row")
    if str(report.get("runtime_inputs_tree_sha256") or "") != str(
        record.get("case_runtime_input_digest") or ""
    ):
        issues.append("prelaunch case runtime-input digest differs from the expected row")
    if str(report.get("suite_content_sha256") or "") != str(
        record.get("suite_content_digest") or ""
    ):
        issues.append("prelaunch suite-content digest differs from the expected row")
    if str(report.get("source_manifest_sha256") or "") != str(
        record.get("source_manifest_digest") or ""
    ):
        issues.append("prelaunch source-manifest digest differs from the expected row")
    if str(report.get("source_manifest_canonical_sha256") or "") != str(
        record.get("source_manifest_canonical_digest") or ""
    ):
        issues.append("prelaunch canonical source-manifest digest differs from the expected row")
    if str(report.get("runtime_input_policy_sha256") or "") != str(
        record.get("runtime_input_policy_digest") or ""
    ):
        issues.append("prelaunch runtime-input-policy digest differs from the expected row")
    if str(record.get("attestation_mode") or "") != "formal_suite_lock":
        issues.append("formal prelaunch row does not require formal_suite_lock attestation mode")
    return list(dict.fromkeys(issues))


def serial_selection_issues(
    queue: dict[str, Any],
    root: Path,
    *,
    batches: list[str] | None,
    harnesses: list[str] | None,
    start_at: str,
    include_post_run: bool,
) -> list[str]:
    """Prevent command filters from bypassing the preregistered row order."""

    issues: list[str] = []
    if batches:
        issues.append("formal serial execution does not allow --batch filtering")
    if harnesses:
        issues.append("formal serial execution does not allow --harness filtering")
    if include_post_run:
        issues.append("formal serial execution must run post-processing in a separate invocation")
    if start_at:
        rows = list(queue.get("serial_rows", []) or [])
        try:
            index = next(i for i, row in enumerate(rows) if str(row.get("batch_id") or "") == start_at)
        except StopIteration:
            issues.append("formal serial --start-at row does not exist in the queue")
        else:
            for row in rows[:index]:
                state = export_paper_run_queue.serial_row_state(root, row)
                valid_count = int(state.get("valid_result_count") or 0)
                protocol_terminal_count = int(
                    state.get("model_protocol_terminal_count") or 0
                )
                accounted_count = int(
                    state.get("accounted_result_count")
                    or valid_count + protocol_terminal_count
                )
                if accounted_count != 1 or int(
                    state.get("in_progress_attempt_count") or 0
                ) != 0:
                    issues.append(
                        "formal serial --start-at requires every preceding row to have exactly one accounted terminal result"
                    )
                    break
    return issues


def queue_artifact_path(root: Path, value: Any) -> Path | None:
    token = str(value or "").strip()
    if not token:
        return None
    path = Path(token)
    return path if path.is_absolute() else root / path


def load_attempt_launch_counts(path: Path | None, *, matrix_id: str = "") -> dict[str, int]:
    counts: dict[str, int] = {}
    if path is None:
        return counts
    for event in export_paper_run_queue.load_formal_launch_events(
        path, expected_matrix_id=matrix_id
    ):
        row_id = str(event["expected_row_id"])
        counts[row_id] = counts.get(row_id, 0) + 1
    return counts


def append_attempt_launch(
    path: Path,
    *,
    matrix_id: str,
    record: dict[str, Any],
    attempt_number: int,
) -> str:
    command = str(record.get("command") or "")
    launch_nonce = export_paper_run_queue.new_formal_launch_nonce()
    command = bind_new_formal_switch(command, "FormalMatrixId", matrix_id)
    command = bind_new_formal_switch(
        command, "FormalQueuePosition", int(record.get("queue_position") or 0)
    )
    command = bind_new_formal_switch(command, "FormalLaunchNonce", launch_nonce)
    command_digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
    event = export_paper_run_queue.append_formal_launch_event(
        path,
        matrix_id=matrix_id,
        expected_row_id=str(record.get("expected_row_id") or ""),
        isolated_home_id=str(record.get("isolated_home_id") or ""),
        queue_position=int(record.get("queue_position") or 0),
        attempt_number=attempt_number,
        command_sha256=command_digest,
        launch_nonce=launch_nonce,
    )
    command = bind_new_formal_switch(command, "FormalLaunchCommandSha256", command_digest)
    command = bind_new_formal_switch(
        command, "FormalLaunchEventSha256", str(event["event_sha256"])
    )
    return command


def acquire_execution_lock(path: Path, *, matrix_id: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"formal queue execution lock already exists: {path}; verify no consumer is running before removal"
        ) from exc
    payload = json.dumps(
        {
            "matrix_id": matrix_id,
            "pid": os.getpid(),
            "acquired_at": datetime.now().isoformat(timespec="seconds"),
        },
        sort_keys=True,
    ).encode("utf-8")
    os.write(descriptor, payload + b"\n")
    return descriptor


def release_execution_lock(path: Path, descriptor: int) -> None:
    os.close(descriptor)
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def split_cli_values(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def select_commands(
    queue: dict[str, Any],
    *,
    queue_mode: str = "coalesced",
    batches: list[str] | None = None,
    harnesses: list[str] | None = None,
    start_at: str = "",
    include_post_run: bool = False,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    if queue_mode == "serial":
        structure_issues = validate_serial_queue_structure(queue)
        if structure_issues:
            raise ValueError("; ".join(structure_issues))
        selected = [
            command_record("serial", index + 1, str(row.get("command") or ""), row)
            for index, row in enumerate(queue.get("serial_rows", []) or [])
            if str(row.get("command") or "")
        ]
    elif queue_mode == "post-run":
        wanted_harnesses = {str(item).lower() for item in harnesses or []}
        post_run_batches = queue.get("post_run_batches", []) or []
        if wanted_harnesses and post_run_batches:
            selected = [
                command_record("post_run", index + 1, str(batch.get("command") or ""), batch)
                for index, batch in enumerate(post_run_batches)
                if str(batch.get("command") or "")
                and str(batch.get("harness") or "").lower() in wanted_harnesses
            ]
        else:
            selected = [
                command_record("post_run", index + 1, command)
                for index, command in enumerate(queue.get("post_run_commands", []) or [])
            ]
    else:
        key = "coalesced_batches" if queue_mode == "coalesced" else "batches"
        selected = [
            command_record(queue_mode, index + 1, str(batch.get("command") or ""), batch)
            for index, batch in enumerate(queue.get(key, []) or [])
            if str(batch.get("command") or "")
        ]

    wanted = set(batches or [])
    if wanted:
        selected = [record for record in selected if record["batch_id"] in wanted]

    if start_at:
        try:
            first_index = next(index for index, record in enumerate(selected) if record["batch_id"] == start_at)
            selected = selected[first_index:]
        except StopIteration:
            selected = []

    if include_post_run and queue_mode != "post-run":
        wanted_harnesses = {str(item).lower() for item in harnesses or []}
        post_run_batches = queue.get("post_run_batches", []) or []
        if wanted_harnesses and post_run_batches:
            selected.extend(
                command_record("post_run", index + 1, str(batch.get("command") or ""), batch)
                for index, batch in enumerate(post_run_batches)
                if str(batch.get("command") or "")
                and str(batch.get("harness") or "").lower() in wanted_harnesses
            )
        else:
            selected.extend(
                command_record("post_run", index + 1, command)
                for index, command in enumerate(queue.get("post_run_commands", []) or [])
            )

    wanted_harnesses = {str(item).lower() for item in harnesses or []}
    if wanted_harnesses:
        selected = [
            record
            for record in selected
            if str(record.get("harness") or "").lower() in wanted_harnesses
        ]

    return [
        {
            **record,
            "index": index + 1,
        }
        for index, record in enumerate(selected)
    ]


def default_runner(command: str) -> tuple[int, str, str]:
    stdout_tail: collections.deque[str] = collections.deque(maxlen=200)
    stderr_tail: collections.deque[str] = collections.deque(maxlen=200)

    def forward(stream: Any, target: Any, tail: collections.deque[str]) -> None:
        for line in iter(stream.readline, ""):
            tail.append(line.rstrip("\n"))
            target.write(line)
            target.flush()

    proc = subprocess.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    stdout_thread = threading.Thread(target=forward, args=(proc.stdout, sys.stdout, stdout_tail), daemon=True)
    stderr_thread = threading.Thread(target=forward, args=(proc.stderr, sys.stderr, stderr_tail), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    return_code = proc.wait()
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    return return_code, "\n".join(stdout_tail), "\n".join(stderr_tail)


def command_requires_kimi(record: dict[str, Any]) -> bool:
    if "requires_kimi" in record:
        return bool(record.get("requires_kimi"))
    harness = str(record.get("harness", "")).lower()
    command = str(record.get("command", "")).lower()
    if harness == "codex":
        return True
    match = re.search(r"(?:^|\s)-harnesses\s+([^\s`]+)", command)
    if not match:
        return False
    harnesses = {item.strip().strip("'\"") for item in match.group(1).split(",")}
    return "codex" in harnesses


def selected_requires_kimi(records: list[dict[str, Any]]) -> bool:
    return any(command_requires_kimi(record) for record in records)


def default_readiness_builder(require_kimi: bool) -> dict[str, Any]:
    return check_paper_readiness.build_readiness(
        require_kimi=True,
        require_codex_kimi=require_kimi,
        root=ROOT,
    )


def build_readiness_gate(
    records: list[dict[str, Any]],
    *,
    execute: bool,
    skip_readiness_check: bool = False,
    readiness_builder: ReadinessBuilder = default_readiness_builder,
) -> dict[str, Any]:
    requires_kimi = selected_requires_kimi(records)
    if not execute:
        return {
            "checked": False,
            "skipped": False,
            "requires_kimi": requires_kimi,
            "ready": None,
            "blockers": [],
            "warnings": [],
        }
    if skip_readiness_check:
        return {
            "checked": False,
            "skipped": True,
            "requires_kimi": requires_kimi,
            "ready": None,
            "blockers": [],
            "warnings": ["readiness check was skipped by --skip-readiness-check"],
        }

    report = readiness_builder(requires_kimi)
    return {
        "checked": True,
        "skipped": False,
        "requires_kimi": requires_kimi,
        "ready": bool(report.get("ready")),
        "blockers": list(report.get("blockers", [])),
        "warnings": list(report.get("warnings", [])),
    }


def blocked_records(records: list[dict[str, Any]], blockers: list[str]) -> list[dict[str, Any]]:
    reason = "; ".join(blockers) if blockers else "readiness check failed"
    started = datetime.now().isoformat(timespec="seconds")
    if not records:
        records = [
            {
                "index": 0,
                "source": "formal_gate",
                "batch_id": "formal_gate",
                "kind": "",
                "harness": "",
                "control_types": [],
                "missing_rows": 0,
                "command": "",
            }
        ]
    return [
        {
            **record,
            "status": "blocked",
            "exit_code": None,
            "runner_invoked": False,
            "started_at": started,
            "elapsed_sec": 0,
            "stdout_tail": "",
            "stderr_tail": reason,
        }
        for record in records
    ]


def pending_after_failure_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **record,
            "status": "pending_after_failure",
            "exit_code": None,
            "runner_invoked": False,
            "started_at": "",
            "elapsed_sec": 0,
            "stdout_tail": "",
            "stderr_tail": f"previous command failed; resume with --start-at {record['batch_id']}",
        }
        for record in records
    ]


def summarize_execution(selected: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    failed = [item for item in results if item["status"] == "failed"]
    blocked = [item for item in results if item["status"] in {"blocked", "blocked_in_progress"}]
    pending = [item for item in results if item["status"] == "pending_after_failure"]
    skipped_completed = [item for item in results if item["status"] == "skipped_completed"]
    model_protocol_terminal = [
        item
        for item in results
        if item["status"] == "terminal_model_protocol_incomplete"
    ]
    incomplete_commands = max(0, len(selected) - len(results))
    resume_batch = pending[0]["batch_id"] if pending else ""
    if not resume_batch and incomplete_commands:
        resume_batch = str(selected[len(results)].get("batch_id") or "")
    return {
        "selected_commands": len(selected),
        "selected_missing_rows": sum(int(item.get("missing_rows") or 0) for item in selected),
        "executed_commands": sum(1 for item in results if item.get("runner_invoked") is True),
        "failed_commands": len(failed),
        "blocked_commands": len(blocked),
        "pending_commands": len(pending),
        "skipped_completed_commands": len(skipped_completed),
        "model_protocol_terminal_commands": len(model_protocol_terminal),
        "incomplete_commands": incomplete_commands,
        "resume_batch": resume_batch,
        "ok": not failed and not blocked and not pending and incomplete_commands == 0,
    }


def build_plan_payload(
    *,
    queue: dict[str, Any],
    queue_path: Path,
    queue_mode: str,
    batches: list[str] | None,
    harnesses: list[str] | None,
    start_at: str,
    include_post_run: bool,
    execute: bool,
    stop_on_failure: bool,
    skip_readiness_check: bool,
    readiness_gate: dict[str, Any],
    selected: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(ROOT),
        "queue_path": relpath(queue_path),
        "matrix_id": queue.get("matrix_id", ""),
        "case_set": queue.get("case_set", ""),
        "queue_summary": queue.get("summary", {}),
        "queue_mode": queue_mode,
        "requested_batches": batches or [],
        "requested_harnesses": harnesses or [],
        "start_at": start_at,
        "include_post_run": include_post_run,
        "execute": execute,
        "stop_on_failure": stop_on_failure,
        "skip_readiness_check": skip_readiness_check,
        "readiness_gate": readiness_gate,
        "summary": summarize_execution(selected, results),
        "commands": results,
    }


def execute_records(
    records: list[dict[str, Any]],
    *,
    execute: bool = False,
    stop_on_failure: bool = True,
    runner: Runner = default_runner,
    row_state_reader: RowStateReader | None = None,
    attempt_recorder: AttemptRecorder | None = None,
    prelaunch_validator: PrelaunchValidator | None = None,
    on_update: Callable[[list[dict[str, Any]]], None] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        started = datetime.now().isoformat(timespec="seconds")
        start = time.monotonic()
        exit_code = 0
        stdout = ""
        stderr = ""
        status = "dry_run"
        runner_invoked = False
        executed_command = ""
        formal_attempt: int | None = None
        state_before: dict[str, Any] = {}
        state_after: dict[str, Any] = {}
        if execute:
            prelaunch_issues: list[str] = []
            if record.get("source") == "serial" and prelaunch_validator is not None:
                try:
                    prelaunch_issues = prelaunch_validator(record)
                except Exception as exc:
                    prelaunch_issues = [f"formal prelaunch verification failed: {exc}"]
            if prelaunch_issues:
                exit_code = 7
                status = "failed"
                stderr = "; ".join(prelaunch_issues)
            elif record.get("source") == "serial":
                if row_state_reader is None:
                    raise ValueError("formal serial execution requires an exact-row state reader")
                state_before = row_state_reader(record)
                valid_before = int(state_before.get("valid_result_count") or 0)
                protocol_terminal_before = int(
                    state_before.get("model_protocol_terminal_count") or 0
                )
                accounted_before = int(
                    state_before.get("accounted_result_count")
                    or valid_before + protocol_terminal_before
                )
                in_progress_before = int(state_before.get("in_progress_attempt_count") or 0)
                attempts_before = int(state_before.get("matching_attempts") or 0)
                max_attempts = int(record.get("max_attempts") or 0)
                if valid_before > 1:
                    exit_code = 2
                    status = "failed"
                    stderr = "duplicate valid results for expected_row_id; refusing formal execution"
                elif accounted_before > 1:
                    exit_code = 2
                    status = "failed"
                    stderr = "duplicate accounted terminal results for expected_row_id; refusing formal execution"
                elif accounted_before == 1 and in_progress_before == 0:
                    status = "skipped_completed"
                elif in_progress_before:
                    exit_code = 3
                    status = "blocked_in_progress"
                    stderr = "matching row attempt is still in progress; refusing a concurrent duplicate"
                elif max_attempts and attempts_before >= max_attempts:
                    exit_code = 4
                    status = "failed"
                    stderr = "fixed infrastructure retry budget is exhausted for expected_row_id"
                else:
                    attempt_number = attempts_before + 1
                    formal_attempt = attempt_number
                    try:
                        executed_command = bind_formal_attempt(
                            str(record["command"]),
                            expected_row_id=str(record.get("expected_row_id") or ""),
                            attempt_number=attempt_number,
                        )
                    except ValueError as exc:
                        exit_code = 6
                        status = "failed"
                        stderr = f"could not bind formal row provenance: {exc}"
                    launch_record = {
                        **record,
                        "command": executed_command,
                        "executed_command": executed_command,
                        "formal_attempt": attempt_number,
                    }
                    if status != "failed" and attempt_recorder is not None:
                        try:
                            executed_command = attempt_recorder(launch_record, attempt_number)
                            if not executed_command:
                                raise ValueError("formal attempt recorder returned an empty command")
                            launch_record["command"] = executed_command
                            launch_record["executed_command"] = executed_command
                        except Exception as exc:
                            exit_code = 6
                            status = "failed"
                            stderr = f"could not record formal launch attempt: {exc}"
                    if status != "failed":
                        runner_invoked = True
                        exit_code, stdout, stderr = runner(executed_command)
                        state_after = row_state_reader(record)
                    valid_after = int(state_after.get("valid_result_count") or 0)
                    protocol_terminal_after = int(
                        state_after.get("model_protocol_terminal_count") or 0
                    )
                    accounted_after = int(
                        state_after.get("accounted_result_count")
                        or valid_after + protocol_terminal_after
                    )
                    if status == "failed" and not runner_invoked:
                        pass
                    elif accounted_after == 1:
                        status = (
                            "terminal_model_protocol_incomplete"
                            if protocol_terminal_after == 1
                            else "passed"
                        )
                    elif valid_after > 1:
                        status = "failed"
                        exit_code = 2
                        stderr = (stderr + "\n" if stderr else "") + (
                            "duplicate valid results produced for expected_row_id"
                        )
                    elif accounted_after > 1:
                        status = "failed"
                        exit_code = 2
                        stderr = (stderr + "\n" if stderr else "") + (
                            "duplicate accounted terminal results produced for expected_row_id"
                        )
                    else:
                        status = "failed"
                        if exit_code == 0:
                            exit_code = 5
                        stderr = (stderr + "\n" if stderr else "") + (
                            "runner returned without exactly one accounted terminal result; "
                            "run_validity.json is authoritative"
                        )
            else:
                runner_invoked = True
                exit_code, stdout, stderr = runner(record["command"])
                status = "passed" if exit_code == 0 else "failed"
        elapsed = round(time.monotonic() - start, 3)
        result = {
            **record,
            "status": status,
            "exit_code": exit_code,
            "runner_invoked": runner_invoked,
            "executed_command": executed_command,
            "formal_attempt": formal_attempt,
            "row_state_before": state_before,
            "row_state_after": state_after,
            "started_at": started,
            "elapsed_sec": elapsed,
            "stdout_tail": "\n".join((stdout or "").splitlines()[-20:]),
            "stderr_tail": "\n".join((stderr or "").splitlines()[-20:]),
        }
        out.append(result)
        if on_update:
            on_update(list(out))
        if execute and status in {"failed", "blocked_in_progress"} and stop_on_failure:
            out.extend(pending_after_failure_records(records[index + 1 :]))
            if on_update:
                on_update(list(out))
            break
    return out


def build_execution_plan(
    *,
    queue_path: Path = DEFAULT_QUEUE,
    queue_mode: str = "coalesced",
    batches: list[str] | None = None,
    harnesses: list[str] | None = None,
    start_at: str = "",
    include_post_run: bool = False,
    execute: bool = False,
    stop_on_failure: bool = True,
    skip_readiness_check: bool = False,
    runner: Runner = default_runner,
    readiness_builder: ReadinessBuilder = default_readiness_builder,
    checkpoint_writer: CheckpointWriter | None = None,
    row_state_reader: RowStateReader | None = None,
    allow_nonformal_test_queue: bool = False,
) -> dict[str, Any]:
    queue_raw = queue_path.read_bytes()
    queue = json.loads(queue_raw.decode("utf-8-sig"))
    queue_file_sha256 = hashlib.sha256(queue_raw).hexdigest()
    queue_root = Path(str(queue.get("root") or ROOT))
    selected = select_commands(
        queue,
        queue_mode=queue_mode,
        batches=batches,
        harnesses=harnesses,
        start_at=start_at,
        include_post_run=include_post_run,
    )
    readiness_gate = build_readiness_gate(
        selected,
        execute=execute,
        skip_readiness_check=skip_readiness_check,
        readiness_builder=readiness_builder,
    )
    if allow_nonformal_test_queue and runner is default_runner:
        raise ValueError("allow_nonformal_test_queue is restricted to dependency-injected tests")
    formal_serial_execute = bool(execute and queue_mode == "serial" and not allow_nonformal_test_queue)
    formal_queue_claimed = bool(
        queue.get("queue_status") == "formal_locked"
        or queue.get("formal_execution_eligible") is True
        or (queue.get("execution_contract", {}) or {}).get("suite_lock_required_for_execute") is True
    )
    mode_blockers = (
        ["formal_locked queue execution requires --queue-mode serial"]
        if execute and formal_queue_claimed and queue_mode != "serial"
        else []
    )
    continue_blockers = (
        ["formal serial execution does not allow --continue-on-failure"]
        if formal_serial_execute and not stop_on_failure
        else []
    )
    suite_lock_required = bool(
        queue_mode == "serial"
        and (
            formal_serial_execute
            or (queue.get("execution_contract", {}) or {}).get("suite_lock_required_for_execute") is True
        )
    )
    suite_lock_blockers = serial_suite_lock_issues(queue, queue_root) if execute and suite_lock_required else []
    structure_blockers = validate_serial_queue_structure(queue) if formal_serial_execute else []
    plan_binding_blockers = (
        serial_plan_binding_issues(queue, queue_root) if formal_serial_execute else []
    )
    skip_readiness_blockers = (
        ["formal serial execution does not allow --skip-readiness-check"]
        if formal_serial_execute and skip_readiness_check
        else []
    )
    selection_blockers = (
        serial_selection_issues(
            queue,
            queue_root,
            batches=batches,
            harnesses=harnesses,
            start_at=start_at,
            include_post_run=include_post_run,
        )
        if formal_serial_execute
        else []
    )
    formal_blockers = (
        mode_blockers
        + suite_lock_blockers
        + structure_blockers
        + plan_binding_blockers
        + skip_readiness_blockers
        + selection_blockers
        + continue_blockers
    )
    readiness_gate["suite_lock_required"] = suite_lock_required
    readiness_gate["suite_lock_checked"] = bool(execute and suite_lock_required)
    readiness_gate["suite_lock_blockers"] = suite_lock_blockers
    readiness_gate["formal_queue_mode_blockers"] = mode_blockers
    readiness_gate["serial_structure_blockers"] = structure_blockers
    readiness_gate["plan_binding_blockers"] = plan_binding_blockers
    readiness_gate["skip_readiness_blockers"] = skip_readiness_blockers
    readiness_gate["serial_selection_blockers"] = selection_blockers
    readiness_gate["continue_on_failure_blockers"] = continue_blockers
    if formal_blockers:
        readiness_gate["checked"] = True
        readiness_gate["ready"] = False
        readiness_gate["blockers"] = list(readiness_gate.get("blockers", [])) + formal_blockers
    attempt_ledger = queue_artifact_path(queue_root, queue.get("attempt_ledger")) if queue_mode == "serial" else None
    launch_counts = load_attempt_launch_counts(
        attempt_ledger, matrix_id=str(queue.get("matrix_id") or "")
    )
    base_row_state_reader = row_state_reader
    if queue_mode == "serial":
        if base_row_state_reader is None:
            base_row_state_reader = lambda record: export_paper_run_queue.serial_row_state(queue_root, record)

        def state_with_attempt_ledger(record: dict[str, Any]) -> dict[str, Any]:
            assert base_row_state_reader is not None
            state = dict(base_row_state_reader(record))
            row_id = str(record.get("expected_row_id") or "")
            recorded_launches = int(launch_counts.get(row_id, 0))
            state["recorded_launch_attempts"] = recorded_launches
            state["matching_attempts"] = max(
                int(state.get("matching_attempts") or 0),
                recorded_launches,
            )
            return state

        row_state_reader = state_with_attempt_ledger

    attempt_recorder: AttemptRecorder | None = None
    if queue_mode == "serial" and attempt_ledger is not None:
        def record_attempt(record: dict[str, Any], attempt_number: int) -> str:
            command = append_attempt_launch(
                attempt_ledger,
                matrix_id=str(queue.get("matrix_id") or ""),
                record=record,
                attempt_number=attempt_number,
            )
            row_id = str(record.get("expected_row_id") or "")
            launch_counts[row_id] = launch_counts.get(row_id, 0) + 1
            return command

        attempt_recorder = record_attempt

    def make_plan(results: list[dict[str, Any]]) -> dict[str, Any]:
        return build_plan_payload(
            queue=queue,
            queue_path=queue_path,
            queue_mode=queue_mode,
            batches=batches,
            harnesses=harnesses,
            start_at=start_at,
            include_post_run=include_post_run,
            execute=execute,
            stop_on_failure=stop_on_failure,
            skip_readiness_check=skip_readiness_check,
            readiness_gate=readiness_gate,
            selected=selected,
            results=results,
        )

    def write_checkpoint(results: list[dict[str, Any]]) -> None:
        if checkpoint_writer:
            checkpoint_writer(make_plan(results))

    def formal_prelaunch(record: dict[str, Any]) -> list[str]:
        return [
            *serial_execution_artifact_issues(
                queue,
                queue_path=queue_path,
                root=queue_root,
                expected_queue_file_sha256=queue_file_sha256,
            ),
            *serial_prelaunch_issues(queue, queue_root, record),
        ]

    execution_lock = queue_artifact_path(queue_root, queue.get("execution_lock")) if queue_mode == "serial" else None
    if execute and readiness_gate["checked"] and not readiness_gate["ready"]:
        results = blocked_records(selected, readiness_gate["blockers"])
        write_checkpoint(results)
    else:
        lock_descriptor: int | None = None
        if execute and queue_mode == "serial" and execution_lock is not None:
            try:
                lock_descriptor = acquire_execution_lock(
                    execution_lock,
                    matrix_id=str(queue.get("matrix_id") or ""),
                )
            except RuntimeError as exc:
                results = blocked_records(selected, [str(exc)])
                write_checkpoint(results)
        if lock_descriptor is not None or not (execute and queue_mode == "serial" and execution_lock is not None):
            try:
                results = execute_records(
                    selected,
                    execute=execute,
                    stop_on_failure=stop_on_failure,
                    runner=runner,
                    row_state_reader=row_state_reader,
                    attempt_recorder=attempt_recorder,
                    prelaunch_validator=(
                        formal_prelaunch
                        if formal_serial_execute
                        else None
                    ),
                    on_update=write_checkpoint if execute else None,
                )
            finally:
                if lock_descriptor is not None and execution_lock is not None:
                    release_execution_lock(execution_lock, lock_descriptor)
    return make_plan(results)


def render_markdown(plan: dict[str, Any]) -> str:
    summary = plan["summary"]
    lines = [
        "# Paper Run Execution Plan",
        "",
        f"- generated_at: `{plan['generated_at']}`",
        f"- matrix_id: `{plan['matrix_id']}`",
        f"- case_set: `{plan['case_set']}`",
        f"- queue_mode: `{plan['queue_mode']}`",
        f"- requested_harnesses: `{','.join(plan.get('requested_harnesses', [])) or 'all'}`",
        f"- execute: `{str(plan['execute']).lower()}`",
        f"- include_post_run: `{str(plan['include_post_run']).lower()}`",
        f"- skip_readiness_check: `{str(plan.get('skip_readiness_check', False)).lower()}`",
        f"- selected_commands: `{summary['selected_commands']}`",
        f"- selected_missing_rows: `{summary.get('selected_missing_rows', 0)}`",
        f"- executed_commands: `{summary['executed_commands']}`",
        f"- failed_commands: `{summary['failed_commands']}`",
        f"- blocked_commands: `{summary.get('blocked_commands', 0)}`",
        f"- pending_commands: `{summary.get('pending_commands', 0)}`",
        f"- skipped_completed_commands: `{summary.get('skipped_completed_commands', 0)}`",
        f"- model_protocol_terminal_commands: `{summary.get('model_protocol_terminal_commands', 0)}`",
        f"- incomplete_commands: `{summary.get('incomplete_commands', 0)}`",
        f"- resume_batch: `{summary.get('resume_batch') or 'n/a'}`",
        f"- ok: `{str(summary['ok']).lower()}`",
        "",
        "## Readiness Gate",
        "",
    ]
    gate = plan.get("readiness_gate", {})
    lines += [
        f"- checked: `{str(gate.get('checked', False)).lower()}`",
        f"- skipped: `{str(gate.get('skipped', False)).lower()}`",
        f"- requires_kimi: `{str(gate.get('requires_kimi', False)).lower()}`",
        f"- ready: `{gate.get('ready') if gate.get('ready') is not None else 'n/a'}`",
        "",
        "### Blockers",
        "",
    ]
    blockers = gate.get("blockers", [])
    if blockers:
        lines.extend(f"- {item}" for item in blockers)
    else:
        lines.append("- none")
    lines += ["", "### Warnings", ""]
    warnings = gate.get("warnings", [])
    if warnings:
        lines.extend(f"- {item}" for item in warnings)
    else:
        lines.append("- none")
    lines += [
        "",
        "## Commands",
        "",
    ]
    if plan["commands"]:
        lines += [
            "| # | Source | Batch | Rows | Status | Command |",
            "| ---: | --- | --- | ---: | --- | --- |",
        ]
        for item in plan["commands"]:
            lines.append(
                f"| {item['index']} | {item['source']} | {item['batch_id']} | "
                f"{item.get('missing_rows', 0)} | {item['status']} | `{item['command']}` |"
            )
    else:
        lines.append("- none")
    if summary.get("resume_batch"):
        lines += [
            "",
            "## Resume",
            "",
            f"- resume with: `--start-at {summary['resume_batch']}`",
        ]
    return "\n".join(lines) + "\n"


def write_execution_outputs(plan: dict[str, Any], out_json: Path, out_md: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_markdown(plan), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run or execute the paper run queue.")
    parser.add_argument("--queue", default=str(DEFAULT_QUEUE))
    parser.add_argument(
        "--queue-mode",
        choices=["serial", "coalesced", "fine", "post-run"],
        default="serial",
        help="Use serial for the formal matrix. Coalesced/fine are compatibility smoke modes.",
    )
    parser.add_argument("--batch", action="append", default=[])
    parser.add_argument("--harness", action="append", default=[], help="Filter selected batches by harness. Repeat or comma-separate values.")
    parser.add_argument("--start-at", default="")
    parser.add_argument("--include-post-run", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--continue-on-failure", action="store_true")
    parser.add_argument(
        "--skip-readiness-check",
        action="store_true",
        help="Execute selected commands without the static paper readiness gate.",
    )
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)

    def checkpoint_writer(plan: dict[str, Any]) -> None:
        write_execution_outputs(plan, out_json, out_md)

    plan = build_execution_plan(
        queue_path=Path(args.queue),
        queue_mode=args.queue_mode,
        batches=args.batch,
        harnesses=split_cli_values(args.harness),
        start_at=args.start_at,
        include_post_run=args.include_post_run,
        execute=args.execute,
        stop_on_failure=not args.continue_on_failure,
        skip_readiness_check=args.skip_readiness_check,
        checkpoint_writer=checkpoint_writer if args.execute else None,
    )
    write_execution_outputs(plan, out_json, out_md)
    return 0 if plan["summary"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
