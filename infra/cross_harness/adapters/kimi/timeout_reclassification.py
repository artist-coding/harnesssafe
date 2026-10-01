"""Audited migration of reviewed 1200-second Kimi prompt timeouts to N-1.

This module exists for executions produced before the executor recorded the
reviewed timeout policy directly.  It never inspects model text.  Eligibility
is established from the launcher configuration, stage result metadata, and
hash-bound stdout/wire locators.  Applying a migration preserves the exact
source state and writes a separate attestation before replacing the live state.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from .disposition import (
    EXECUTION_INVALID,
    MODEL_PROTOCOL_INCOMPLETE,
    MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS,
)


class KimiTimeoutReclassificationError(ValueError):
    """Historical timeout evidence does not satisfy the reviewed migration."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _regular_file(path: Path, label: str) -> Path:
    supplied = path.absolute()
    if supplied.is_symlink() or not supplied.is_file():
        raise KimiTimeoutReclassificationError(
            f"{label} is missing, linked, or not a regular file"
        )
    return supplied.resolve()


def _owned_file(path: Path, *, run_dir: Path, label: str) -> Path:
    resolved = _regular_file(path, label)
    try:
        resolved.relative_to(run_dir)
    except ValueError as exc:
        raise KimiTimeoutReclassificationError(
            f"{label} escapes the Kimi run directory"
        ) from exc
    return resolved


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiTimeoutReclassificationError(f"{label} must be an object")
    return value


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    source = _regular_file(path, label)
    payload = source.read_bytes()
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiTimeoutReclassificationError(f"{label} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise KimiTimeoutReclassificationError(f"{label} must contain an object")
    return document, payload


def _launcher_fields(path: Path) -> tuple[dict[str, str], bytes]:
    launcher = _regular_file(path, "resume launcher log")
    payload = launcher.read_bytes()
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise KimiTimeoutReclassificationError(
            "resume launcher log is not UTF-8"
        ) from exc
    fields: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not key or key in fields:
            raise KimiTimeoutReclassificationError(
                "resume launcher log has malformed or duplicate fields"
            )
        fields[key] = value
    return fields, payload


def _validate_hash_bound_file(
    *,
    raw_path: Any,
    raw_sha256: Any,
    run_dir: Path,
    label: str,
) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise KimiTimeoutReclassificationError(f"{label} path is invalid")
    if (
        not isinstance(raw_sha256, str)
        or len(raw_sha256) != 64
        or any(char not in "0123456789abcdef" for char in raw_sha256)
    ):
        raise KimiTimeoutReclassificationError(f"{label} SHA-256 is invalid")
    path = _owned_file(Path(raw_path), run_dir=run_dir, label=label)
    if _sha256_bytes(path.read_bytes()) != raw_sha256:
        raise KimiTimeoutReclassificationError(f"{label} SHA-256 drifted")
    return path


def _eligible_timeout(
    *,
    record: Mapping[str, Any],
    case_id: str,
    run_id: str,
    run_dir: Path,
) -> dict[str, Any]:
    if (
        record.get("status") != EXECUTION_INVALID
        or record.get("failure_category") != "PROVIDER_TIMEOUT"
        or record.get("retry_eligible") is not True
        or record.get("attempt") != 2
    ):
        raise KimiTimeoutReclassificationError(
            f"case is not an attempt-2 retryable provider timeout: {case_id}"
        )
    evidence = _mapping(record.get("evidence"), f"{case_id} evidence")
    if (
        evidence.get("outcome") != EXECUTION_INVALID
        or evidence.get("failure_category") != "PROVIDER_TIMEOUT"
        or evidence.get("retry_eligible") is not True
    ):
        raise KimiTimeoutReclassificationError(
            f"case execution evidence is not the source timeout disposition: {case_id}"
        )
    metadata = _mapping(evidence.get("metadata"), f"{case_id} execution metadata")
    stages = metadata.get("stages")
    if not isinstance(stages, list) or not stages:
        raise KimiTimeoutReclassificationError(
            f"case execution metadata has no stages: {case_id}"
        )
    captured = _mapping(stages[-1], f"{case_id} final captured stage")
    result_path_raw = captured.get("result_path")
    if not isinstance(result_path_raw, str) or not result_path_raw:
        raise KimiTimeoutReclassificationError(
            f"case final stage result path is invalid: {case_id}"
        )
    result_path = _owned_file(
        Path(result_path_raw),
        run_dir=run_dir,
        label=f"{case_id} final stage result",
    )
    stage, stage_payload = _read_json(result_path, f"{case_id} final stage result")
    stage_identity = _mapping(stage.get("stage"), f"{case_id} stage identity")
    argv = stage.get("argv")
    if (
        stage.get("schema_name") != "safety_bench_kimi_stage_execution"
        or stage.get("harness_id") != "kimi"
        or stage.get("run_id") != run_id
        or stage.get("case_id") != case_id
        or stage.get("timed_out") is not True
        or stage.get("return_code") != evidence.get("return_code")
        or stage_identity.get("index") != captured.get("index")
        or stage_identity.get("name") != captured.get("name")
        or not isinstance(argv, list)
        or len(argv) < 2
        or argv[1] != "--prompt"
    ):
        raise KimiTimeoutReclassificationError(
            f"case final stage is not a directly captured prompt timeout: {case_id}"
        )
    stage_stdout = _mapping(stage.get("stdout"), f"{case_id} stage stdout")
    stage_wire = _mapping(stage.get("wire"), f"{case_id} stage wire")
    stdout_path = _validate_hash_bound_file(
        raw_path=captured.get("stdout_path"),
        raw_sha256=captured.get("stdout_sha256"),
        run_dir=run_dir,
        label=f"{case_id} stdout",
    )
    wire_path = _validate_hash_bound_file(
        raw_path=captured.get("main_wire_path"),
        raw_sha256=captured.get("main_wire_sha256"),
        run_dir=run_dir,
        label=f"{case_id} wire",
    )
    if (
        Path(str(stage_stdout.get("path"))).absolute().resolve() != stdout_path
        or stage_stdout.get("sha256") != captured.get("stdout_sha256")
        or Path(str(stage_wire.get("main_path"))).absolute().resolve() != wire_path
        or stage_wire.get("main_sha256") != captured.get("main_wire_sha256")
        or Path(str(evidence.get("raw_stdout_path"))).absolute().resolve()
        != stdout_path
        or Path(str(evidence.get("raw_wire_path"))).absolute().resolve()
        != wire_path
    ):
        raise KimiTimeoutReclassificationError(
            f"case timeout locators are not mutually hash-bound: {case_id}"
        )
    return {
        "case_id": case_id,
        "attempt": 2,
        "stage_index": stage_identity["index"],
        "stage_name": stage_identity["name"],
        "stage_result_path": str(result_path),
        "stage_result_sha256": _sha256_bytes(stage_payload),
        "stdout_path": str(stdout_path),
        "stdout_sha256": captured["stdout_sha256"],
        "wire_path": str(wire_path),
        "wire_sha256": captured["main_wire_sha256"],
        "source_outcome": EXECUTION_INVALID,
        "source_failure_category": "PROVIDER_TIMEOUT",
        "target_outcome": MODEL_PROTOCOL_INCOMPLETE,
        "target_failure_category": "MODEL_STAGE_TIMEOUT",
    }


def prepare_timeout_reclassification(
    *,
    state_path: Path,
    launcher_log_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Return migrated state, attestation, and exact source-state bytes."""

    state_file = _regular_file(state_path, "Kimi state")
    run_dir = state_file.parent.resolve()
    launcher_file = _owned_file(
        launcher_log_path,
        run_dir=run_dir,
        label="resume launcher log",
    )
    state, source_state_bytes = _read_json(state_file, "Kimi state")
    launcher, launcher_bytes = _launcher_fields(launcher_file)
    run_id = state.get("run_id")
    cases = state.get("cases")
    if (
        state.get("schema_name") != "safety_bench_kimi_run_state"
        or state.get("harness_id") != "kimi"
        or not isinstance(run_id, str)
        or not run_id
        or not isinstance(cases, dict)
        or launcher.get("command") != "resume"
        or launcher.get("run_id") != run_id
        or launcher.get("timeout_seconds")
        != str(MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS)
    ):
        raise KimiTimeoutReclassificationError(
            "state and reviewed 1200-second resume launcher identities do not match"
        )
    eligible: list[dict[str, Any]] = []
    for case_id, raw_record in cases.items():
        if not isinstance(case_id, str) or not isinstance(raw_record, Mapping):
            raise KimiTimeoutReclassificationError("state case records are malformed")
        if (
            raw_record.get("status") == EXECUTION_INVALID
            and raw_record.get("failure_category") == "PROVIDER_TIMEOUT"
            and raw_record.get("retry_eligible") is True
        ):
            eligible.append(
                _eligible_timeout(
                    record=raw_record,
                    case_id=case_id,
                    run_id=run_id,
                    run_dir=run_dir,
                )
            )
    if not eligible:
        raise KimiTimeoutReclassificationError(
            "state contains no eligible reviewed 1200-second prompt timeouts"
        )

    migrated = deepcopy(state)
    changed_at = _utc_now()
    reason = (
        "direct execution evidence records a prompt stage that did not complete "
        f"within the reviewed {MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS}-second "
        "model protocol limit; terminal outcome; no score was produced"
    )
    for item in eligible:
        record = migrated["cases"][item["case_id"]]
        record["status"] = MODEL_PROTOCOL_INCOMPLETE
        record["failure_category"] = "MODEL_STAGE_TIMEOUT"
        record["retry_eligible"] = False
        record["reason"] = reason
        evidence = record["evidence"]
        evidence["outcome"] = MODEL_PROTOCOL_INCOMPLETE
        evidence["failure_category"] = "MODEL_STAGE_TIMEOUT"
        evidence["retry_eligible"] = False
        metadata = evidence["metadata"]
        metadata["execution_disposition"] = {
            "outcome": MODEL_PROTOCOL_INCOMPLETE,
            "failure_category": "MODEL_STAGE_TIMEOUT",
            "retry_eligible": False,
            "reason": (
                "Kimi prompt stage did not complete within the reviewed "
                f"{MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS}-second "
                "model protocol limit"
            ),
            "source": "audited_timeout_reclassification",
            "timed_out": True,
            "timeout_seconds": MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS,
        }
        final_stage = metadata["stages"][-1]
        final_stage["timed_out"] = True
        final_stage["timeout_seconds"] = (
            MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS
        )
        history = record.get("history")
        if not isinstance(history, list):
            raise KimiTimeoutReclassificationError(
                f"case history is malformed: {item['case_id']}"
            )
        history.append(
            {
                "at": changed_at,
                "status": MODEL_PROTOCOL_INCOMPLETE,
                "reason": reason,
                "failure_category": "MODEL_STAGE_TIMEOUT",
                "retry_eligible": False,
            }
        )
    migrated["updated_at"] = changed_at
    migrated_bytes = _canonical_bytes(migrated)
    attestation = {
        "schema_name": "safety_bench_kimi_timeout_reclassification",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": run_id,
        "created_at": changed_at,
        "policy": {
            "source_outcome": EXECUTION_INVALID,
            "source_failure_category": "PROVIDER_TIMEOUT",
            "target_outcome": MODEL_PROTOCOL_INCOMPLETE,
            "target_failure_category": "MODEL_STAGE_TIMEOUT",
            "prompt_timeout_seconds": (
                MODEL_PROTOCOL_NONCOMPLETION_TIMEOUT_SECONDS
            ),
            "retry_eligible": False,
        },
        "source_state": {
            "path": str(state_file),
            "sha256": _sha256_bytes(source_state_bytes),
        },
        "resume_launcher_log": {
            "path": str(launcher_file),
            "sha256": _sha256_bytes(launcher_bytes),
        },
        "migrated_state_sha256": _sha256_bytes(migrated_bytes),
        "case_count": len(eligible),
        "cases": eligible,
    }
    return migrated, attestation, source_state_bytes


def _exclusive_write(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _atomic_replace(path: Path, payload: bytes) -> None:
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply_timeout_reclassification(
    *,
    state_path: Path,
    launcher_log_path: Path,
) -> dict[str, Any]:
    """Apply the migration while retaining exact before/after provenance."""

    state_file = _regular_file(state_path, "Kimi state")
    migrated, attestation, source_state_bytes = prepare_timeout_reclassification(
        state_path=state_file,
        launcher_log_path=launcher_log_path,
    )
    source_sha = attestation["source_state"]["sha256"]
    run_id = attestation["run_id"]
    backup_path = state_file.parent / (
        f"state-before-timeout-reclassification-{source_sha[:16]}.json"
    )
    attestation_path = state_file.parent / (
        f"timeout-reclassification-kimi-{run_id}.json"
    )
    if backup_path.exists() or backup_path.is_symlink():
        if (
            backup_path.is_symlink()
            or not backup_path.is_file()
            or backup_path.read_bytes() != source_state_bytes
        ):
            raise KimiTimeoutReclassificationError(
                "existing source-state backup does not match the reviewed state"
            )
    else:
        _exclusive_write(backup_path, source_state_bytes)
    if attestation_path.exists() or attestation_path.is_symlink():
        raise KimiTimeoutReclassificationError(
            "timeout reclassification attestation already exists"
        )
    attestation["source_state"]["backup_path"] = str(backup_path)
    attestation_bytes = _canonical_bytes(attestation)
    _exclusive_write(attestation_path, attestation_bytes)
    _atomic_replace(state_file, _canonical_bytes(migrated))
    return {
        "state_path": str(state_file),
        "state_sha256": attestation["migrated_state_sha256"],
        "source_state_backup_path": str(backup_path),
        "attestation_path": str(attestation_path),
        "attestation_sha256": _sha256_bytes(attestation_bytes),
        "case_count": attestation["case_count"],
        "case_ids": [item["case_id"] for item in attestation["cases"]],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--launcher-log", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if args.apply:
        result = apply_timeout_reclassification(
            state_path=args.state,
            launcher_log_path=args.launcher_log,
        )
    else:
        _, attestation, _ = prepare_timeout_reclassification(
            state_path=args.state,
            launcher_log_path=args.launcher_log,
        )
        result = {
            "dry_run": True,
            "run_id": attestation["run_id"],
            "case_count": attestation["case_count"],
            "case_ids": [item["case_id"] for item in attestation["cases"]],
            "target_outcome": MODEL_PROTOCOL_INCOMPLETE,
        }
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
