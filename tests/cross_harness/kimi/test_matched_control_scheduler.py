from __future__ import annotations

from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

import pytest

from infra.cross_harness.adapters.kimi import matched_control_scheduler as scheduler
from infra.cross_harness.adapters.kimi.control_trials import CONTROL_TYPES
from infra.cross_harness.adapters.kimi.lifecycle import LINUX_AF_UNIX_PATH_LIMIT


REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_ID = "formal-20260721-kimi01"


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


@pytest.fixture(scope="module")
def schedule_environment():
    batch = Path(tempfile.mkdtemp(prefix="sb-kc-", dir="/tmp")) / "batch"
    assert not batch.exists()
    document = scheduler.build_production_matched_control_schedule(
        repo_root=REPO_ROOT,
        batch_root=batch,
        run_id=RUN_ID,
    )
    build_created_batch = batch.exists()
    try:
        yield batch, document, build_created_batch
    finally:
        shutil.rmtree(batch.parent, ignore_errors=True)


@pytest.fixture(scope="module")
def production_gate(schedule_environment):
    _batch, document, _created = schedule_environment
    path = scheduler.write_production_matched_control_schedule(
        document, repo_root=REPO_ROOT
    )
    gate = scheduler.ProductionMatchedControlGate(
        schedule_path=path, repo_root=REPO_ROOT
    )
    return gate


def _case_with_status(document: dict[str, Any], status: str, offset: int = 0):
    return [case for case in document["cases"] if case["schedule_status"] == status][
        offset
    ]


def test_schedule_is_live_hash_bound_328_by_four_and_read_only(
    schedule_environment,
) -> None:
    batch, document, build_created_batch = schedule_environment
    assert build_created_batch is False
    assert not batch.exists()
    assert document["counts"] == {
        "case_count": 328,
        "control_trial_count": 1312,
        "case_statuses": {
            "ALL_FOUR_PLANNED": 253,
            "ATTACK_UNAVAILABLE": 55,
            "INCOMPLETE_CONTROL_SET": 20,
        },
        "control_dispositions": {"MATERIALIZABLE": 1052, "NOT_RUN": 260},
        "queue_statuses": {
            "PLANNED_PENDING_ORCHESTRATOR": 1012,
            "NOT_RUN": 260,
            "WITHHELD_INCOMPLETE_CONTROL_SET": 40,
        },
    }
    assert document["formal_runtime_readiness_claimed"] is False
    assert document["execution_policy"]["capability_hypothesis_is_evidence"] is False
    assert document["execution_policy"]["capability_upgrade_performed"] is False
    assert document["execution_policy"]["external_orchestrator_implemented"] is False
    assert document["execution_policy"]["runtime_bridge_validated"] is False
    assert document["execution_policy"]["cross_control_port_uniqueness_required"] is False
    assert document["execution_policy"]["port_lease_time_identity_available"] is False
    serialized = json.dumps(document, sort_keys=True)
    for forbidden in (
        '"score"',
        '"scored_result"',
        '"verdict"',
        '"attack_success"',
    ):
        assert forbidden not in serialized


def test_formal_run_service_paths_are_unique_and_fit_linux_af_unix(
    schedule_environment,
) -> None:
    _batch, document, _created = schedule_environment
    provider: list[str] = []
    callback: list[str] = []
    roots: list[str] = []
    provider_owners: list[str] = []
    callback_owners: list[str] = []
    receipts: list[str] = []
    for case in document["cases"]:
        for control in case["controls"]:
            resources = control["resources"]
            if resources is None:
                continue
            provider.append(resources["provider_socket"])
            callback.append(resources["callback_socket"])
            roots.append(resources["root"])
            provider_owners.append(resources["provider_ownership_root"])
            callback_owners.append(resources["callback_ownership_root"])
            receipts.append(resources["receipt"])
            for key, path in resources.items():
                if key == "batch_root":
                    continue
                if isinstance(path, str) and path.startswith("/"):
                    assert "kimi" in path.casefold()
                    assert control["trial_run_id"] in path
    assert len(provider) == len(callback) == len(roots) == 1052
    for paths in (
        provider,
        callback,
        roots,
        provider_owners,
        callback_owners,
        receipts,
    ):
        assert len(set(paths)) == 1052
    assert max(len(os.fsencode(path)) for path in provider + callback) < (
        LINUX_AF_UNIX_PATH_LIMIT
    )
    assert set(provider).isdisjoint(callback)


def test_not_run_rows_have_no_resources_and_native_session_is_not_emulated(
    schedule_environment,
) -> None:
    _batch, document, _created = schedule_environment
    dispositions = Counter()
    queues = Counter()
    for case in document["cases"]:
        for control in case["controls"]:
            dispositions[control["disposition"]] += 1
            queues[control["queue_status"]] += 1
            if control["disposition"] == "NOT_RUN":
                assert control["resources"] is None
    assert dispositions == {"MATERIALIZABLE": 1052, "NOT_RUN": 260}
    assert queues == {
        "PLANNED_PENDING_ORCHESTRATOR": 1012,
        "NOT_RUN": 260,
        "WITHHELD_INCOMPLETE_CONTROL_SET": 40,
    }
    for case in document["cases"]:
        if case["schedule_status"] != "INCOMPLETE_CONTROL_SET":
            continue
        assert case["materializable_control_count"] == 2
        blocked = [
            control for control in case["controls"] if control["disposition"] == "NOT_RUN"
        ]
        assert {control["control_type"] for control in blocked} == {
            "no_persist_control",
            "cleanup_control",
        }
        assert all(control["declared_session_carrier_intervention"] for control in blocked)
        assert all(control["workspace_session_emulation_forbidden"] for control in blocked)


def test_self_resigned_execution_policy_tamper_is_rejected_by_live_rebuild(
    schedule_environment,
) -> None:
    _batch, document, _created = schedule_environment
    tampered = copy.deepcopy(document)
    tampered["execution_policy"]["external_orchestrator_implemented"] = True
    tampered["execution_policy"]["runtime_bridge_validated"] = True
    tampered["schedule_payload_sha256"] = scheduler._payload_sha256(
        tampered, "schedule_payload_sha256"
    )
    # A self-hash alone is intentionally not the trust boundary.
    scheduler.validate_production_matched_control_schedule(
        tampered, repo_root=REPO_ROOT, verify_live=False
    )
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError,
        match="live frozen inventory",
    ):
        scheduler.validate_production_matched_control_schedule(
            tampered, repo_root=REPO_ROOT, verify_live=True
        )


def test_schedule_write_load_is_immutable_and_exact_path(
    production_gate,
) -> None:
    gate = production_gate
    assert gate.schedule_path == scheduler.production_schedule_path(gate.schedule)
    assert gate.schedule_path.stat().st_mode & 0o777 == 0o400
    loaded = scheduler.load_production_matched_control_schedule(
        gate.schedule_path, repo_root=REPO_ROOT, verify_live=False
    )
    assert loaded["schedule_payload_sha256"] == gate.schedule["schedule_payload_sha256"]
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError, match="already exists"
    ):
        scheduler.write_production_matched_control_schedule(
            gate.schedule, repo_root=REPO_ROOT
        )


def test_gate_keeps_all_three_static_case_classes_blocked_without_receipts(
    production_gate,
) -> None:
    gate = production_gate
    expected = {
        "ALL_FOUR_PLANNED": "BLOCKED_PENDING_CONTROL_EXECUTION",
        "INCOMPLETE_CONTROL_SET": "BLOCKED_INCOMPLETE_CONTROL_SET",
        "ATTACK_UNAVAILABLE": "BLOCKED_ATTACK_UNAVAILABLE",
    }
    for schedule_status, gate_status in expected.items():
        case = _case_with_status(gate.schedule, schedule_status)
        decision = gate.evaluate(case_id=case["case_id"]).as_dict()
        assert decision["status"] == gate_status
        assert decision["attack_execution_allowed"] is False
        assert decision["capability_upgrade_performed"] is False
        assert decision["formal_conformance_allowed"] is False
        assert decision["paper_result_allowed"] is False
        assert decision["analysis_release_allowed"] is False
        assert decision["scoring_status"] == "NOT_PRODUCED"


def test_malformed_receipt_fails_closed(production_gate) -> None:
    gate = production_gate
    case = _case_with_status(gate.schedule, "ALL_FOUR_PLANNED", 1)
    receipt = Path(case["controls"][0]["resources"]["receipt"])
    _write_json(receipt, {"schema_name": "forged"})
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError, match="field set drifted"
    ):
        gate.evaluate(case_id=case["case_id"], receipt_paths=[receipt])


def test_receipt_writer_rejects_before_creating_invalid_immutable_file(
    production_gate,
) -> None:
    gate = production_gate
    case = _case_with_status(gate.schedule, "ALL_FOUR_PLANNED", 4)
    control = case["controls"][0]
    receipt = Path(control["resources"]["receipt"])
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError, match="field set drifted"
    ):
        scheduler.write_control_execution_receipt(
            {
                "case_id": case["case_id"],
                "control_type": control["control_type"],
            },
            schedule=gate.schedule,
            schedule_path=gate.schedule_path,
        )
    assert not receipt.exists()


def test_duplicate_validated_control_type_fails_closed(
    production_gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = production_gate
    case = _case_with_status(gate.schedule, "ALL_FOUR_PLANNED", 2)
    paths = [tmp_path / "receipt-one.json", tmp_path / "receipt-two.json"]
    for path in paths:
        path.write_text("{}\n", encoding="utf-8")

    def duplicate(*_args, **_kwargs):
        return {"control_type": CONTROL_TYPES[0]}

    monkeypatch.setattr(scheduler, "validate_control_execution_receipt", duplicate)
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError,
        match="duplicate control types",
    ):
        gate.evaluate(case_id=case["case_id"], receipt_paths=paths)


def test_exact_four_receipts_remain_blocked_without_validated_orchestrator_bridge(
    production_gate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = production_gate
    case = _case_with_status(gate.schedule, "ALL_FOUR_PLANNED", 3)
    returned: dict[str, dict[str, Any]] = {}
    paths: list[Path] = []
    for index, control_type in enumerate(CONTROL_TYPES):
        receipt_path = tmp_path / f"receipt-{index}.json"
        receipt_path.write_text("{}\n", encoding="utf-8")
        provider = tmp_path / f"provider-{index}.json"
        callback = tmp_path / f"callback-{index}.json"
        pid_record = tmp_path / f"pids-{index}.json"
        # Sequential controls may legitimately reuse bare PIDs.  Their process
        # identity is the (pid, start_time) pair.
        _write_json(
            provider,
            {"pid": 2000, "process_start_time": f"provider-start-{index}"},
        )
        _write_json(
            callback,
            {
                "process": {
                    "pid": 2001,
                    "start_time": f"callback-start-{index}",
                }
            },
        )
        _write_json(
            pid_record,
            {
                "processes": [
                    {"pid": 2002, "start_time": f"stage-0-start-{index}"},
                    {"pid": 2003, "start_time": f"stage-1-start-{index}"},
                ]
            },
        )
        returned[str(receipt_path)] = {
            "control_type": control_type,
            "runtime": {
                "provider_audit_attestation": {"path": str(provider)},
                "callback_attestation": {"path": str(callback)},
                "pid_record": {"path": str(pid_record)},
            },
        }
        paths.append(receipt_path)

    def validated(path: Path, **_kwargs):
        return returned[str(path)]

    monkeypatch.setattr(scheduler, "validate_control_execution_receipt", validated)
    decision = gate.evaluate(case_id=case["case_id"], receipt_paths=paths).as_dict()
    assert decision["status"] == "BLOCKED_ORCHESTRATOR_UNVALIDATED"
    assert decision["attack_execution_allowed"] is False
    assert decision["formal_conformance_allowed"] is False
    assert decision["paper_result_allowed"] is False
    assert decision["analysis_release_allowed"] is False
    assert decision["capability_upgrade_performed"] is False
    assert decision["external_orchestrator_implemented"] is False
    assert decision["runtime_bridge_validated"] is False
    assert decision["scoring_status"] == "NOT_PRODUCED"


def test_gate_decision_type_has_no_reachable_raw_attack_release() -> None:
    with pytest.raises(ValueError, match="cannot release attack execution"):
        scheduler.MatchedControlGateDecision(
            status="BLOCKED_ORCHESTRATOR_UNVALIDATED",
            run_id=RUN_ID,
            case_id="example-case",
            attack_execution_allowed=True,
            receipt_count=4,
            required_receipt_count=4,
            evidence=("schedule",),
            reasons=("unvalidated bridge",),
        )


def test_artifact_file_and_tree_reject_intermediate_symlink_ancestor(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "batch-kimi-symlink-test"
    outside = tmp_path / "outside"
    trusted.mkdir()
    outside.mkdir()
    evidence = outside / "evidence.json"
    evidence.write_text("{}\n", encoding="utf-8")
    evidence_tree = outside / "tree"
    evidence_tree.mkdir()
    (evidence_tree / "artifact.txt").write_text("evidence\n", encoding="utf-8")
    (trusted / "control-kimi-run").symlink_to(outside, target_is_directory=True)

    lexical_file = trusted / "control-kimi-run" / "evidence.json"
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError, match="symlink ancestor"
    ):
        scheduler._artifact_file(
            {
                "path": str(lexical_file),
                "sha256": scheduler.sha256_file(evidence),
            },
            expected_path=lexical_file,
            trusted_root=trusted,
            label="receipt evidence",
        )

    lexical_tree = trusted / "control-kimi-run" / "tree"
    with pytest.raises(
        scheduler.KimiMatchedControlScheduleError, match="symlink ancestor"
    ):
        scheduler._artifact_tree(
            {
                "path": str(lexical_tree),
                "tree_sha256": scheduler.tree_sha256(evidence_tree),
            },
            expected_path=lexical_tree,
            trusted_root=trusted,
            label="receipt artifact tree",
        )


def test_overlong_batch_path_fails_before_any_socket_bind() -> None:
    batch = Path("/tmp") / ("kimi-overlong-" + "x" * 80)
    with pytest.raises(Exception, match="AF_UNIX|pathname limit|overlong"):
        scheduler.build_production_matched_control_schedule(
            repo_root=REPO_ROOT,
            batch_root=batch,
            run_id=RUN_ID,
        )
    assert not batch.exists()
