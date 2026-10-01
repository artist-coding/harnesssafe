"""Production matched-control schedule and launch gate for Kimi Code.

This module is deliberately upstream of model execution and downstream of the
frozen 328-case inventory.  It does not run Kimi, invoke an analyzer, emit a
score, or upgrade a Contract-v1 capability.  Its two responsibilities are:

* deterministically rebuild a hash-bound 328 x 4 matched-control schedule with
  independent resource identities for every materializable control; and
* validate exact-four immutable ``COMPLETED`` control receipts without
  treating them as authority to launch an attack.

The current production runner has no external matched-control orchestrator or
validated ``ControlTrialLayout`` runtime bridge.  The expected live decision
is therefore ``BLOCKED_PENDING_CONTROL_EXECUTION`` before four receipts and
``BLOCKED_ORCHESTRATOR_UNVALIDATED`` after four receipts for the 253 cases
whose controls are statically materializable.  Neither state releases raw
attack execution through this deferred control workflow.  The separate
attack-only runner does not consume this gate under the current experiment
policy.  Twenty cases are blocked by the native-session intervention gap and
55 have no approved Kimi attack variant.  A workspace file is never accepted
as a replacement for a native session intervention.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any

from infra.cross_harness.contract import CAPABILITIES, validate_event_document

from .bench_inventory import EXPECTED_CASE_COUNT, load_frozen_inventory
from .bench_materializer import (
    build_bench_case_plan,
    iter_active_case_references,
    load_bench_materialization_manifest,
)
from .callback_collector import (
    CALLBACK_ATTESTATION_SCHEMA_NAME,
    CALLBACK_ATTESTATION_SCHEMA_VERSION,
    CALLBACK_SOCKET_BASENAME,
    callback_root_name,
)
from .control_trials import (
    CONTROL_TYPES,
    EXPECTED_CONTROL_TRIAL_COUNT,
    allocate_control_layout,
    build_control_trial_plan,
    load_control_trial_plan,
)
from .executor import ATTESTATION_SCHEMA_NAME, ATTESTATION_SCHEMA_VERSION
from .lifecycle import (
    LINUX_AF_UNIX_PATH_LIMIT,
    RunLayout,
    encoded_unix_socket_path_length,
    validate_bench_run_id,
    validate_linux_unix_socket_path,
)
from .materializer import sha256_file, tree_sha256
from .provider_broker import (
    AUDIT_ATTESTATION_SCHEMA_NAME,
    AUDIT_ATTESTATION_SCHEMA_VERSION,
    BROKER_ATTESTATION_SCHEMA_NAME,
    BROKER_ATTESTATION_SCHEMA_VERSION,
    BROKER_SOCKET_BASENAME,
    broker_root_name,
)


SCHEDULE_SCHEMA_NAME = "safety_bench_kimi_matched_control_schedule"
SCHEDULE_SCHEMA_VERSION = 1
RECEIPT_SCHEMA_NAME = "safety_bench_kimi_control_execution_receipt"
RECEIPT_SCHEMA_VERSION = 1
GATE_DECISION_SCHEMA_NAME = "safety_bench_kimi_matched_control_gate_decision"
GATE_DECISION_SCHEMA_VERSION = 1

CASE_SCHEDULE_STATUSES = (
    "ALL_FOUR_PLANNED",
    "INCOMPLETE_CONTROL_SET",
    "ATTACK_UNAVAILABLE",
)
CONTROL_QUEUE_STATUSES = (
    "PLANNED_PENDING_ORCHESTRATOR",
    "WITHHELD_INCOMPLETE_CONTROL_SET",
    "NOT_RUN",
)
GATE_STATUSES = (
    "BLOCKED_PENDING_CONTROL_EXECUTION",
    "BLOCKED_ORCHESTRATOR_UNVALIDATED",
    "BLOCKED_INCOMPLETE_CONTROL_SET",
    "BLOCKED_ATTACK_UNAVAILABLE",
)

_EXPECTED_CASE_STATUS_COUNTS = {
    "ALL_FOUR_PLANNED": 253,
    "INCOMPLETE_CONTROL_SET": 20,
    "ATTACK_UNAVAILABLE": 55,
}
_EXPECTED_CONTROL_DISPOSITIONS = {"MATERIALIZABLE": 1052, "NOT_RUN": 260}
_EXPECTED_QUEUE_COUNTS = {
    "PLANNED_PENDING_ORCHESTRATOR": 1012,
    "WITHHELD_INCOMPLETE_CONTROL_SET": 40,
    "NOT_RUN": 260,
}
_CAPABILITY_HYPOTHESIS = {capability: "SUPPORTED" for capability in CAPABILITIES}
_SHA256_HEX = frozenset("0123456789abcdef")
_FORBIDDEN_OUTPUT_KEYS = frozenset(
    {
        "attack_success",
        "confirmed_compromise",
        "oracle",
        "oracle_path",
        "progress_node",
        "risk_score",
        "score",
        "scored_result",
        "verdict",
    }
)


class KimiMatchedControlScheduleError(RuntimeError):
    """A production schedule, receipt, or launch-gate input failed closed."""


@dataclass(frozen=True)
class MatchedControlGateDecision:
    status: str
    run_id: str
    case_id: str
    attack_execution_allowed: bool
    receipt_count: int
    required_receipt_count: int
    evidence: tuple[str, ...]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in GATE_STATUSES:
            raise ValueError("invalid matched-control gate status")
        if self.attack_execution_allowed:
            raise ValueError(
                "matched-control gate cannot release attack execution without a "
                "validated external orchestrator/runtime bridge"
            )
        if self.required_receipt_count != len(CONTROL_TYPES):
            raise ValueError("matched-control gate must require exactly four receipts")
        if self.receipt_count < 0 or self.receipt_count > self.required_receipt_count:
            raise ValueError("matched-control receipt count is invalid")
        if not self.evidence or not self.reasons:
            raise ValueError("matched-control gate requires evidence and reasons")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_name": GATE_DECISION_SCHEMA_NAME,
            "schema_version": GATE_DECISION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": self.run_id,
            "case_id": self.case_id,
            "status": self.status,
            "attack_execution_allowed": self.attack_execution_allowed,
            "receipt_count": self.receipt_count,
            "required_receipt_count": self.required_receipt_count,
            "evidence": list(self.evidence),
            "reasons": list(self.reasons),
            "capability_upgrade_performed": False,
            "formal_conformance_allowed": False,
            "paper_result_allowed": False,
            "analysis_release_allowed": False,
            "external_orchestrator_implemented": False,
            "runtime_bridge_validated": False,
            "scoring_status": "NOT_PRODUCED",
        }


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KimiMatchedControlScheduleError(
            "matched-control document is not JSON-canonicalizable"
        ) from exc


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _payload_sha256(document: Mapping[str, Any], field: str) -> str:
    return _canonical_sha256({key: value for key, value in document.items() if key != field})


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise KimiMatchedControlScheduleError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise KimiMatchedControlScheduleError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise KimiMatchedControlScheduleError(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise KimiMatchedControlScheduleError(
            f"{label} must be an integer >= {minimum}"
        )
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_HEX for character in value)
    ):
        raise KimiMatchedControlScheduleError(f"{label} must be a lowercase SHA-256")
    return value


def _forbidden_paths(value: Any, prefix: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if str(key).casefold() in _FORBIDDEN_OUTPUT_KEYS:
                found.append(path)
            found.extend(_forbidden_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_forbidden_paths(child, f"{prefix}[{index}]"))
    return found


def _assert_no_scoring(value: Any, label: str) -> None:
    forbidden = _forbidden_paths(value)
    if forbidden:
        raise KimiMatchedControlScheduleError(
            f"{label} contains analyzer/scoring fields: " + ", ".join(forbidden)
        )


def _external_batch_root(repo_root: Path, batch_root: Path) -> Path:
    repo = Path(repo_root).resolve(strict=True)
    root = Path(batch_root).resolve()
    try:
        root.relative_to(repo)
    except ValueError:
        pass
    else:
        raise KimiMatchedControlScheduleError(
            "matched-control batch_root must be external to the repository"
        )
    if any(
        part.casefold() in {".claude", ".codex", ".kimi-code"}
        for part in root.parts
    ):
        raise KimiMatchedControlScheduleError(
            "matched-control batch_root must not use harness user state"
        )
    return root


def _assert_path_identity(
    path: Path, *, root: Path, run_id: str, label: str, allow_root: bool = False
) -> Path:
    candidate = Path(path).absolute()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise KimiMatchedControlScheduleError(f"{label} is not an absolute safe path")
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise KimiMatchedControlScheduleError(f"{label} escapes batch_root") from exc
    if not relative.parts and not allow_root:
        raise KimiMatchedControlScheduleError(f"{label} may not equal batch_root")
    rendered = candidate.as_posix()
    if "kimi" not in rendered.casefold() or run_id not in rendered:
        raise KimiMatchedControlScheduleError(
            f"{label} lacks exact Kimi/control-run identity"
        )
    return candidate


def _assert_symlink_free_descendant(
    path: Path, *, trusted_root: Path, label: str
) -> Path:
    """Reject every symlink component in a schedule-bound lexical path.

    Comparing ``path.resolve()`` with ``expected_path.resolve()`` is not a
    security boundary when both values are the same attacker-influenced
    lexical path.  This check first binds the lexical path below a root taken
    from the live-rebuilt schedule, then uses ``lstat`` on the leaf and every
    ancestor (including ancestors of the trusted root) without following any
    component.
    """

    candidate = Path(path).absolute()
    root = Path(trusted_root).absolute()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise KimiMatchedControlScheduleError(
            f"{label} escapes its trusted schedule root"
        ) from exc
    for component in (candidate, *candidate.parents):
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise KimiMatchedControlScheduleError(
                f"{label} has an unavailable path component: {component}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise KimiMatchedControlScheduleError(
                f"{label} has a symlink ancestor: {component}"
            )
    return candidate


def _implementation_pins() -> dict[str, dict[str, str]]:
    package = Path(__file__).resolve().parent
    paths = {
        "scheduler_gate": package / "matched_control_scheduler.py",
        "control_materializer_and_boundary": package / "control_trials.py",
        "stage_executor": package / "executor.py",
    }
    repo = Path(__file__).resolve().parents[4]
    return {
        name: {
            "path": path.relative_to(repo).as_posix(),
            "sha256": sha256_file(path),
        }
        for name, path in paths.items()
    }


def _control_resource_plan(
    *,
    batch_root: Path,
    case_id: str,
    control_id: str,
    layout: Any,
) -> dict[str, Any]:
    run_id = str(layout.trial_run_id)
    token = str(layout.control_token)
    provider_owner = batch_root / f"provider-kimi-{run_id}"
    callback_owner = batch_root / f"callback-kimi-{run_id}"
    provider_service = provider_owner / broker_root_name(run_id, case_id, control_id)
    callback_service = callback_owner / callback_root_name(run_id, case_id, control_id)
    provider_socket = validate_linux_unix_socket_path(
        provider_service / BROKER_SOCKET_BASENAME,
        label="matched-control provider socket path",
    )
    callback_socket = validate_linux_unix_socket_path(
        callback_service / CALLBACK_SOCKET_BASENAME,
        label="matched-control callback socket path",
    )
    resources = {
        **layout.as_dict(),
        "provider_ownership_root": str(provider_owner),
        "provider_service_root": str(provider_service),
        "provider_socket": str(provider_socket),
        "provider_audit_attestation": str(
            provider_service / f"audit-attestation-kimi-{run_id}.json"
        ),
        "provider_launcher_attestation": str(
            provider_service / f"attestation-kimi-{run_id}.json"
        ),
        "provider_audit_log": str(
            provider_service / f"audit-kimi-{run_id}.jsonl"
        ),
        "callback_ownership_root": str(callback_owner),
        "callback_service_root": str(callback_service),
        "callback_socket": str(callback_socket),
        "callback_attestation": str(
            callback_service / f"callback-attestation-kimi-{run_id}.json"
        ),
        "callback_evidence": str(
            callback_service / f"callback-evidence-kimi-{run_id}.jsonl"
        ),
        "callback_manifest": str(
            callback_service / f"callback-manifest-kimi-{run_id}.json"
        ),
        "port_lease_evidence": str(
            layout.root / f"port-lease-kimi-{run_id}-{token}.json"
        ),
        "runtime_close_evidence": str(
            layout.root / f"runtime-close-kimi-{run_id}-{token}.json"
        ),
        "control_plan": str(layout.root / f"control-plan-kimi-{run_id}.json"),
        "intervention_evidence": str(layout.root / "control_intervention.json"),
        "bench_manifest": str(layout.root / f"manifest-kimi-{run_id}.json"),
        "initial_bench_manifest": str(
            layout.root / f"initial-manifest-kimi-{run_id}-{token}.json"
        ),
        "materialized_case": str(layout.root / "materialized_case"),
        "materialized_port_record": str(
            layout.root / "materialized_case" / f"port-kimi-{run_id}.json"
        ),
        "launcher_attestation": str(
            layout.root
            / f"isolated-launcher-kimi-{run_id}"
            / f"attestation-kimi-{run_id}.json"
        ),
        "receipt": str(layout.root / f"receipt-kimi-{run_id}-{token}.json"),
    }
    for key, raw in resources.items():
        if key in {"batch_root", "parent_run_id", "trial_run_id", "control_id", "control_token"}:
            continue
        _assert_path_identity(
            Path(str(raw)), root=batch_root, run_id=run_id, label=f"control {key}"
        )
    if encoded_unix_socket_path_length(provider_socket) >= LINUX_AF_UNIX_PATH_LIMIT:
        raise KimiMatchedControlScheduleError("provider AF_UNIX path is overlong")
    if encoded_unix_socket_path_length(callback_socket) >= LINUX_AF_UNIX_PATH_LIMIT:
        raise KimiMatchedControlScheduleError("callback AF_UNIX path is overlong")
    return resources


def _attack_resource_plan(
    *, layout: RunLayout, case_id: str, attempt: int
) -> dict[str, str]:
    case = layout.for_case(case_id, attempt=attempt)
    provider, callback = layout.production_service_paths(
        case, trial_id=f"attack-attempt-{attempt:03d}"
    )
    return {
        "run_id": layout.run_id,
        "case_id": case_id,
        "root": str(case.root),
        "workspace": str(case.workspace),
        "config": str(case.config),
        "session": str(case.session),
        "cache": str(case.cache),
        "trace": str(case.trace),
        "result": str(case.result),
        "artifact": str(case.artifact),
        "pid_record": str(case.pid_record),
        "provider_socket": str(provider),
        "callback_socket": str(callback),
    }


def build_production_matched_control_schedule(
    *,
    repo_root: Path,
    batch_root: Path,
    run_id: str,
    attempt: int = 1,
) -> dict[str, Any]:
    """Rebuild the exact 328 x 4 schedule without creating runtime resources."""

    checked_run_id = validate_bench_run_id(run_id)
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise KimiMatchedControlScheduleError("schedule attempt must be positive")
    repo = Path(repo_root).resolve(strict=True)
    batch = _external_batch_root(repo, Path(batch_root))
    attack_layout = RunLayout(repo, batch, checked_run_id)
    frozen = load_frozen_inventory(repo, verify_live=True)
    references = iter_active_case_references(repo)
    if len(references) != EXPECTED_CASE_COUNT:
        raise KimiMatchedControlScheduleError(
            "live Kimi inventory is not exactly 328 cases"
        )
    frozen_cases = {
        str(record["case_id"]): record
        for record in _array(frozen.get("cases"), "frozen inventory cases")
        if isinstance(record, Mapping) and isinstance(record.get("case_id"), str)
    }
    if len(frozen_cases) != EXPECTED_CASE_COUNT:
        raise KimiMatchedControlScheduleError(
            "frozen Kimi inventory contains duplicate/missing cases"
        )

    case_records: list[dict[str, Any]] = []
    case_statuses: Counter[str] = Counter()
    control_dispositions: Counter[str] = Counter()
    queue_statuses: Counter[str] = Counter()
    control_ids: set[str] = set()
    control_run_ids: set[str] = set()
    control_roots: set[str] = set()
    provider_roots: set[str] = set()
    callback_roots: set[str] = set()
    receipt_paths: set[str] = set()
    attack_roots: set[str] = set()

    for reference in references:
        case_dir = Path(str(reference["case_dir"])).resolve(strict=True)
        suite_id = _string(reference.get("suite_id"), "active suite_id")
        base = build_bench_case_plan(
            repo_root=repo,
            case_dir=case_dir,
            capability_states=_CAPABILITY_HYPOTHESIS,
            expected_suite_id=suite_id,
        )
        case_id = _string(base.get("case_id"), "base Kimi case_id")
        if case_id not in frozen_cases:
            raise KimiMatchedControlScheduleError(
                "active case is absent from the frozen Kimi inventory"
            )
        raw_controls: list[dict[str, Any]] = []
        materializable_count = 0
        for control_type in CONTROL_TYPES:
            plan = build_control_trial_plan(
                repo_root=repo,
                case_dir=case_dir,
                batch_root=batch,
                run_id=checked_run_id,
                control_type=control_type,
                capability_states=_CAPABILITY_HYPOTHESIS,
                expected_suite_id=suite_id,
                base_plan=base,
            )
            disposition = _string(plan.get("disposition"), "control disposition")
            if disposition not in {"MATERIALIZABLE", "NOT_RUN"}:
                raise KimiMatchedControlScheduleError(
                    "control plan returned an unknown disposition"
                )
            control_dispositions[disposition] += 1
            control_id = _string(plan.get("control_id"), "control_id")
            trial_run_id = _string(plan.get("trial_run_id"), "control trial_run_id")
            if control_id in control_ids or trial_run_id in control_run_ids:
                raise KimiMatchedControlScheduleError(
                    "matched-control schedule contains duplicate identities"
                )
            control_ids.add(control_id)
            control_run_ids.add(trial_run_id)
            resources: dict[str, Any] | None = None
            if disposition == "MATERIALIZABLE":
                materializable_count += 1
                layout = allocate_control_layout(
                    batch_root=batch,
                    run_id=checked_run_id,
                    control_id=control_id,
                )
                if layout.trial_run_id != trial_run_id:
                    raise KimiMatchedControlScheduleError(
                        "control layout changed its trial run identity"
                    )
                resources = _control_resource_plan(
                    batch_root=batch,
                    case_id=case_id,
                    control_id=control_id,
                    layout=layout,
                )
                for value, seen, label in (
                    (resources["root"], control_roots, "control root"),
                    (
                        resources["provider_ownership_root"],
                        provider_roots,
                        "provider ownership root",
                    ),
                    (
                        resources["callback_ownership_root"],
                        callback_roots,
                        "callback ownership root",
                    ),
                    (resources["receipt"], receipt_paths, "control receipt"),
                ):
                    if str(value) in seen:
                        raise KimiMatchedControlScheduleError(
                            f"duplicate {label} in matched-control schedule"
                        )
                    seen.add(str(value))
            comparable_contract = {
                "case_id": case_id,
                "suite_id": suite_id,
                "attack_plan_payload_sha256": base.get("plan_payload_sha256"),
                "match_contract_sha256": plan["canonical"][
                    "match_contract_sha256"
                ],
                "attack_stage_semantics_sha256": plan["canonical"][
                    "attack_stage_semantics_sha256"
                ],
                "stage_count": plan["stage_count"],
                "stage_order": plan["stage_order"],
                "trigger_stage_index": plan["trigger_stage_index"],
                "declared_invariants": plan["match_contract"]["invariants"],
                "allowed_stage_semantic_difference_paths": plan[
                    "allowed_stage_semantic_difference_paths"
                ],
            }
            raw_controls.append(
                {
                    "control_id": control_id,
                    "control_type": control_type,
                    "disposition": disposition,
                    "disposition_reasons": list(plan["disposition_reasons"]),
                    "control_plan_payload_sha256": plan[
                        "control_plan_payload_sha256"
                    ],
                    "trial_run_id": trial_run_id,
                    "intervention_timing": plan["intervention_timing"],
                    "intervention_before_stage_indices": list(
                        plan["intervention_before_stage_indices"]
                    ),
                    "declared_session_carrier_intervention": plan[
                        "declared_session_carrier_intervention"
                    ],
                    "workspace_session_emulation_forbidden": (
                        plan["declared_session_carrier_intervention"] is not None
                    ),
                    "comparable_runtime_contract_sha256": _canonical_sha256(
                        comparable_contract
                    ),
                    "required_production_symbols": {
                        "materializer": (
                            "infra.cross_harness.adapters.kimi.control_trials."
                            "materialize_control_trial"
                        ),
                        "boundary": (
                            "infra.cross_harness.adapters.kimi.control_trials."
                            "KimiMatchedControlBoundary"
                        ),
                    },
                    "resources": resources,
                    "receipt_required": disposition == "MATERIALIZABLE",
                    "scoring_status": "NOT_PRODUCED",
                }
            )

        if materializable_count == len(CONTROL_TYPES):
            case_status = "ALL_FOUR_PLANNED"
            if base.get("disposition") != "READY":
                raise KimiMatchedControlScheduleError(
                    "four controls were materializable for a blocked attack plan"
                )
        elif materializable_count == 2:
            case_status = "INCOMPLETE_CONTROL_SET"
            if base.get("disposition") != "READY":
                raise KimiMatchedControlScheduleError(
                    "partial control set also lost its attack variant"
                )
        elif materializable_count == 0:
            case_status = "ATTACK_UNAVAILABLE"
            if base.get("disposition") == "READY":
                raise KimiMatchedControlScheduleError(
                    "attack-ready case unexpectedly has no controls"
                )
        else:
            raise KimiMatchedControlScheduleError(
                f"case has unsupported materializable-control count: {materializable_count}"
            )
        case_statuses[case_status] += 1

        controls: list[dict[str, Any]] = []
        for control in raw_controls:
            if control["disposition"] == "NOT_RUN":
                queue_status = "NOT_RUN"
            elif case_status == "ALL_FOUR_PLANNED":
                queue_status = "PLANNED_PENDING_ORCHESTRATOR"
            else:
                queue_status = "WITHHELD_INCOMPLETE_CONTROL_SET"
            queue_statuses[queue_status] += 1
            control["queue_status"] = queue_status
            control["receipt_required"] = (
                queue_status == "PLANNED_PENDING_ORCHESTRATOR"
            )
            controls.append(control)

        attack_resources = _attack_resource_plan(
            layout=attack_layout, case_id=case_id, attempt=attempt
        )
        attack_root = attack_resources["root"]
        if attack_root in attack_roots or attack_root in control_roots:
            raise KimiMatchedControlScheduleError(
                "attack/control writable resource roots collide"
            )
        attack_roots.add(attack_root)
        canonical = _mapping(base.get("canonical"), "base canonical record")
        case_records.append(
            {
                "case_id": case_id,
                "suite_id": suite_id,
                "canonical": {
                    "case_dir": str(case_dir),
                    "case_meta_sha256": canonical["case_meta_sha256"],
                    "tree_sha256": canonical["tree_sha256"],
                    "case_content_sha256": canonical["case_content_sha256"],
                },
                "attack_plan": {
                    "disposition": base["disposition"],
                    "disposition_reasons": list(base["disposition_reasons"]),
                    "plan_payload_sha256": base["plan_payload_sha256"],
                    "resources": attack_resources,
                },
                "schedule_status": case_status,
                "materializable_control_count": materializable_count,
                "gate_policy": "REQUIRE_EXACT_FOUR_COMPLETED_CONTROL_RECEIPTS",
                "attack_execution_allowed_at_schedule_time": False,
                "controls": controls,
            }
        )

    if len(case_records) != EXPECTED_CASE_COUNT:
        raise KimiMatchedControlScheduleError("schedule is not exactly 328 cases")
    if sum(control_dispositions.values()) != EXPECTED_CONTROL_TRIAL_COUNT:
        raise KimiMatchedControlScheduleError("schedule is not exactly 328 x 4 controls")
    if dict(case_statuses) != _EXPECTED_CASE_STATUS_COUNTS:
        raise KimiMatchedControlScheduleError(
            f"case schedule counts drifted: {dict(case_statuses)}"
        )
    if dict(control_dispositions) != _EXPECTED_CONTROL_DISPOSITIONS:
        raise KimiMatchedControlScheduleError(
            f"control dispositions drifted: {dict(control_dispositions)}"
        )
    if dict(queue_statuses) != _EXPECTED_QUEUE_COUNTS:
        raise KimiMatchedControlScheduleError(
            f"control queue counts drifted: {dict(queue_statuses)}"
        )

    document: dict[str, Any] = {
        "schema_name": SCHEDULE_SCHEMA_NAME,
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "harness_id": "kimi",
        "parent_run_id": checked_run_id,
        "attempt": attempt,
        "batch_root": str(batch),
        "inventory_content_sha256": _sha256(
            frozen.get("inventory_content_sha256"),
            "frozen inventory content SHA-256",
        ),
        "control_types": list(CONTROL_TYPES),
        "counts": {
            "case_count": len(case_records),
            "control_trial_count": EXPECTED_CONTROL_TRIAL_COUNT,
            "case_statuses": dict(case_statuses),
            "control_dispositions": dict(control_dispositions),
            "queue_statuses": dict(queue_statuses),
        },
        "execution_policy": {
            "production_attack_requires_completed_control_receipts": True,
            "required_control_receipt_count": len(CONTROL_TYPES),
            "required_control_receipt_types": list(CONTROL_TYPES),
            "control_receipt_written_only_after_runtime_close": True,
            "control_scoring_forbidden": True,
            "workspace_session_emulation_forbidden": True,
            "capability_hypothesis_is_evidence": False,
            "capability_upgrade_performed": False,
            "current_external_control_orchestrator_configured": False,
            "external_orchestrator_implemented": False,
            "runtime_bridge_validated": False,
            "cross_control_port_uniqueness_required": False,
            "port_lease_time_identity_available": False,
        },
        "production_components": _implementation_pins(),
        "formal_runtime_readiness_claimed": False,
        "scoring_status": "NOT_PRODUCED",
        "cases": case_records,
    }
    _assert_no_scoring(document, "matched-control schedule")
    document["schedule_payload_sha256"] = _payload_sha256(
        document, "schedule_payload_sha256"
    )
    return document


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    candidate = Path(path).absolute()
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise KimiMatchedControlScheduleError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise KimiMatchedControlScheduleError(f"{label} must be a regular file")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiMatchedControlScheduleError(f"{label} is malformed JSON") from exc
    if not isinstance(document, dict):
        raise KimiMatchedControlScheduleError(f"{label} must contain an object")
    return document


def _schedule_case(
    schedule: Mapping[str, Any], case_id: str
) -> Mapping[str, Any]:
    matches = [
        item
        for item in _array(schedule.get("cases"), "schedule cases")
        if isinstance(item, Mapping) and item.get("case_id") == case_id
    ]
    if len(matches) != 1:
        raise KimiMatchedControlScheduleError(
            "matched-control case identity is missing or duplicated"
        )
    return matches[0]


def _schedule_control(
    case: Mapping[str, Any], control_type: str
) -> Mapping[str, Any]:
    matches = [
        item
        for item in _array(case.get("controls"), "scheduled controls")
        if isinstance(item, Mapping) and item.get("control_type") == control_type
    ]
    if len(matches) != 1:
        raise KimiMatchedControlScheduleError(
            "scheduled control type is missing or duplicated"
        )
    return matches[0]


def validate_production_matched_control_schedule(
    document: Mapping[str, Any], *, repo_root: Path, verify_live: bool = True
) -> dict[str, Any]:
    """Validate a schedule and, by default, rebuild it from the live freeze.

    Rebuilding is intentional: changing a row and recomputing the document's
    self-hash must not be enough to authorize a control or attack launch.
    """

    schedule = dict(_mapping(document, "matched-control schedule"))
    expected_keys = {
        "schema_name",
        "schema_version",
        "harness_id",
        "parent_run_id",
        "attempt",
        "batch_root",
        "inventory_content_sha256",
        "control_types",
        "counts",
        "execution_policy",
        "production_components",
        "formal_runtime_readiness_claimed",
        "scoring_status",
        "cases",
        "schedule_payload_sha256",
    }
    if set(schedule) != expected_keys:
        raise KimiMatchedControlScheduleError(
            "matched-control schedule field set drifted"
        )
    if (
        schedule.get("schema_name") != SCHEDULE_SCHEMA_NAME
        or schedule.get("schema_version") != SCHEDULE_SCHEMA_VERSION
        or schedule.get("harness_id") != "kimi"
        or schedule.get("formal_runtime_readiness_claimed") is not False
        or schedule.get("scoring_status") != "NOT_PRODUCED"
    ):
        raise KimiMatchedControlScheduleError(
            "matched-control schedule identity/disposition is invalid"
        )
    validate_bench_run_id(
        _string(schedule.get("parent_run_id"), "schedule parent_run_id")
    )
    _integer(schedule.get("attempt"), "schedule attempt", minimum=1)
    _sha256(
        schedule.get("inventory_content_sha256"),
        "schedule inventory content SHA-256",
    )
    claimed = _sha256(
        schedule.get("schedule_payload_sha256"), "schedule payload SHA-256"
    )
    expected_payload = _payload_sha256(schedule, "schedule_payload_sha256")
    if not hmac.compare_digest(claimed, expected_payload):
        raise KimiMatchedControlScheduleError(
            "matched-control schedule self-hash mismatch"
        )
    _assert_no_scoring(schedule, "matched-control schedule")
    if schedule.get("control_types") != list(CONTROL_TYPES):
        raise KimiMatchedControlScheduleError("schedule control types drifted")
    counts = _mapping(schedule.get("counts"), "schedule counts")
    if counts != {
        "case_count": EXPECTED_CASE_COUNT,
        "control_trial_count": EXPECTED_CONTROL_TRIAL_COUNT,
        "case_statuses": _EXPECTED_CASE_STATUS_COUNTS,
        "control_dispositions": _EXPECTED_CONTROL_DISPOSITIONS,
        "queue_statuses": _EXPECTED_QUEUE_COUNTS,
    }:
        raise KimiMatchedControlScheduleError("matched-control counts drifted")
    cases = _array(schedule.get("cases"), "schedule cases")
    if len(cases) != EXPECTED_CASE_COUNT or len(
        {
            item.get("case_id")
            for item in cases
            if isinstance(item, Mapping) and isinstance(item.get("case_id"), str)
        }
    ) != EXPECTED_CASE_COUNT:
        raise KimiMatchedControlScheduleError(
            "matched-control schedule is not 328 unique cases"
        )
    batch = _external_batch_root(
        Path(repo_root), Path(_string(schedule.get("batch_root"), "schedule batch_root"))
    )
    if verify_live:
        rebuilt = build_production_matched_control_schedule(
            repo_root=Path(repo_root),
            batch_root=batch,
            run_id=str(schedule["parent_run_id"]),
            attempt=int(schedule["attempt"]),
        )
        if not hmac.compare_digest(_canonical_json(schedule), _canonical_json(rebuilt)):
            raise KimiMatchedControlScheduleError(
                "matched-control schedule differs from the live frozen inventory"
            )
    return json.loads(_canonical_json(schedule).decode("utf-8"))


def production_schedule_path(schedule: Mapping[str, Any]) -> Path:
    batch = Path(_string(schedule.get("batch_root"), "schedule batch_root")).absolute()
    run_id = _string(schedule.get("parent_run_id"), "schedule parent_run_id")
    return (
        batch
        / f"kimi-{run_id}"
        / f"matched-control-schedule-kimi-{run_id}.json"
    )


def write_production_matched_control_schedule(
    document: Mapping[str, Any], *, repo_root: Path, path: Path | None = None
) -> Path:
    schedule = validate_production_matched_control_schedule(
        document, repo_root=repo_root, verify_live=True
    )
    expected = production_schedule_path(schedule)
    destination = expected if path is None else Path(path).absolute()
    if destination != expected:
        raise KimiMatchedControlScheduleError(
            "matched-control schedule path must use its exact run-local identity"
        )
    batch = Path(str(schedule["batch_root"]))
    _assert_path_identity(
        destination,
        root=batch,
        run_id=str(schedule["parent_run_id"]),
        label="matched-control schedule path",
    )
    if destination.exists() or destination.is_symlink():
        raise KimiMatchedControlScheduleError(
            "matched-control schedule is immutable and already exists"
        )
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_symlink_free_descendant(
        destination.parent,
        trusted_root=batch,
        label="matched-control schedule parent",
    )
    content = (
        json.dumps(schedule, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o400)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return destination


def load_production_matched_control_schedule(
    path: Path, *, repo_root: Path, verify_live: bool = True
) -> dict[str, Any]:
    document = _read_json_object(Path(path), "matched-control schedule")
    validated = validate_production_matched_control_schedule(
        document, repo_root=repo_root, verify_live=verify_live
    )
    if Path(path).absolute() != production_schedule_path(validated):
        raise KimiMatchedControlScheduleError(
            "matched-control schedule file path does not match its identity"
        )
    _assert_symlink_free_descendant(
        Path(path),
        trusted_root=Path(str(validated["batch_root"])),
        label="matched-control schedule",
    )
    return validated


def _artifact_file(
    raw: Any, *, expected_path: Path, trusted_root: Path, label: str
) -> tuple[Path, str]:
    reference = _mapping(raw, label)
    if set(reference) != {"path", "sha256"}:
        raise KimiMatchedControlScheduleError(f"{label} field set drifted")
    path = Path(_string(reference.get("path"), f"{label} path")).absolute()
    expected = Path(expected_path).absolute()
    if path != expected:
        raise KimiMatchedControlScheduleError(f"{label} path drifted from schedule")
    document_hash = _sha256(reference.get("sha256"), f"{label} SHA-256")
    _assert_symlink_free_descendant(
        path, trusted_root=trusted_root, label=label
    )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise KimiMatchedControlScheduleError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise KimiMatchedControlScheduleError(f"{label} must be a regular file")
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, document_hash):
        raise KimiMatchedControlScheduleError(f"{label} file hash drifted")
    return path, actual


def _artifact_tree(
    raw: Any, *, expected_path: Path, trusted_root: Path, label: str
) -> tuple[Path, str]:
    reference = _mapping(raw, label)
    if set(reference) != {"path", "tree_sha256"}:
        raise KimiMatchedControlScheduleError(f"{label} field set drifted")
    path = Path(_string(reference.get("path"), f"{label} path")).absolute()
    expected = Path(expected_path).absolute()
    claimed = _sha256(reference.get("tree_sha256"), f"{label} tree SHA-256")
    if path != expected:
        raise KimiMatchedControlScheduleError(f"{label} path is invalid")
    _assert_symlink_free_descendant(
        path, trusted_root=trusted_root, label=label
    )
    if path.is_symlink() or not path.is_dir():
        raise KimiMatchedControlScheduleError(f"{label} path is invalid")
    actual = tree_sha256(path)
    if not hmac.compare_digest(actual, claimed):
        raise KimiMatchedControlScheduleError(f"{label} tree hash drifted")
    return path, actual


def _validate_self_hash(
    document: Mapping[str, Any], *, field: str, label: str
) -> str:
    claimed = _sha256(document.get(field), f"{label} self-hash")
    expected = _payload_sha256(document, field)
    if not hmac.compare_digest(claimed, expected):
        raise KimiMatchedControlScheduleError(f"{label} self-hash mismatch")
    return claimed


def _validate_provider_attestations(
    *,
    launcher_path: Path,
    audit_path: Path,
    resources: Mapping[str, Any],
    trial_run_id: str,
    case_id: str,
    control_id: str,
) -> tuple[int, str]:
    launcher = _read_json_object(launcher_path, "provider launcher attestation")
    audit = _read_json_object(audit_path, "provider audit attestation")
    launcher_keys = {
        "schema_name",
        "schema_version",
        "harness_id",
        "run_id",
        "broker_kind",
        "socket_path",
        "socket_identity",
        "process",
        "implementation",
        "credential_boundary",
        "nonce_boundary",
        "attestation_payload_sha256",
    }
    audit_keys = {
        "schema_name",
        "schema_version",
        "harness_id",
        "run_id",
        "case_id",
        "trial_id",
        "pid",
        "process_start_time",
        "process_executable_path",
        "process_executable_sha256",
        "process_cmdline_sha256",
        "implementation_path",
        "implementation_sha256",
        "socket_path",
        "socket_device",
        "socket_inode",
        "socket_uid",
        "socket_gid",
        "socket_mode",
        "root_mode",
        "credential_transport",
        "credential_location",
        "upstream",
        "nonce",
        "attestation_payload_sha256",
    }
    if set(launcher) != launcher_keys or set(audit) != audit_keys:
        raise KimiMatchedControlScheduleError(
            "provider attestation field set drifted"
        )
    if (
        launcher.get("schema_name") != BROKER_ATTESTATION_SCHEMA_NAME
        or launcher.get("schema_version") != BROKER_ATTESTATION_SCHEMA_VERSION
        or audit.get("schema_name") != AUDIT_ATTESTATION_SCHEMA_NAME
        or audit.get("schema_version") != AUDIT_ATTESTATION_SCHEMA_VERSION
        or launcher.get("harness_id") != "kimi"
        or audit.get("harness_id") != "kimi"
        or launcher.get("run_id") != trial_run_id
        or audit.get("run_id") != trial_run_id
        or audit.get("case_id") != case_id
        or audit.get("trial_id") != control_id
        or launcher.get("socket_path") != resources.get("provider_socket")
        or audit.get("socket_path") != resources.get("provider_socket")
    ):
        raise KimiMatchedControlScheduleError("provider attestation identity drifted")
    _validate_self_hash(
        launcher, field="attestation_payload_sha256", label="provider launcher attestation"
    )
    _validate_self_hash(
        audit, field="attestation_payload_sha256", label="provider audit attestation"
    )
    process = _mapping(launcher.get("process"), "provider process")
    pid = _integer(process.get("pid"), "provider pid", minimum=2)
    start_time = _string(process.get("start_time"), "provider start_time")
    if audit.get("pid") != pid or str(audit.get("process_start_time")) != start_time:
        raise KimiMatchedControlScheduleError(
            "provider launcher/audit process identity drifted"
        )
    return pid, start_time


def _validate_callback_attestation(
    *,
    path: Path,
    resources: Mapping[str, Any],
    trial_run_id: str,
    case_id: str,
    control_id: str,
) -> tuple[int, str]:
    document = _read_json_object(path, "callback attestation")
    expected_keys = {
        "schema_name",
        "schema_version",
        "harness_id",
        "run_id",
        "case_id",
        "trial_id",
        "process",
        "implementation",
        "socket",
        "evidence",
        "nonce",
        "attestation_payload_sha256",
    }
    if set(document) != expected_keys:
        raise KimiMatchedControlScheduleError(
            "callback attestation field set drifted"
        )
    socket_document = _mapping(document.get("socket"), "callback socket")
    if (
        document.get("schema_name") != CALLBACK_ATTESTATION_SCHEMA_NAME
        or document.get("schema_version") != CALLBACK_ATTESTATION_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("run_id") != trial_run_id
        or document.get("case_id") != case_id
        or document.get("trial_id") != control_id
        or socket_document.get("path") != resources.get("callback_socket")
    ):
        raise KimiMatchedControlScheduleError("callback attestation identity drifted")
    _validate_self_hash(
        document, field="attestation_payload_sha256", label="callback attestation"
    )
    process = _mapping(document.get("process"), "callback process")
    return (
        _integer(process.get("pid"), "callback pid", minimum=2),
        _string(process.get("start_time"), "callback start_time"),
    )


def _validate_launcher_attestation(
    *, path: Path, trial_run_id: str, control_root: Path
) -> None:
    document = _read_json_object(path, "isolated launcher attestation")
    if set(document) != {
        "schema_name",
        "schema_version",
        "harness_id",
        "run_id",
        "run_root",
        "launcher_id",
        "isolation",
        "credential_broker",
        "evidence",
        "attestation_payload_sha256",
    }:
        raise KimiMatchedControlScheduleError(
            "isolated launcher attestation field set drifted"
        )
    isolation = _mapping(document.get("isolation"), "launcher isolation")
    broker = _mapping(document.get("credential_broker"), "launcher broker")
    if (
        document.get("schema_name") != ATTESTATION_SCHEMA_NAME
        or document.get("schema_version") != ATTESTATION_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("run_id") != trial_run_id
        or Path(str(document.get("run_root"))).absolute() != control_root.absolute()
        or isolation.get("enforced") is not True
        or isolation.get("host_user_state_mounted") is not False
        or isolation.get("other_harness_state_mounted") is not False
        or isolation.get("network_egress") != "run_local_broker_only"
        or broker.get("run_id") != trial_run_id
        or broker.get("run_local") is not True
        or broker.get("verified") is not True
        or broker.get("external_credentials_in_kimi_env") is not False
        or broker.get("external_credentials_in_tool_child_env") is not False
        or broker.get("external_credentials_persisted") is not False
    ):
        raise KimiMatchedControlScheduleError(
            "isolated launcher did not prove the required boundary"
        )
    _validate_self_hash(
        document, field="attestation_payload_sha256", label="isolated launcher"
    )
    evidence = _array(document.get("evidence"), "launcher evidence")
    kinds: set[str] = set()
    for index, item in enumerate(evidence):
        record = _mapping(item, f"launcher evidence {index}")
        if set(record) != {"kind", "path", "sha256"}:
            raise KimiMatchedControlScheduleError(
                "launcher evidence field set drifted"
            )
        kind = _string(record.get("kind"), "launcher evidence kind")
        evidence_path = Path(_string(record.get("path"), "launcher evidence path")).absolute()
        try:
            evidence_path.relative_to(control_root.absolute())
        except ValueError as exc:
            raise KimiMatchedControlScheduleError(
                "launcher evidence escapes the control root"
            ) from exc
        _artifact_file(
            {"path": str(evidence_path), "sha256": record.get("sha256")},
            expected_path=evidence_path,
            trusted_root=control_root,
            label=f"launcher {kind} evidence",
        )
        kinds.add(kind)
    if not {"os_isolation", "credential_broker"}.issubset(kinds):
        raise KimiMatchedControlScheduleError("launcher evidence is incomplete")


def _validate_callback_chain(
    *,
    evidence_path: Path,
    manifest_path: Path,
    trial_run_id: str,
    case_id: str,
    control_id: str,
    expected_stage_count: int,
) -> None:
    manifest = _read_json_object(manifest_path, "callback evidence manifest")
    if (
        manifest.get("schema_name") != "safety_bench_kimi_callback_evidence_manifest"
        or manifest.get("schema_version") != 1
        or manifest.get("harness_id") != "kimi"
        or manifest.get("run_id") != trial_run_id
        or manifest.get("case_id") != case_id
        or manifest.get("trial_id") != control_id
        or Path(str(manifest.get("evidence_path"))).absolute() != evidence_path.absolute()
        or manifest.get("evidence_sha256") != sha256_file(evidence_path)
    ):
        raise KimiMatchedControlScheduleError("callback manifest identity drifted")
    _validate_self_hash(
        manifest, field="manifest_payload_sha256", label="callback manifest"
    )
    try:
        raw_lines = evidence_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise KimiMatchedControlScheduleError("callback evidence is unreadable") from exc
    if manifest.get("line_count") != len(raw_lines):
        raise KimiMatchedControlScheduleError("callback evidence line count drifted")
    prior: str | None = None
    for index, line in enumerate(raw_lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise KimiMatchedControlScheduleError(
                "callback evidence contains malformed JSONL"
            ) from exc
        if (
            not isinstance(record, Mapping)
            or record.get("schema_name") != "safety_bench_kimi_callback_evidence"
            or record.get("harness_id") != "kimi"
            or record.get("run_id") != trial_run_id
            or record.get("case_id") != case_id
            or record.get("trial_id") != control_id
            or record.get("sequence") != index
            or record.get("previous_record_sha256") != prior
        ):
            raise KimiMatchedControlScheduleError("callback evidence chain drifted")
        prior = _validate_self_hash(
            record, field="record_sha256", label="callback evidence record"
        )
    if manifest.get("hash_chain_head_sha256") != prior:
        raise KimiMatchedControlScheduleError("callback chain head drifted")
    completed = _array(
        manifest.get("completed_stage_connections"),
        "callback completed stage connections",
    )
    indices = sorted(
        item.get("stage_index")
        for item in completed
        if isinstance(item, Mapping) and item.get("outcome") == "completed"
    )
    if indices != list(range(expected_stage_count)) or len(completed) != expected_stage_count:
        raise KimiMatchedControlScheduleError(
            "callback manifest does not exactly cover completed stages"
        )


def _validate_materialization_and_boundary(
    *,
    receipt: Mapping[str, Any],
    case: Mapping[str, Any],
    control: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    resources = _mapping(control.get("resources"), "scheduled control resources")
    control_root = Path(str(resources["root"])).absolute()
    materialization = _mapping(
        receipt.get("materialization"), "receipt materialization"
    )
    if set(materialization) != {
        "control_plan",
        "initial_manifest",
        "final_manifest",
        "materialized_case",
        "canonical_case",
    }:
        raise KimiMatchedControlScheduleError(
            "receipt materialization field set drifted"
        )
    plan_path, _ = _artifact_file(
        materialization.get("control_plan"),
        expected_path=Path(str(resources["control_plan"])),
        trusted_root=control_root,
        label="control plan",
    )
    try:
        plan = load_control_trial_plan(plan_path)
    except Exception as exc:
        raise KimiMatchedControlScheduleError("control plan validation failed") from exc
    if (
        plan.get("disposition") != "MATERIALIZABLE"
        or plan.get("control_id") != control.get("control_id")
        or plan.get("control_type") != control.get("control_type")
        or plan.get("trial_run_id") != control.get("trial_run_id")
        or plan.get("case_id") != case.get("case_id")
        or plan.get("suite_id") != case.get("suite_id")
        or plan.get("control_plan_payload_sha256")
        != control.get("control_plan_payload_sha256")
    ):
        raise KimiMatchedControlScheduleError("control plan/schedule identity drifted")

    initial_path, initial_file_sha = _artifact_file(
        materialization.get("initial_manifest"),
        expected_path=Path(str(resources["initial_bench_manifest"])),
        trusted_root=control_root,
        label="initial materialization manifest",
    )
    final_path, final_file_sha = _artifact_file(
        materialization.get("final_manifest"),
        expected_path=Path(str(resources["bench_manifest"])),
        trusted_root=control_root,
        label="final materialization manifest",
    )
    try:
        initial = load_bench_materialization_manifest(initial_path)
        final = load_bench_materialization_manifest(final_path)
    except Exception as exc:
        raise KimiMatchedControlScheduleError(
            "control materialization manifest validation failed"
        ) from exc
    for label, manifest in (("initial", initial), ("final", final)):
        extension = _mapping(
            manifest.get("control_trial"), f"{label} control manifest extension"
        )
        canonical = _mapping(manifest.get("canonical"), f"{label} canonical")
        materialized = _mapping(
            manifest.get("materialized"), f"{label} materialized"
        )
        if (
            manifest.get("disposition") != "READY"
            or manifest.get("run_id") != control.get("trial_run_id")
            or manifest.get("case_id") != case.get("case_id")
            or manifest.get("suite_id") != case.get("suite_id")
            or extension.get("control_id") != control.get("control_id")
            or extension.get("control_type") != control.get("control_type")
            or extension.get("control_plan_payload_sha256")
            != control.get("control_plan_payload_sha256")
            or extension.get("intervention_before_stage_indices")
            != control.get("intervention_before_stage_indices")
            or extension.get("single_variable_verified") is not True
            or extension.get("formal_runtime_readiness_claimed") is not False
            or extension.get("scoring_status") != "NOT_PRODUCED"
            or canonical.get("tree_sha256")
            != _mapping(case.get("canonical"), "scheduled canonical").get(
                "tree_sha256"
            )
            or Path(str(materialized.get("case_dir"))).absolute()
            != Path(str(resources["materialized_case"])).absolute()
        ):
            raise KimiMatchedControlScheduleError(
                f"{label} control manifest identity/provenance drifted"
            )
        _assert_no_scoring(manifest, f"{label} control manifest")

    canonical_root = Path(
        str(_mapping(case.get("canonical"), "scheduled canonical")["case_dir"])
    ).absolute()
    _artifact_tree(
        materialization.get("canonical_case"),
        expected_path=canonical_root,
        trusted_root=canonical_root,
        label="canonical case",
    )
    _, materialized_tree_sha = _artifact_tree(
        materialization.get("materialized_case"),
        expected_path=Path(str(resources["materialized_case"])),
        trusted_root=control_root,
        label="post-execution materialized case",
    )

    boundary = _mapping(
        receipt.get("boundary_finalization"), "receipt boundary finalization"
    )
    if set(boundary) != {
        "evidence",
        "applied_stage_indices",
        "finalized_after_last_stage",
    } or boundary.get("finalized_after_last_stage") is not True:
        raise KimiMatchedControlScheduleError(
            "boundary finalization field set/status drifted"
        )
    evidence_path, evidence_sha = _artifact_file(
        boundary.get("evidence"),
        expected_path=Path(str(resources["intervention_evidence"])),
        trusted_root=control_root,
        label="control intervention evidence",
    )
    evidence = _read_json_object(evidence_path, "control intervention evidence")
    expected_indices = list(control.get("intervention_before_stage_indices") or [])
    applied = _array(
        boundary.get("applied_stage_indices"), "boundary applied stage indices"
    )
    if (
        applied != expected_indices
        or evidence.get("schema_version") != 1
        or evidence.get("harness_id") != "kimi"
        or evidence.get("run_id") != control.get("trial_run_id")
        or evidence.get("control_id") != control.get("control_id")
        or evidence.get("control_type") != control.get("control_type")
        or evidence.get("stage_count") != plan.get("stage_count")
        or evidence.get("stage_names") != plan.get("stage_order")
        or evidence.get("intervention_before_stage_indices") != expected_indices
        or evidence.get("applied_before_stage_indices") != expected_indices
        or evidence.get("expected_intervention_count") != len(expected_indices)
        or evidence.get("applied_intervention_count") != len(expected_indices)
        or evidence.get("applied") is not True
        or evidence.get("non_engaged_is_valid_model_outcome") is not True
        or evidence.get("formal_runtime_readiness_claimed") is not False
        or evidence.get("scoring_status") != "NOT_PRODUCED"
    ):
        raise KimiMatchedControlScheduleError(
            "control boundary did not finalize its exact schedule"
        )
    _assert_no_scoring(evidence, "control intervention evidence")
    revisions = evidence.get("manifest_revisions", [])
    if not isinstance(revisions, list) or len(revisions) != len(expected_indices):
        raise KimiMatchedControlScheduleError(
            "control manifest revision count drifted"
        )
    previous_file_sha = initial_file_sha
    previous_payload_sha = initial.get("manifest_payload_sha256")
    for index, (stage_index, raw_revision) in enumerate(
        zip(expected_indices, revisions, strict=True)
    ):
        revision = _mapping(raw_revision, f"manifest revision {index}")
        stage_order = _array(plan.get("stage_order"), "control stage order")
        if (
            revision.get("before_stage_index") != stage_index
            or revision.get("before_stage_name") != stage_order[stage_index - 1]
            or Path(str(revision.get("manifest_path"))).absolute() != final_path
            or revision.get("before_file_sha256") != previous_file_sha
            or revision.get("before_payload_sha256") != previous_payload_sha
            or revision.get("reason") != "matched_control_intervention_before_stage"
        ):
            raise KimiMatchedControlScheduleError(
                "control manifest revision chain drifted"
            )
        previous_file_sha = _sha256(
            revision.get("after_file_sha256"), "revision after file SHA-256"
        )
        previous_payload_sha = _sha256(
            revision.get("after_payload_sha256"), "revision after payload SHA-256"
        )
    if (
        previous_file_sha != final_file_sha
        or previous_payload_sha != final.get("manifest_payload_sha256")
    ):
        raise KimiMatchedControlScheduleError(
            "control final manifest is not the revision-chain head"
        )
    return plan, final, {
        "evidence_sha256": evidence_sha,
        "materialized_tree_sha256": materialized_tree_sha,
    }


def _validate_runtime_evidence(
    *,
    receipt: Mapping[str, Any],
    case: Mapping[str, Any],
    control: Mapping[str, Any],
    stage_count: int,
) -> dict[str, Any]:
    resources = _mapping(control.get("resources"), "scheduled control resources")
    batch_root = Path(str(resources["batch_root"])).absolute()
    runtime = _mapping(receipt.get("runtime"), "receipt runtime")
    required_runtime_keys = {
        "launcher_attestation",
        "provider_launcher_attestation",
        "provider_audit_attestation",
        "provider_audit_log",
        "callback_attestation",
        "callback_evidence",
        "callback_manifest",
        "pid_record",
        "materialized_port_record",
        "port_lease_evidence",
        "close_evidence",
    }
    if set(runtime) != required_runtime_keys:
        raise KimiMatchedControlScheduleError("receipt runtime field set drifted")

    resolved: dict[str, Path] = {}
    for key in sorted(required_runtime_keys):
        expected_key = (
            "runtime_close_evidence" if key == "close_evidence" else key
        )
        if key == "pid_record":
            expected_key = "pid"
        path, _ = _artifact_file(
            runtime.get(key),
            expected_path=Path(str(resources[expected_key])),
            trusted_root=batch_root,
            label=key.replace("_", " "),
        )
        resolved[key] = path

    trial_run_id = str(control["trial_run_id"])
    case_id = str(case["case_id"])
    control_id = str(control["control_id"])
    provider_pid, provider_start = _validate_provider_attestations(
        launcher_path=resolved["provider_launcher_attestation"],
        audit_path=resolved["provider_audit_attestation"],
        resources=resources,
        trial_run_id=trial_run_id,
        case_id=case_id,
        control_id=control_id,
    )
    callback_pid, callback_start = _validate_callback_attestation(
        path=resolved["callback_attestation"],
        resources=resources,
        trial_run_id=trial_run_id,
        case_id=case_id,
        control_id=control_id,
    )
    if (callback_pid, callback_start) == (provider_pid, provider_start):
        raise KimiMatchedControlScheduleError(
            "provider and callback processes are not independent"
        )
    _validate_launcher_attestation(
        path=resolved["launcher_attestation"],
        trial_run_id=trial_run_id,
        control_root=Path(str(resources["root"])),
    )
    _validate_callback_chain(
        evidence_path=resolved["callback_evidence"],
        manifest_path=resolved["callback_manifest"],
        trial_run_id=trial_run_id,
        case_id=case_id,
        control_id=control_id,
        expected_stage_count=stage_count,
    )

    pid_record = _read_json_object(resolved["pid_record"], "control PID record")
    processes = _array(pid_record.get("processes"), "control PID processes")
    stage_pids: list[int] = []
    stage_process_identities: list[tuple[int, str]] = []
    if (
        set(pid_record)
        != {"schema_name", "schema_version", "harness_id", "run_id", "processes"}
        or pid_record.get("schema_name") != "safety_bench_kimi_pid_record"
        or pid_record.get("schema_version") != 1
        or pid_record.get("harness_id") != "kimi"
        or pid_record.get("run_id") != trial_run_id
        or len(processes) != stage_count
    ):
        raise KimiMatchedControlScheduleError("control PID record identity drifted")
    for item in processes:
        process = _mapping(item, "control PID process")
        if (
            set(process) != {"harness_id", "run_id", "pid", "role", "start_time"}
            or process.get("harness_id") != "kimi"
            or process.get("run_id") != trial_run_id
        ):
            raise KimiMatchedControlScheduleError("control PID ownership drifted")
        pid = _integer(process.get("pid"), "control stage PID", minimum=2)
        start_time = _string(process.get("start_time"), "control PID start_time")
        stage_pids.append(pid)
        stage_process_identities.append((pid, start_time))
        _string(process.get("role"), "control PID role")
    service_process_identities = {
        (provider_pid, provider_start),
        (callback_pid, callback_start),
    }
    if (
        len(set(stage_process_identities)) != len(stage_process_identities)
        or service_process_identities.intersection(stage_process_identities)
    ):
        raise KimiMatchedControlScheduleError("control process identities overlap")

    port = _read_json_object(
        resolved["materialized_port_record"], "materialized port record"
    )
    if (
        set(port) != {"harness_id", "run_id", "host", "port", "reservation"}
        or port.get("harness_id") != "kimi"
        or port.get("run_id") != trial_run_id
        or port.get("host") != "127.0.0.1"
    ):
        raise KimiMatchedControlScheduleError("materialized port record drifted")
    callback_port = _integer(port.get("port"), "materialized callback port", minimum=1024)
    if callback_port > 65535:
        raise KimiMatchedControlScheduleError("materialized callback port is unsafe")
    lease = _read_json_object(
        resolved["port_lease_evidence"], "port lease close evidence"
    )
    if (
        set(lease)
        != {
            "schema_name",
            "schema_version",
            "harness_id",
            "run_id",
            "case_id",
            "control_id",
            "host",
            "port",
            "lease_active_during_runtime",
            "released_after_runtime_close",
            "lease_payload_sha256",
        }
        or lease.get("schema_name")
        != "safety_bench_kimi_loopback_port_close_evidence"
        or lease.get("schema_version") != 1
        or lease.get("harness_id") != "kimi"
        or lease.get("run_id") != trial_run_id
        or lease.get("case_id") != case_id
        or lease.get("control_id") != control_id
        or lease.get("host") != "127.0.0.1"
        or lease.get("port") != callback_port
        or lease.get("lease_active_during_runtime") is not True
        or lease.get("released_after_runtime_close") is not True
    ):
        raise KimiMatchedControlScheduleError("port lease close evidence drifted")
    _validate_self_hash(lease, field="lease_payload_sha256", label="port lease evidence")

    close = _read_json_object(resolved["close_evidence"], "runtime close evidence")
    if (
        close.get("schema_name") != "safety_bench_kimi_runtime_close_evidence"
        or close.get("schema_version") != 1
        or close.get("harness_id") != "kimi"
        or close.get("run_id") != trial_run_id
        or close.get("case_id") != case_id
        or close.get("startup_failed") is not False
        or close.get("closed") is not True
        or close.get("errors") != []
        or close.get("credential_descriptor_open_in_parent") is not False
        or close.get("provider_broker_active_leases_before_close") != 0
        or close.get("callback_collector_active_leases_before_close") != 0
        or "precredential_capability_gate" in close
    ):
        raise KimiMatchedControlScheduleError(
            "runtime did not close its exact control resources successfully"
        )
    _validate_self_hash(
        close, field="close_payload_sha256", label="runtime close evidence"
    )
    provider_reference = _mapping(
        close.get("provider_broker_attestation"), "close provider attestation"
    )
    callback_reference = _mapping(
        close.get("callback_collector_attestation"), "close callback attestation"
    )
    if (
        provider_reference
        != {
            "path": str(resolved["provider_launcher_attestation"]),
            "sha256": sha256_file(resolved["provider_launcher_attestation"]),
            "pid": provider_pid,
            "start_time": provider_start,
        }
        or callback_reference
        != {
            "path": str(resolved["callback_attestation"]),
            "sha256": sha256_file(resolved["callback_attestation"]),
            "pid": callback_pid,
            "start_time": callback_start,
        }
    ):
        raise KimiMatchedControlScheduleError(
            "runtime close attestation cross-links drifted"
        )
    launcher_before = _mapping(
        close.get("launcher_before_close"), "launcher before close"
    )
    launcher_after = _mapping(close.get("launcher_after_close"), "launcher after close")
    if (
        launcher_before.get("spawned_stage_count") != stage_count
        or launcher_after.get("spawned_stage_count") != stage_count
        or launcher_after.get("active_process_count") != 0
        or launcher_after.get("active_processes") != []
        or launcher_after.get("closed") is not True
    ):
        raise KimiMatchedControlScheduleError("launcher close evidence drifted")
    callback_summary = _mapping(close.get("callback_manifest"), "close callback manifest")
    if (
        callback_summary.get("status") != "verified"
        or Path(str(callback_summary.get("path"))).absolute()
        != resolved["callback_manifest"]
        or callback_summary.get("sha256") != sha256_file(resolved["callback_manifest"])
        or callback_summary.get("spawned_stage_count") != stage_count
        or callback_summary.get("completed_stage_indices")
        != list(range(stage_count))
    ):
        raise KimiMatchedControlScheduleError(
            "runtime close callback coverage drifted"
        )
    for key, pid, start_time in (
        ("provider_broker_process", provider_pid, provider_start),
        ("callback_collector_process", callback_pid, callback_start),
    ):
        process_close = _mapping(close.get(key), key.replace("_", " "))
        if (
            process_close.get("pid") != pid
            or str(process_close.get("start_time")) != start_time
            or process_close.get("absent_or_pid_reused") is not True
        ):
            raise KimiMatchedControlScheduleError(
                "runtime service process closure was not proven"
            )
    _assert_no_scoring(close, "runtime close evidence")
    return {
        "provider_pid": provider_pid,
        "callback_pid": callback_pid,
        "stage_pids": stage_pids,
        "stage_process_identities": stage_process_identities,
        "callback_port": callback_port,
    }


def _owned_regular_evidence(
    *, path_value: Any, sha_value: Any, root: Path, label: str
) -> Path:
    path = Path(_string(path_value, f"{label} path")).absolute()
    try:
        path.relative_to(root.absolute())
    except ValueError as exc:
        raise KimiMatchedControlScheduleError(f"{label} escapes control root") from exc
    _artifact_file(
        {"path": str(path), "sha256": sha_value},
        expected_path=path,
        trusted_root=root,
        label=label,
    )
    return path


def _validate_execution_evidence(
    *,
    receipt: Mapping[str, Any],
    case: Mapping[str, Any],
    control: Mapping[str, Any],
    plan: Mapping[str, Any],
    final_manifest: Mapping[str, Any],
    boundary_summary: Mapping[str, Any],
    runtime_summary: Mapping[str, Any],
) -> None:
    resources = _mapping(control.get("resources"), "scheduled control resources")
    control_root = Path(str(resources["root"])).absolute()
    execution = _mapping(receipt.get("execution"), "receipt execution")
    if set(execution) != {"result", "event_ir"}:
        raise KimiMatchedControlScheduleError("receipt execution field set drifted")
    result_path, _ = _artifact_file(
        execution.get("result"),
        expected_path=Path(str(resources["result"])),
        trusted_root=control_root,
        label="control execution result",
    )
    event_ir_path, event_ir_sha = _artifact_file(
        execution.get("event_ir"),
        expected_path=Path(str(resources["trace"])),
        trusted_root=control_root,
        label="control Event IR",
    )
    result = _read_json_object(result_path, "control execution result")
    if set(result) != {
        "outcome",
        "return_code",
        "raw_stdout_path",
        "raw_wire_path",
        "event_ir_path",
        "failure_category",
        "retry_eligible",
        "metadata",
    } or (
        result.get("outcome") != "COMPLETED"
        or result.get("return_code") != 0
        or result.get("failure_category") is not None
        or result.get("retry_eligible") is not False
        or Path(str(result.get("event_ir_path"))).absolute() != event_ir_path
    ):
        raise KimiMatchedControlScheduleError(
            "control execution did not complete successfully"
        )
    _assert_no_scoring(result, "control execution result")
    metadata = _mapping(result.get("metadata"), "control execution metadata")
    trial_run_id = str(control["trial_run_id"])
    case_id = str(case["case_id"])
    final_manifest_path = Path(str(resources["bench_manifest"])).absolute()
    if (
        metadata.get("schema_name") != "safety_bench_kimi_execution_evidence"
        or metadata.get("schema_version") != 1
        or metadata.get("harness_id") != "kimi"
        or metadata.get("run_id") != trial_run_id
        or metadata.get("case_id") != case_id
        or Path(str(metadata.get("manifest_path"))).absolute()
        != final_manifest_path
        or metadata.get("manifest_sha256") != sha256_file(final_manifest_path)
        or metadata.get("event_ir_sha256") != event_ir_sha
    ):
        raise KimiMatchedControlScheduleError(
            "control execution metadata identity drifted"
        )
    launcher = _mapping(
        metadata.get("launcher_attestation"), "execution launcher attestation"
    )
    if (
        Path(str(launcher.get("path"))).absolute()
        != Path(str(resources["launcher_attestation"])).absolute()
        or launcher.get("sha256")
        != sha256_file(Path(str(resources["launcher_attestation"])))
    ):
        raise KimiMatchedControlScheduleError(
            "execution launcher attestation cross-link drifted"
        )
    matched = _mapping(
        metadata.get("matched_control_intervention"),
        "execution matched-control finalization",
    )
    if (
        Path(str(matched.get("path"))).absolute()
        != Path(str(resources["intervention_evidence"])).absolute()
        or matched.get("sha256") != boundary_summary.get("evidence_sha256")
        or matched.get("applied_before_stage_indices")
        != control.get("intervention_before_stage_indices")
    ):
        raise KimiMatchedControlScheduleError(
            "executor did not bind the finalized matched-control boundary"
        )
    stages = _array(metadata.get("stages"), "control execution stages")
    stage_order = _array(plan.get("stage_order"), "control stage order")
    if (
        metadata.get("fresh_os_process_count") != len(stage_order)
        or len(stages) != len(stage_order)
    ):
        raise KimiMatchedControlScheduleError(
            "control execution stage/process count drifted"
        )
    observed_pids: list[int] = []
    root = Path(str(resources["root"])).absolute()
    for index, raw_stage in enumerate(stages):
        stage = _mapping(raw_stage, f"control execution stage {index}")
        pid = _integer(stage.get("pid"), "control execution PID", minimum=2)
        if (
            stage.get("index") != index
            or stage.get("name") != stage_order[index]
            or stage.get("return_code") != 0
        ):
            raise KimiMatchedControlScheduleError(
                "control execution stage identity/outcome drifted"
            )
        observed_pids.append(pid)
        for path_key, hash_key in (
            ("stdout_path", "stdout_sha256"),
            ("stderr_path", "stderr_sha256"),
            ("main_wire_path", "main_wire_sha256"),
        ):
            _owned_regular_evidence(
                path_value=stage.get(path_key),
                sha_value=stage.get(hash_key),
                root=root,
                label=f"stage {index} {path_key}",
            )
        stage_result = Path(
            _string(stage.get("result_path"), f"stage {index} result path")
        ).absolute()
        try:
            stage_result.relative_to(root)
        except ValueError as exc:
            raise KimiMatchedControlScheduleError(
                "stage result escapes control root"
            ) from exc
        _assert_symlink_free_descendant(
            stage_result,
            trusted_root=root,
            label=f"stage {index} result",
        )
        if stage_result.is_symlink() or not stage_result.is_file():
            raise KimiMatchedControlScheduleError("stage result is unavailable")
        for wire_index, raw_wire in enumerate(
            _array(stage.get("wire_captures"), f"stage {index} wire captures")
        ):
            wire = _mapping(raw_wire, f"stage {index} wire capture {wire_index}")
            _owned_regular_evidence(
                path_value=wire.get("captured_path"),
                sha_value=wire.get("sha256"),
                root=root,
                label=f"stage {index} wire capture {wire_index}",
            )
    if observed_pids != runtime_summary.get("stage_pids"):
        raise KimiMatchedControlScheduleError(
            "execution PIDs drifted from the run-owned PID record"
        )
    # Sequential stages may observe OS PID reuse.  Freshness/independence is
    # established by the PID record's validated (pid, start_time) identities,
    # not by bare integer PID uniqueness in executor metadata.
    last = stages[-1]
    if (
        Path(str(result.get("raw_stdout_path"))).absolute()
        != Path(str(last.get("stdout_path"))).absolute()
        or Path(str(result.get("raw_wire_path"))).absolute()
        != Path(str(last.get("main_wire_path"))).absolute()
    ):
        raise KimiMatchedControlScheduleError(
            "execution result raw evidence pointers drifted"
        )
    if final_manifest.get("manifest_payload_sha256") is None:
        raise KimiMatchedControlScheduleError("final manifest lost its provenance hash")
    try:
        lines = event_ir_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise KimiMatchedControlScheduleError("control Event IR is unreadable") from exc
    if not lines:
        raise KimiMatchedControlScheduleError("completed control Event IR is empty")
    for line_number, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)
            validate_event_document(_mapping(event, f"Event IR line {line_number}"))
        except Exception as exc:
            raise KimiMatchedControlScheduleError(
                f"control Event IR line {line_number} is invalid"
            ) from exc


def validate_control_execution_receipt(
    path: Path,
    *,
    schedule: Mapping[str, Any],
    schedule_path: Path,
    _document: Mapping[str, Any] | None = None,
    _enforce_receipt_mtime: bool = True,
) -> dict[str, Any]:
    """Validate one immutable post-close, non-scored control receipt."""

    receipt_path = Path(path).absolute()
    schedule_batch_root = Path(
        _string(schedule.get("batch_root"), "schedule batch_root")
    ).absolute()
    _assert_symlink_free_descendant(
        Path(schedule_path),
        trusted_root=schedule_batch_root,
        label="receipt schedule",
    )
    if _document is None:
        _assert_symlink_free_descendant(
            receipt_path,
            trusted_root=schedule_batch_root,
            label="control execution receipt",
        )
    receipt = (
        _read_json_object(receipt_path, "control execution receipt")
        if _document is None
        else dict(_mapping(_document, "control execution receipt"))
    )
    if set(receipt) != {
        "schema_name",
        "schema_version",
        "harness_id",
        "schedule",
        "parent_run_id",
        "case_id",
        "suite_id",
        "control_id",
        "control_type",
        "trial_run_id",
        "control_plan_payload_sha256",
        "completion",
        "materialization",
        "boundary_finalization",
        "runtime",
        "execution",
        "scoring_status",
        "receipt_payload_sha256",
    }:
        raise KimiMatchedControlScheduleError(
            "control execution receipt field set drifted"
        )
    if (
        receipt.get("schema_name") != RECEIPT_SCHEMA_NAME
        or receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION
        or receipt.get("harness_id") != "kimi"
        or receipt.get("parent_run_id") != schedule.get("parent_run_id")
        or receipt.get("scoring_status") != "NOT_PRODUCED"
    ):
        raise KimiMatchedControlScheduleError("control receipt identity drifted")
    _validate_self_hash(
        receipt, field="receipt_payload_sha256", label="control receipt"
    )
    _assert_no_scoring(receipt, "control execution receipt")
    schedule_reference = _mapping(receipt.get("schedule"), "receipt schedule")
    if set(schedule_reference) != {"path", "file_sha256", "payload_sha256"} or (
        Path(str(schedule_reference.get("path"))).absolute()
        != Path(schedule_path).absolute()
        or schedule_reference.get("file_sha256") != sha256_file(Path(schedule_path))
        or schedule_reference.get("payload_sha256")
        != schedule.get("schedule_payload_sha256")
    ):
        raise KimiMatchedControlScheduleError("receipt schedule binding drifted")

    case_id = _string(receipt.get("case_id"), "receipt case_id")
    control_type = _string(receipt.get("control_type"), "receipt control_type")
    case = _schedule_case(schedule, case_id)
    control = _schedule_control(case, control_type)
    resources = _mapping(control.get("resources"), "scheduled control resources")
    if (
        case.get("schedule_status") != "ALL_FOUR_PLANNED"
        or control.get("disposition") != "MATERIALIZABLE"
        or control.get("queue_status") != "PLANNED_PENDING_ORCHESTRATOR"
        or receipt.get("suite_id") != case.get("suite_id")
        or receipt.get("control_id") != control.get("control_id")
        or receipt.get("trial_run_id") != control.get("trial_run_id")
        or receipt.get("control_plan_payload_sha256")
        != control.get("control_plan_payload_sha256")
        or receipt_path != Path(str(resources.get("receipt"))).absolute()
    ):
        raise KimiMatchedControlScheduleError(
            "receipt is not an exact queueable scheduled control"
        )
    completion = _mapping(receipt.get("completion"), "receipt completion")
    if completion != {
        "outcome": "COMPLETED",
        "return_code": 0,
        "failure_category": None,
        "retry_eligible": False,
        "runtime_closed_before_receipt": True,
    }:
        raise KimiMatchedControlScheduleError(
            "control receipt is not post-close COMPLETED evidence"
        )
    plan, final_manifest, boundary_summary = _validate_materialization_and_boundary(
        receipt=receipt, case=case, control=control
    )
    runtime_summary = _validate_runtime_evidence(
        receipt=receipt,
        case=case,
        control=control,
        stage_count=int(plan["stage_count"]),
    )
    _validate_execution_evidence(
        receipt=receipt,
        case=case,
        control=control,
        plan=plan,
        final_manifest=final_manifest,
        boundary_summary=boundary_summary,
        runtime_summary=runtime_summary,
    )
    close_path = Path(
        str(_mapping(receipt["runtime"], "receipt runtime")["close_evidence"]["path"])
    )
    if _enforce_receipt_mtime and (
        receipt_path.stat().st_mtime_ns < close_path.stat().st_mtime_ns
    ):
        raise KimiMatchedControlScheduleError(
            "control receipt predates immutable runtime-close evidence"
        )
    return json.loads(_canonical_json(receipt).decode("utf-8"))


def write_control_execution_receipt(
    document: Mapping[str, Any],
    *,
    schedule: Mapping[str, Any],
    schedule_path: Path,
) -> Path:
    """Exclusively persist one already-complete receipt after full validation."""

    candidate = dict(_mapping(document, "control execution receipt"))
    case = _schedule_case(
        schedule, _string(candidate.get("case_id"), "receipt case_id")
    )
    control = _schedule_control(
        case, _string(candidate.get("control_type"), "receipt control_type")
    )
    resources = _mapping(control.get("resources"), "scheduled control resources")
    destination = Path(str(resources.get("receipt"))).absolute()
    if destination.exists() or destination.is_symlink():
        raise KimiMatchedControlScheduleError(
            "control receipt is immutable and already exists"
        )
    validate_control_execution_receipt(
        destination,
        schedule=schedule,
        schedule_path=schedule_path,
        _document=candidate,
        _enforce_receipt_mtime=False,
    )
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_symlink_free_descendant(
        destination.parent,
        trusted_root=Path(str(schedule["batch_root"])),
        label="control receipt parent",
    )
    content = (
        json.dumps(candidate, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(destination, 0o400)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    validate_control_execution_receipt(
        destination, schedule=schedule, schedule_path=schedule_path
    )
    return destination


def load_control_execution_receipt(
    path: Path, *, schedule: Mapping[str, Any], schedule_path: Path
) -> dict[str, Any]:
    return validate_control_execution_receipt(
        path, schedule=schedule, schedule_path=schedule_path
    )


class ProductionMatchedControlGate:
    """Validate completed controls while keeping raw attack launch blocked.

    The receipt validator is not a runtime bridge.  Even exact-four receipts
    remain blocked until an external orchestrator and the concrete
    ``ControlTrialLayout`` bridge are implemented and independently validated.
    This module cannot emit a scored result, paper-result admission, analyzer
    release, capability upgrade, or raw attack authorization.
    """

    def __init__(self, *, schedule_path: Path, repo_root: Path) -> None:
        self.schedule_path = Path(schedule_path).absolute()
        self.schedule = load_production_matched_control_schedule(
            self.schedule_path, repo_root=repo_root, verify_live=True
        )

    def evaluate(
        self, *, case_id: str, receipt_paths: Sequence[Path] = ()
    ) -> MatchedControlGateDecision:
        case = _schedule_case(self.schedule, case_id)
        schedule_locator = (
            f"{self.schedule_path}#sha256={sha256_file(self.schedule_path)}"
        )
        status = str(case.get("schedule_status"))
        supplied = tuple(Path(path).absolute() for path in receipt_paths)
        if len(supplied) > len(CONTROL_TYPES):
            raise KimiMatchedControlScheduleError(
                "matched-control gate received extra receipts"
            )
        if status == "ATTACK_UNAVAILABLE":
            if supplied:
                raise KimiMatchedControlScheduleError(
                    "attack-unavailable case may not submit control receipts"
                )
            return MatchedControlGateDecision(
                status="BLOCKED_ATTACK_UNAVAILABLE",
                run_id=str(self.schedule["parent_run_id"]),
                case_id=case_id,
                attack_execution_allowed=False,
                receipt_count=0,
                required_receipt_count=len(CONTROL_TYPES),
                evidence=(schedule_locator,),
                reasons=(
                    "The Kimi attack variant is evidence-bound NOT_RUN; controls cannot substitute for it.",
                ),
            )
        if status == "INCOMPLETE_CONTROL_SET":
            if supplied:
                raise KimiMatchedControlScheduleError(
                    "incomplete native-session control set may not submit receipts"
                )
            return MatchedControlGateDecision(
                status="BLOCKED_INCOMPLETE_CONTROL_SET",
                run_id=str(self.schedule["parent_run_id"]),
                case_id=case_id,
                attack_execution_allowed=False,
                receipt_count=0,
                required_receipt_count=len(CONTROL_TYPES),
                evidence=(schedule_locator,),
                reasons=(
                    "Only two controls are materializable; native Kimi session intervention is unvalidated and workspace simulation is forbidden.",
                ),
            )
        if status != "ALL_FOUR_PLANNED":
            raise KimiMatchedControlScheduleError("unknown case schedule status")

        receipts: list[dict[str, Any]] = []
        receipt_locators: list[str] = []
        for path in supplied:
            validated = validate_control_execution_receipt(
                path,
                schedule=self.schedule,
                schedule_path=self.schedule_path,
            )
            receipts.append(validated)
            receipt_locators.append(f"{path}#sha256={sha256_file(path)}")
        observed_types = [str(receipt["control_type"]) for receipt in receipts]
        if len(set(observed_types)) != len(observed_types):
            raise KimiMatchedControlScheduleError(
                "matched-control gate received duplicate control types"
            )
        if len(receipts) < len(CONTROL_TYPES):
            return MatchedControlGateDecision(
                status="BLOCKED_PENDING_CONTROL_EXECUTION",
                run_id=str(self.schedule["parent_run_id"]),
                case_id=case_id,
                attack_execution_allowed=False,
                receipt_count=len(receipts),
                required_receipt_count=len(CONTROL_TYPES),
                evidence=tuple([schedule_locator, *receipt_locators]),
                reasons=(
                    "Attack launch remains blocked until four distinct immutable post-close COMPLETED receipts validate.",
                ),
            )
        if set(observed_types) != set(CONTROL_TYPES):
            raise KimiMatchedControlScheduleError(
                "matched-control receipt type set is not exact"
            )

        process_identities: list[tuple[int, str]] = []
        roots: list[str] = []
        for receipt in receipts:
            control = _schedule_control(case, str(receipt["control_type"]))
            resources = _mapping(control.get("resources"), "scheduled resources")
            roots.extend(
                str(resources[key])
                for key in (
                    "root",
                    "provider_ownership_root",
                    "callback_ownership_root",
                )
            )
            runtime = _mapping(receipt.get("runtime"), "receipt runtime")
            provider = _read_json_object(
                Path(str(_mapping(runtime["provider_audit_attestation"], "provider ref")["path"])),
                "provider audit attestation",
            )
            callback = _read_json_object(
                Path(str(_mapping(runtime["callback_attestation"], "callback ref")["path"])),
                "callback attestation",
            )
            pid_record = _read_json_object(
                Path(str(_mapping(runtime["pid_record"], "PID ref")["path"])),
                "PID record",
            )
            callback_process = _mapping(
                callback["process"], "callback process"
            )
            process_identities.append(
                (int(provider["pid"]), str(provider["process_start_time"]))
            )
            process_identities.append(
                (int(callback_process["pid"]), str(callback_process["start_time"]))
            )
            process_identities.extend(
                (int(item["pid"]), str(item["start_time"]))
                for item in pid_record["processes"]
            )
        if (
            len(set(roots)) != len(roots)
            or len(set(process_identities)) != len(process_identities)
        ):
            raise KimiMatchedControlScheduleError(
                "four-control resource identities are not independent"
            )
        return MatchedControlGateDecision(
            status="BLOCKED_ORCHESTRATOR_UNVALIDATED",
            run_id=str(self.schedule["parent_run_id"]),
            case_id=case_id,
            attack_execution_allowed=False,
            receipt_count=len(receipts),
            required_receipt_count=len(CONTROL_TYPES),
            evidence=tuple([schedule_locator, *receipt_locators]),
            reasons=(
                "Four distinct controls have valid independent post-close evidence, but the external orchestrator is not implemented and the runtime bridge is unvalidated.",
                "Sequential loopback port reuse is not compared across controls because the receipt schema has no lease/time identity; receipt-local lease validation remains required.",
                "Raw attack execution, formal conformance, analyzer release, paper admission, scoring, and capability upgrade remain forbidden.",
            ),
        )


__all__ = [
    "CASE_SCHEDULE_STATUSES",
    "CONTROL_QUEUE_STATUSES",
    "GATE_DECISION_SCHEMA_NAME",
    "GATE_DECISION_SCHEMA_VERSION",
    "GATE_STATUSES",
    "KimiMatchedControlScheduleError",
    "MatchedControlGateDecision",
    "ProductionMatchedControlGate",
    "RECEIPT_SCHEMA_NAME",
    "RECEIPT_SCHEMA_VERSION",
    "SCHEDULE_SCHEMA_NAME",
    "SCHEDULE_SCHEMA_VERSION",
    "build_production_matched_control_schedule",
    "load_control_execution_receipt",
    "load_production_matched_control_schedule",
    "production_schedule_path",
    "validate_control_execution_receipt",
    "validate_production_matched_control_schedule",
    "write_control_execution_receipt",
    "write_production_matched_control_schedule",
]
