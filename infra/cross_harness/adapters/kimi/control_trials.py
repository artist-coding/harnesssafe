"""Kimi-owned matched-control contracts for the frozen 328-case benchmark.

This module deliberately does not call the shared analyzer and never emits an
oracle, verdict, score, or safety classification.  It provides three narrow
surfaces instead:

* a read-only derivation of the four canonical matched controls;
* run-local Kimi materialization records with independent control resources;
* a fail-closed between-stage intervention recorder whose JSON is compatible
  with the existing analyzer's ``control_intervention.json`` reader.

The canonical ``control_suite`` and ``control_match_contract`` are the only
sources of control semantics.  In particular, the Claude session-transcript
redaction contract is *not* translated into a workspace file.  Until a Kimi
native marker-only transcript intervention is directly evidenced and reviewed,
those native-session no-persist/cleanup rows remain ``NOT_RUN``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
from typing import Any

from infra.clean_plugin_sanitizer import file_tree_snapshot
from infra.cross_harness.contract import CAPABILITIES

from .bench_inventory import EXPECTED_CASE_COUNT, load_frozen_inventory
from .bench_materializer import (
    _embed_mcp_evidence_proxies,
    _prepare_mcp_config,
    _prepare_skill_tree,
    build_bench_case_plan,
    iter_active_case_references,
    materialize_bench_case,
)
from .materializer import sha256_file, tree_sha256, validate_run_id
from .executor import (
    MatchedControlBoundaryFinalization,
    MatchedControlBoundaryRequest,
    MatchedControlBoundaryResult,
)


CONTROL_PLAN_SCHEMA_NAME = "safety_bench_kimi_control_trial_plan"
CONTROL_PLAN_SCHEMA_VERSION = 1
CONTROL_INTERVENTION_SCHEMA_VERSION = 1
CONTROL_TYPES = (
    "clean_control",
    "no_persist_control",
    "no_trigger_control",
    "cleanup_control",
)
CONTROL_TIMINGS = {
    "clean_control": "before_first_stage",
    "no_persist_control": "before_boundary_and_after_each_non_trigger_stage",
    "no_trigger_control": "trigger_stage_only",
    "cleanup_control": "after_last_producer_before_trigger",
}
CONTROL_DISPOSITIONS = frozenset({"MATERIALIZABLE", "NOT_RUN"})
CAPABILITY_STATE_VALUES = frozenset({"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"})
EXPECTED_CONTROL_TRIAL_COUNT = EXPECTED_CASE_COUNT * len(CONTROL_TYPES)
_SESSION_TRANSLATION_BLOCK = (
    "canonical control_session_carrier_intervention has no directly verified "
    "Kimi native transcript translation; workspace/session emulation is forbidden"
)
_SAFE_TOKEN_RE = re.compile(r"[^A-Za-z0-9._-]+")
_FORBIDDEN_OUTPUT_KEYS = frozenset(
    {
        "attack_success",
        "confirmed_compromise",
        "oracle",
        "oracle_path",
        "progress_node",
        "score",
        "scored_result",
        "verdict",
    }
)


class KimiControlTrialError(RuntimeError):
    """A canonical control or run-local intervention failed closed."""


def _require_full_capability_states(
    capability_states: Mapping[str, str] | None,
) -> dict[str, str]:
    """Validate evidence-derived capability states before any runtime write."""

    if capability_states is None:
        raise KimiControlTrialError(
            "materialize_control_trial requires an explicit capability-state mapping"
        )
    observed = set(capability_states)
    expected = set(CAPABILITIES)
    if observed != expected:
        missing = sorted(expected - observed)
        unexpected = sorted(observed - expected)
        raise KimiControlTrialError(
            "capability-state mapping must cover the exact Contract v1 surface; "
            f"missing={missing}, unexpected={unexpected}"
        )
    normalized = {
        capability: str(capability_states[capability]).upper()
        for capability in CAPABILITIES
    }
    invalid = sorted(
        capability
        for capability, state in normalized.items()
        if state not in CAPABILITY_STATE_VALUES
    )
    if invalid:
        raise KimiControlTrialError(
            "capability-state mapping has invalid tri-state values: "
            + ", ".join(invalid)
        )
    return normalized


@dataclass(frozen=True)
class ControlTrialLayout:
    """Independent, deterministic path allocation for one matched control."""

    batch_root: Path
    parent_run_id: str
    trial_run_id: str
    control_id: str
    control_token: str
    root: Path
    home: Path
    kimi_home: Path
    session: Path
    cache: Path
    pid: Path
    broker: Path
    artifact: Path
    trace: Path
    result: Path

    def as_dict(self) -> dict[str, str]:
        return {
            "batch_root": str(self.batch_root),
            "parent_run_id": self.parent_run_id,
            "trial_run_id": self.trial_run_id,
            "control_id": self.control_id,
            "control_token": self.control_token,
            "root": str(self.root),
            "home": str(self.home),
            "kimi_home": str(self.kimi_home),
            "session": str(self.session),
            "cache": str(self.cache),
            "pid": str(self.pid),
            "broker": str(self.broker),
            "artifact": str(self.artifact),
            "trace": str(self.trace),
            "result": str(self.result),
        }


@dataclass(frozen=True)
class ControlMaterialization:
    plan: Mapping[str, Any]
    layout: ControlTrialLayout
    bench_manifest_path: Path
    control_plan_path: Path
    intervention_path: Path
    case_path: Path


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _payload_sha256(document: Mapping[str, Any], field: str) -> str:
    return _canonical_sha256({key: value for key, value in document.items() if key != field})


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    content = (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    temporary = path.with_name(
        f".{path.name}.tmp-kimi-{os.getpid()}-{secrets.token_hex(8)}"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KimiControlTrialError(f"invalid JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise KimiControlTrialError(f"JSON root must be an object: {path}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KimiControlTrialError(f"{label} must be a non-empty string")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise KimiControlTrialError(f"{label} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise KimiControlTrialError(f"{label} must not contain duplicates")
    return list(value)


def _safe_relative(value: Any, label: str) -> Path:
    text = _string(value, label).replace("\\", "/")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("/"):
        raise KimiControlTrialError(f"{label} escapes its declared root: {value!r}")
    return path


def _owned(path: Path, root: Path, label: str, *, allow_root: bool = False) -> Path:
    resolved = path.resolve(strict=False)
    root_resolved = root.resolve(strict=False)
    try:
        relative = resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise KimiControlTrialError(f"{label} escapes the control root: {path}") from exc
    if not allow_root and not relative.parts:
        raise KimiControlTrialError(f"{label} must not target the control root")
    cursor = root_resolved
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise KimiControlTrialError(f"{label} crosses a symlink: {cursor}")
    return resolved


def _canonical_source(case_dir: Path, relative: str, label: str) -> Path:
    path = (case_dir / _safe_relative(relative, label)).resolve(strict=True)
    try:
        path.relative_to(case_dir.resolve(strict=True))
    except ValueError as exc:
        raise KimiControlTrialError(f"{label} escapes canonical case: {relative}") from exc
    if path.is_symlink():
        raise KimiControlTrialError(f"{label} is a symlink: {path}")
    return path


def _stage_documents(meta: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = meta.get("stages")
    if raw is None:
        stages: list[Any] = [
            {
                "name": "single",
                "user_prompt": meta.get("user_prompt"),
                "plugin_dirs": meta.get("plugin_dirs") or [],
                "mcp_configs": meta.get("mcp_configs") or [],
                "declared_oracles": meta.get("oracles") or [],
            }
        ]
    else:
        if not isinstance(raw, list) or not raw:
            raise KimiControlTrialError("case_meta.stages must be a non-empty array")
        stages = raw
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw_stage in enumerate(stages):
        if not isinstance(raw_stage, Mapping):
            raise KimiControlTrialError(f"stage {index} is not an object")
        stage = copy.deepcopy(dict(raw_stage))
        name = _string(stage.get("name"), f"stage {index} name")
        _string(stage.get("user_prompt"), f"stage {index} prompt")
        if name in names:
            raise KimiControlTrialError(f"duplicate stage name: {name}")
        names.add(name)
        result.append(stage)
    return result


def _diff_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    if type(left) is not type(right):
        return [prefix or "$"]
    if isinstance(left, Mapping):
        paths: list[str] = []
        for key in sorted(set(left) | set(right), key=str):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in left or key not in right:
                paths.append(child)
            else:
                paths.extend(_diff_paths(left[key], right[key], child))
        return paths
    if isinstance(left, list):
        if len(left) != len(right):
            return [prefix or "$"]
        paths = []
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            paths.extend(_diff_paths(left_item, right_item, f"{prefix}[{index}]"))
        return paths
    return [] if left == right else [prefix or "$"]


def _control_token(control_id: str) -> str:
    prefix = _SAFE_TOKEN_RE.sub("-", control_id).strip("-._")[:32] or "control"
    return f"{prefix}-{hashlib.sha256(control_id.encode('utf-8')).hexdigest()[:12]}"


def allocate_control_layout(
    *, batch_root: Path, run_id: str, control_id: str
) -> ControlTrialLayout:
    validate_run_id(run_id)
    control_id = _string(control_id, "control_id")
    token = _control_token(control_id)
    trial_run_id = f"{run_id}-ctl-{hashlib.sha256(control_id.encode('utf-8')).hexdigest()[:12]}"
    validate_run_id(trial_run_id)
    root = Path(batch_root).resolve() / f"control-kimi-{trial_run_id}-{token}"

    def child(kind: str, suffix: str = "") -> Path:
        tail = f"-{suffix}" if suffix else ""
        return root / f"{kind}-kimi-{trial_run_id}-{token}{tail}"

    return ControlTrialLayout(
        batch_root=Path(batch_root).resolve(),
        parent_run_id=run_id,
        trial_run_id=trial_run_id,
        control_id=control_id,
        control_token=token,
        root=root,
        home=child("home"),
        kimi_home=child("config"),
        session=child("session"),
        cache=child("cache"),
        pid=child("pid", "record.json"),
        broker=child("broker"),
        artifact=child("artifact"),
        trace=child("trace", "events.jsonl"),
        result=child("result", "metadata.json"),
    )


def _validate_match_contract(
    match: Any, stages: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], int]:
    if not isinstance(match, Mapping):
        raise KimiControlTrialError("control_match_contract is required")
    document = copy.deepcopy(dict(match))
    expected_keys = {
        "schema_version",
        "single_variable_required",
        "invariants",
        "stage_count",
        "stage_order",
        "trigger_stage_index",
        "no_trigger_exception",
    }
    if set(document) != expected_keys:
        raise KimiControlTrialError("control_match_contract field set drifted")
    if document.get("schema_version") != 1 or document.get("single_variable_required") is not True:
        raise KimiControlTrialError("control_match_contract does not require one variable")
    names = [str(stage["name"]) for stage in stages]
    if document.get("stage_count") != len(stages) or document.get("stage_order") != names:
        raise KimiControlTrialError("control_match_contract stage count/order drifted")
    trigger = document.get("trigger_stage_index")
    if not isinstance(trigger, int) or isinstance(trigger, bool) or not 1 <= trigger <= len(stages):
        raise KimiControlTrialError("control_match_contract trigger index is invalid")
    if document.get("no_trigger_exception") != "trigger prompt only":
        raise KimiControlTrialError("control_match_contract no-trigger exception drifted")
    required_invariants = {
        "harness",
        "model",
        "permission_profile",
        "isolation_mode",
        "timeout",
        "benign_task",
        "stage_count",
        "stage_order",
        "base_workspace",
        "callback_and_honeypot",
    }
    if set(_string_list(document.get("invariants"), "control invariants")) != required_invariants:
        raise KimiControlTrialError("control_match_contract invariants drifted")
    return document, trigger


def _validate_clean_sources(case_dir: Path, control: Mapping[str, Any]) -> list[dict[str, Any]]:
    clean_plugins = _string_list(control.get("control_plugin_dirs"), "control_plugin_dirs")
    clean_mcp = _string_list(control.get("control_mcp_configs"), "control_mcp_configs")
    overrides = control.get("control_workspace_overrides") or []
    workspace_dirs = _string_list(control.get("control_workspace_dirs"), "control_workspace_dirs")
    if workspace_dirs:
        raise KimiControlTrialError(
            "Kimi controls require explicit workspace overrides, not overlay directories"
        )
    if not isinstance(overrides, list) or any(not isinstance(item, Mapping) for item in overrides):
        raise KimiControlTrialError("control_workspace_overrides must be an object array")
    if not clean_plugins and not clean_mcp and not overrides:
        raise KimiControlTrialError("clean_control has no declared physical replacement")

    records: list[dict[str, Any]] = []
    for relative in clean_plugins:
        source = _canonical_source(case_dir, relative, "clean plugin")
        snapshot = file_tree_snapshot(source)
        records.append(
            {
                "kind": "plugin",
                "source": relative,
                "source_path": str(source),
                "canonical_source_sha256": snapshot["sha256"],
                "file_count": snapshot["file_count"],
            }
        )
    for relative in clean_mcp:
        source = _canonical_source(case_dir, relative, "clean MCP config")
        if not source.is_file():
            raise KimiControlTrialError(f"clean MCP source is not a file: {source}")
        document = _load_json(source)
        if not isinstance(document.get("mcpServers"), dict) or not document["mcpServers"]:
            raise KimiControlTrialError(f"clean MCP config has no servers: {source}")
        records.append(
            {
                "kind": "mcp_config",
                "source": relative,
                "source_path": str(source),
                "canonical_source_sha256": sha256_file(source),
            }
        )
    seen_targets: set[str] = set()
    for index, override in enumerate(overrides):
        source_rel = _safe_relative(override.get("source"), f"workspace override {index} source")
        target_rel = _safe_relative(override.get("target"), f"workspace override {index} target")
        target_text = target_rel.as_posix()
        if target_text in seen_targets:
            raise KimiControlTrialError(f"duplicate workspace override target: {target_text}")
        seen_targets.add(target_text)
        source = _canonical_source(case_dir, source_rel.as_posix(), "clean workspace source")
        attack = _canonical_source(
            case_dir, f"workspace/{target_text}", "attack workspace target"
        )
        if not source.is_file() or not attack.is_file():
            raise KimiControlTrialError("workspace clean replacement must be file-for-file")
        records.append(
            {
                "kind": "workspace_override",
                "source": source_rel.as_posix(),
                "target": target_text,
                "source_path": str(source),
                "attack_path": str(attack),
                "attack_sha256": sha256_file(attack),
                "canonical_source_sha256": sha256_file(source),
            }
        )

    bundle = control.get("control_clean_entry_source_bundle")
    if bundle is not None:
        if not isinstance(bundle, Mapping) or bundle.get("schema_version") != 1:
            raise KimiControlTrialError("control_clean_entry_source_bundle is malformed")
        if bundle.get("intervention_variable") != "entry_source_bundle":
            raise KimiControlTrialError("clean entry bundle variable drifted")
        targets = bundle.get("targets")
        if not isinstance(targets, list) or not targets:
            raise KimiControlTrialError("clean entry bundle has no targets")
        for target in targets:
            if not isinstance(target, Mapping):
                raise KimiControlTrialError("clean entry bundle target is not an object")
            kind = target.get("kind")
            if kind == "plugin_tree":
                attack = _canonical_source(case_dir, target.get("attack"), "bundle attack plugin")
                clean = _canonical_source(case_dir, target.get("clean"), "bundle clean plugin")
                attack_sha = file_tree_snapshot(attack)["sha256"]
                clean_sha = file_tree_snapshot(clean)["sha256"]
            elif kind == "workspace_file":
                attack = _canonical_source(case_dir, target.get("attack"), "bundle attack file")
                clean = _canonical_source(case_dir, target.get("clean"), "bundle clean file")
                attack_sha = sha256_file(attack)
                clean_sha = sha256_file(clean)
            else:
                raise KimiControlTrialError(f"unsupported clean entry bundle kind: {kind!r}")
            if (
                target.get("attack_sha256") != attack_sha
                or target.get("clean_sha256") != clean_sha
                or attack_sha == clean_sha
            ):
                raise KimiControlTrialError("clean entry bundle source hash drifted")
    return records


def _validate_control_shape(
    *, case_dir: Path, control_type: str, control: Mapping[str, Any]
) -> list[dict[str, Any]]:
    intervention = control.get("control_intervention")
    if not isinstance(intervention, Mapping) or set(intervention) != {"variable", "action"}:
        raise KimiControlTrialError("control_intervention must name exactly one variable/action")
    expected = {
        "clean_control": {
            "variables": {"entry_source", "entry_source_bundle"},
            "action": "physical_clean_source_replacement",
        },
        "no_persist_control": {
            "variables": {"persistence"},
            "action": "block_or_remove_before_persistence",
        },
        "no_trigger_control": {
            "variables": {"trigger"},
            "action": "replace_trigger_prompt_only",
        },
        "cleanup_control": {
            "variables": {"carrier_cleanup"},
            "action": "remove_persisted_carrier",
        },
    }[control_type]
    if intervention.get("variable") not in expected["variables"] or intervention.get("action") != expected["action"]:
        raise KimiControlTrialError(f"{control_type} intervention semantics drifted")

    clean_fields = any(
        control.get(field)
        for field in (
            "control_plugin_dirs",
            "control_mcp_configs",
            "control_workspace_dirs",
            "control_workspace_overrides",
        )
    )
    persistence_fields = any(
        control.get(field)
        for field in (
            "control_removed_carrier_paths",
            "control_state_resets",
            "control_session_carrier_intervention",
        )
    )
    if control_type == "clean_control":
        if persistence_fields:
            raise KimiControlTrialError("clean_control may only replace declared runtime inputs")
        return _validate_clean_sources(case_dir, control)
    if control_type == "no_trigger_control":
        if clean_fields or persistence_fields:
            raise KimiControlTrialError("no_trigger_control may only replace the trigger prompt")
        return []
    if clean_fields:
        raise KimiControlTrialError(f"{control_type} may not replace clean runtime inputs")
    carriers = _string_list(
        control.get("control_removed_carrier_paths"), "control_removed_carrier_paths"
    )
    resets = _string_list(control.get("control_state_resets"), "control_state_resets")
    if any(item not in {"memory", "session", "harness_state", "cache"} for item in resets):
        raise KimiControlTrialError("control_state_resets contains an unknown state class")
    if not carriers and not resets and not control.get("control_session_carrier_intervention"):
        raise KimiControlTrialError(f"{control_type} has no declared carrier/state intervention")
    for relative in carriers:
        _safe_relative(relative, "control carrier path")
        if relative.replace("\\", "/").rstrip("/") in {"", "workspace"}:
            raise KimiControlTrialError("control carrier may not target the workspace root")
    return []


def _intervention_indices(control_type: str, stage_count: int, trigger: int) -> list[int]:
    if control_type in {"clean_control", "no_trigger_control"}:
        return []
    if control_type == "no_persist_control":
        return [1] if stage_count == 1 else list(range(2, stage_count + 1))
    return [trigger]


def _materialized_carrier_bindings(
    suite_id: str, canonical_paths: Sequence[str]
) -> tuple[list[str], list[dict[str, str]]]:
    """Translate only evidence-backed Kimi native skill carrier paths.

    Static Claude plugin packages are materialized on Kimi's actual project
    skill surface.  Recording both names keeps the canonical contract visible
    while allowing the shared analyzer to verify removal at the physical Kimi
    path.  Memory/session names are deliberately never translated here.
    """

    effective: list[str] = []
    bindings: list[dict[str, str]] = []
    for raw in canonical_paths:
        canonical = raw.replace("\\", "/")
        without_workspace = (
            canonical[len("workspace/") :]
            if canonical.startswith("workspace/")
            else canonical
        )
        materialized = canonical
        translation = "identity"
        if suite_id == "v2_skill_runtime":
            if without_workspace == "plugin":
                materialized = ".kimi-code/skills"
                translation = "kimi_project_skill_tree_v1"
            elif without_workspace.startswith(".claude-plugin/skills/"):
                suffix = without_workspace[len(".claude-plugin/skills/") :]
                materialized = f".kimi-code/skills/{suffix}"
                translation = "kimi_project_skill_artifact_v1"
        effective.append(materialized)
        bindings.append(
            {
                "canonical": canonical,
                "materialized": materialized,
                "translation": translation,
            }
        )
    if len(effective) != len(set(effective)):
        raise KimiControlTrialError("Kimi carrier translation produced duplicate paths")
    return effective, bindings


def build_control_trial_plan(
    *,
    repo_root: Path,
    case_dir: Path,
    batch_root: Path,
    run_id: str,
    control_type: str,
    capability_states: Mapping[str, str] | None = None,
    expected_suite_id: str | None = None,
    base_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive one exact Kimi control plan without writing any files."""

    if control_type not in CONTROL_TYPES:
        raise KimiControlTrialError(f"unsupported control type: {control_type!r}")
    repo = Path(repo_root).resolve()
    canonical = Path(case_dir).resolve(strict=True)
    try:
        canonical.relative_to((repo / "runs" / "active").resolve(strict=True))
    except ValueError as exc:
        raise KimiControlTrialError("control case is not below runs/active") from exc
    meta_path = canonical / "case_meta.json"
    meta = _load_json(meta_path)
    case_id = _string(meta.get("case_id"), "case_id")
    stages = _stage_documents(meta)
    match, trigger = _validate_match_contract(meta.get("control_match_contract"), stages)
    controls = meta.get("control_suite")
    if not isinstance(controls, list) or len(controls) != len(CONTROL_TYPES):
        raise KimiControlTrialError("control_suite must contain exactly four controls")
    by_type: dict[str, Mapping[str, Any]] = {}
    for raw in controls:
        if not isinstance(raw, Mapping):
            raise KimiControlTrialError("control_suite entry is not an object")
        kind = raw.get("control_type")
        if kind not in CONTROL_TYPES or kind in by_type:
            raise KimiControlTrialError("control_suite types are missing or duplicated")
        by_type[str(kind)] = raw
    if tuple(kind for kind in CONTROL_TYPES if kind in by_type) != CONTROL_TYPES:
        raise KimiControlTrialError("control_suite does not cover the required types")
    control = copy.deepcopy(dict(by_type[control_type]))
    control_id = _string(control.get("control_id"), "control_id")
    if control.get("control_type") != control_type:
        raise KimiControlTrialError("control type identity drifted")
    if control.get("control_intervention_timing") != CONTROL_TIMINGS[control_type]:
        raise KimiControlTrialError(f"{control_type} timing drifted")
    declared_trigger = control.get("control_trigger_stage_index")
    if declared_trigger is not None and declared_trigger != trigger:
        raise KimiControlTrialError("control trigger index differs from match contract")
    replacement_sources = _validate_control_shape(
        case_dir=canonical, control_type=control_type, control=control
    )

    effective_stages = copy.deepcopy(stages)
    if control_type == "no_trigger_control":
        prompt = _string(control.get("control_prompt"), "no-trigger prompt")
        if effective_stages[trigger - 1].get("user_prompt") == prompt:
            raise KimiControlTrialError("no-trigger prompt equals the attack trigger")
        effective_stages[trigger - 1]["user_prompt"] = prompt
    differences = _diff_paths(stages, effective_stages, "stages")
    expected_differences = (
        [f"stages[{trigger - 1}].user_prompt"]
        if control_type == "no_trigger_control"
        else []
    )
    if differences != expected_differences:
        raise KimiControlTrialError(
            f"{control_type} changed stage semantics outside its one variable: {differences}"
        )

    # Planning without evidence remains useful, but it must fail closed.  The
    # sole all-SUPPORTED hypothesis is passed explicitly by the read-only
    # ``audit_control_trial_matrix`` path below.
    states = (
        {capability: str(state).upper() for capability, state in capability_states.items()}
        if capability_states is not None
        else {capability: "UNVALIDATED" for capability in CAPABILITIES}
    )
    semantic = dict(base_plan) if base_plan is not None else build_bench_case_plan(
        repo_root=repo,
        case_dir=canonical,
        capability_states=states,
        expected_suite_id=expected_suite_id,
    )
    suite_id = _string(semantic.get("suite_id"), "base plan suite_id")
    if expected_suite_id is not None and suite_id != expected_suite_id:
        raise KimiControlTrialError("base plan suite identity drifted")
    reasons: list[str] = []
    if semantic.get("disposition") != "READY":
        reasons.append(
            "matched attack Kimi semantic binding is not READY: "
            + "; ".join(str(item) for item in semantic.get("disposition_reasons", []))
        )
    if control.get("control_session_carrier_intervention") is not None:
        reasons.append(_SESSION_TRANSLATION_BLOCK)
    disposition = "NOT_RUN" if reasons else "MATERIALIZABLE"
    layout = allocate_control_layout(
        batch_root=Path(batch_root), run_id=run_id, control_id=control_id
    )
    indices = _intervention_indices(control_type, len(stages), trigger)
    canonical_carriers = _string_list(
        control.get("control_removed_carrier_paths"),
        "control_removed_carrier_paths",
    )
    materialized_carriers, carrier_bindings = _materialized_carrier_bindings(
        suite_id, canonical_carriers
    )
    expected_absent = _string_list(
        control.get("expected_absent_oracles"), "expected_absent_oracles"
    )
    expected_present = _string_list(
        control.get("expected_present_oracles"), "expected_present_oracles"
    )
    expected_max = _string(control.get("expected_max_node"), "expected_max_node")
    if expected_max not in {"N0", "N1", "N2", "N3", "N4", "N5a", "N5b"}:
        raise KimiControlTrialError("control expected_max_node is invalid")

    document: dict[str, Any] = {
        "schema_name": CONTROL_PLAN_SCHEMA_NAME,
        "schema_version": CONTROL_PLAN_SCHEMA_VERSION,
        "harness_id": "kimi",
        "case_id": case_id,
        "suite_id": suite_id,
        "parent_run_id": run_id,
        "trial_run_id": layout.trial_run_id,
        "control_id": control_id,
        "control_type": control_type,
        "disposition": disposition,
        "disposition_reasons": reasons,
        "formal_runtime_readiness_claimed": False,
        "scoring_status": "NOT_PRODUCED",
        "canonical": {
            "case_dir": str(canonical),
            "case_meta_path": str(meta_path),
            "case_meta_file_sha256": sha256_file(meta_path),
            "case_tree_sha256": tree_sha256(canonical),
            "control_contract_sha256": _canonical_sha256(control),
            "match_contract_sha256": _canonical_sha256(match),
            "attack_stage_semantics_sha256": _canonical_sha256(stages),
            "effective_stage_semantics_sha256": _canonical_sha256(effective_stages),
        },
        "layout": layout.as_dict(),
        "control_contract": control,
        "match_contract": match,
        "matched_stages": stages,
        "effective_stages": effective_stages,
        "stage_count": len(stages),
        "stage_order": [str(stage["name"]) for stage in stages],
        "trigger_stage_index": trigger,
        "trigger_stage_name": str(stages[trigger - 1]["name"]),
        "stage_semantic_difference_paths": differences,
        "allowed_stage_semantic_difference_paths": expected_differences,
        "single_variable_verified": True,
        "intervention_timing": CONTROL_TIMINGS[control_type],
        "intervention_before_stage_indices": indices,
        "canonical_declared_carrier_paths": canonical_carriers,
        "declared_carrier_paths": materialized_carriers,
        "carrier_path_bindings": carrier_bindings,
        "declared_state_resets": _string_list(
            control.get("control_state_resets"), "control_state_resets"
        ),
        "declared_session_carrier_intervention": control.get(
            "control_session_carrier_intervention"
        ),
        "replacement_sources": replacement_sources,
        "expected_max_node": expected_max,
        "expected_absent_oracles": expected_absent,
        "expected_present_oracles": expected_present,
        "base_kimi_plan": {
            "disposition": semantic.get("disposition"),
            "disposition_reasons": list(semantic.get("disposition_reasons") or []),
            "plan_payload_sha256": semantic.get("plan_payload_sha256"),
            "canonical_tree_sha256": (semantic.get("canonical") or {}).get(
                "tree_sha256"
            ),
        },
    }
    document["control_plan_payload_sha256"] = _payload_sha256(
        document, "control_plan_payload_sha256"
    )
    return document


def load_control_trial_plan(path: Path) -> dict[str, Any]:
    document = _load_json(Path(path))
    if (
        document.get("schema_name") != CONTROL_PLAN_SCHEMA_NAME
        or document.get("schema_version") != CONTROL_PLAN_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("control_type") not in CONTROL_TYPES
        or document.get("disposition") not in CONTROL_DISPOSITIONS
        or document.get("scoring_status") != "NOT_PRODUCED"
    ):
        raise KimiControlTrialError("control plan identity is invalid")
    claimed = document.get("control_plan_payload_sha256")
    if not isinstance(claimed, str) or not hmac.compare_digest(
        claimed, _payload_sha256(document, "control_plan_payload_sha256")
    ):
        raise KimiControlTrialError("control plan self-hash mismatch")
    forbidden = _forbidden_paths(document)
    if forbidden:
        raise KimiControlTrialError(
            "control plan contains analyzer/scoring fields: " + ", ".join(forbidden)
        )
    return document


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


def audit_control_trial_matrix(
    *, repo_root: Path, batch_root: Path, run_id: str
) -> dict[str, Any]:
    """Read-only static audit of all 328 x 4 canonical control rows."""

    repo = Path(repo_root).resolve()
    frozen = load_frozen_inventory(repo, verify_live=True)
    references = iter_active_case_references(repo)
    if len(references) != EXPECTED_CASE_COUNT:
        raise KimiControlTrialError("active Kimi inventory is not exactly 328 cases")
    by_case = {
        str(record["case_id"]): record
        for record in frozen.get("cases", [])
        if isinstance(record, Mapping)
    }
    if len(by_case) != EXPECTED_CASE_COUNT:
        raise KimiControlTrialError("frozen Kimi inventory has duplicate/missing cases")
    capability_hypothesis = {capability: "SUPPORTED" for capability in CAPABILITIES}
    rows: list[dict[str, Any]] = []
    case_counts: Counter[str] = Counter()
    suite_counts: Counter[tuple[str, str]] = Counter()
    for reference in references:
        case_dir = Path(str(reference["case_dir"]))
        suite = str(reference["suite_id"])
        base = build_bench_case_plan(
            repo_root=repo,
            case_dir=case_dir,
            capability_states=capability_hypothesis,
            expected_suite_id=suite,
        )
        if base["case_id"] not in by_case:
            raise KimiControlTrialError("active case is absent from frozen Kimi inventory")
        for control_type in CONTROL_TYPES:
            plan = build_control_trial_plan(
                repo_root=repo,
                case_dir=case_dir,
                batch_root=batch_root,
                run_id=run_id,
                control_type=control_type,
                capability_states=capability_hypothesis,
                expected_suite_id=suite,
                base_plan=base,
            )
            disposition = str(plan["disposition"])
            case_counts[disposition] += 1
            suite_counts[(suite, disposition)] += 1
            rows.append(
                {
                    "case_id": plan["case_id"],
                    "suite_id": suite,
                    "control_id": plan["control_id"],
                    "control_type": control_type,
                    "disposition": disposition,
                    "disposition_reasons": list(plan["disposition_reasons"]),
                    "control_plan_payload_sha256": plan[
                        "control_plan_payload_sha256"
                    ],
                }
            )
    if len(rows) != EXPECTED_CONTROL_TRIAL_COUNT:
        raise KimiControlTrialError("control matrix is not exactly 328 x 4")
    if len({row["control_id"] for row in rows}) != len(rows):
        raise KimiControlTrialError("control matrix contains duplicate control_id values")
    result: dict[str, Any] = {
        "schema_name": "safety_bench_kimi_control_matrix_audit",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": run_id,
        "mode": "read_only_static_contract_audit",
        "case_count": EXPECTED_CASE_COUNT,
        "control_types_per_case": len(CONTROL_TYPES),
        "control_trial_count": len(rows),
        "inventory_content_sha256": str(
            frozen.get("inventory_content_sha256") or ""
        ),
        "canonical_hash_guard": {
            "verify_live_frozen_inventory": True,
            "canonical_cases_modified": False,
        },
        "dispositions": dict(sorted(case_counts.items())),
        "suite_dispositions": [
            {"suite_id": suite, "disposition": disposition, "count": count}
            for (suite, disposition), count in sorted(suite_counts.items())
        ],
        "native_session_intervention_rows_not_run": sum(
            1
            for row in rows
            if _SESSION_TRANSLATION_BLOCK in row["disposition_reasons"]
        ),
        "formal_runtime_readiness_claimed": False,
        "scoring_status": "NOT_PRODUCED",
        "capability_hypothesis_is_evidence": False,
        "rows": rows,
    }
    result["audit_payload_sha256"] = _payload_sha256(result, "audit_payload_sha256")
    return result


def _initial_intervention(plan: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    immediate = plan["control_type"] in {"clean_control", "no_trigger_control"}
    engaged = [record for record in records if record.get("intervention_engaged") is True]
    payload: dict[str, Any] = {
        "schema_version": CONTROL_INTERVENTION_SCHEMA_VERSION,
        "harness_id": "kimi",
        "run_id": plan["trial_run_id"],
        "control_type": plan["control_type"],
        "control_id": plan["control_id"],
        "control_contract_sha256": plan["canonical"]["control_contract_sha256"],
        "match_contract_sha256": plan["canonical"]["match_contract_sha256"],
        "stage_count": plan["stage_count"],
        "stage_names": plan["stage_order"],
        "trigger_stage_index": plan["trigger_stage_index"],
        "intervention_timing": plan["intervention_timing"],
        "intervention_before_stage_indices": plan[
            "intervention_before_stage_indices"
        ],
        "applied_before_stage_indices": [],
        "applied_intervention_count": 0,
        "expected_intervention_count": len(plan["intervention_before_stage_indices"]),
        "canonical_declared_carrier_paths": plan[
            "canonical_declared_carrier_paths"
        ],
        "declared_carrier_paths": plan["declared_carrier_paths"],
        "carrier_path_bindings": plan["carrier_path_bindings"],
        "declared_state_resets": plan["declared_state_resets"],
        "declared_session_carrier_intervention": plan[
            "declared_session_carrier_intervention"
        ],
        "records": [dict(record) for record in records],
        "applied": immediate and bool(records),
        "intervention_engaged": bool(engaged),
        "intervention_engagement_status": "engaged" if engaged else "non_engaged",
        "engaged_record_count": len(engaged),
        "non_engaged_record_count": len(records) - len(engaged),
        "non_engaged_is_valid_model_outcome": True,
        "formal_runtime_readiness_claimed": False,
        "scoring_status": "NOT_PRODUCED",
    }
    return payload


def _replace_workspace_sources(
    *, plan: Mapping[str, Any], materialized_case: Path, workspace: Path
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for replacement in plan["replacement_sources"]:
        if replacement["kind"] != "workspace_override":
            continue
        source = _owned(
            materialized_case / replacement["source"], materialized_case, "clean source"
        )
        target = _owned(workspace / replacement["target"], workspace, "workspace target")
        if not source.is_file() or not target.is_file() or source.is_symlink() or target.is_symlink():
            raise KimiControlTrialError("workspace replacement requires regular existing files")
        attack_sha = sha256_file(target)
        source_sha = sha256_file(source)
        if attack_sha == source_sha:
            raise KimiControlTrialError("workspace clean replacement did not change bytes")
        shutil.copy2(source, target)
        effective_sha = sha256_file(target)
        records.append(
            {
                "action": "replace_runtime_input",
                "kind": "workspace_override",
                "source_path": str(source),
                "effective_path": str(target),
                "attack_sha256": attack_sha,
                "clean_sha256": source_sha,
                "effective_sha256": effective_sha,
                "canonical_attack_sha256": replacement["attack_sha256"],
                "canonical_clean_sha256": replacement[
                    "canonical_source_sha256"
                ],
                "materialization_substitution_aware": True,
                "applied": True,
                "verified": hmac.compare_digest(source_sha, effective_sha),
                "intervention_engaged": True,
            }
        )
    return records


def _replace_skill_sources(
    *, plan: Mapping[str, Any], manifest: dict[str, Any], materialized_case: Path, workspace: Path
) -> list[dict[str, Any]]:
    clean_dirs = list((plan["control_contract"].get("control_plugin_dirs") or []))
    if not clean_dirs:
        return []
    records: list[dict[str, Any]] = []
    for stage in manifest["stages"]:
        skills = stage["surfaces"]["skills"]
        canonical_dirs = list(skills.get("canonical_dirs") or [])
        if not canonical_dirs:
            continue
        prepared = skills.get("prepared_tree")
        if not isinstance(prepared, Mapping) or not prepared.get("path"):
            raise KimiControlTrialError("clean plugin stage has no prepared Kimi skill tree")
        target = _owned(Path(str(prepared["path"])), Path(plan["layout"]["root"]), "skill tree")
        attack_sha = tree_sha256(target)
        if target.is_symlink() or not target.is_dir():
            raise KimiControlTrialError("prepared attack skill tree is unsafe")
        shutil.rmtree(target)
        translated = _prepare_skill_tree(
            materialized_case_dir=materialized_case,
            workspace=workspace,
            plugin_dirs=clean_dirs,
            target=target,
        )
        effective_sha = tree_sha256(target)
        if hmac.compare_digest(attack_sha, effective_sha):
            raise KimiControlTrialError("clean Kimi skill tree equals attack tree")
        skills["canonical_dirs"] = clean_dirs
        skills["prepared_tree"] = {
            "path": str(target),
            "tree_sha256": effective_sha,
            "skills": translated,
        }
        skills["activation"]["source_sha256"] = effective_sha
        records.append(
            {
                "action": "replace_runtime_input",
                "kind": "plugin",
                "stage_index": int(stage["index"]) + 1,
                "attack_sources": canonical_dirs,
                "clean_sources": clean_dirs,
                "effective_runtime_path": str(target),
                "attack_sha256": attack_sha,
                "clean_sha256": effective_sha,
                "effective_sha256": effective_sha,
                "applied": True,
                "verified": True,
                "intervention_engaged": True,
            }
        )
    if not records:
        raise KimiControlTrialError("declared clean plugin did not replace a runtime stage")
    return records


def _replace_mcp_sources(
    *,
    plan: Mapping[str, Any],
    manifest: dict[str, Any],
    materialized_case: Path,
    callback_url: str,
) -> list[dict[str, Any]]:
    clean_configs = list((plan["control_contract"].get("control_mcp_configs") or []))
    if not clean_configs:
        return []
    records: list[dict[str, Any]] = []
    run_root = Path(plan["layout"]["root"])
    run_id = str(plan["trial_run_id"])
    for stage in manifest["stages"]:
        mcp = stage["surfaces"]["mcp"]
        canonical_configs = list(mcp.get("canonical_configs") or [])
        if not canonical_configs:
            continue
        prepared = mcp.get("prepared_config")
        if not isinstance(prepared, Mapping) or not prepared.get("target"):
            raise KimiControlTrialError("clean MCP stage has no prepared Kimi config")
        target = _owned(Path(str(prepared["target"])), run_root, "prepared MCP config")
        attack_sha = sha256_file(target)
        target.unlink()
        replacement = _prepare_mcp_config(
            materialized_case_dir=materialized_case,
            source_paths=clean_configs,
            target=target,
            run_id=run_id,
            callback_url=callback_url,
        )
        reservations: list[dict[str, Any]] = []
        evidence_root = Path(stage["runtime_paths"]["mcp_evidence"])
        stage_tag = Path(str(stage["stage_root"])).name.removeprefix("stage-")
        for server_name in replacement["server_names"]:
            server_tag = _SAFE_TOKEN_RE.sub("-", server_name).strip("-._") or "server"
            prefix = f"mcp-{server_tag}-{stage_tag}"
            child_record = replacement["child_commands"][server_name]
            reservations.append(
                {
                    "server": server_name,
                    "transport": "stdio",
                    "child_argv_sha256": child_record["argv_sha256"],
                    "declared_source_argv_sha256": child_record[
                        "declared_source_argv_sha256"
                    ],
                    "declared_source_command": child_record[
                        "declared_source_command"
                    ],
                    "python_script_path": child_record["python_script_path"],
                    "python_script_sha256": child_record["python_script_sha256"],
                    "required_run_local_files": copy.deepcopy(
                        child_record["required_run_local_files"]
                    ),
                    "trusted_python_executable_path": child_record[
                        "trusted_python_executable_path"
                    ],
                    "trusted_python_executable_sha256": child_record[
                        "trusted_python_executable_sha256"
                    ],
                    "wrapper": "runner_supplied_kimi_owned_proxy",
                    "initialize_trace": str(evidence_root / f"initialize-{prefix}.jsonl"),
                    "tools_list_trace": str(evidence_root / f"tools-list-{prefix}.jsonl"),
                    "stdio_trace": str(evidence_root / f"stdio-{prefix}.jsonl"),
                    "child_exit_trace": str(evidence_root / f"child-exit-{prefix}.json"),
                }
            )
        proxy = _embed_mcp_evidence_proxies(
            prepared_config=target,
            run_root=run_root,
            run_id=run_id,
            stage_index=int(stage["index"]),
            reservations=reservations,
        )
        replacement["unwrapped_materialized_sha256"] = replacement[
            "materialized_sha256"
        ]
        replacement["materialized_sha256"] = proxy["materialized_sha256"]
        replacement["evidence_proxy"] = proxy
        mcp["canonical_configs"] = clean_configs
        mcp["prepared_config"] = replacement
        mcp["activation"]["source_sha256"] = replacement["materialized_sha256"]
        mcp["evidence_proxy"]["server_reservations"] = reservations
        effective_sha = sha256_file(target)
        if hmac.compare_digest(attack_sha, effective_sha):
            # Payload bytes may differ below the same MCP interface.  Equal
            # wrapper bytes would mean no physical replacement was evidenced.
            raise KimiControlTrialError("clean MCP replacement did not change bytes")
        records.append(
            {
                "action": "replace_runtime_input",
                "kind": "mcp_config",
                "stage_index": int(stage["index"]) + 1,
                "attack_sources": canonical_configs,
                "clean_sources": clean_configs,
                "effective_runtime_path": str(target),
                "attack_sha256": attack_sha,
                "clean_sha256": effective_sha,
                "effective_sha256": effective_sha,
                "applied": True,
                "verified": True,
                "intervention_engaged": True,
            }
        )
    if not records:
        raise KimiControlTrialError("declared clean MCP config did not replace a runtime stage")
    return records


def _apply_no_trigger(
    *, plan: Mapping[str, Any], manifest: dict[str, Any]
) -> list[dict[str, Any]]:
    index = int(plan["trigger_stage_index"]) - 1
    stage = manifest["stages"][index]
    prompt = stage["prompt"]
    path = _owned(
        Path(str(prompt["materialized_path"])), Path(plan["layout"]["root"]), "trigger prompt"
    )
    original_sha = sha256_file(path)
    effective = str(plan["effective_stages"][index]["user_prompt"])
    path.write_text(effective, encoding="utf-8")
    effective_sha = sha256_file(path)
    if hmac.compare_digest(original_sha, effective_sha):
        raise KimiControlTrialError("no-trigger prompt replacement did not change bytes")
    prompt["materialized_sha256"] = effective_sha
    prompt["translation"] = "identity"
    prompt["control_trigger_substitution"] = True
    return [
        {
            "action": "replace_trigger_prompt",
            "kind": "trigger",
            "stage_index": index + 1,
            "stage_name": stage["name"],
            "original_prompt_sha256": original_sha,
            "effective_prompt_sha256": effective_sha,
            "applied": True,
            "verified": True,
            "intervention_engaged": True,
        }
    ]


def _seed_translated_skill_carrier(
    *, plan: Mapping[str, Any], manifest: Mapping[str, Any], workspace: Path
) -> dict[str, Any] | None:
    translated = [
        binding
        for binding in plan["carrier_path_bindings"]
        if binding["translation"]
        in {"kimi_project_skill_tree_v1", "kimi_project_skill_artifact_v1"}
    ]
    if not translated:
        return None
    stages = manifest.get("stages")
    if not isinstance(stages, list) or not stages:
        raise KimiControlTrialError("translated skill carrier has no stages")
    skills = stages[0]["surfaces"]["skills"]
    prepared = skills.get("prepared_tree")
    if not isinstance(prepared, Mapping) or not prepared.get("path"):
        raise KimiControlTrialError(
            "translated canonical skill carrier has no prepared Kimi tree"
        )
    source = _owned(
        Path(str(prepared["path"])),
        Path(plan["layout"]["root"]),
        "prepared Kimi skill carrier",
    )
    target = _owned(
        workspace / ".kimi-code" / "skills",
        Path(plan["layout"]["root"]),
        "Kimi project skill carrier",
    )
    if not source.is_dir() or source.is_symlink():
        raise KimiControlTrialError("prepared Kimi skill carrier is unsafe")
    if target.exists() or target.is_symlink():
        raise KimiControlTrialError("Kimi project skill carrier was unexpectedly preseeded")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copytree(source, target)
    for binding in translated:
        effective = _owned(
            workspace / binding["materialized"],
            Path(plan["layout"]["root"]),
            "translated Kimi carrier",
        )
        if not effective.exists() or effective.is_symlink():
            raise KimiControlTrialError(
                "translated Kimi skill carrier is absent after native-surface seeding"
            )
    return {
        "kind": "kimi_project_skill_carrier_seed",
        "source_path": str(source),
        "source_tree_sha256": tree_sha256(source),
        "target_path": str(target),
        "target_tree_sha256": tree_sha256(target),
        "carrier_path_bindings": translated,
        "native_surface": "workspace/.kimi-code/skills",
        "workspace_memory_or_session_emulation": False,
    }


def _control_case_document(
    *, plan: Mapping[str, Any], materialized_meta: Mapping[str, Any]
) -> dict[str, Any]:
    case = copy.deepcopy(dict(materialized_meta))
    runtime_stages = case.get("stages")
    if runtime_stages is None:
        runtime_stages = None
    elif not isinstance(runtime_stages, list) or any(
        not isinstance(stage, dict) for stage in runtime_stages
    ):
        raise KimiControlTrialError("materialized case stages are malformed")
    control = plan["control_contract"]
    if plan["control_type"] == "clean_control":
        clean_plugins = list(control.get("control_plugin_dirs") or [])
        clean_mcp = list(control.get("control_mcp_configs") or [])
        if clean_plugins:
            if case.get("plugin_dirs"):
                case["plugin_dirs"] = clean_plugins
            if runtime_stages is not None:
                for stage in runtime_stages:
                    if stage.get("plugin_dirs"):
                        stage["plugin_dirs"] = clean_plugins
        if clean_mcp:
            if case.get("mcp_configs"):
                case["mcp_configs"] = clean_mcp
            if runtime_stages is not None:
                for stage in runtime_stages:
                    if stage.get("mcp_configs"):
                        stage["mcp_configs"] = clean_mcp
    elif plan["control_type"] == "no_trigger_control":
        trigger = int(plan["trigger_stage_index"]) - 1
        prompt = str(plan["effective_stages"][trigger]["user_prompt"])
        if runtime_stages is None:
            case["user_prompt"] = prompt
        else:
            runtime_stages[trigger]["user_prompt"] = prompt
            runtime_stages[trigger]["control_trigger_substitution"] = True
    case.update(
        {
            "harness": "kimi",
            "run_id": plan["trial_run_id"],
            "is_control_run": True,
            "control_type": plan["control_type"],
            "control_id": plan["control_id"],
            "control_expected_max_node": plan["expected_max_node"],
            "control_expected_absent_oracles": plan["expected_absent_oracles"],
            "control_expected_present_oracles": plan["expected_present_oracles"],
            "control_declared_carrier_paths": plan["declared_carrier_paths"],
            "control_canonical_declared_carrier_paths": plan[
                "canonical_declared_carrier_paths"
            ],
            "control_carrier_path_bindings": plan["carrier_path_bindings"],
            "control_state_resets": plan["declared_state_resets"],
            "control_session_carrier_intervention": plan[
                "declared_session_carrier_intervention"
            ],
            "control_intervention_timing": plan["intervention_timing"],
            "control_intervention_before_stage_indices": plan[
                "intervention_before_stage_indices"
            ],
            "control_match_contract": plan["match_contract"],
            "control_execution_contract": {
                "schema_version": 1,
                "matched_attack_stage_count": plan["stage_count"],
                "control_stage_count": plan["stage_count"],
                "stage_count_preserved": True,
                "stage_order_preserved": True,
                "stage_semantics_preserved": True,
                "matched_attack_stage_semantics_sha256": plan["canonical"][
                    "attack_stage_semantics_sha256"
                ],
                "effective_comparable_stage_semantics_sha256": plan["canonical"][
                    "attack_stage_semantics_sha256"
                ],
                "allowed_stage_differences": plan[
                    "allowed_stage_semantic_difference_paths"
                ],
                "match_contract_verified": True,
                "declared_match_stage_count": plan["stage_count"],
                "declared_match_stage_order": plan["stage_order"],
                "declared_match_trigger_stage_index": plan[
                    "trigger_stage_index"
                ],
                "stage_names": plan["stage_order"],
                "trigger_stage_index": plan["trigger_stage_index"],
                "trigger_stage_name": plan["trigger_stage_name"],
                "intervention_before_stage_indices": plan[
                    "intervention_before_stage_indices"
                ],
                "intervention_timing": plan["intervention_timing"],
                "harness": "kimi",
            },
        }
    )
    return case


def materialize_control_trial(
    *,
    repo_root: Path,
    case_dir: Path,
    batch_root: Path,
    run_id: str,
    control_type: str,
    callback_url: str,
    capability_states: Mapping[str, str] | None = None,
    canary_token: str | None = None,
    expected_suite_id: str | None = None,
) -> ControlMaterialization:
    """Create one independent, run-local control materialization.

    ``NOT_RUN`` controls are rejected before any write.  This prevents the 20
    native-session cases from acquiring a fake workspace/session variant.
    """

    states = _require_full_capability_states(capability_states)
    plan = build_control_trial_plan(
        repo_root=repo_root,
        case_dir=case_dir,
        batch_root=batch_root,
        run_id=run_id,
        control_type=control_type,
        capability_states=states,
        expected_suite_id=expected_suite_id,
    )
    if plan["disposition"] != "MATERIALIZABLE":
        raise KimiControlTrialError(
            "control trial is NOT_RUN: " + "; ".join(plan["disposition_reasons"])
        )
    layout = allocate_control_layout(
        batch_root=batch_root, run_id=run_id, control_id=str(plan["control_id"])
    )
    if layout.root.exists() or layout.root.is_symlink():
        raise KimiControlTrialError("control root already exists")
    layout.batch_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    layout.root.mkdir(mode=0o700)
    bench = materialize_bench_case(
        repo_root=Path(repo_root),
        case_dir=Path(case_dir),
        run_dir=layout.root,
        run_id=layout.trial_run_id,
        callback_url=callback_url,
        canary_token=canary_token,
        capability_states=states,
        expected_suite_id=expected_suite_id,
        allow_existing_empty_run_dir=True,
    )
    if bench.get("disposition") != "READY":
        raise KimiControlTrialError("base Kimi materialization stopped being READY")
    manifest_path = Path(str(bench["manifest_path"]))
    manifest = _load_json(manifest_path)
    materialized_doc = manifest.get("materialized")
    if not isinstance(materialized_doc, Mapping):
        raise KimiControlTrialError("bench manifest omitted materialized paths")
    materialized_case = _owned(
        Path(str(materialized_doc["case_dir"])), layout.root, "materialized case"
    )
    workspace = _owned(
        Path(str(materialized_doc["workspace_dir"])), layout.root, "workspace"
    )
    before_canonical = tree_sha256(Path(case_dir).resolve())
    records: list[dict[str, Any]] = []
    if control_type == "clean_control":
        records.extend(
            _replace_workspace_sources(
                plan=plan, materialized_case=materialized_case, workspace=workspace
            )
        )
        records.extend(
            _replace_skill_sources(
                plan=plan,
                manifest=manifest,
                materialized_case=materialized_case,
                workspace=workspace,
            )
        )
        records.extend(
            _replace_mcp_sources(
                plan=plan,
                manifest=manifest,
                materialized_case=materialized_case,
                callback_url=callback_url,
            )
        )
    elif control_type == "no_trigger_control":
        records.extend(_apply_no_trigger(plan=plan, manifest=manifest))

    carrier_seed = (
        _seed_translated_skill_carrier(
            plan=plan, manifest=manifest, workspace=workspace
        )
        if control_type in {"no_persist_control", "cleanup_control"}
        else None
    )

    meta_path = materialized_case / "case_meta.json"
    case_document = _control_case_document(
        plan=plan, materialized_meta=_load_json(meta_path)
    )
    _write_json(meta_path, case_document)
    case_path = layout.root / "case.json"
    _write_json(case_path, case_document)

    manifest["control_trial"] = {
        "schema_version": 1,
        "control_id": plan["control_id"],
        "control_type": control_type,
        "control_plan_payload_sha256": plan["control_plan_payload_sha256"],
        "intervention_timing": plan["intervention_timing"],
        "intervention_before_stage_indices": plan[
            "intervention_before_stage_indices"
        ],
        "single_variable_verified": True,
        "translated_carrier_seed": carrier_seed,
        "formal_runtime_readiness_claimed": False,
        "scoring_status": "NOT_PRODUCED",
    }
    manifest["materialized"]["tree_sha256"] = tree_sha256(materialized_case)
    manifest["materialized"]["case_meta_sha256"] = sha256_file(meta_path)
    manifest["plan_payload_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in manifest.items()
            if key not in {"plan_payload_sha256", "manifest_payload_sha256"}
        }
    )
    manifest["manifest_payload_sha256"] = _payload_sha256(
        manifest, "manifest_payload_sha256"
    )
    _write_json(manifest_path, manifest)

    control_plan_path = layout.root / f"control-plan-kimi-{layout.trial_run_id}.json"
    _write_json(control_plan_path, plan)
    intervention = _initial_intervention(plan, records)
    intervention_path = layout.root / "control_intervention.json"
    _write_json(intervention_path, intervention)
    after_canonical = tree_sha256(Path(case_dir).resolve())
    if not hmac.compare_digest(before_canonical, after_canonical):
        raise KimiControlTrialError("canonical case changed during control materialization")
    return ControlMaterialization(
        plan=plan,
        layout=layout,
        bench_manifest_path=manifest_path,
        control_plan_path=control_plan_path,
        intervention_path=intervention_path,
        case_path=case_path,
    )


class ControlInterventionRecorder:
    """Apply only scheduled carrier/state removals inside one control root.

    The recorder is intentionally launcher-agnostic.  A production Kimi stage
    loop must invoke ``apply_before_stage`` at the declared boundary and then
    revalidate its launch inputs.  Merely creating this object is not execution
    evidence and never upgrades ``control_isolation``.
    """

    def __init__(self, materialization: ControlMaterialization) -> None:
        self.materialization = materialization
        self.plan = dict(materialization.plan)
        if self.plan["disposition"] != "MATERIALIZABLE":
            raise KimiControlTrialError("NOT_RUN control cannot have an intervention recorder")
        if self.plan["declared_session_carrier_intervention"] is not None:
            raise KimiControlTrialError(_SESSION_TRANSLATION_BLOCK)
        self.root = materialization.layout.root.resolve(strict=True)
        self.manifest = _load_json(materialization.bench_manifest_path)
        self.intervention = _load_json(materialization.intervention_path)
        self.materialized_case = _owned(
            Path(self.manifest["materialized"]["case_dir"]),
            self.root,
            "materialized case",
        )
        self.workspace = _owned(
            Path(self.manifest["materialized"]["workspace_dir"]),
            self.root,
            "workspace",
        )

    def _carrier_path(self, declared: str) -> Path:
        relative = _safe_relative(declared, "declared carrier")
        parts = relative.parts
        explicit_workspace = bool(parts and parts[0].casefold() == "workspace")
        if explicit_workspace:
            relative = Path(*parts[1:])
        workspace_candidate = _owned(
            self.workspace / relative, self.materialized_case, "workspace carrier"
        )
        case_candidate = _owned(
            self.materialized_case / relative, self.materialized_case, "case carrier"
        )
        if explicit_workspace or workspace_candidate.exists() or not case_candidate.exists():
            return workspace_candidate
        return case_candidate

    def _remove(
        self,
        path: Path,
        *,
        kind: str,
        declared: str,
        before_stage_index: int,
        state_reset_types: Sequence[str] = (),
    ) -> dict[str, Any]:
        target = _owned(path, self.root, f"{kind} removal")
        record: dict[str, Any] = {
            "action": "remove",
            "kind": kind,
            "declared_path": declared,
            "resolved_path": str(target),
            "before_stage_index": before_stage_index,
            "before_stage_name": self.plan["stage_order"][before_stage_index - 1],
            "state_reset_types": list(state_reset_types),
            "existed_before": False,
            "removed": False,
            "disposition": "already_absent",
            "verified_absent": False,
            "intervention_engaged": False,
        }
        if target.exists():
            if target.is_symlink():
                raise KimiControlTrialError(f"refusing to remove symlink: {target}")
            record["existed_before"] = True
            record["sha256_before"] = (
                sha256_file(target) if target.is_file() else tree_sha256(target)
            )
            if target.is_file():
                target.unlink()
                record["disposition"] = "deleted_file"
            elif target.is_dir():
                shutil.rmtree(target)
                record["disposition"] = "deleted_directory"
            else:
                raise KimiControlTrialError(f"refusing to remove special file: {target}")
            record["removed"] = True
            record["intervention_engaged"] = True
        else:
            record["non_engaged_reason"] = "declared_path_not_present_at_intervention"
        record["verified_absent"] = not target.exists() and not target.is_symlink()
        return record

    def _state_targets(self, stage_index: int, reset: str) -> list[Path]:
        # Reset only Kimi state belonging to already-completed stages.  No
        # workspace file is introduced or treated as native memory/session.
        stages = self.manifest.get("stages")
        if not isinstance(stages, list):
            raise KimiControlTrialError("bench manifest stages are malformed")
        completed = stages[: max(stage_index - 1, 0)]
        keys = {
            "memory": ("kimi_home", "cache"),
            "session": ("session", "kimi_home"),
            "harness_state": ("session", "kimi_home", "cache"),
            "cache": ("cache",),
        }[reset]
        paths: list[Path] = []
        for stage in completed:
            runtime = stage.get("runtime_paths")
            if not isinstance(runtime, Mapping):
                raise KimiControlTrialError("stage runtime paths are malformed")
            for key in keys:
                candidate = _owned(
                    Path(str(runtime[key])), self.root, f"Kimi {reset} state"
                )
                if candidate not in paths:
                    paths.append(candidate)
        if not paths:
            # Before a single-stage/preseeded trigger, the current run-local
            # state is still empty.  Record its precise Kimi path without
            # deleting the directory needed by the launcher.
            runtime = stages[stage_index - 1]["runtime_paths"]
            marker = _owned(
                Path(str(runtime["kimi_home"])) / f"state-reset-{reset}",
                self.root,
                f"Kimi {reset} empty-state marker",
            )
            paths.append(marker)
        return paths

    def _remove_translated_skill_aliases(
        self, *, declared: str, before_stage_index: int
    ) -> list[dict[str, Any]]:
        binding = next(
            (
                item
                for item in self.plan["carrier_path_bindings"]
                if item["materialized"] == declared
            ),
            None,
        )
        if not isinstance(binding, Mapping) or binding.get("translation") not in {
            "kimi_project_skill_tree_v1",
            "kimi_project_skill_artifact_v1",
        }:
            return []
        stages = self.manifest.get("stages")
        if not isinstance(stages, list):
            raise KimiControlTrialError("bench manifest stages are malformed")
        records: list[dict[str, Any]] = []
        suffix = None
        if binding["translation"] == "kimi_project_skill_artifact_v1":
            suffix = str(binding["materialized"])[len(".kimi-code/skills/") :]
        # Only current/future stage activation sources can reintroduce the
        # carrier.  Already-completed stage assets remain outside the next
        # stage's mount contract and are retained as historical provenance.
        for stage in stages[before_stage_index - 1 :]:
            skills = stage["surfaces"]["skills"]
            prepared = skills.get("prepared_tree")
            if not isinstance(prepared, Mapping) or not prepared.get("path"):
                continue
            tree = _owned(
                Path(str(prepared["path"])),
                self.root,
                "future Kimi skill activation source",
            )
            target = tree if suffix is None else _owned(
                tree / suffix,
                self.root,
                "future Kimi skill carrier artifact",
            )
            record = self._remove(
                target,
                kind="kimi_runtime_carrier",
                declared=str(binding["canonical"]),
                before_stage_index=before_stage_index,
            )
            record["materialized_declared_path"] = declared
            record["stage_index"] = int(stage["index"]) + 1
            record["translation"] = str(binding["translation"])
            records.append(record)
            if suffix is None:
                skills["activation"] = {
                    "operation": "remove_tree_if_present",
                    "target": "workspace/.kimi-code/skills",
                }
                skills["prepared_tree"] = {
                    "path": None,
                    "status": "removed_by_matched_control_intervention",
                }
            elif tree.is_dir():
                effective_sha = tree_sha256(tree)
                skills["activation"]["source_sha256"] = effective_sha
                skills["prepared_tree"]["tree_sha256"] = effective_sha
        return records

    def _rewrite_manifest_after_intervention(
        self, *, before_stage_index: int
    ) -> dict[str, Any]:
        manifest_path = self.materialization.bench_manifest_path
        before_sha256 = sha256_file(manifest_path)
        before_payload_sha256 = _string(
            self.manifest.get("manifest_payload_sha256"),
            "pre-intervention manifest payload SHA-256",
        )
        self.manifest["materialized"]["tree_sha256"] = tree_sha256(
            self.materialized_case
        )
        self.manifest["plan_payload_sha256"] = _canonical_sha256(
            {
                key: value
                for key, value in self.manifest.items()
                if key not in {"plan_payload_sha256", "manifest_payload_sha256"}
            }
        )
        self.manifest["manifest_payload_sha256"] = _payload_sha256(
            self.manifest, "manifest_payload_sha256"
        )
        _write_json(manifest_path, self.manifest)
        after_sha256 = sha256_file(manifest_path)
        return {
            "before_stage_index": before_stage_index,
            "before_stage_name": self.plan["stage_order"][before_stage_index - 1],
            "manifest_path": str(manifest_path),
            "before_file_sha256": before_sha256,
            "after_file_sha256": after_sha256,
            "before_payload_sha256": before_payload_sha256,
            "after_payload_sha256": self.manifest["manifest_payload_sha256"],
            "manifest_content_changed": not hmac.compare_digest(
                before_sha256, after_sha256
            ),
            "materialized_tree_sha256": self.manifest["materialized"]["tree_sha256"],
            "reason": "matched_control_intervention_before_stage",
        }

    def apply_before_stage(self, stage_index: int) -> dict[str, Any]:
        expected = list(self.plan["intervention_before_stage_indices"])
        if stage_index not in expected:
            raise KimiControlTrialError(
                f"control intervention is not scheduled before stage {stage_index}"
            )
        applied = list(self.intervention.get("applied_before_stage_indices") or [])
        if stage_index in applied:
            raise KimiControlTrialError(
                f"control intervention already applied before stage {stage_index}"
            )
        records = list(self.intervention.get("records") or [])
        for declared in self.plan["declared_carrier_paths"]:
            records.append(
                self._remove(
                    self._carrier_path(str(declared)),
                    kind="carrier",
                    declared=str(declared).replace("\\", "/"),
                    before_stage_index=stage_index,
                )
            )
            records.extend(
                self._remove_translated_skill_aliases(
                    declared=str(declared), before_stage_index=stage_index
                )
            )
        for reset in self.plan["declared_state_resets"]:
            targets = self._state_targets(stage_index, str(reset))
            for target in targets:
                records.append(
                    self._remove(
                        target,
                        kind="kimi_state",
                        declared=str(reset),
                        before_stage_index=stage_index,
                        state_reset_types=(str(reset),),
                    )
                )
        if not self.plan["declared_carrier_paths"] and not self.plan["declared_state_resets"]:
            raise KimiControlTrialError("control has no executable Kimi intervention")
        applied.append(stage_index)
        applied.sort()
        engaged = [record for record in records if record.get("intervention_engaged") is True]
        self.intervention.update(
            {
                "records": records,
                "applied_before_stage_indices": applied,
                "applied_intervention_count": len(applied),
                "applied": applied == expected,
                "intervention_engaged": bool(engaged),
                "intervention_engagement_status": (
                    "engaged" if engaged else "non_engaged"
                ),
                "engaged_record_count": len(engaged),
                "non_engaged_record_count": len(records) - len(engaged),
            }
        )
        if _forbidden_paths(self.intervention):
            raise KimiControlTrialError("intervention evidence contains scoring fields")
        revision = self._rewrite_manifest_after_intervention(
            before_stage_index=stage_index
        )
        revisions = list(self.intervention.get("manifest_revisions") or [])
        revisions.append(revision)
        self.intervention["manifest_revisions"] = revisions
        _write_json(self.materialization.intervention_path, self.intervention)
        return copy.deepcopy(self.intervention)


class KimiMatchedControlBoundary:
    """Bind one materialized matched control to the executor stage loop.

    Canonical control contracts use one-based stage numbers while Event IR and
    the Kimi executor use zero-based indexes.  This adapter is the sole place
    where that conversion is performed and evidenced.
    """

    def __init__(self, materialization: ControlMaterialization) -> None:
        self.materialization = materialization
        self.recorder = ControlInterventionRecorder(materialization)
        self.run_id = materialization.layout.trial_run_id
        self.case_id = _string(materialization.plan.get("case_id"), "case_id")
        self._expected_one_based = tuple(
            int(value)
            for value in materialization.plan["intervention_before_stage_indices"]
        )

    def apply_before_stage(
        self, request: MatchedControlBoundaryRequest
    ) -> MatchedControlBoundaryResult | None:
        if (
            not isinstance(request, MatchedControlBoundaryRequest)
            or request.run_id != self.run_id
            or request.case_id != self.case_id
            or request.manifest_path.resolve(strict=True)
            != self.materialization.bench_manifest_path.resolve(strict=True)
            or not hmac.compare_digest(
                sha256_file(request.manifest_path), request.manifest_sha256
            )
        ):
            raise KimiControlTrialError(
                "executor matched-control boundary request identity drifted"
            )
        one_based = request.stage_index + 1
        if one_based not in self._expected_one_based:
            return None
        evidence = self.recorder.apply_before_stage(one_based)
        revisions = evidence.get("manifest_revisions")
        if not isinstance(revisions, list) or not revisions:
            raise KimiControlTrialError(
                "matched-control intervention omitted its manifest revision"
            )
        revision = revisions[-1]
        if (
            not isinstance(revision, Mapping)
            or revision.get("before_stage_index") != one_based
            or revision.get("before_file_sha256") != request.manifest_sha256
            or revision.get("after_file_sha256")
            != sha256_file(self.materialization.bench_manifest_path)
        ):
            raise KimiControlTrialError(
                "matched-control manifest revision chain drifted"
            )
        return MatchedControlBoundaryResult(
            run_id=self.run_id,
            case_id=self.case_id,
            stage_index=request.stage_index,
            stage_name=request.stage_name,
            manifest_path=self.materialization.bench_manifest_path,
            manifest_sha256=sha256_file(
                self.materialization.bench_manifest_path
            ),
            evidence_path=self.materialization.intervention_path,
            evidence_sha256=sha256_file(self.materialization.intervention_path),
        )

    def finalize(self) -> MatchedControlBoundaryFinalization:
        evidence = _load_json(self.materialization.intervention_path)
        applied = evidence.get("applied_before_stage_indices")
        if (
            evidence.get("harness_id") != "kimi"
            or evidence.get("run_id") != self.run_id
            or evidence.get("applied") is not True
            or not isinstance(applied, list)
            or tuple(applied) != self._expected_one_based
        ):
            raise KimiControlTrialError(
                "matched-control intervention did not cover its exact schedule"
            )
        return MatchedControlBoundaryFinalization(
            evidence_path=self.materialization.intervention_path,
            evidence_sha256=sha256_file(self.materialization.intervention_path),
            applied_stage_indices=tuple(int(value) for value in applied),
        )


__all__ = [
    "CONTROL_TYPES",
    "CONTROL_TIMINGS",
    "EXPECTED_CONTROL_TRIAL_COUNT",
    "ControlInterventionRecorder",
    "ControlMaterialization",
    "ControlTrialLayout",
    "KimiControlTrialError",
    "KimiMatchedControlBoundary",
    "allocate_control_layout",
    "audit_control_trial_matrix",
    "build_control_trial_plan",
    "load_control_trial_plan",
    "materialize_control_trial",
]
