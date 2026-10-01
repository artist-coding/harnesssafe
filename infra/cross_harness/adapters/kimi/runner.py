"""Fail-closed orchestration skeleton for all 328 active Kimi cases.

The runner is intentionally separate from the shared PowerShell harness
runner.  It never writes canonical cases, never scores a trial, and has no
built-in subprocess implementation.  A real execution requires injected,
reviewed materializer and executor implementations *plus* explicit execution
and external-model authorization flags.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from infra.check_paper_suite_lock import canonical_case_content_record
from infra.cross_harness.contract import CAPABILITIES

from .bench_inventory import (
    EXPECTED_CASE_COUNT,
    EXPECTED_SUITE_COUNTS,
    KimiBenchInventoryError,
    load_frozen_inventory,
)
from .disposition import (
    COMPLETED,
    EXECUTION_INVALID,
    MODEL_PROTOCOL_INCOMPLETE,
    RETRYABLE_EXECUTION_FAILURE_CATEGORIES,
    KimiExecutionDispositionError,
    validate_failure_disposition,
)
from .lifecycle import (
    CaseRunLayout,
    LoopbackPortLease,
    OwnedProcessRegistry,
    ProcessInspector,
    ProcessTerminator,
    RunLayout,
    atomic_write_json,
)


_CAPABILITY_STATUSES = {"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"}
_FORBIDDEN_EXECUTOR_METADATA = {
    "attack_success",
    "confirmed_compromise",
    "oracle",
    "oracle_path",
    "progress_node",
    "score",
    "scored_result",
    "verdict",
}


def _normalize_capability_context(
    capability_states: Mapping[str, str],
    capability_evidence: Mapping[str, Sequence[str]],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """Validate one complete, evidence-bound Contract-v1 capability snapshot."""

    if not isinstance(capability_states, Mapping) or set(capability_states) != set(
        CAPABILITIES
    ):
        raise ValueError(
            "capability_states must exactly cover the Contract v1 capability set"
        )
    if not isinstance(capability_evidence, Mapping) or set(
        capability_evidence
    ) != set(CAPABILITIES):
        raise ValueError(
            "capability_evidence must exactly cover the Contract v1 capability set"
        )
    states: dict[str, str] = {}
    evidence: dict[str, tuple[str, ...]] = {}
    for capability in sorted(CAPABILITIES):
        state = capability_states[capability]
        if not isinstance(state, str) or state not in _CAPABILITY_STATUSES:
            raise ValueError(
                f"invalid capability state for {capability}: {state!r}"
            )
        raw_locators = capability_evidence[capability]
        if isinstance(raw_locators, (str, bytes)) or not isinstance(
            raw_locators, Sequence
        ):
            raise ValueError(
                f"capability evidence for {capability} must be a sequence"
            )
        locators = tuple(raw_locators)
        if not locators or any(
            not isinstance(locator, str) or not locator.strip()
            for locator in locators
        ):
            raise ValueError(
                f"capability evidence for {capability} requires direct locators"
            )
        states[capability] = state
        evidence[capability] = locators
    return states, evidence


def _validate_callback_url(callback_url: str) -> str:
    if not isinstance(callback_url, str) or not callback_url.strip():
        raise ValueError("runtime preflight callback_url must be non-empty")
    parsed = urlsplit(callback_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("runtime preflight callback_url must use loopback HTTP")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("runtime preflight callback_url has an invalid port") from exc
    if port is None or not 1024 <= port <= 65535 or parsed.username or parsed.password:
        raise ValueError("runtime preflight callback_url requires a safe explicit port")
    if parsed.query or parsed.fragment:
        raise ValueError("runtime preflight callback_url cannot contain query/fragment")
    return callback_url.rstrip("/")


class KimiBenchRunnerError(RuntimeError):
    """A static inventory, plan, state, or executor contract is invalid."""


class KimiRuntimePreflightError(KimiBenchRunnerError):
    """A private trial runtime failed to close with auditable evidence."""

    def __init__(self, message: str, *, close_evidence: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.close_evidence = dict(close_evidence)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _forbidden_metadata_paths(value: Any, prefix: str = "metadata") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{prefix}.{key_text}"
            if key_text.casefold() in _FORBIDDEN_EXECUTOR_METADATA:
                found.append(child_path)
            found.extend(_forbidden_metadata_paths(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.extend(_forbidden_metadata_paths(child, f"{prefix}[{index}]"))
    return found


@dataclass(frozen=True)
class StageSpec:
    index: int
    name: str
    session_action: str = "fresh"
    runtime_mode: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "session_action": self.session_action,
            "runtime_mode": self.runtime_mode,
        }


@dataclass(frozen=True)
class BenchCase:
    case_id: str
    suite: str
    case_dir: Path
    case_meta_sha256: str
    stages: tuple[StageSpec, ...]
    case_content_sha256: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "suite": self.suite,
            "case_dir": str(self.case_dir),
            "case_meta_sha256": self.case_meta_sha256,
            "case_content_sha256": self.case_content_sha256,
            "stages": [stage.as_dict() for stage in self.stages],
        }


@dataclass(frozen=True)
class InventoryValidation:
    valid: bool
    active_case_count: int
    suite_counts: Mapping[str, int]
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "active_case_count": self.active_case_count,
            "suite_counts": dict(self.suite_counts),
            "errors": list(self.errors),
        }


class InventorySource(Protocol):
    def list_cases(self) -> Sequence[BenchCase]: ...

    def validate(self) -> InventoryValidation: ...


class ManifestInventory:
    """Projection of the hash-frozen inventory with a mandatory live drift gate."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.manifest_path = self.repo_root / "runs" / "manifest.json"
        self._cases: tuple[BenchCase, ...] | None = None

    def _load(self) -> tuple[BenchCase, ...]:
        try:
            frozen = load_frozen_inventory(self.repo_root, verify_live=True)
        except KimiBenchInventoryError as exc:
            raise KimiBenchRunnerError(
                f"Kimi frozen inventory/live drift gate failed: {exc}"
            ) from exc
        cases: list[BenchCase] = []
        for record in frozen["cases"]:
            case_id = str(record["case_id"])
            case_dir = (self.repo_root / str(record["case_dir"])).resolve()
            meta_path = case_dir / "case_meta.json"
            try:
                metadata = json.loads(meta_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError) as exc:
                raise KimiBenchRunnerError(
                    f"frozen case {case_id} has unreadable case_meta.json"
                ) from exc
            enriched_metadata = dict(metadata)
            enriched_metadata["_kimi_inventory_required_capabilities"] = list(
                record["required_capabilities"]
            )
            enriched_metadata["_kimi_inventory_binding_kind"] = record["binding_kind"]
            enriched_metadata["_kimi_inventory_execution_class"] = record[
                "execution_class"
            ]
            enriched_metadata["_kimi_inventory_binding_usable"] = bool(
                record.get(
                    "kimi_binding_usable_by_kimi",
                    record["canonical_binding_usable_by_kimi"],
                )
            )
            enriched_metadata["_kimi_inventory_semantic_binding"] = record.get(
                "kimi_semantic_binding"
            )
            enriched_metadata["_kimi_inventory_harness_restrictions"] = list(
                record["canonical_harness_restrictions"]
            )
            enriched_metadata["_kimi_inventory_repo_root"] = str(self.repo_root)
            stages = tuple(
                StageSpec(
                    index=int(stage["index"]),
                    name=str(stage["name"]),
                    session_action=str(stage.get("session_action") or "fresh"),
                    runtime_mode=str(stage.get("runtime_mode") or ""),
                )
                for stage in record["stages"]
            )
            cases.append(
                BenchCase(
                    case_id=case_id,
                    suite=str(record["suite"]),
                    case_dir=case_dir,
                    case_meta_sha256=str(record["case_meta_file_sha256"]),
                    stages=stages,
                    case_content_sha256=str(record["case_content_sha256"]),
                    metadata=enriched_metadata,
                )
            )
        return tuple(cases)

    def list_cases(self) -> Sequence[BenchCase]:
        if self._cases is None:
            self._cases = self._load()
        return self._cases

    def validate(self) -> InventoryValidation:
        errors: list[str] = []
        try:
            cases = tuple(self.list_cases())
        except KimiBenchRunnerError as exc:
            return InventoryValidation(False, 0, {}, (str(exc),))
        counts: dict[str, int] = {}
        seen: set[str] = set()
        for case in cases:
            counts[case.suite] = counts.get(case.suite, 0) + 1
            if case.case_id in seen:
                errors.append(f"duplicate case_id: {case.case_id}")
            seen.add(case.case_id)
        if counts != EXPECTED_SUITE_COUNTS:
            errors.append(
                f"active suite counts differ from the frozen 328-case scope: {counts}"
            )
        if len(cases) != EXPECTED_CASE_COUNT:
            errors.append(
                f"expected {EXPECTED_CASE_COUNT} active cases, found {len(cases)}"
            )
        return InventoryValidation(not errors, len(cases), counts, tuple(errors))


@dataclass(frozen=True)
class CasePlan:
    case: BenchCase
    required_capabilities: tuple[str, ...]
    binding_kind: str
    stages: tuple[StageSpec, ...]
    launch_eligible: bool = False
    blocking_reasons: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.as_dict(),
            "required_capabilities": list(self.required_capabilities),
            "binding_kind": self.binding_kind,
            "launch_eligible": self.launch_eligible,
            "blocking_reasons": list(self.blocking_reasons),
            "stages": [stage.as_dict() for stage in self.stages],
            "assumptions": list(self.assumptions),
        }


class PlanBuilder(Protocol):
    def build(self, case: BenchCase, layout: CaseRunLayout) -> CasePlan: ...


class DefaultPlanBuilder:
    """Conservative surface inference until a reviewed 328 binding is injected."""

    _BASE = (
        "headless_execution",
        "structured_trace",
        "workspace_isolation",
        "artifact_hash_provenance",
    )

    def build(self, case: BenchCase, layout: CaseRunLayout) -> CasePlan:
        del layout
        frozen_required = case.metadata.get("_kimi_inventory_required_capabilities")
        frozen_binding_kind = case.metadata.get("_kimi_inventory_binding_kind")
        frozen_execution_class = case.metadata.get("_kimi_inventory_execution_class")
        frozen_binding_usable = case.metadata.get("_kimi_inventory_binding_usable")
        frozen_restrictions = case.metadata.get(
            "_kimi_inventory_harness_restrictions"
        )
        frozen_repo_root = case.metadata.get("_kimi_inventory_repo_root")
        if (
            isinstance(frozen_required, list)
            and frozen_required
            and all(isinstance(item, str) and item for item in frozen_required)
            and isinstance(frozen_binding_kind, str)
            and frozen_binding_kind in {"native", "neutral", "hybrid"}
        ):
            semantic_required: tuple[str, ...] = ()
            semantic_ready = frozen_binding_usable is True
            semantic_blockers: tuple[str, ...] = ()
            if isinstance(frozen_repo_root, str) and frozen_repo_root:
                # Supply an all-SUPPORTED *hypothesis* only to ask the reviewed
                # materializer whether a semantic translation exists.  These
                # values never enter runtime evidence; the runner separately
                # probes the resulting required capability union below.
                from infra.cross_harness.contract import CAPABILITIES

                from .bench_materializer import build_bench_case_plan

                semantic = build_bench_case_plan(
                    repo_root=Path(frozen_repo_root),
                    case_dir=case.case_dir,
                    capability_states={
                        capability: "SUPPORTED" for capability in CAPABILITIES
                    },
                    expected_suite_id=case.suite,
                )
                semantic_required = tuple(semantic["required_capabilities"])
                semantic_ready = (
                    semantic.get("disposition") == "READY"
                    and frozen_binding_usable is True
                )
                semantic_blockers = tuple(
                    str(reason)
                    for reason in semantic.get("disposition_reasons", [])
                )
            restriction_blockers = (
                ()
                if frozen_binding_usable is True
                else (
                    "canonical stage restricts execution to: "
                    + ",".join(frozen_restrictions or []),
                )
            )
            blockers = tuple(
                dict.fromkeys((*restriction_blockers, *semantic_blockers))
            )
            if not semantic_ready and not blockers:
                blockers = (
                    "reviewed Kimi semantic materializer did not return READY",
                )
            return CasePlan(
                case=case,
                # Every runner invocation is a fresh OS process and every
                # formal row needs exact run-local artifact provenance, even
                # where the canonical surface classifier does not require a
                # cross-stage boundary.
                required_capabilities=tuple(
                    dict.fromkeys(
                        (
                            *frozen_required,
                            *semantic_required,
                            "fresh_process",
                            "artifact_hash_provenance",
                        )
                    )
                ),
                binding_kind=frozen_binding_kind,
                stages=case.stages,
                launch_eligible=semantic_ready,
                blocking_reasons=blockers,
                assumptions=(
                    "Plan is derived from the hash-frozen Kimi 328-case inventory.",
                    "Semantic eligibility is checked by the reviewed full-bench materializer.",
                    "Runner-wide fresh-process and artifact-provenance gates are added.",
                    f"execution_class={frozen_execution_class}",
                ),
            )
        required = list(self._BASE)
        metadata = case.metadata
        if case.suite == "v2_skill_runtime":
            required.extend(("skill_discovery", "skill_activation_trace"))
        if case.suite == "v2_tool_mcp_runtime" or metadata.get("mcp_configs"):
            required.extend(
                ("mcp_configuration", "mcp_health_trace", "mcp_tool_trace")
            )
        if case.suite == "T2_memory_to_skill":
            required.extend(
                ("instruction_loading", "skill_discovery", "skill_activation_trace")
            )
        if case.suite == "T3_subagent_poisoning":
            required.append("subagent_delegation")
        if case.suite == "T3_compaction_resume_poisoning":
            required.extend(("session_resume", "session_compaction"))
        if len(case.stages) > 1 or any(
            stage.session_action == "fresh" for stage in case.stages
        ):
            required.append("fresh_process")
        required = list(dict.fromkeys(required))
        return CasePlan(
            case=case,
            required_capabilities=tuple(required),
            binding_kind="unreviewed",
            stages=case.stages,
            launch_eligible=False,
            blocking_reasons=("No reviewed Kimi 328-case binding was injected.",),
            assumptions=(
                "Default plan is conservative and is not a reviewed Kimi semantic binding.",
            ),
        )


@dataclass(frozen=True)
class CapabilityDecision:
    status: str
    required_capabilities: tuple[str, ...]
    evidence: tuple[str, ...]
    reasons: tuple[str, ...]
    capability_states: Mapping[str, str] | None = field(default=None, repr=False)
    capability_evidence: Mapping[str, Sequence[str]] | None = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        if self.status not in _CAPABILITY_STATUSES:
            raise ValueError(f"invalid capability status: {self.status}")
        if not self.required_capabilities or len(set(self.required_capabilities)) != len(
            self.required_capabilities
        ):
            raise ValueError("required capabilities must be non-empty and unique")
        if not self.evidence:
            raise ValueError("capability decision requires raw evidence locators")
        if self.status == "SUPPORTED" and self.reasons:
            raise ValueError("SUPPORTED capability decision cannot contain failure reasons")
        if self.status != "SUPPORTED" and not self.reasons:
            raise ValueError(f"{self.status} capability decision requires reasons")
        if (self.capability_states is None) != (self.capability_evidence is None):
            raise ValueError(
                "capability decision full states and evidence must be supplied together"
            )
        if self.capability_states is not None:
            states, evidence = _normalize_capability_context(
                self.capability_states, self.capability_evidence or {}
            )
            object.__setattr__(self, "capability_states", states)
            object.__setattr__(self, "capability_evidence", evidence)

    def as_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "status": self.status,
            "required_capabilities": list(self.required_capabilities),
            "evidence": list(self.evidence),
            "reasons": list(self.reasons),
        }
        if self.capability_states is not None:
            document["capability_states"] = dict(self.capability_states)
            document["capability_evidence"] = {
                capability: list(locators)
                for capability, locators in (self.capability_evidence or {}).items()
            }
        return document


class CapabilitySource(Protocol):
    def probe(self, required_capabilities: Sequence[str]) -> CapabilityDecision: ...


class UnvalidatedCapabilitySource:
    """Safe CLI default: static surfaces are not runtime evidence."""

    def probe(self, required_capabilities: Sequence[str]) -> CapabilityDecision:
        required = tuple(required_capabilities)
        return CapabilityDecision(
            status="UNVALIDATED",
            required_capabilities=required,
            evidence=("kimi:runtime-capability-source-not-configured",),
            reasons=(
                "No version-scoped Kimi runtime evidence source was injected; "
                "formal execution is blocked.",
            ),
            capability_states={
                capability: "UNVALIDATED" for capability in CAPABILITIES
            },
            capability_evidence={
                capability: ("kimi:runtime-capability-source-not-configured",)
                for capability in CAPABILITIES
            },
        )


@dataclass(frozen=True)
class MaterializedCase:
    case_id: str
    root: Path
    workspace: Path
    config: Path
    trace: Path
    result: Path
    session: Path
    cache: Path
    artifact: Path
    manifest_path: Path
    stage_runtime_paths: tuple[Mapping[str, Any], ...] = ()
    launch_disposition: str = "READY"
    launch_reasons: tuple[str, ...] = ()


@dataclass
class MaterializationContext:
    run_id: str
    case_layout: CaseRunLayout
    loopback_port: LoopbackPortLease
    capability_states: Mapping[str, str]
    capability_evidence: Mapping[str, Sequence[str]]
    callback_url: str
    preexisting_service_paths: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        states, evidence = _normalize_capability_context(
            self.capability_states, self.capability_evidence
        )
        self.capability_states = states
        self.capability_evidence = evidence
        self.callback_url = _validate_callback_url(self.callback_url)
        self.preexisting_service_paths = tuple(
            Path(path).absolute() for path in self.preexisting_service_paths
        )


@dataclass(frozen=True)
class RuntimePreflight:
    """Runtime evidence returned after starting one trial's private services."""

    capability: CapabilityDecision
    capability_states: Mapping[str, str]
    capability_evidence: Mapping[str, Sequence[str]]
    callback_url: str
    preexisting_service_paths: tuple[Path, ...] = ()
    materializer: object | None = field(default=None, repr=False)
    executor: object | None = field(default=None, repr=False)
    close_evidence: Mapping[str, Any] = field(default_factory=dict, repr=False)


class RuntimePreflightHook(Protocol):
    def __call__(
        self,
        *,
        plan: CasePlan,
        layout: CaseRunLayout,
        process_registry: OwnedProcessRegistry,
        loopback_port: LoopbackPortLease,
    ) -> AbstractContextManager[RuntimePreflight]: ...


class CaseMaterializer(Protocol):
    def materialize(
        self,
        plan: CasePlan,
        layout: CaseRunLayout,
        context: MaterializationContext,
    ) -> MaterializedCase: ...


class BenchMaterializerBridge:
    """Adapt the reviewed full-bench materializer to the runner protocol."""

    def __init__(
        self,
        *,
        repo_root: Path,
        canary_token: str | None = None,
        shared_materializer: Callable[..., Any] | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.canary_token = canary_token
        self.shared_materializer = shared_materializer

    def materialize(
        self,
        plan: CasePlan,
        layout: CaseRunLayout,
        context: MaterializationContext,
    ) -> MaterializedCase:
        from .bench_materializer import (
            load_bench_materialization_manifest,
            materialize_bench_case_for_runner,
        )

        kwargs: dict[str, Any] = {
            "repo_root": self.repo_root,
            "case_dir": plan.case.case_dir,
            "run_dir": layout.root,
            "run_id": context.run_id,
            "callback_url": context.callback_url,
            "canary_token": self.canary_token,
            "capability_states": context.capability_states,
            "capability_evidence": context.capability_evidence,
            "expected_suite_id": plan.case.suite,
            "allow_existing_empty_run_dir": True,
            "preexisting_service_paths": context.preexisting_service_paths,
        }
        if self.shared_materializer is not None:
            kwargs["shared_materializer"] = self.shared_materializer
        projection = materialize_bench_case_for_runner(**kwargs)
        manifest = load_bench_materialization_manifest(projection.manifest_path)
        stages = tuple(dict(stage) for stage in projection.stage_runtime_paths)
        if not stages:
            raise KimiBenchRunnerError("bench materializer returned no stage runtime paths")
        first = stages[0]

        def stage_path(key: str) -> Path:
            value = first.get(key)
            if not isinstance(value, str) or not value:
                raise KimiBenchRunnerError(
                    f"bench materializer omitted stage runtime path: {key}"
                )
            return Path(value)

        return MaterializedCase(
            case_id=projection.case_id,
            root=projection.run_dir,
            workspace=projection.workspace_dir,
            config=stage_path("kimi_home"),
            trace=stage_path("trace").parent,
            result=stage_path("result").parent,
            session=stage_path("session"),
            cache=stage_path("cache"),
            artifact=stage_path("artifact"),
            manifest_path=projection.manifest_path,
            stage_runtime_paths=stages,
            launch_disposition=str(manifest.get("disposition") or "NOT_RUN"),
            launch_reasons=tuple(str(item) for item in manifest.get("disposition_reasons", [])),
        )


@dataclass
class ExecutionContext:
    run_id: str
    case_layout: CaseRunLayout
    process_registry: OwnedProcessRegistry
    loopback_port: LoopbackPortLease


@dataclass(frozen=True)
class ExecutionResult:
    outcome: str
    return_code: int | None
    raw_stdout_path: Path | None
    raw_wire_path: Path | None
    event_ir_path: Path | None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    failure_category: str | None = None
    retry_eligible: bool = False

    def __post_init__(self) -> None:
        validate_failure_disposition(
            outcome=self.outcome,
            failure_category=self.failure_category,
            retry_eligible=self.retry_eligible,
        )
        if self.outcome == MODEL_PROTOCOL_INCOMPLETE and (
            self.raw_stdout_path is None or self.raw_wire_path is None
        ):
            raise ValueError(
                "MODEL_PROTOCOL_INCOMPLETE requires directly captured stdout and wire evidence"
            )
        forbidden = sorted(_forbidden_metadata_paths(self.metadata))
        if forbidden:
            raise ValueError(
                "executor may not return analyzer/scoring fields: " + ", ".join(forbidden)
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "return_code": self.return_code,
            "raw_stdout_path": (
                str(self.raw_stdout_path) if self.raw_stdout_path is not None else None
            ),
            "raw_wire_path": (
                str(self.raw_wire_path) if self.raw_wire_path is not None else None
            ),
            "event_ir_path": str(self.event_ir_path) if self.event_ir_path else None,
            "failure_category": self.failure_category,
            "retry_eligible": self.retry_eligible,
            "metadata": dict(self.metadata),
        }


class CaseExecutor(Protocol):
    def execute(
        self,
        plan: CasePlan,
        materialized: MaterializedCase,
        context: ExecutionContext,
    ) -> ExecutionResult: ...


@dataclass(frozen=True)
class CaseRunResult:
    case_id: str
    suite: str
    outcome: str
    reason: str
    state_path: Path
    capability: CapabilityDecision
    evidence: Mapping[str, Any] = field(default_factory=dict)
    failure_category: str | None = None
    retry_eligible: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "suite": self.suite,
            "outcome": self.outcome,
            "reason": self.reason,
            "state_path": str(self.state_path),
            "capability": self.capability.as_dict(),
            "evidence": dict(self.evidence),
            "failure_category": self.failure_category,
            "retry_eligible": self.retry_eligible,
            "scoring_status": "NOT_PRODUCED",
        }


def _call_builder(builder: object, case: BenchCase, layout: CaseRunLayout) -> CasePlan:
    method = getattr(builder, "build", None)
    result = (
        method(case, layout)
        if callable(method)
        else builder(case, layout)  # type: ignore[operator]
    )
    if not isinstance(result, CasePlan):
        raise KimiBenchRunnerError("plan builder did not return CasePlan")
    if result.case.case_id != case.case_id:
        raise KimiBenchRunnerError("plan builder changed case identity")
    if not result.required_capabilities or len(set(result.required_capabilities)) != len(
        result.required_capabilities
    ):
        raise KimiBenchRunnerError(
            "plan required_capabilities must be non-empty and unique"
        )
    if not result.stages or len({stage.index for stage in result.stages}) != len(
        result.stages
    ):
        raise KimiBenchRunnerError("plan stages must be non-empty with unique indexes")
    if not result.launch_eligible and not result.blocking_reasons:
        raise KimiBenchRunnerError(
            "non-launch-eligible plan requires explicit blocking reasons"
        )
    return result


def _call_probe(source: object, required: Sequence[str]) -> CapabilityDecision:
    method = getattr(source, "probe", None)
    if not callable(method):
        method = getattr(source, "probe_capabilities", None)
    result = method(required) if callable(method) else source(required)  # type: ignore[operator]
    if isinstance(result, CapabilityDecision):
        decision = result
    else:
        # Accept the shared CapabilityProbe shape without importing adapter internals.
        try:
            decision = CapabilityDecision(
                status=str(result.status),
                required_capabilities=tuple(result.required_capabilities),
                evidence=tuple(result.evidence),
                reasons=tuple(result.reasons),
                capability_states=getattr(result, "capability_states", None),
                capability_evidence=getattr(result, "capability_evidence", None),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise KimiBenchRunnerError("capability source returned an invalid decision") from exc
    if tuple(required) != decision.required_capabilities:
        raise KimiBenchRunnerError("capability source changed the required capability set")
    if decision.capability_states is None:
        raw_matrix = getattr(source, "last_capability_matrix", None)
        if isinstance(raw_matrix, Mapping):
            if set(raw_matrix) != set(CAPABILITIES):
                raise KimiBenchRunnerError(
                    "capability source exposed an incomplete last_capability_matrix"
                )
            states: dict[str, str] = {}
            evidence: dict[str, tuple[str, ...]] = {}
            for capability in CAPABILITIES:
                item = raw_matrix[capability]
                state = getattr(item, "status", None)
                locators = getattr(item, "evidence", None)
                if (
                    getattr(item, "capability", capability) != capability
                    or state not in _CAPABILITY_STATUSES
                    or isinstance(locators, (str, bytes))
                    or not isinstance(locators, Sequence)
                    or not locators
                    or any(
                        not isinstance(locator, str) or not locator.strip()
                        for locator in locators
                    )
                ):
                    raise KimiBenchRunnerError(
                        "capability source exposed an invalid last_capability_matrix"
                    )
                states[capability] = state
                evidence[capability] = tuple(locators)
            required_states = [states[capability] for capability in required]
            expected_status = (
                "UNSUPPORTED"
                if "UNSUPPORTED" in required_states
                else "UNVALIDATED"
                if "UNVALIDATED" in required_states
                else "SUPPORTED"
            )
            if expected_status != decision.status:
                raise KimiBenchRunnerError(
                    "capability aggregate disagrees with last_capability_matrix"
                )
            decision = CapabilityDecision(
                status=decision.status,
                required_capabilities=decision.required_capabilities,
                evidence=decision.evidence,
                reasons=decision.reasons,
                capability_states=states,
                capability_evidence=evidence,
            )
    return decision


def _validate_final_capability_gate(
    *,
    plan: CasePlan,
    decision: CapabilityDecision,
    capability_states: Mapping[str, str],
    capability_evidence: Mapping[str, Sequence[str]],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    if decision.required_capabilities != plan.required_capabilities:
        raise KimiBenchRunnerError(
            "runtime preflight changed the required capability set"
        )
    try:
        states, evidence = _normalize_capability_context(
            capability_states, capability_evidence
        )
    except ValueError as exc:
        raise KimiBenchRunnerError(
            f"runtime preflight capability evidence is incomplete: {exc}"
        ) from exc
    required_states = [states[capability] for capability in plan.required_capabilities]
    expected = (
        "UNSUPPORTED"
        if "UNSUPPORTED" in required_states
        else "UNVALIDATED"
        if "UNVALIDATED" in required_states
        else "SUPPORTED"
    )
    if decision.status != expected:
        raise KimiBenchRunnerError(
            "runtime preflight aggregate decision contradicts its full capability states"
        )
    return states, evidence


def _enter_runtime_preflight(
    hook: object,
    *,
    plan: CasePlan,
    layout: CaseRunLayout,
    registry: OwnedProcessRegistry,
    port_lease: LoopbackPortLease,
) -> AbstractContextManager[RuntimePreflight]:
    manager = hook(
        plan=plan,
        layout=layout,
        process_registry=registry,
        loopback_port=port_lease,
    )  # type: ignore[operator]
    if not callable(getattr(manager, "__enter__", None)) or not callable(
        getattr(manager, "__exit__", None)
    ):
        raise KimiBenchRunnerError(
            "runtime preflight hook did not return a context manager"
        )
    return manager  # type: ignore[return-value]


def _run_with_runtime_preflight(
    manager: AbstractContextManager[RuntimePreflight],
    operation: Callable[[RuntimePreflight], Any],
) -> tuple[Any, Mapping[str, Any]]:
    """Run one operation and close its runtime without permitting suppression."""

    def close_failure_evidence(exc: BaseException) -> dict[str, Any]:
        for attribute in ("close_evidence", "_kimi_runtime_close_evidence"):
            value = getattr(exc, attribute, None)
            if isinstance(value, Mapping) and value:
                return dict(value)
        return {
            "closed": False,
            "error_type": type(exc).__name__,
        }

    runtime = manager.__enter__()
    if not isinstance(runtime, RuntimePreflight):
        try:
            manager.__exit__(None, None, None)
        except BaseException as close_exc:
            raise KimiRuntimePreflightError(
                "invalid runtime preflight context also failed to close: "
                f"{type(close_exc).__name__}: {close_exc}",
                close_evidence=close_failure_evidence(close_exc),
            ) from close_exc
        raise KimiBenchRunnerError(
            "runtime preflight context did not yield RuntimePreflight"
        )
    error: BaseException | None = None
    traceback = None
    result: Any = None
    try:
        result = operation(runtime)
    except BaseException as exc:  # cleanup must also run for interruption
        error = exc
        traceback = sys.exc_info()[2]
    try:
        suppressed = manager.__exit__(
            type(error) if error is not None else None,
            error,
            traceback,
        )
    except BaseException as close_exc:
        raise KimiRuntimePreflightError(
            "runtime preflight close failed: "
            f"{type(close_exc).__name__}: {close_exc}",
            close_evidence=close_failure_evidence(close_exc),
        ) from close_exc
    if suppressed:
        raise KimiRuntimePreflightError(
            "runtime preflight context attempted to suppress a pipeline failure",
            close_evidence={"closed": False, "suppression_rejected": True},
        )
    if not isinstance(runtime.close_evidence, Mapping) or not runtime.close_evidence:
        raise KimiRuntimePreflightError(
            "runtime preflight close produced no exact close evidence",
            close_evidence={"closed": False, "evidence_missing": True},
        )
    forbidden = _forbidden_metadata_paths(
        runtime.close_evidence, prefix="runtime_close_evidence"
    )
    if forbidden:
        raise KimiRuntimePreflightError(
            "runtime close evidence contains analyzer/scoring fields: "
            + ", ".join(sorted(forbidden)),
            close_evidence={"closed": False, "evidence_rejected": True},
        )
    close_evidence = dict(runtime.close_evidence)
    try:
        json.dumps(close_evidence, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise KimiRuntimePreflightError(
            "runtime close evidence is not JSON-serializable",
            close_evidence={"closed": False, "evidence_rejected": True},
        ) from exc
    if error is not None:
        try:
            setattr(error, "_kimi_runtime_close_evidence", close_evidence)
        except Exception:
            raise KimiRuntimePreflightError(
                "pipeline failed after runtime close, but close evidence could not be bound",
                close_evidence=close_evidence,
            ) from error
        raise error.with_traceback(traceback)
    return result, close_evidence


def _call_materializer(
    materializer: object,
    plan: CasePlan,
    layout: CaseRunLayout,
    context: MaterializationContext,
) -> MaterializedCase:
    method = getattr(materializer, "materialize", None)
    result = (
        method(plan, layout, context)
        if callable(method)
        else materializer(plan, layout, context)  # type: ignore[operator]
    )
    if not isinstance(result, MaterializedCase):
        raise KimiBenchRunnerError("materializer did not return MaterializedCase")
    return result


def _call_executor(
    executor: object,
    plan: CasePlan,
    materialized: MaterializedCase,
    context: ExecutionContext,
) -> ExecutionResult:
    method = getattr(executor, "execute", None)
    result = (
        method(plan, materialized, context)
        if callable(method)
        else executor(plan, materialized, context)  # type: ignore[operator]
    )
    if not isinstance(result, ExecutionResult):
        raise KimiBenchRunnerError("executor did not return ExecutionResult")
    return result


class KimiBenchRunner:
    """Dependency-injected Kimi-only scheduler with a fail-closed state machine."""

    def __init__(
        self,
        *,
        repo_root: Path,
        result_root: Path,
        run_id: str,
        inventory: InventorySource,
        plan_builder: PlanBuilder | Callable[[BenchCase, CaseRunLayout], CasePlan],
        capability_source: CapabilitySource | Callable[[Sequence[str]], CapabilityDecision],
        materializer: CaseMaterializer | Callable[..., MaterializedCase] | None = None,
        executor: CaseExecutor | Callable[..., ExecutionResult] | None = None,
        process_inspector: ProcessInspector | None = None,
        process_terminator: ProcessTerminator | None = None,
        port_lease_factory: Callable[[], LoopbackPortLease] = LoopbackPortLease,
        runtime_preflight_hook: RuntimePreflightHook | Callable[..., Any] | None = None,
    ) -> None:
        self.layout = RunLayout(Path(repo_root), Path(result_root), run_id)
        self.inventory = inventory
        self.plan_builder = plan_builder
        self.capability_source = capability_source
        self.materializer = materializer
        self.executor = executor
        self.process_inspector = process_inspector
        self.process_terminator = process_terminator
        self.port_lease_factory = port_lease_factory
        self.runtime_preflight_hook = runtime_preflight_hook

    @property
    def run_id(self) -> str:
        return self.layout.run_id

    def list_cases(self, *, suite: str | None = None) -> tuple[BenchCase, ...]:
        cases = tuple(self.inventory.list_cases())
        if suite is not None:
            cases = tuple(case for case in cases if case.suite == suite)
            if not cases:
                raise KimiBenchRunnerError(f"unknown or empty active suite: {suite}")
        return cases

    def validate_inventory(self) -> InventoryValidation:
        return self.inventory.validate()

    def _select_case(self, case_id: str) -> BenchCase:
        matches = [case for case in self.list_cases() if case.case_id == case_id]
        if len(matches) != 1:
            raise KimiBenchRunnerError(f"expected one active case for {case_id!r}")
        return matches[0]

    def plan_cases(
        self, cases: Iterable[BenchCase], *, write: bool = True
    ) -> tuple[CasePlan, ...]:
        plans = tuple(
            _call_builder(self.plan_builder, case, self.layout.for_case(case.case_id))
            for case in cases
        )
        if write:
            self.layout.initialize()
            atomic_write_json(
                self.layout.plan_path,
                {
                    "schema_name": "safety_bench_kimi_run_plan",
                    "schema_version": 1,
                    "harness_id": "kimi",
                    "run_id": self.run_id,
                    "created_at": _utc_now(),
                    "execution_default": "dry-run",
                    "scoring_status": "NOT_PRODUCED",
                    "plans": [plan.as_dict() for plan in plans],
                },
                run_id=self.run_id,
            )
        return plans

    def plan_case(self, case_id: str) -> CasePlan:
        return self.plan_cases((self._select_case(case_id),))[0]

    def plan_suite(self, suite: str) -> tuple[CasePlan, ...]:
        return self.plan_cases(self.list_cases(suite=suite))

    def plan_all(self) -> tuple[CasePlan, ...]:
        validation = self.validate_inventory()
        if not validation.valid:
            raise KimiBenchRunnerError("cannot plan invalid active inventory")
        return self.plan_cases(self.list_cases())

    def _validate_materialized(
        self, materialized: MaterializedCase, plan: CasePlan, case_layout: CaseRunLayout
    ) -> None:
        if materialized.case_id != plan.case.case_id:
            raise KimiBenchRunnerError("materializer changed case identity")
        canonical = plan.case.case_dir.resolve()
        for label in (
            "root",
            "workspace",
            "config",
            "trace",
            "result",
            "session",
            "cache",
            "artifact",
        ):
            path = Path(getattr(materialized, label))
            owned = self.layout.assert_owned(path)
            if owned == canonical or canonical in owned.parents:
                raise KimiBenchRunnerError("materialized path aliases the canonical case")
            try:
                owned.relative_to(case_layout.root.resolve())
            except ValueError as exc:
                raise KimiBenchRunnerError(
                    f"materialized {label} path escapes the assigned case leaf"
                ) from exc
            if path.is_symlink():
                raise KimiBenchRunnerError(f"materialized {label} path is a symlink")
            if "kimi" not in str(owned) or self.run_id not in str(owned):
                raise KimiBenchRunnerError(
                    f"materialized {label} path lacks Kimi run ownership"
                )
        if materialized.root.resolve() != case_layout.root.resolve():
            raise KimiBenchRunnerError(
                "materializer did not use the assigned per-attempt case root"
            )
        manifest_path = self.layout.assert_owned(materialized.manifest_path)
        try:
            manifest_path.relative_to(case_layout.root.resolve())
        except ValueError as exc:
            raise KimiBenchRunnerError(
                "materialization manifest must be below the assigned case root"
            ) from exc
        if materialized.manifest_path.is_symlink() or not manifest_path.is_file():
            raise KimiBenchRunnerError(
                "materialization manifest must be a regular run-local file"
            )
        stage_paths = materialized.stage_runtime_paths
        if len(stage_paths) != len(plan.stages):
            raise KimiBenchRunnerError(
                "materialized stage runtime path count differs from the plan"
            )
        required_stage_paths = (
            "workspace",
            "home",
            "kimi_home",
            "trace",
            "wire",
            "result",
            "session",
            "pid_record",
            "cache",
            "artifact",
        )
        for planned_stage, stage in zip(plan.stages, stage_paths):
            if (
                not isinstance(stage, Mapping)
                or stage.get("index") != planned_stage.index
                or not isinstance(stage.get("name"), str)
                or not stage.get("name")
            ):
                raise KimiBenchRunnerError(
                    "materialized stage runtime index/name is invalid"
                )
            for key in required_stage_paths:
                raw_path = stage.get(key)
                if not isinstance(raw_path, str) or not raw_path:
                    raise KimiBenchRunnerError(
                        f"materialized stage omitted {key} path"
                    )
                path = Path(raw_path)
                owned = self.layout.assert_owned(path)
                try:
                    owned.relative_to(case_layout.root.resolve())
                except ValueError as exc:
                    raise KimiBenchRunnerError(
                        f"materialized stage {key} escapes the assigned case leaf"
                    ) from exc
                if path.is_symlink():
                    raise KimiBenchRunnerError(
                        f"materialized stage {key} path is a symlink"
                    )

    def _validate_evidence_paths(
        self, result: ExecutionResult
    ) -> None:
        paths = (
            result.raw_stdout_path,
            result.raw_wire_path,
            result.event_ir_path,
        )
        if result.outcome == COMPLETED and (
            result.raw_stdout_path is None or result.event_ir_path is None
        ):
            raise KimiBenchRunnerError(
                "completed execution requires raw stdout and Event IR evidence"
            )
        for path in paths:
            if path is not None:
                owned = self.layout.assert_owned(path)
                if path.is_symlink() or not owned.is_file():
                    raise KimiBenchRunnerError(
                        f"execution evidence is not a regular run-local file: {path}"
                    )

    def _new_state(self, plans: Sequence[CasePlan], *, execute: bool) -> dict[str, Any]:
        queued_at = _utc_now()
        return {
            "schema_name": "safety_bench_kimi_run_state",
            "schema_version": 2,
            "harness_id": "kimi",
            "run_id": self.run_id,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "execution_requested": execute,
            "scoring_status": "NOT_PRODUCED",
            "case_order": [plan.case.case_id for plan in plans],
            "cases": {
                plan.case.case_id: {
                    "case_id": plan.case.case_id,
                    "suite": plan.case.suite,
                    "attempt": 0,
                    "status": "QUEUED",
                    "reason": "case has not started",
                    "failure_category": "NOT_STARTED",
                    "retry_eligible": True,
                    "history": [
                        {
                            "status": "QUEUED",
                            "at": queued_at,
                            "reason": "case has not started",
                            "failure_category": "NOT_STARTED",
                            "retry_eligible": True,
                        }
                    ],
                    "scoring_status": "NOT_PRODUCED",
                }
                for plan in plans
            },
        }

    def _persist_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = _utc_now()
        atomic_write_json(self.layout.state_path, state, run_id=self.run_id)

    def _transition(
        self,
        state: dict[str, Any],
        plan: CasePlan,
        status: str,
        *,
        reason: str = "",
        extra: Mapping[str, Any] | None = None,
        failure_category: str | None = None,
        retry_eligible: bool = False,
    ) -> None:
        if not isinstance(retry_eligible, bool):
            raise KimiBenchRunnerError("retry_eligible must be a boolean")
        if status in {COMPLETED, MODEL_PROTOCOL_INCOMPLETE} and retry_eligible:
            raise KimiBenchRunnerError(f"terminal status {status} cannot be retried")
        if status == EXECUTION_INVALID and retry_eligible and (
            failure_category not in RETRYABLE_EXECUTION_FAILURE_CATEGORIES
        ):
            raise KimiBenchRunnerError(
                "execution-invalid retry requires an explicitly reviewed transient category"
            )
        if extra and {"failure_category", "retry_eligible"}.intersection(extra):
            raise KimiBenchRunnerError(
                "transition extra cannot override execution disposition fields"
            )
        record = state["cases"].setdefault(
            plan.case.case_id,
            {
                "case_id": plan.case.case_id,
                "suite": plan.case.suite,
                "attempt": 1,
                "history": [],
                "scoring_status": "NOT_PRODUCED",
            },
        )
        record["status"] = status
        record["reason"] = reason
        record["failure_category"] = failure_category
        record["retry_eligible"] = retry_eligible
        record["history"].append(
            {
                "status": status,
                "at": _utc_now(),
                "reason": reason,
                "failure_category": failure_category,
                "retry_eligible": retry_eligible,
            }
        )
        if extra:
            record.update(dict(extra))
        self._persist_state(state)

    def _not_run(
        self,
        *,
        state: dict[str, Any],
        plan: CasePlan,
        decision: CapabilityDecision,
        reason: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> CaseRunResult:
        extra: dict[str, Any] = {"capability": decision.as_dict()}
        if evidence:
            extra["evidence"] = dict(evidence)
        self._transition(
            state,
            plan,
            "NOT_RUN",
            reason=reason,
            extra=extra,
        )
        return CaseRunResult(
            case_id=plan.case.case_id,
            suite=plan.case.suite,
            outcome="NOT_RUN",
            reason=reason,
            state_path=self.layout.state_path,
            capability=decision,
            evidence=dict(evidence or {}),
            retry_eligible=False,
        )

    def _run_one(
        self,
        *,
        state: dict[str, Any],
        plan: CasePlan,
        execute: bool,
        external_model_execution_authorized: bool,
    ) -> CaseRunResult:
        self._transition(state, plan, "PREFLIGHT")
        dynamic_preflight = (
            self.runtime_preflight_hook is not None
            and execute
            and external_model_execution_authorized
            and plan.launch_eligible
        )
        if dynamic_preflight:
            declared_dynamic = getattr(
                self.runtime_preflight_hook,
                "dynamically_provable_capabilities",
                None,
            )
            if declared_dynamic is not None:
                if (
                    isinstance(declared_dynamic, (str, bytes))
                    or not isinstance(declared_dynamic, Sequence)
                    or any(
                        not isinstance(capability, str)
                        or capability not in CAPABILITIES
                        for capability in declared_dynamic
                    )
                    or len(set(declared_dynamic)) != len(declared_dynamic)
                ):
                    return self._not_run(
                        state=state,
                        plan=plan,
                        decision=CapabilityDecision(
                            status="UNVALIDATED",
                            required_capabilities=plan.required_capabilities,
                            evidence=(
                                "kimi:runtime-dynamic-capability-declaration-invalid",
                            ),
                            reasons=(
                                "Production runtime did not declare a valid set of "
                                "dynamically provable capabilities.",
                            ),
                        ),
                        reason=(
                            "production runtime dynamic-capability declaration is "
                            "invalid; outcome=NOT_RUN"
                        ),
                    )
                try:
                    preliminary = _call_probe(
                        self.capability_source, plan.required_capabilities
                    )
                except Exception as exc:
                    preliminary = CapabilityDecision(
                        status="UNVALIDATED",
                        required_capabilities=plan.required_capabilities,
                        evidence=("kimi:precredential-capability-probe-invalid",),
                        reasons=(
                            "Credential-free capability probe did not produce "
                            "trustworthy evidence: "
                            f"{type(exc).__name__}: {exc}",
                        ),
                    )
                if preliminary.capability_states is not None:
                    required_states = [
                        preliminary.capability_states[capability]
                        for capability in plan.required_capabilities
                    ]
                    expected_status = (
                        "UNSUPPORTED"
                        if "UNSUPPORTED" in required_states
                        else "UNVALIDATED"
                        if "UNVALIDATED" in required_states
                        else "SUPPORTED"
                    )
                    if preliminary.status != expected_status:
                        preliminary = CapabilityDecision(
                            status="UNVALIDATED",
                            required_capabilities=plan.required_capabilities,
                            evidence=(
                                "kimi:precredential-capability-aggregate-invalid",
                            ),
                            reasons=(
                                "Credential-free capability aggregate disagreed "
                                "with its complete tri-state matrix.",
                            ),
                        )
                dynamic_set = set(declared_dynamic)
                if (
                    preliminary.capability_states is None
                    or preliminary.capability_evidence is None
                ):
                    blockers = tuple(plan.required_capabilities)
                else:
                    blockers = tuple(
                        capability
                        for capability in plan.required_capabilities
                        if preliminary.capability_states[capability]
                        == "UNSUPPORTED"
                        or (
                            preliminary.capability_states[capability]
                            == "UNVALIDATED"
                            and capability not in dynamic_set
                        )
                    )
                if blockers:
                    return self._not_run(
                        state=state,
                        plan=plan,
                        decision=preliminary,
                        reason=(
                            "credential-free production preflight found required "
                            "capabilities that the runtime cannot dynamically prove; "
                            "outcome=NOT_RUN; blockers="
                            + ",".join(blockers)
                            + "; "
                            + "; ".join(preliminary.reasons)
                        ),
                        evidence={
                            "precredential_capability_gate": {
                                "blocked": True,
                                "blocking_capabilities": list(blockers),
                                "runtime_hook_started": False,
                                "loopback_port_allocated": False,
                            }
                        },
                    )
            # This placeholder is never used as the launch gate.  The private
            # per-trial runtime must return the final evidence-bound decision
            # after its services have started.
            decision = CapabilityDecision(
                status="UNVALIDATED",
                required_capabilities=plan.required_capabilities,
                evidence=("kimi:runtime-preflight-pending",),
                reasons=("Per-trial runtime preflight has not completed.",),
            )
        else:
            try:
                decision = _call_probe(
                    self.capability_source, plan.required_capabilities
                )
            except Exception as exc:
                decision = CapabilityDecision(
                    status="UNVALIDATED",
                    required_capabilities=plan.required_capabilities,
                    evidence=("kimi:capability-probe-invalid",),
                    reasons=(
                        "Capability probe did not produce trustworthy evidence: "
                        f"{type(exc).__name__}: {exc}",
                    ),
                )
            if decision.status != "SUPPORTED":
                reason = (
                    f"required Kimi capabilities are {decision.status}; "
                    "outcome=NOT_RUN; " + "; ".join(decision.reasons)
                )
                return self._not_run(
                    state=state, plan=plan, decision=decision, reason=reason
                )
        if not plan.launch_eligible:
            reason = (
                "Kimi semantic binding is not launch-eligible; outcome=NOT_RUN; "
                + "; ".join(plan.blocking_reasons)
            )
            return self._not_run(state=state, plan=plan, decision=decision, reason=reason)
        if not execute:
            reason = "dry-run is the default; no materialization or subprocess was started"
            self._transition(
                state,
                plan,
                "DRY_RUN",
                reason=reason,
                extra={"capability": decision.as_dict()},
                failure_category="DRY_RUN_REQUESTED",
                retry_eligible=True,
            )
            return CaseRunResult(
                case_id=plan.case.case_id,
                suite=plan.case.suite,
                outcome="DRY_RUN",
                reason=reason,
                state_path=self.layout.state_path,
                capability=decision,
                failure_category="DRY_RUN_REQUESTED",
                retry_eligible=True,
            )
        if not external_model_execution_authorized:
            return self._not_run(
                state=state,
                plan=plan,
                decision=decision,
                reason=(
                    "--execute requires an independent external-model authorization; "
                    "outcome=NOT_RUN"
                ),
            )
        if (
            not dynamic_preflight
            and (self.materializer is None or self.executor is None)
        ):
            return self._not_run(
                state=state,
                plan=plan,
                decision=decision,
                reason=(
                    "reviewed Kimi materializer/executor is not configured; "
                    "outcome=NOT_RUN"
                ),
            )

        case_layout = self.layout.for_case(plan.case.case_id)
        registry: OwnedProcessRegistry | None = None
        cleanup: Mapping[str, Any] = {"terminated": [], "skipped": []}
        try:
            attempt = int(state["cases"][plan.case.case_id].get("attempt", 1))
            case_layout = self.layout.for_case(plan.case.case_id, attempt=attempt)
            self.layout.initialize_case(case_layout)
            canonical_before = canonical_case_content_record(plan.case.case_dir)[
                "case_content_sha256"
            ]
            if (
                plan.case.case_content_sha256
                and canonical_before != plan.case.case_content_sha256
            ):
                return self._not_run(
                    state=state,
                    plan=plan,
                    decision=decision,
                    reason=(
                        "canonical case drifted from the hash-frozen Kimi inventory; "
                        "outcome=NOT_RUN"
                    ),
                )
            registry_kwargs: dict[str, Any] = {
                "run_id": self.run_id,
                "record_path": case_layout.pid_record,
            }
            if self.process_inspector is not None:
                registry_kwargs["inspector"] = self.process_inspector
            if self.process_terminator is not None:
                registry_kwargs["terminator"] = self.process_terminator
            registry = OwnedProcessRegistry(**registry_kwargs)
            with self.port_lease_factory() as port_lease:
                def run_pipeline(
                    runtime: RuntimePreflight | None,
                ) -> Mapping[str, Any]:
                    nonlocal decision
                    if runtime is not None:
                        decision = runtime.capability
                        states, capability_evidence = _validate_final_capability_gate(
                            plan=plan,
                            decision=decision,
                            capability_states=runtime.capability_states,
                            capability_evidence=runtime.capability_evidence,
                        )
                        callback_url = _validate_callback_url(runtime.callback_url)
                        preexisting_paths = runtime.preexisting_service_paths
                        selected_materializer = runtime.materializer or self.materializer
                        selected_executor = runtime.executor or self.executor
                    else:
                        if (
                            decision.capability_states is None
                            or decision.capability_evidence is None
                        ):
                            raise KimiBenchRunnerError(
                                "non-runtime capability source omitted the complete "
                                "materialization evidence matrix"
                            )
                        states, capability_evidence = _validate_final_capability_gate(
                            plan=plan,
                            decision=decision,
                            capability_states=decision.capability_states,
                            capability_evidence=decision.capability_evidence,
                        )
                        callback_url = (
                            f"http://{port_lease.host}:{port_lease.port}"
                        )
                        preexisting_paths = ()
                        selected_materializer = self.materializer
                        selected_executor = self.executor

                    # This is the final gate.  Service startup may precede it,
                    # but neither materialization nor Kimi execution may.
                    if decision.status != "SUPPORTED":
                        return {
                            "kind": "NOT_RUN",
                            "reason": (
                                f"required Kimi capabilities are {decision.status}; "
                                "outcome=NOT_RUN; " + "; ".join(decision.reasons)
                            ),
                        }
                    if selected_materializer is None or selected_executor is None:
                        return {
                            "kind": "NOT_RUN",
                            "reason": (
                                "reviewed Kimi materializer/executor is not configured; "
                                "outcome=NOT_RUN"
                            ),
                        }

                    materialization_context = MaterializationContext(
                        run_id=self.run_id,
                        case_layout=case_layout,
                        loopback_port=port_lease,
                        capability_states=states,
                        capability_evidence=capability_evidence,
                        callback_url=callback_url,
                        preexisting_service_paths=preexisting_paths,
                    )
                    self._transition(state, plan, "MATERIALIZING")
                    materialized = _call_materializer(
                        selected_materializer,
                        plan,
                        case_layout,
                        materialization_context,
                    )
                    self._validate_materialized(materialized, plan, case_layout)
                    if materialized.launch_disposition != "READY":
                        return {
                            "kind": "NOT_RUN",
                            "reason": (
                                "materialized Kimi semantic plan is not READY; "
                                "outcome=NOT_RUN; "
                                + "; ".join(materialized.launch_reasons)
                            ),
                        }
                    self._transition(state, plan, "RUNNING")
                    context = ExecutionContext(
                        run_id=self.run_id,
                        case_layout=case_layout,
                        process_registry=registry,
                        loopback_port=port_lease,
                    )
                    execution_result = _call_executor(
                        selected_executor, plan, materialized, context
                    )
                    callback_port = urlsplit(callback_url).port
                    if callback_port is None:
                        raise KimiBenchRunnerError(
                            "validated callback URL lost its explicit port"
                        )
                    return {
                        "kind": "EXECUTION",
                        "execution": execution_result,
                        "assigned_port": callback_port,
                        "callback_url": callback_url,
                    }

                runtime_close_evidence: Mapping[str, Any] = {}
                if dynamic_preflight:
                    assert self.runtime_preflight_hook is not None
                    manager = _enter_runtime_preflight(
                        self.runtime_preflight_hook,
                        plan=plan,
                        layout=case_layout,
                        registry=registry,
                        port_lease=port_lease,
                    )
                    pipeline, runtime_close_evidence = _run_with_runtime_preflight(
                        manager, lambda runtime: run_pipeline(runtime)
                    )
                else:
                    pipeline = run_pipeline(None)

                if pipeline.get("kind") == "NOT_RUN":
                    return self._not_run(
                        state=state,
                        plan=plan,
                        decision=decision,
                        reason=str(pipeline["reason"]),
                        evidence=(
                            {"runtime_close": dict(runtime_close_evidence)}
                            if runtime_close_evidence
                            else None
                        ),
                    )
                execution = pipeline.get("execution")
                assigned_port = pipeline.get("assigned_port")
                assigned_callback_url = pipeline.get("callback_url")
                if (
                    not isinstance(execution, ExecutionResult)
                    or not isinstance(assigned_port, int)
                    or not isinstance(assigned_callback_url, str)
                ):
                    raise KimiBenchRunnerError(
                        "runtime execution pipeline returned an invalid result"
                    )
            self._validate_evidence_paths(execution)
            canonical_after = canonical_case_content_record(plan.case.case_dir)[
                "case_content_sha256"
            ]
            if canonical_after != canonical_before:
                raise KimiBenchRunnerError(
                    "canonical case changed during Kimi execution; result is invalid"
                )
            evidence = execution.as_dict()
            evidence.update(
                {
                    "loopback_host": "127.0.0.1",
                    "loopback_port": assigned_port,
                    "callback_url": assigned_callback_url,
                    "canonical_case_content_sha256": canonical_after,
                }
            )
            if runtime_close_evidence:
                evidence["runtime_close"] = dict(runtime_close_evidence)
            if execution.outcome == COMPLETED:
                if isinstance(execution.metadata.get("analysis_pipeline"), Mapping):
                    reason = (
                        "executor completed raw evidence capture and invoked the "
                        "unchanged shared analyzer with hash-pinned Kimi projection; "
                        "the adapter did not interpret or assign a score"
                    )
                else:
                    reason = (
                        "executor completed raw evidence capture; analyzer/scoring "
                        "was not run"
                    )
            elif execution.outcome == MODEL_PROTOCOL_INCOMPLETE:
                reason = (
                    "hard execution evidence attributes a required protocol "
                    "noncompletion to the model; terminal outcome; no score was produced"
                )
            else:
                reason = (
                    "executor reported invalid execution evidence; no score was produced; "
                    f"retry_eligible={str(execution.retry_eligible).lower()}"
                )
            self._transition(
                state,
                plan,
                execution.outcome,
                reason=reason,
                extra={"capability": decision.as_dict(), "evidence": evidence},
                failure_category=execution.failure_category,
                retry_eligible=execution.retry_eligible,
            )
            return CaseRunResult(
                case_id=plan.case.case_id,
                suite=plan.case.suite,
                outcome=execution.outcome,
                reason=reason,
                state_path=self.layout.state_path,
                capability=decision,
                evidence=evidence,
                failure_category=execution.failure_category,
                retry_eligible=execution.retry_eligible,
            )
        except KimiExecutionDispositionError as exc:
            close_evidence = getattr(exc, "_kimi_runtime_close_evidence", None)
            transition_extra: dict[str, Any] = {"capability": decision.as_dict()}
            result_evidence: dict[str, Any] = {}
            if isinstance(close_evidence, Mapping):
                result_evidence["runtime_close"] = dict(close_evidence)
                transition_extra["evidence"] = result_evidence
            if exc.outcome == MODEL_PROTOCOL_INCOMPLETE:
                # A bare exception has no runner-validated raw locator.  The
                # concrete executor must catch controller/normalizer protocol
                # errors and return an evidence-bound ExecutionResult instead.
                outcome = EXECUTION_INVALID
                failure_category = "MODEL_PROTOCOL_DISPOSITION_UNBOUND"
                retry_eligible = False
            else:
                outcome = exc.outcome
                failure_category = exc.failure_category
                retry_eligible = exc.retry_eligible
            reason = (
                "Kimi execution pipeline produced a typed fail-closed disposition: "
                f"{type(exc).__name__}: {exc}"
            )
            self._transition(
                state,
                plan,
                outcome,
                reason=reason,
                extra=transition_extra,
                failure_category=failure_category,
                retry_eligible=retry_eligible,
            )
            return CaseRunResult(
                case_id=plan.case.case_id,
                suite=plan.case.suite,
                outcome=outcome,
                reason=reason,
                state_path=self.layout.state_path,
                capability=decision,
                evidence=result_evidence,
                failure_category=failure_category,
                retry_eligible=retry_eligible,
            )
        except Exception as exc:
            close_evidence = getattr(exc, "_kimi_runtime_close_evidence", None)
            if isinstance(exc, KimiRuntimePreflightError):
                close_evidence = exc.close_evidence
            result_evidence = {}
            transition_extra: dict[str, Any] = {"capability": decision.as_dict()}
            if isinstance(close_evidence, Mapping):
                result_evidence["runtime_close"] = dict(close_evidence)
                transition_extra["evidence"] = result_evidence
            reason = f"Kimi execution pipeline failed closed: {type(exc).__name__}: {exc}"
            self._transition(
                state,
                plan,
                EXECUTION_INVALID,
                reason=reason,
                extra=transition_extra,
                failure_category="EXECUTION_PIPELINE_INVALID",
                retry_eligible=False,
            )
            return CaseRunResult(
                case_id=plan.case.case_id,
                suite=plan.case.suite,
                outcome=EXECUTION_INVALID,
                reason=reason,
                state_path=self.layout.state_path,
                capability=decision,
                evidence=result_evidence,
                failure_category="EXECUTION_PIPELINE_INVALID",
                retry_eligible=False,
            )
        finally:
            if registry is not None:
                cleanup = registry.cleanup()
            lifecycle = {
                "schema_name": "safety_bench_kimi_lifecycle_log",
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": self.run_id,
                "case_id": plan.case.case_id,
                "cleanup": cleanup,
            }
            if case_layout.root.is_dir() and not case_layout.root.is_symlink():
                atomic_write_json(
                    case_layout.root / f"cleanup-kimi-{self.run_id}.json",
                    lifecycle,
                    run_id=self.run_id,
                )

    def _run_selected(
        self,
        cases: Iterable[BenchCase],
        *,
        execute: bool,
        external_model_execution_authorized: bool,
        existing_state: dict[str, Any] | None = None,
    ) -> tuple[CaseRunResult, ...]:
        plans = self.plan_cases(tuple(cases))
        state = existing_state or self._new_state(plans, execute=execute)
        state["execution_requested"] = execute
        for plan in plans:
            previous = state["cases"].get(plan.case.case_id)
            if not isinstance(previous, Mapping):
                raise KimiBenchRunnerError(
                    f"run state lacks a valid case record: {plan.case.case_id}"
                )
            prior_attempt = int(previous.get("attempt", 0))
            if existing_state is None or (
                previous.get("status") == "QUEUED" and prior_attempt == 0
            ):
                previous["attempt"] = 1
            else:
                previous["attempt"] = prior_attempt + 1
        self._persist_state(state)
        return tuple(
            self._run_one(
                state=state,
                plan=plan,
                execute=execute,
                external_model_execution_authorized=external_model_execution_authorized,
            )
            for plan in plans
        )

    def run_case(
        self,
        case_id: str,
        *,
        execute: bool = False,
        external_model_execution_authorized: bool = False,
    ) -> CaseRunResult:
        return self._run_selected(
            (self._select_case(case_id),),
            execute=execute,
            external_model_execution_authorized=external_model_execution_authorized,
        )[0]

    def run_suite(
        self,
        suite: str,
        *,
        execute: bool = False,
        external_model_execution_authorized: bool = False,
    ) -> tuple[CaseRunResult, ...]:
        return self._run_selected(
            self.list_cases(suite=suite),
            execute=execute,
            external_model_execution_authorized=external_model_execution_authorized,
        )

    def run_all(
        self,
        *,
        execute: bool = False,
        external_model_execution_authorized: bool = False,
    ) -> tuple[CaseRunResult, ...]:
        validation = self.validate_inventory()
        if not validation.valid:
            raise KimiBenchRunnerError("cannot run invalid active inventory")
        return self._run_selected(
            self.list_cases(),
            execute=execute,
            external_model_execution_authorized=external_model_execution_authorized,
        )

    def resume(
        self,
        *,
        execute: bool = False,
        external_model_execution_authorized: bool = False,
    ) -> tuple[CaseRunResult, ...]:
        try:
            state = json.loads(self.layout.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KimiBenchRunnerError("no valid Kimi run state is available to resume") from exc
        if (
            state.get("schema_name") != "safety_bench_kimi_run_state"
            or state.get("harness_id") != "kimi"
            or state.get("run_id") != self.run_id
            or not isinstance(state.get("cases"), dict)
        ):
            raise KimiBenchRunnerError("resume state identity is invalid")
        forbidden_state = _forbidden_metadata_paths(state, prefix="state")
        if forbidden_state:
            raise KimiBenchRunnerError(
                "resume state contains analyzer/scoring fields: "
                + ", ".join(sorted(forbidden_state))
            )
        case_order = state.get("case_order")
        if (
            not isinstance(case_order, list)
            or any(not isinstance(case_id, str) or not case_id for case_id in case_order)
            or len(case_order) != len(set(case_order))
        ):
            raise KimiBenchRunnerError(
                "resume case_order must contain unique non-empty case identifiers"
            )
        state_schema_version = state.get("schema_version")
        if state_schema_version not in {1, 2}:
            raise KimiBenchRunnerError("resume state schema version is unsupported")
        pending_ids: list[str] = []
        for case_id in case_order:
            record = state["cases"].get(case_id)
            if not isinstance(record, Mapping):
                if state_schema_version == 1:
                    # Old state never explicitly authorized a retry.
                    continue
                raise KimiBenchRunnerError(
                    f"resume state lacks a case record: {case_id}"
                )
            status = record.get("status")
            retry_eligible = record.get("retry_eligible", False)
            if not isinstance(retry_eligible, bool):
                raise KimiBenchRunnerError(
                    f"resume state has non-boolean retry_eligible: {case_id}"
                )
            if status in {COMPLETED, MODEL_PROTOCOL_INCOMPLETE}:
                if retry_eligible:
                    raise KimiBenchRunnerError(
                        f"terminal case cannot be retry-eligible: {case_id}"
                    )
                continue
            if not retry_eligible:
                continue
            if status == EXECUTION_INVALID:
                category = record.get("failure_category")
                if category not in RETRYABLE_EXECUTION_FAILURE_CATEGORIES:
                    raise KimiBenchRunnerError(
                        "resume state requests an unreviewed execution-invalid retry: "
                        f"{case_id}"
                    )
            elif status not in {"QUEUED", "DRY_RUN"}:
                raise KimiBenchRunnerError(
                    f"resume state requests retry from a non-resumable status: {case_id}"
                )
            pending_ids.append(case_id)
        current = {case.case_id: case for case in self.list_cases()}
        if any(case_id not in current for case_id in pending_ids):
            raise KimiBenchRunnerError("resume state references a non-active case")
        pending = tuple(current[case_id] for case_id in pending_ids)
        if not pending:
            return ()
        return self._run_selected(
            pending,
            execute=execute,
            external_model_execution_authorized=external_model_execution_authorized,
            existing_state=state,
        )


def default_runner(*, repo_root: Path, result_root: Path, run_id: str) -> KimiBenchRunner:
    """Construct the safe CLI runner with version-scoped capability evidence.

    The concrete model executor remains deliberately unconfigured.  Native
    capability probes can therefore improve the NOT_RUN explanation, but can
    never start a subprocess or bypass the per-trial workspace isolation gate.
    Matched-control isolation remains a separate, deferred control workflow.
    """

    from .adapter import KimiHarnessAdapter

    capability_source = KimiHarnessAdapter(
        run_id=run_id,
        state_root=(
            Path(result_root).resolve()
            / f"kimi-capability-state-{run_id}"
        ),
    )

    return KimiBenchRunner(
        repo_root=repo_root,
        result_root=result_root,
        run_id=run_id,
        inventory=ManifestInventory(repo_root),
        plan_builder=DefaultPlanBuilder(),
        capability_source=capability_source,
    )
