from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

import pytest

from infra.cross_harness.contract import CAPABILITIES
from infra.cross_harness.adapters.kimi.cli import _result_exit_code, build_parser, main
from infra.cross_harness.adapters.kimi.disposition import (
    KimiExecutionInvalidError,
    KimiModelProtocolIncompleteError,
)
from infra.cross_harness.adapters.kimi.lifecycle import (
    KimiLifecycleError,
    OwnedProcessRegistry,
    ProcessSnapshot,
    RunLayout,
    case_attempt_component,
)
from infra.cross_harness.adapters.kimi.runner import (
    BenchMaterializerBridge,
    BenchCase,
    CapabilityDecision,
    CasePlan,
    DefaultPlanBuilder,
    default_runner,
    ExecutionResult,
    InventoryValidation,
    KimiBenchRunner,
    KimiBenchRunnerError,
    ManifestInventory,
    MaterializedCase,
    MaterializationContext,
    RuntimePreflight,
    StageSpec,
    UnvalidatedCapabilitySource,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


class StaticInventory:
    def __init__(self, cases: Sequence[BenchCase]) -> None:
        self.cases = tuple(cases)

    def list_cases(self) -> Sequence[BenchCase]:
        return self.cases

    def validate(self) -> InventoryValidation:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.suite] = counts.get(case.suite, 0) + 1
        return InventoryValidation(True, len(self.cases), counts)


class SupportedCapabilities:
    def probe(self, required_capabilities: Sequence[str]) -> CapabilityDecision:
        states = {capability: "SUPPORTED" for capability in CAPABILITIES}
        evidence = {
            capability: (f"fixture:capability-evidence:{capability}",)
            for capability in CAPABILITIES
        }
        return CapabilityDecision(
            status="SUPPORTED",
            required_capabilities=tuple(required_capabilities),
            evidence=("fixture:capability-evidence",),
            reasons=(),
            capability_states=states,
            capability_evidence=evidence,
        )


class FakeMaterializer:
    def __init__(self) -> None:
        self.calls = 0

    def materialize(self, plan: CasePlan, layout, context) -> MaterializedCase:
        assert context.loopback_port.port == FakePortLease.port
        self.calls += 1
        for directory in (
            layout.workspace,
            layout.config,
            layout.trace,
            layout.result,
            layout.session,
            layout.cache,
            layout.artifact,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        manifest = layout.root / f"materialization-kimi-{layout.run_id}.json"
        manifest.write_text(
            json.dumps({"harness_id": "kimi", "case_id": plan.case.case_id}) + "\n",
            encoding="utf-8",
        )
        stage_runtime_paths = []
        for stage in plan.stages:
            suffix = f"kimi-{layout.run_id}-stage-{stage.index:03d}"
            stage_root = layout.root / f"runtime-{suffix}"
            paths = {
                "index": stage.index,
                "name": stage.name,
                "workspace": str(layout.workspace),
                "home": str(stage_root / f"home-{suffix}"),
                "kimi_home": str(stage_root / f"config-{suffix}"),
                "trace": str(stage_root / f"trace-{suffix}.jsonl"),
                "wire": str(stage_root / f"wire-{suffix}.jsonl"),
                "result": str(stage_root / f"result-{suffix}.json"),
                "session": str(stage_root / f"session-{suffix}"),
                "pid_record": str(stage_root / f"pid-{suffix}.json"),
                "cache": str(stage_root / f"cache-{suffix}"),
                "artifact": str(stage_root / f"artifact-{suffix}"),
            }
            for key in ("home", "kimi_home", "session", "cache", "artifact"):
                Path(paths[key]).mkdir(parents=True, exist_ok=True)
            stage_runtime_paths.append(paths)
        return MaterializedCase(
            case_id=plan.case.case_id,
            root=layout.root,
            workspace=layout.workspace,
            config=layout.config,
            trace=layout.trace,
            result=layout.result,
            session=layout.session,
            cache=layout.cache,
            artifact=layout.artifact,
            manifest_path=manifest,
            stage_runtime_paths=tuple(stage_runtime_paths),
        )


class FakeExecutor:
    def __init__(self) -> None:
        self.calls = 0
        self.observed_port: int | None = None

    def execute(self, plan, materialized, context) -> ExecutionResult:
        self.calls += 1
        self.observed_port = context.loopback_port.port
        stdout = materialized.trace / f"stdout-kimi-{context.run_id}.jsonl"
        wire = materialized.trace / f"wire-kimi-{context.run_id}.jsonl"
        event_ir = materialized.trace / f"event-ir-kimi-{context.run_id}.jsonl"
        stdout.write_text('{"role":"assistant"}\n', encoding="utf-8")
        wire.write_text('{"type":"turn_begin"}\n', encoding="utf-8")
        event_ir.write_text('{"event_type":"process.start"}\n', encoding="utf-8")
        return ExecutionResult(
            outcome="COMPLETED",
            return_code=0,
            raw_stdout_path=stdout,
            raw_wire_path=wire,
            event_ir_path=event_ir,
            metadata={"stage_count": len(plan.stages)},
        )


class FakePortLease:
    """Network-free stand-in; production uses an OS-assigned loopback socket."""

    host = "127.0.0.1"
    port = 43123

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class FakeRuntimeHook:
    def __init__(
        self,
        events: list[str],
        *,
        status: str = "SUPPORTED",
        materializer=None,
        executor=None,
        close_error: Exception | None = None,
        mutate_states_after_enter: bool = False,
    ) -> None:
        self.events = events
        self.status = status
        self.materializer = materializer
        self.executor = executor
        self.close_error = close_error
        self.mutate_states_after_enter = mutate_states_after_enter
        self.calls = 0

    def __call__(self, *, plan, layout, process_registry, loopback_port):
        del process_registry
        self.calls += 1
        hook = self

        class Manager:
            def __enter__(self):
                hook.events.append("service")
                service = layout.root / f"services-kimi-{layout.run_id}"
                service.mkdir(mode=0o700)
                marker = service / "attestation.json"
                marker.write_text('{"ready":true}\n', encoding="utf-8")
                marker.chmod(0o600)
                states = {
                    capability: "SUPPORTED" for capability in CAPABILITIES
                }
                if hook.status != "SUPPORTED":
                    states[plan.required_capabilities[0]] = hook.status
                evidence = {
                    capability: (f"fixture:runtime:{capability}",)
                    for capability in CAPABILITIES
                }
                decision = CapabilityDecision(
                    status=hook.status,
                    required_capabilities=plan.required_capabilities,
                    evidence=("fixture:runtime:aggregate",),
                    reasons=(
                        ()
                        if hook.status == "SUPPORTED"
                        else ("runtime evidence did not validate the required surface",)
                    ),
                )
                self.close_evidence: dict[str, object] = {}
                self.runtime = RuntimePreflight(
                    capability=decision,
                    capability_states=states,
                    capability_evidence=evidence,
                    callback_url=(
                        f"http://{loopback_port.host}:{loopback_port.port}/callback"
                    ),
                    preexisting_service_paths=(service,),
                    materializer=hook.materializer,
                    executor=hook.executor,
                    close_evidence=self.close_evidence,
                )
                if hook.mutate_states_after_enter:
                    del self.runtime.capability_states[plan.required_capabilities[0]]
                return self.runtime

            def __exit__(self, *_):
                hook.events.append("close")
                if hook.close_error is not None:
                    raise hook.close_error
                self.close_evidence.update(
                    {
                        "closed": True,
                        "locator": f"fixture:runtime-close:{layout.run_id}",
                    }
                )
                return False

        return Manager()


@pytest.fixture
def bench_case(tmp_path: Path) -> BenchCase:
    case_dir = tmp_path / "repo" / "runs" / "active" / "fixture" / "case_001"
    workspace = case_dir / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "input.txt").write_text("immutable canonical input\n", encoding="utf-8")
    meta = case_dir / "case_meta.json"
    meta.write_text('{"case_id":"fixture_case"}\n', encoding="utf-8")
    return BenchCase(
        case_id="fixture_case",
        suite="fixture_suite",
        case_dir=case_dir,
        case_meta_sha256="0" * 64,
        stages=(StageSpec(0, "attack"), StageSpec(1, "trigger")),
        metadata={
            "_kimi_inventory_required_capabilities": [
                "headless_execution",
                "structured_trace",
                "workspace_isolation",
                "fresh_process",
            ],
            "_kimi_inventory_binding_kind": "neutral",
            "_kimi_inventory_execution_class": "unit_fixture",
            "_kimi_inventory_binding_usable": True,
            "_kimi_inventory_harness_restrictions": [],
        },
    )


def make_runner(
    tmp_path: Path,
    bench_case: BenchCase,
    *,
    capability_source=None,
    materializer=None,
    executor=None,
    runtime_preflight_hook=None,
    port_lease_factory=FakePortLease,
) -> KimiBenchRunner:
    return KimiBenchRunner(
        repo_root=tmp_path / "repo",
        result_root=tmp_path / "external-results",
        run_id="unit-001",
        inventory=StaticInventory((bench_case,)),
        plan_builder=DefaultPlanBuilder(),
        capability_source=capability_source or UnvalidatedCapabilitySource(),
        materializer=materializer,
        executor=executor,
        port_lease_factory=port_lease_factory,
        runtime_preflight_hook=runtime_preflight_hook,
    )


def test_manifest_inventory_covers_exact_active_328() -> None:
    inventory = ManifestInventory(REPO_ROOT)
    validation = inventory.validate()

    assert validation.valid, validation.errors
    assert validation.active_case_count == 328
    assert sum(validation.suite_counts.values()) == 328
    assert len({case.case_id for case in inventory.list_cases()}) == 328


def test_reviewed_bench_materializer_bridge_is_runner_compatible(
    tmp_path: Path,
) -> None:
    inventory = ManifestInventory(REPO_ROOT)
    case = next(
        item for item in inventory.list_cases() if item.suite == "v2_skill_runtime"
    )
    executor = FakeExecutor()
    runner = KimiBenchRunner(
        repo_root=REPO_ROOT,
        result_root=tmp_path / "external-results",
        run_id="bridge-001",
        inventory=inventory,
        plan_builder=DefaultPlanBuilder(),
        capability_source=SupportedCapabilities(),
        materializer=BenchMaterializerBridge(repo_root=REPO_ROOT),
        executor=executor,
        port_lease_factory=FakePortLease,
    )

    result = runner.run_case(
        case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "COMPLETED", result.reason
    assert executor.calls == 1
    state = json.loads(runner.layout.state_path.read_text(encoding="utf-8"))
    manifests = list(runner.layout.run_dir.rglob("manifest-kimi-bridge-001.json"))
    assert len(manifests) == 1 and manifests[0].is_file()
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert set(manifest["runtime_capability_states"]) == set(CAPABILITIES)
    assert set(manifest["runtime_capability_evidence"]) == set(CAPABILITIES)
    assert all(
        locators == [f"fixture:capability-evidence:{capability}"]
        for capability, locators in manifest["runtime_capability_evidence"].items()
    )
    assert state["cases"][case.case_id]["scoring_status"] == "NOT_PRODUCED"


def test_bench_bridge_preserves_context_state_instead_of_inventing_support(
    tmp_path: Path,
) -> None:
    inventory = ManifestInventory(REPO_ROOT)
    case = next(
        item for item in inventory.list_cases() if item.suite == "v2_skill_runtime"
    )
    run_layout = RunLayout(
        REPO_ROOT, tmp_path / "external-results", "bridge-context-001"
    )
    case_layout = run_layout.for_case(case.case_id)
    run_layout.initialize_case(case_layout)
    plan = DefaultPlanBuilder().build(case, case_layout)
    states = {capability: "SUPPORTED" for capability in CAPABILITIES}
    states["skill_activation_trace"] = "UNVALIDATED"
    evidence = {
        capability: (f"fixture:bridge-context:{capability}",)
        for capability in CAPABILITIES
    }
    with FakePortLease() as lease:
        context = MaterializationContext(
            run_id="bridge-context-001",
            case_layout=case_layout,
            loopback_port=lease,
            capability_states=states,
            capability_evidence=evidence,
            callback_url=f"http://{lease.host}:{lease.port}/callback",
        )
        materialized = BenchMaterializerBridge(repo_root=REPO_ROOT).materialize(
            plan, case_layout, context
        )

    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    assert materialized.launch_disposition == "CONDITIONAL"
    assert manifest["runtime_capability_states"]["skill_activation_trace"] == (
        "UNVALIDATED"
    )
    assert "unvalidated capability: skill_activation_trace" in (
        materialized.launch_reasons
    )


def test_untranslated_t2_binding_is_not_run_before_materialization(
    tmp_path: Path,
) -> None:
    inventory = ManifestInventory(REPO_ROOT)
    case = next(
        item
        for item in inventory.list_cases()
        if item.metadata.get("_kimi_inventory_execution_class")
        == "requires_kimi_native_memory_to_skill"
    )
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = KimiBenchRunner(
        repo_root=REPO_ROOT,
        result_root=tmp_path / "external-results",
        run_id="restriction-001",
        inventory=inventory,
        plan_builder=DefaultPlanBuilder(),
        capability_source=SupportedCapabilities(),
        materializer=materializer,
        executor=executor,
        port_lease_factory=FakePortLease,
    )

    result = runner.run_case(
        case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "NOT_RUN"
    assert "not launch-eligible" in result.reason
    assert materializer.calls == executor.calls == 0


def test_reviewed_m_binding_is_usable_without_broadening_canonical_row(
    tmp_path: Path,
) -> None:
    inventory = ManifestInventory(REPO_ROOT)
    case = next(
        item for item in inventory.list_cases() if item.suite == "T3_subagent_poisoning"
    )
    assert case.metadata["_kimi_inventory_harness_restrictions"] == ["claude"]
    assert case.metadata["_kimi_inventory_semantic_binding"] == {
        "binding_class": "M",
        "variant_kind": "native",
        "translation": "kimi_agent_coder_exact_artifact_v1",
        "status": "reviewed_materializable",
    }
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = KimiBenchRunner(
        repo_root=REPO_ROOT,
        result_root=tmp_path / "external-results",
        run_id="semantic-binding-001",
        inventory=inventory,
        plan_builder=DefaultPlanBuilder(),
        capability_source=SupportedCapabilities(),
        materializer=materializer,
        executor=executor,
        port_lease_factory=FakePortLease,
    )

    result = runner.run_case(
        case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "COMPLETED", result.reason
    assert materializer.calls == executor.calls == 1


def test_run_layout_is_kimi_scoped_and_rejects_repository_runs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "runs" / "active").mkdir(parents=True)
    layout = RunLayout(repo, tmp_path / "external", "isolation-01")
    case = layout.for_case("case/with unsafe chars")

    for path in case.owned_paths():
        assert "kimi" in str(path)
        assert "isolation-01" in str(path)
    with pytest.raises(KimiLifecycleError, match="external"):
        RunLayout(repo, repo / "runs" / "kimi-results", "bad-root")
    with pytest.raises(KimiLifecycleError, match="user-state"):
        RunLayout(repo, tmp_path / ".claude" / "results", "bad-state")


def test_unvalidated_capability_is_not_run_before_materialization(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        materializer=materializer,
        executor=executor,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "NOT_RUN"
    assert materializer.calls == 0
    assert executor.calls == 0
    state = json.loads(runner.layout.state_path.read_text(encoding="utf-8"))
    assert state["scoring_status"] == "NOT_PRODUCED"
    assert "oracle" not in state


def test_malformed_capability_evidence_fails_closed_before_materialization(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    class MalformedCapabilities:
        def probe(self, required_capabilities):
            return object()

    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=MalformedCapabilities(),
        materializer=materializer,
        executor=executor,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "NOT_RUN"
    assert result.capability.status == "UNVALIDATED"
    assert materializer.calls == executor.calls == 0


def test_supported_dry_run_never_materializes_or_executes(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=materializer,
        executor=executor,
    )

    result = runner.run_case(bench_case.case_id)

    assert result.outcome == "DRY_RUN"
    assert materializer.calls == executor.calls == 0


def test_static_dry_run_never_starts_runtime_preflight(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []
    hook = FakeRuntimeHook(events)
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=FakeExecutor(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(bench_case.case_id)

    assert result.outcome == "DRY_RUN"
    assert hook.calls == 0
    assert events == []


def test_production_precredential_gate_blocks_before_port_or_runtime_hook(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    metadata = dict(bench_case.metadata)
    metadata["_kimi_inventory_required_capabilities"] = [
        *metadata["_kimi_inventory_required_capabilities"],
        "control_isolation",
    ]
    gated_case = BenchCase(
        case_id=bench_case.case_id,
        suite=bench_case.suite,
        case_dir=bench_case.case_dir,
        case_meta_sha256=bench_case.case_meta_sha256,
        stages=bench_case.stages,
        metadata=metadata,
    )

    class PreliminaryCapabilities:
        class Item:
            def __init__(self, capability, status):
                self.capability = capability
                self.status = status
                self.evidence = (f"fixture:precredential:{capability}",)

        class SharedProbe:
            def __init__(self, required_capabilities):
                self.status = "UNVALIDATED"
                self.required_capabilities = tuple(required_capabilities)
                self.evidence = ("fixture:precredential:aggregate",)
                self.reasons = (
                    "workspace isolation needs a live launcher self-test",
                    "matched-control execution receipts are absent",
                )

        def probe_capabilities(self, required_capabilities):
            states = {capability: "SUPPORTED" for capability in CAPABILITIES}
            states["workspace_isolation"] = "UNVALIDATED"
            states["control_isolation"] = "UNVALIDATED"
            self.last_capability_matrix = {
                capability: self.Item(capability, states[capability])
                for capability in CAPABILITIES
            }
            return self.SharedProbe(required_capabilities)

    class ProductionLikeHook(FakeRuntimeHook):
        dynamically_provable_capabilities = ("workspace_isolation",)

    class ForbiddenPortLease:
        def __init__(self):
            raise AssertionError("loopback port must not be allocated")

    events: list[str] = []
    hook = ProductionLikeHook(events)
    runner = make_runner(
        tmp_path,
        gated_case,
        capability_source=PreliminaryCapabilities(),
        runtime_preflight_hook=hook,
        port_lease_factory=ForbiddenPortLease,
    )

    result = runner.run_case(
        gated_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "NOT_RUN"
    assert "control_isolation" in result.reason
    assert hook.calls == 0
    assert events == []
    assert result.evidence["precredential_capability_gate"] == {
        "blocked": True,
        "blocking_capabilities": ["control_isolation"],
        "runtime_hook_started": False,
        "loopback_port_allocated": False,
    }


def test_dynamic_runtime_orders_service_gate_materialize_execute_close(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []

    class OrderedMaterializer(FakeMaterializer):
        def materialize(self, plan, layout, context):
            events.append("materialize")
            assert set(context.capability_states) == set(CAPABILITIES)
            assert set(context.capability_evidence) == set(CAPABILITIES)
            assert context.callback_url.endswith("/callback")
            assert len(context.preexisting_service_paths) == 1
            return super().materialize(plan, layout, context)

    class OrderedExecutor(FakeExecutor):
        def execute(self, plan, materialized, context):
            events.append("execute")
            return super().execute(plan, materialized, context)

    materializer = OrderedMaterializer()
    executor = OrderedExecutor()
    hook = FakeRuntimeHook(
        events, materializer=materializer, executor=executor
    )
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=UnvalidatedCapabilitySource(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "COMPLETED", result.reason
    assert events == ["service", "materialize", "execute", "close"]
    assert result.evidence["runtime_close"]["closed"] is True
    assert materializer.calls == executor.calls == hook.calls == 1


def test_dynamic_unvalidated_gate_closes_without_materialization(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    hook = FakeRuntimeHook(
        events,
        status="UNVALIDATED",
        materializer=materializer,
        executor=executor,
    )
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "NOT_RUN"
    assert events == ["service", "close"]
    assert materializer.calls == executor.calls == 0
    assert result.evidence["runtime_close"]["closed"] is True
    assert not list(runner.layout.run_dir.rglob("materialization-kimi-*.json"))


def test_dynamic_partial_capability_map_fails_before_materialization_and_closes(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    hook = FakeRuntimeHook(
        events,
        materializer=materializer,
        executor=executor,
        mutate_states_after_enter=True,
    )
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "EXECUTION_INVALID"
    assert "incomplete" in result.reason
    assert events == ["service", "close"]
    assert materializer.calls == executor.calls == 0
    assert result.evidence["runtime_close"]["closed"] is True
    assert not list(runner.layout.run_dir.rglob("materialization-kimi-*.json"))


def test_runtime_close_error_overrides_success_as_execution_invalid(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    hook = FakeRuntimeHook(
        events,
        materializer=materializer,
        executor=executor,
        close_error=RuntimeError("exact close attestation unavailable"),
    )
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "EXECUTION_INVALID"
    assert result.failure_category == "EXECUTION_PIPELINE_INVALID"
    assert "runtime preflight close failed" in result.reason
    assert result.evidence["runtime_close"] == {
        "closed": False,
        "error_type": "RuntimeError",
    }
    assert events == ["service", "close"]
    assert materializer.calls == executor.calls == 1


def test_runtime_close_error_preserves_exact_factory_evidence(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    close_error = RuntimeError("exact production close failed")
    close_error.close_evidence = {  # type: ignore[attr-defined]
        "schema_name": "safety_bench_kimi_runtime_close_evidence",
        "closed": False,
        "run_id": "runner-test",
        "errors": ["callback_collector_close:RuntimeError"],
    }
    hook = FakeRuntimeHook(
        events,
        materializer=materializer,
        executor=executor,
        close_error=close_error,
    )
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "EXECUTION_INVALID"
    assert result.evidence["runtime_close"] == close_error.close_evidence  # type: ignore[attr-defined]
    assert events == ["service", "close"]
    assert materializer.calls == executor.calls == 1


def test_unauthorized_execution_does_not_create_runtime_hook(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    events: list[str] = []
    hook = FakeRuntimeHook(events)
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=FakeExecutor(),
        runtime_preflight_hook=hook,
    )

    result = runner.run_case(bench_case.case_id, execute=True)

    assert result.outcome == "NOT_RUN"
    assert hook.calls == 0
    assert events == []


def test_execute_without_independent_authorization_is_not_run(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=materializer,
        executor=executor,
    )

    result = runner.run_case(bench_case.case_id, execute=True)

    assert result.outcome == "NOT_RUN"
    assert "authorization" in result.reason
    assert materializer.calls == executor.calls == 0


def test_explicit_authorized_execution_preserves_raw_evidence_without_scoring(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    canonical_before = (bench_case.case_dir / "workspace" / "input.txt").read_bytes()
    materializer = FakeMaterializer()
    executor = FakeExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=materializer,
        executor=executor,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "COMPLETED"
    assert materializer.calls == executor.calls == 1
    assert executor.observed_port is not None and executor.observed_port > 0
    assert result.evidence["raw_stdout_path"].endswith(".jsonl")
    assert result.evidence["raw_wire_path"].endswith(".jsonl")
    assert result.evidence["event_ir_path"].endswith(".jsonl")
    assert case_attempt_component(bench_case.case_id, attempt=1) in Path(
        result.evidence["raw_stdout_path"]
    ).parts
    assert (bench_case.case_dir / "workspace" / "input.txt").read_bytes() == canonical_before
    state_text = runner.layout.state_path.read_text(encoding="utf-8")
    assert '"scoring_status": "NOT_PRODUCED"' in state_text
    assert "progress_node" not in state_text
    assert "oracle_path" not in state_text
    state = json.loads(state_text)
    assert state["cases"][bench_case.case_id]["attempt"] == 1
    assert state["cases"][bench_case.case_id]["retry_eligible"] is False


def test_resume_replans_and_reprobes_incomplete_case(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    first = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
    )
    assert first.run_case(bench_case.case_id).outcome == "DRY_RUN"

    materializer = FakeMaterializer()
    executor = FakeExecutor()
    resumed = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=materializer,
        executor=executor,
    )
    results = resumed.resume(
        execute=True,
        external_model_execution_authorized=True,
    )

    assert [result.outcome for result in results] == ["COMPLETED"]
    assert case_attempt_component(bench_case.case_id, attempt=2) in Path(
        results[0].evidence["raw_stdout_path"]
    ).parts
    state = json.loads(resumed.layout.state_path.read_text(encoding="utf-8"))
    assert state["cases"][bench_case.case_id]["attempt"] == 2


def test_resume_rejects_tampered_scoring_state(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
    )
    assert runner.run_case(bench_case.case_id).outcome == "DRY_RUN"
    state = json.loads(runner.layout.state_path.read_text(encoding="utf-8"))
    state["cases"][bench_case.case_id]["progress_node"] = "N5b"
    runner.layout.state_path.write_text(json.dumps(state) + "\n", encoding="utf-8")

    with pytest.raises(KimiBenchRunnerError, match="analyzer/scoring"):
        runner.resume()


def test_executor_cannot_smuggle_scored_oracle_fields(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    class ScoringExecutor:
        def execute(self, *_):
            return ExecutionResult(
                outcome="COMPLETED",
                return_code=0,
                raw_stdout_path=None,
                raw_wire_path=None,
                event_ir_path=None,
                metadata={"progress_node": "N5b"},
            )

    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=ScoringExecutor(),
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "EXECUTION_INVALID"
    assert result.failure_category == "EXECUTION_PIPELINE_INVALID"
    assert result.retry_eligible is False
    assert "scoring fields" in result.reason


def test_model_protocol_incomplete_is_terminal_and_never_resumed(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    class ProtocolExecutor(FakeExecutor):
        def execute(self, plan, materialized, context):
            captured = super().execute(plan, materialized, context)
            return ExecutionResult(
                outcome="MODEL_PROTOCOL_INCOMPLETE",
                return_code=0,
                raw_stdout_path=captured.raw_stdout_path,
                raw_wire_path=captured.raw_wire_path,
                event_ir_path=None,
                failure_category="MODEL_PROTOCOL_DEVIATION",
            )

    executor = ProtocolExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=executor,
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "MODEL_PROTOCOL_INCOMPLETE"
    assert result.retry_eligible is False
    assert runner.resume(
        execute=True,
        external_model_execution_authorized=True,
    ) == ()
    assert executor.calls == 1
    state = json.loads(runner.layout.state_path.read_text(encoding="utf-8"))
    record = state["cases"][bench_case.case_id]
    assert record["status"] == "MODEL_PROTOCOL_INCOMPLETE"
    assert record["retry_eligible"] is False
    assert record["attempt"] == 1


def test_unbound_typed_model_protocol_exception_is_execution_invalid(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    class ProtocolExecutor:
        def execute(self, *_):
            raise KimiModelProtocolIncompleteError(
                "direct trace proves the required neutral handoff was skipped"
            )

    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=ProtocolExecutor(),
    )

    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )

    assert result.outcome == "EXECUTION_INVALID"
    assert result.failure_category == "MODEL_PROTOCOL_DISPOSITION_UNBOUND"
    assert result.retry_eligible is False


def test_only_explicit_timeout_category_is_retryable_and_gets_new_attempt(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    class TimeoutThenCompleteExecutor(FakeExecutor):
        def execute(self, plan, materialized, context) -> ExecutionResult:
            if self.calls == 0:
                self.calls += 1
                return ExecutionResult(
                    outcome="EXECUTION_INVALID",
                    return_code=-15,
                    raw_stdout_path=None,
                    raw_wire_path=None,
                    event_ir_path=None,
                    failure_category="PROVIDER_TIMEOUT",
                    retry_eligible=True,
                )
            return super().execute(plan, materialized, context)

    executor = TimeoutThenCompleteExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=executor,
    )

    first = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )
    assert first.outcome == "EXECUTION_INVALID"
    assert first.failure_category == "PROVIDER_TIMEOUT"
    assert first.retry_eligible is True

    retried = runner.resume(
        execute=True,
        external_model_execution_authorized=True,
    )
    assert [item.outcome for item in retried] == ["COMPLETED"]
    assert case_attempt_component(bench_case.case_id, attempt=2) in Path(
        retried[0].evidence["raw_stdout_path"]
    ).parts
    state = json.loads(runner.layout.state_path.read_text(encoding="utf-8"))
    assert state["cases"][bench_case.case_id]["attempt"] == 2
    assert state["cases"][bench_case.case_id]["retry_eligible"] is False


def test_non_transient_invalid_and_unreviewed_retry_are_fail_closed(
    tmp_path: Path, bench_case: BenchCase
) -> None:
    class InvalidExecutor:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, *_):
            self.calls += 1
            raise KimiExecutionInvalidError(
                "captured trace hash changed",
                failure_category="TRACE_CORRUPTION",
            )

    executor = InvalidExecutor()
    runner = make_runner(
        tmp_path,
        bench_case,
        capability_source=SupportedCapabilities(),
        materializer=FakeMaterializer(),
        executor=executor,
    )
    result = runner.run_case(
        bench_case.case_id,
        execute=True,
        external_model_execution_authorized=True,
    )
    assert result.outcome == "EXECUTION_INVALID"
    assert result.retry_eligible is False
    assert runner.resume(
        execute=True,
        external_model_execution_authorized=True,
    ) == ()
    assert executor.calls == 1

    with pytest.raises(ValueError, match="explicitly reviewed transient"):
        ExecutionResult(
            outcome="EXECUTION_INVALID",
            return_code=1,
            raw_stdout_path=None,
            raw_wire_path=None,
            event_ir_path=None,
            failure_category="TRACE_CORRUPTION",
            retry_eligible=True,
        )
    with pytest.raises(ValueError, match="directly captured stdout and wire"):
        ExecutionResult(
            outcome="MODEL_PROTOCOL_INCOMPLETE",
            return_code=0,
            raw_stdout_path=None,
            raw_wire_path=None,
            event_ir_path=None,
            failure_category="MODEL_PROTOCOL_DEVIATION",
        )


def test_cli_exit_codes_preserve_non_scoring_execution_dispositions() -> None:
    class Result:
        def __init__(self, outcome: str) -> None:
            self.outcome = outcome

    assert _result_exit_code((Result("COMPLETED"),)) == 0
    assert _result_exit_code((Result("MODEL_PROTOCOL_INCOMPLETE"),)) == 6
    assert _result_exit_code((Result("EXECUTION_INVALID"),)) == 4


def test_pid_cleanup_uses_run_ownership_not_process_name(tmp_path: Path) -> None:
    snapshots = {
        101: ProcessSnapshot(
            "start-a",
            {
                "SAFETY_BENCH_HARNESS": "kimi",
                "SAFETY_BENCH_RUN_ID": "owner-a",
            },
            ("arbitrary-process",),
        ),
        202: ProcessSnapshot(
            "start-b",
            {
                "SAFETY_BENCH_HARNESS": "kimi",
                "SAFETY_BENCH_RUN_ID": "owner-b",
            },
            ("kimi",),
        ),
    }
    terminated: list[int] = []
    registry = OwnedProcessRegistry(
        run_id="owner-a",
        record_path=tmp_path / "pids-kimi-owner-a.json",
        inspector=snapshots.get,
        terminator=terminated.append,
    )
    registry.register(101, role="mcp")
    cleanup = registry.cleanup()

    assert cleanup["terminated"] == [101]
    assert terminated == [101]
    assert 202 not in terminated


def test_pid_reuse_or_owner_drift_is_never_terminated(tmp_path: Path) -> None:
    current = {
        "value": ProcessSnapshot(
            "start-a",
            {
                "SAFETY_BENCH_HARNESS": "kimi",
                "SAFETY_BENCH_RUN_ID": "owner-a",
            },
            ("server",),
        )
    }
    terminated: list[int] = []
    registry = OwnedProcessRegistry(
        run_id="owner-a",
        record_path=tmp_path / "pids-kimi-owner-a.json",
        inspector=lambda _: current["value"],
        terminator=terminated.append,
    )
    registry.register(303, role="mcp")
    current["value"] = ProcessSnapshot(
        "reused-start",
        {
            "SAFETY_BENCH_HARNESS": "kimi",
            "SAFETY_BENCH_RUN_ID": "owner-a",
        },
        ("server",),
    )

    cleanup = registry.cleanup()

    assert terminated == []
    assert cleanup["skipped"] == [{"pid": 303, "reason": "start_time_mismatch"}]


def test_cli_exposes_required_commands_and_validate_is_read_only(
    tmp_path: Path, capsys
) -> None:
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices
    assert {
        "list",
        "validate",
        "plan",
        "run-case",
        "run-suite",
        "run-all",
        "resume",
    }.issubset(commands)

    result_root = tmp_path / "external"
    exit_code = main(
        [
            "--repo-root",
            str(REPO_ROOT),
            "--result-root",
            str(result_root),
            "validate",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["active_case_count"] == 328
    assert not result_root.exists()

    rejected = main(
        [
            "--repo-root",
            str(REPO_ROOT),
            "--result-root",
            str(REPO_ROOT / "runs" / "forbidden-kimi-output"),
            "validate",
        ]
    )
    rejected_output = json.loads(capsys.readouterr().out)
    assert rejected == 2
    assert rejected_output["error"] == "KimiLifecycleError"


def test_default_runner_uses_kimi_version_scoped_capability_source(
    tmp_path: Path,
) -> None:
    runner = default_runner(
        repo_root=REPO_ROOT,
        result_root=tmp_path / "external-kimi-results",
        run_id="capability-source-001",
    )

    assert runner.capability_source.harness_id == "kimi"
    assert runner.capability_source.run_id == "capability-source-001"
    assert "kimi-capability-state-capability-source-001" in str(
        runner.capability_source.state_root
    )
    assert not runner.capability_source.state_root.exists()
