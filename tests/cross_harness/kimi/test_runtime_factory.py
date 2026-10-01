from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from infra.cross_harness.adapter import CapabilityProbe, HarnessIdentity
from infra.cross_harness.contract import CAPABILITIES
from infra.cross_harness.adapters.kimi.capabilities import CapabilityEvidence
from infra.cross_harness.adapters.kimi.analysis_pipeline import (
    KimiAnalyzingExecutor,
    build_kimi_analyzing_executor,
)
from infra.cross_harness.adapters.kimi.controllers import (
    KimiAcpCompactionController,
    KimiExactSessionController,
    KimiSubagentArtifactController,
)
from infra.cross_harness.adapters.kimi.executor import (
    ATTESTATION_SCHEMA_NAME,
    ATTESTATION_SCHEMA_VERSION,
)
from infra.cross_harness.adapters.kimi.lifecycle import (
    CaseRunLayout,
    OwnedProcessRegistry,
    callback_service_component,
    case_attempt_component,
    case_identity_digest,
    provider_service_component,
)
from infra.cross_harness.adapters.kimi.materializer import sha256_file, tree_sha256
from infra.cross_harness.adapters.kimi.runner import (
    BenchCase,
    CasePlan,
    RuntimePreflight,
    StageSpec,
)
from infra.cross_harness.adapters.kimi.runtime_factory import (
    KimiProductionRuntimeError,
    KimiProductionRuntimeHook,
    ReopenedSealedMemfdCredentialSupplier,
    ReviewedKimiRuntimePins,
)


def _canonical_sha(document: Mapping[str, Any], omitted: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {key: value for key, value in document.items() if key != omitted},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass
class _FixtureRuntime:
    repo_root: Path
    pins: ReviewedKimiRuntimePins
    executable: Path


@pytest.fixture
def reviewed_runtime(tmp_path: Path) -> _FixtureRuntime:
    repo = tmp_path / "repository"
    repo.mkdir()
    package = tmp_path / "runtime" / "kimi-code"
    entrypoint = package / "dist" / "main.mjs"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    entrypoint.chmod(0o755)
    node = tmp_path / "runtime" / "node"
    node.write_bytes(b"fake-reviewed-node\n")
    node.chmod(0o755)
    pins = ReviewedKimiRuntimePins(
        version="0.26.0-test",
        package_root=package,
        package_tree_sha256=tree_sha256(package),
        entrypoint_path=entrypoint,
        entrypoint_sha256=sha256_file(entrypoint),
        node_path=node,
        node_sha256=sha256_file(node),
    )
    return _FixtureRuntime(repo_root=repo, pins=pins, executable=entrypoint)


@pytest.fixture
def short_layout_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="krf-", dir="/tmp"))
    root.chmod(0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root)


def _layout(tmp_path: Path, *, run_id: str, case_id: str) -> CaseRunLayout:
    parent = tmp_path / f"kimi-{run_id}"
    parent.mkdir(mode=0o700, exist_ok=True)
    root = parent / case_attempt_component(case_id, attempt=1)
    root.mkdir(mode=0o700)
    return CaseRunLayout(
        run_id=run_id,
        case_id=case_id,
        root=root,
        workspace=root / "w",
        config=root / "cfg",
        trace=root / "tr",
        result=root / "r",
        session=root / "s",
        cache=root / "k",
        artifact=root / "a",
        pid_record=root / "pids.json",
        case_digest=case_identity_digest(case_id),
        attempt=1,
    )


def _plan(
    tmp_path: Path,
    *,
    case_id: str,
    required: tuple[str, ...],
) -> CasePlan:
    case_dir = tmp_path / f"canonical-{case_id}"
    case_dir.mkdir()
    stage = StageSpec(index=0, name="stage-1")
    case = BenchCase(
        case_id=case_id,
        suite="fixture_suite",
        case_dir=case_dir,
        case_meta_sha256="0" * 64,
        case_content_sha256="1" * 64,
        stages=(stage,),
    )
    return CasePlan(
        case=case,
        required_capabilities=required,
        binding_kind="native",
        stages=(stage,),
        launch_eligible=True,
    )


class _LoopbackLease:
    host = "127.0.0.1"
    port = 32123
    active = True


class _FakeAdapter:
    def __init__(self, fixture: _FixtureRuntime, **kwargs: Any) -> None:
        self.fixture = fixture
        self.kwargs = kwargs
        self.last_capability_matrix: dict[str, CapabilityEvidence] = {}

    def detect_identity(self) -> HarnessIdentity:
        return HarnessIdentity(
            harness_id="kimi",
            version=self.fixture.pins.version,
            executable=str(self.fixture.executable),
            feature_flags={
                "resolved_executable": str(self.fixture.executable.resolve()),
                "binary_sha256": self.fixture.pins.entrypoint_sha256,
            },
        )

    def probe_capabilities(self, required: tuple[str, ...]) -> CapabilityProbe:
        unvalidated = {
            "workspace_isolation",
            "control_isolation",
            "durable_memory_write",
            "durable_memory_retrieval",
        }
        self.last_capability_matrix = {
            capability: CapabilityEvidence(
                capability=capability,
                status="UNVALIDATED" if capability in unvalidated else "SUPPORTED",
                evidence=(f"fixture:evidence:{capability}",),
                detail=(
                    f"fixture deliberately leaves {capability} unvalidated"
                    if capability in unvalidated
                    else "fixture supported"
                ),
            )
            for capability in CAPABILITIES
        }
        required_states = [
            self.last_capability_matrix[item].status for item in required
        ]
        status = "UNVALIDATED" if "UNVALIDATED" in required_states else "SUPPORTED"
        return CapabilityProbe(
            status=status,
            required_capabilities=tuple(required),
            evidence=tuple(
                self.last_capability_matrix[item].evidence[0] for item in required
            ),
            reasons=(
                tuple(
                    f"{item}: unvalidated"
                    for item in required
                    if self.last_capability_matrix[item].status != "SUPPORTED"
                )
                if status != "SUPPORTED"
                else ()
            ),
        )


class _FakeBroker:
    instances: list["_FakeBroker"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.credential_inode = os.fstat(kwargs["credential_fd"]).st_ino
        try:
            self.credential_offset = os.lseek(
                kwargs["credential_fd"], 0, os.SEEK_CUR
            )
        except OSError:
            self.credential_offset = None
        self.run_id = kwargs["run_id"]
        self.case_id = kwargs["case_id"]
        self.trial_id = kwargs["trial_id"]
        self.root = Path(kwargs["ownership_root"]) / (
            provider_service_component(self.run_id, self.case_id, self.trial_id)
        )
        self.root.mkdir(mode=0o700)
        self.attestation_path = self.root / f"attestation-kimi-{self.run_id}.json"
        self.attestation_path.write_text("{}\n", encoding="utf-8")
        self.attestation_path.chmod(0o600)
        self.socket_path = self.root / "p.sock"
        self.process_executable_path = self.attestation_path
        self.process_executable_sha256 = sha256_file(self.attestation_path)
        self.implementation_path = self.attestation_path
        self.implementation_sha256 = sha256_file(self.attestation_path)
        self.credential_transport = "fixture_fd"
        self.pid = 900_001 + len(self.instances)
        self.start_time = f"broker-start-{len(self.instances)}"
        self.closed = False
        self.leases = 0
        self.instances.append(self)

    @property
    def active_lease_count(self) -> int:
        return self.leases

    def close(self) -> None:
        self.closed = True


class _FakeCallbackCollector:
    instances: list["_FakeCallbackCollector"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.run_id = kwargs["run_id"]
        self.case_id = kwargs["case_id"]
        self.trial_id = kwargs["trial_id"]
        self.root = Path(kwargs["ownership_root"]) / (
            callback_service_component(self.run_id, self.case_id, self.trial_id)
        )
        self.root.mkdir(mode=0o700)
        self.attestation_path = self.root / (
            f"callback-attestation-kimi-{self.run_id}.json"
        )
        self.attestation_path.write_text("{}\n", encoding="utf-8")
        self.attestation_path.chmod(0o600)
        self.evidence_manifest_path = self.root / (
            f"callback-manifest-kimi-{self.run_id}.json"
        )
        self.evidence_path = self.root / f"callback-evidence-kimi-{self.run_id}.jsonl"
        self.socket_path = self.root / "c.sock"
        self.pid = 910_001 + len(self.instances)
        self.start_time = f"callback-start-{len(self.instances)}"
        self.closed = False
        self.leases = 0
        self.instances.append(self)

    @property
    def active_lease_count(self) -> int:
        return self.leases

    def verify_evidence_manifest(self) -> Mapping[str, Any]:
        return json.loads(self.evidence_manifest_path.read_text(encoding="utf-8"))

    def close(self) -> None:
        self.closed = True


class _FakeLauncher:
    instances: list["_FakeLauncher"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.run_id = kwargs["run_id"]
        self.root = Path(kwargs["ownership_root"])
        self.contexts = 0
        self.owned = 0
        self.spawned = 0
        self.active: list[dict[str, Any]] = []
        self.closed = False
        self.instances.append(self)

    def attest(self, *, run_id: str, run_root: Path) -> Path:
        assert run_id == self.run_id
        assert Path(run_root) == self.root
        directory = self.root / f"isolated-launcher-kimi-{run_id}"
        directory.mkdir(mode=0o700)
        path = directory / f"attestation-kimi-{run_id}.json"
        document: dict[str, Any] = {
            "schema_name": ATTESTATION_SCHEMA_NAME,
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": run_id,
            "run_root": str(self.root),
            "launcher_id": "linux-bubblewrap-run-local-provider-callback-v1",
            "isolation": {
                "kind": "linux_bubblewrap_allowlist_namespaces_v1",
                "enforced": True,
                "host_user_state_mounted": False,
                "other_harness_state_mounted": False,
                "network_egress": "run_local_broker_only",
            },
            "credential_broker": {
                "kind": "fixture",
                "run_id": run_id,
                "run_local": True,
                "verified": True,
                "external_credentials_in_kimi_env": False,
                "external_credentials_in_tool_child_env": False,
                "external_credentials_persisted": False,
            },
            "evidence": [],
        }
        document["attestation_payload_sha256"] = _canonical_sha(
            document, "attestation_payload_sha256"
        )
        path.write_text(
            json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
        )
        path.chmod(0o600)
        self.contexts = 1
        return path

    def resource_snapshot(self) -> Mapping[str, Any]:
        return {
            "run_id": self.run_id,
            "owned_process_count": self.owned,
            "active_processes": list(self.active),
            "attested_context_count": self.contexts,
            "spawned_stage_count": self.spawned,
        }

    def close(self) -> None:
        self.closed = True
        self.contexts = 0
        self.owned = 0
        self.spawned = 0
        self.active = []


class _FailingAttestationLauncher(_FakeLauncher):
    def attest(self, *, run_id: str, run_root: Path) -> Path:
        raise KimiProductionRuntimeError("fixture live attestation failed")


class _FixtureExecutor:
    def __init__(self, **kwargs: Any) -> None:
        self.kind = "fixture-executor"
        self.kwargs = kwargs

    def execute(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("fixture executor must not run in runtime-factory tests")


class _FixtureWrappedExecutor:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate

    def execute(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("fixture wrapper must not run in runtime-factory tests")


@pytest.fixture(autouse=True)
def clear_fake_instances() -> None:
    _FakeBroker.instances.clear()
    _FakeCallbackCollector.instances.clear()
    _FakeLauncher.instances.clear()
    _FailingAttestationLauncher.instances.clear()


def _hook(
    fixture: _FixtureRuntime,
    supplier: Any,
    *,
    launcher_factory: Any = _FakeLauncher,
    adapter_factory: Any | None = None,
    executor_calls: list[Mapping[str, Any]] | None = None,
    executor_wrapper_factory: Any | None = None,
) -> KimiProductionRuntimeHook:
    captured = executor_calls if executor_calls is not None else []

    def make_adapter(**kwargs: Any) -> _FakeAdapter:
        if adapter_factory is not None:
            return adapter_factory(**kwargs)
        return _FakeAdapter(fixture, **kwargs)

    def make_executor(**kwargs: Any) -> Any:
        captured.append(dict(kwargs))
        return _FixtureExecutor(**kwargs)

    return KimiProductionRuntimeHook(
        repo_root=fixture.repo_root,
        upstream_url="http://127.0.0.1:18999/v1",
        credential_fd_supplier=supplier,
        model_name="fixture-model",
        executable=fixture.executable,
        bwrap_path=fixture.pins.node_path,
        runtime_pins=fixture.pins,
        adapter_factory=make_adapter,
        broker_factory=_FakeBroker,
        callback_collector_factory=_FakeCallbackCollector,
        launcher_factory=launcher_factory,
        normalizer_factory=lambda **kwargs: SimpleNamespace(**kwargs),
        direct_observer_factory=lambda broker: ("direct-observer", broker),
        executor_factory=make_executor,
        executor_wrapper_factory=executor_wrapper_factory,
        materializer_factory=lambda **kwargs: SimpleNamespace(
            kind="fixture-materializer", kwargs=kwargs
        ),
        process_identity_probe=lambda _pid: None,
    )


def _registry(layout: CaseRunLayout) -> OwnedProcessRegistry:
    return OwnedProcessRegistry(run_id=layout.run_id, record_path=layout.pid_record)


def _one_fd_supplier() -> tuple[Any, list[int]]:
    descriptors: list[int] = []

    def supply() -> int:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            os.write(write_fd, b"fixture-credential")
        finally:
            os.close(write_fd)
        descriptors.append(read_fd)
        return read_fd

    return supply, descriptors


def test_runtime_factory_wires_attested_trial_and_closes_exact_resources(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, descriptors = _one_fd_supplier()
    executor_calls: list[Mapping[str, Any]] = []
    hook = _hook(
        reviewed_runtime, supplier, executor_calls=executor_calls
    )
    run_id = "runtime-001"
    plan = _plan(
        tmp_path,
        case_id="case-001",
        required=(
            "headless_execution",
            "workspace_isolation",
        ),
    )
    layout = _layout(short_layout_root, run_id=run_id, case_id=plan.case.case_id)

    manager = hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    )
    with manager as runtime:
        assert isinstance(runtime, RuntimePreflight)
        assert runtime.capability.status == "SUPPORTED"
        assert runtime.capability_states["workspace_isolation"] == "SUPPORTED"
        assert runtime.capability_states["control_isolation"] == "UNVALIDATED"
        assert runtime.capability_states["durable_memory_write"] == "UNVALIDATED"
        assert runtime.capability_states["durable_memory_retrieval"] == "UNVALIDATED"
        assert runtime.callback_url == "http://127.0.0.1:32123"
        assert set(runtime.preexisting_service_paths) == set(layout.root.iterdir())
        assert len(runtime.preexisting_service_paths) == 4
        assert runtime.materializer.kind == "fixture-materializer"
        assert runtime.executor.kind == "fixture-executor"
        assert runtime.close_evidence == {}

        executor = executor_calls[0]
        assert isinstance(executor["resume_controller"], KimiExactSessionController)
        assert isinstance(executor["compact_controller"], KimiAcpCompactionController)
        assert isinstance(executor["subagent_controller"], KimiSubagentArtifactController)
        assert executor["direct_evidence_observer"][0] == "direct-observer"
        assert executor["direct_evidence_observer"][1] is _FakeBroker.instances[0]
        assert executor["executable"] == reviewed_runtime.executable.resolve()

    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert runtime.close_evidence["closed"] is True
    assert runtime.close_evidence["provider_broker_active_leases_before_close"] == 0
    assert runtime.close_evidence["callback_collector_active_leases_before_close"] == 0
    assert runtime.close_evidence["callback_manifest"]["status"] == (
        "not_created_no_stage_spawned"
    )
    assert runtime.close_evidence["launcher_after_close"] == {
        "run_id": run_id,
        "owned_process_count": 0,
        "attested_context_count": 0,
        "spawned_stage_count": 0,
        "active_processes": [],
    }
    assert runtime.close_evidence["provider_broker_process"][
        "absent_or_pid_reused"
    ] is True
    assert runtime.close_evidence["callback_collector_process"][
        "absent_or_pid_reused"
    ] is True
    assert _FakeBroker.instances[0].closed is True
    assert _FakeCallbackCollector.instances[0].closed is True
    assert _FakeLauncher.instances[0].closed is True
    serialized = json.dumps(runtime.close_evidence, sort_keys=True).casefold()
    for forbidden in (
        '"score"',
        '"verdict"',
        '"oracle"',
        '"progress_node"',
        '"attack_success"',
    ):
        assert forbidden not in serialized


def test_known_matched_control_blocker_stops_before_credential_or_launcher(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, descriptors = _one_fd_supplier()
    hook = _hook(reviewed_runtime, supplier)
    plan = _plan(
        tmp_path,
        case_id="case-control-equivalence",
        required=("workspace_isolation", "control_isolation"),
    )
    layout = _layout(
        short_layout_root,
        run_id="runtime-control-equivalence",
        case_id=plan.case.case_id,
    )

    with hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    ) as runtime:
        assert runtime.capability.status == "UNVALIDATED"
        assert runtime.capability_states["workspace_isolation"] == "UNVALIDATED"
        assert runtime.capability_states["control_isolation"] == "UNVALIDATED"
        assert runtime.capability.reasons == (
            "workspace_isolation: fixture deliberately leaves "
            "workspace_isolation unvalidated",
            "control_isolation: fixture deliberately leaves "
            "control_isolation unvalidated",
        )
        assert not any(
            "attestation-kimi" in locator
            for locator in runtime.capability_evidence["control_isolation"]
        )
        assert runtime.materializer is None
        assert runtime.executor is None
        assert len(runtime.preexisting_service_paths) == 1

    assert descriptors == []
    assert _FakeBroker.instances == []
    assert _FakeCallbackCollector.instances == []
    assert _FakeLauncher.instances == []
    assert runtime.close_evidence["closed"] is True
    assert runtime.close_evidence["precredential_capability_gate"] == {
        "blocked": True,
        "blocking_capabilities": ["control_isolation"],
        "credential_supplier_called": False,
        "provider_callback_launcher_started": False,
    }


def test_runtime_close_binds_exact_callback_manifest_stage_coverage(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, _ = _one_fd_supplier()
    hook = _hook(reviewed_runtime, supplier)
    plan = _plan(
        tmp_path, case_id="case-callback", required=("workspace_isolation",)
    )
    layout = _layout(
        short_layout_root, run_id="runtime-callback", case_id=plan.case.case_id
    )
    with hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    ) as runtime:
        launcher = _FakeLauncher.instances[0]
        launcher.spawned = 1
        launcher.owned = 1
        collector = _FakeCallbackCollector.instances[0]
        collector.evidence_manifest_path.write_text(
            json.dumps(
                {
                    "line_count": 0,
                    "completed_stage_connections": [
                        {"stage_index": 0, "outcome": "completed"}
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        collector.evidence_manifest_path.chmod(0o600)
    assert runtime.close_evidence["closed"] is True
    assert runtime.close_evidence["callback_manifest"][
        "completed_stage_indices"
    ] == [0]


def test_durable_memory_blocker_prevents_credential_and_live_attestation(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, descriptors = _one_fd_supplier()
    hook = _hook(reviewed_runtime, supplier)
    plan = _plan(
        tmp_path,
        case_id="case-memory",
        required=("durable_memory_write", "workspace_isolation"),
    )
    layout = _layout(
        short_layout_root, run_id="runtime-002", case_id=plan.case.case_id
    )
    with hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    ) as runtime:
        assert runtime.capability.status == "UNVALIDATED"
        assert runtime.capability_states["workspace_isolation"] == "UNVALIDATED"
        assert runtime.capability_states["durable_memory_write"] == "UNVALIDATED"
        assert runtime.capability.reasons == (
            "durable_memory_write: fixture deliberately leaves "
            "durable_memory_write unvalidated",
            "workspace_isolation: fixture deliberately leaves "
            "workspace_isolation unvalidated",
        )
    assert descriptors == []
    assert _FakeBroker.instances == []
    assert _FakeCallbackCollector.instances == []
    assert _FakeLauncher.instances == []
    assert runtime.close_evidence["precredential_capability_gate"][
        "blocking_capabilities"
    ] == ["durable_memory_write"]


def test_live_attestation_never_upgrades_explicitly_unsupported_capability(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    class UnsupportedWorkspaceAdapter(_FakeAdapter):
        def probe_capabilities(
            self, required: tuple[str, ...]
        ) -> CapabilityProbe:
            probe = super().probe_capabilities(required)
            self.last_capability_matrix["workspace_isolation"] = CapabilityEvidence(
                capability="workspace_isolation",
                status="UNSUPPORTED",
                evidence=("fixture:evidence:workspace-unsupported",),
                detail="fixture explicitly rejects workspace isolation",
            )
            return probe

    supplier, descriptors = _one_fd_supplier()
    hook = _hook(
        reviewed_runtime,
        supplier,
        adapter_factory=lambda **kwargs: UnsupportedWorkspaceAdapter(
            reviewed_runtime, **kwargs
        ),
    )
    plan = _plan(
        tmp_path,
        case_id="case-unsupported",
        required=("workspace_isolation",),
    )
    layout = _layout(
        short_layout_root,
        run_id="runtime-unsupported",
        case_id=plan.case.case_id,
    )
    with hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    ) as runtime:
        assert runtime.capability.status == "UNSUPPORTED"
        assert runtime.capability_states["workspace_isolation"] == "UNSUPPORTED"
        assert runtime.capability.reasons == (
            "workspace_isolation: fixture explicitly rejects workspace isolation",
        )
    assert descriptors == []
    assert _FakeBroker.instances == []
    assert _FakeCallbackCollector.instances == []
    assert _FakeLauncher.instances == []
    assert runtime.close_evidence["precredential_capability_gate"][
        "blocking_capabilities"
    ] == ["workspace_isolation"]


def test_reusing_one_underlying_credential_object_across_cases_is_rejected(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    base, writer = os.pipe2(os.O_CLOEXEC)
    os.write(writer, b"fixture-credential")
    os.close(writer)
    supplied: list[int] = []

    def supplier() -> int:
        descriptor = os.dup(base)
        supplied.append(descriptor)
        return descriptor

    hook = _hook(reviewed_runtime, supplier)
    first = _plan(
        tmp_path, case_id="case-reuse-a", required=("workspace_isolation",)
    )
    first_layout = _layout(
        short_layout_root, run_id="runtime-reuse", case_id=first.case.case_id
    )
    with hook(
        plan=first,
        layout=first_layout,
        process_registry=_registry(first_layout),
        loopback_port=_LoopbackLease(),
    ):
        pass

    second = _plan(
        tmp_path, case_id="case-reuse-b", required=("workspace_isolation",)
    )
    second_layout = _layout(
        short_layout_root, run_id="runtime-reuse", case_id=second.case.case_id
    )
    with pytest.raises(KimiProductionRuntimeError, match="reuse across Kimi cases"):
        with hook(
            plan=second,
            layout=second_layout,
            process_registry=_registry(second_layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    assert len(supplied) == 2
    for descriptor in supplied:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    os.close(base)


@pytest.mark.skipif(
    not hasattr(os, "memfd_create"), reason="sealed memfd requires Linux memfd_create"
)
def test_controlled_proc_reopen_allows_sealed_memfd_batch_without_shared_offset(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    source = os.memfd_create(
        "kimi-runtime-test-credential",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    os.write(source, b"fixture-secret-never-persisted")
    fcntl.fcntl(
        source,
        fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE,
    )
    supplier = ReopenedSealedMemfdCredentialSupplier(source)
    hook = _hook(reviewed_runtime, supplier)

    observed_inodes: list[int] = []
    for ordinal in (1, 2):
        plan = _plan(
            tmp_path,
            case_id=f"case-memfd-{ordinal}",
            required=("workspace_isolation",),
        )
        layout = _layout(
                short_layout_root,
                run_id="runtime-memfd",
                case_id=plan.case.case_id,
        )
        with hook(
            plan=plan,
            layout=layout,
            process_registry=_registry(layout),
            loopback_port=_LoopbackLease(),
        ) as runtime:
            observed_inodes.append(_FakeBroker.instances[-1].credential_inode)
            assert _FakeBroker.instances[-1].credential_offset == 0
        assert runtime.close_evidence["credential_transport"] == "sealed_memfd"
        assert "fixture-secret-never-persisted" not in json.dumps(
            runtime.close_evidence, sort_keys=True
        )
    assert observed_inodes[0] == observed_inodes[1] == os.fstat(source).st_ino
    # Broker acquisitions use independent procfs opens, so the source open
    # file description retains its original post-write offset across cases.
    assert os.lseek(source, 0, os.SEEK_CUR) == len(
        b"fixture-secret-never-persisted"
    )
    os.close(source)


@pytest.mark.skipif(
    not hasattr(os, "memfd_create"), reason="sealed memfd requires Linux memfd_create"
)
def test_plain_dup_of_sealed_memfd_is_not_accepted_as_batch_reopen(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    source = os.memfd_create(
        "kimi-runtime-test-dup",
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    os.write(source, b"fixture-credential")
    os.lseek(source, 0, os.SEEK_SET)
    fcntl.fcntl(
        source,
        fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_SEAL
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_WRITE,
    )
    hook = _hook(reviewed_runtime, lambda: os.dup(source))
    first = _plan(
        tmp_path, case_id="case-dup-a", required=("workspace_isolation",)
    )
    first_layout = _layout(
        short_layout_root, run_id="runtime-dup", case_id=first.case.case_id
    )
    with hook(
        plan=first,
        layout=first_layout,
        process_registry=_registry(first_layout),
        loopback_port=_LoopbackLease(),
    ):
        pass

    second = _plan(
        tmp_path, case_id="case-dup-b", required=("workspace_isolation",)
    )
    second_layout = _layout(
        short_layout_root, run_id="runtime-dup", case_id=second.case.case_id
    )
    with pytest.raises(KimiProductionRuntimeError, match="shared-offset memfd reuse"):
        with hook(
            plan=second,
            layout=second_layout,
            process_registry=_registry(second_layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    os.close(source)


def test_live_attestation_failure_closes_only_created_trial_services(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, descriptors = _one_fd_supplier()
    hook = _hook(
        reviewed_runtime, supplier, launcher_factory=_FailingAttestationLauncher
    )
    plan = _plan(
        tmp_path, case_id="case-attest", required=("workspace_isolation",)
    )
    layout = _layout(
        short_layout_root, run_id="runtime-003", case_id=plan.case.case_id
    )
    with pytest.raises(KimiProductionRuntimeError, match="live attestation failed"):
        with hook(
            plan=plan,
            layout=layout,
            process_registry=_registry(layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert _FakeBroker.instances[0].closed is True
    assert _FakeCallbackCollector.instances[0].closed is True
    assert _FailingAttestationLauncher.instances[0].closed is True


def test_identity_pin_failure_happens_before_credential_fd_is_requested(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    calls = 0

    def supplier() -> int:
        nonlocal calls
        calls += 1
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        os.close(write_fd)
        return read_fd

    class WrongVersionAdapter(_FakeAdapter):
        def detect_identity(self) -> HarnessIdentity:
            identity = super().detect_identity()
            return HarnessIdentity(
                harness_id="kimi",
                version="99.0.0",
                executable=identity.executable,
                feature_flags=identity.feature_flags,
            )

    hook = _hook(
        reviewed_runtime,
        supplier,
        adapter_factory=lambda **kwargs: WrongVersionAdapter(
            reviewed_runtime, **kwargs
        ),
    )
    plan = _plan(
        tmp_path, case_id="case-pin", required=("workspace_isolation",)
    )
    layout = _layout(
        short_layout_root, run_id="runtime-004", case_id=plan.case.case_id
    )
    with pytest.raises(KimiProductionRuntimeError, match="reviewed runtime pins"):
        with hook(
            plan=plan,
            layout=layout,
            process_registry=_registry(layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    assert calls == 0


def test_runtime_rejects_nonempty_case_root_before_any_credential_access(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    calls = 0

    def supplier() -> int:
        nonlocal calls
        calls += 1
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        os.close(write_fd)
        return read_fd

    hook = _hook(reviewed_runtime, supplier)
    plan = _plan(
        tmp_path, case_id="case-dirty", required=("workspace_isolation",)
    )
    layout = _layout(
        short_layout_root, run_id="runtime-005", case_id=plan.case.case_id
    )
    (layout.root / "foreign-file").write_text("do not touch", encoding="utf-8")
    with pytest.raises(KimiProductionRuntimeError, match="empty per-attempt"):
        with hook(
            plan=plan,
            layout=layout,
            process_registry=_registry(layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    assert calls == 0
    assert (layout.root / "foreign-file").read_text(encoding="utf-8") == "do not touch"


def test_overlong_unix_socket_layout_fails_before_credential_access(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
) -> None:
    calls = 0

    def supplier() -> int:
        nonlocal calls
        calls += 1
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        os.close(write_fd)
        return read_fd

    hook = _hook(reviewed_runtime, supplier)
    plan = _plan(
        tmp_path, case_id="case-long-socket", required=("workspace_isolation",)
    )
    long_root = tmp_path / ("long-result-root-" + "x" * 64)
    long_root.mkdir(mode=0o700)
    layout = _layout(
        long_root, run_id="runtime-long", case_id=plan.case.case_id
    )
    with pytest.raises(
        KimiProductionRuntimeError, match="socket layout is unavailable"
    ):
        with hook(
            plan=plan,
            layout=layout,
            process_registry=_registry(layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    assert calls == 0


def test_executor_wrapper_factory_receives_exact_trial_context(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, _ = _one_fd_supplier()
    calls: list[Mapping[str, Any]] = []

    def wrapper(**kwargs: Any) -> _FixtureWrappedExecutor:
        calls.append(dict(kwargs))
        return _FixtureWrappedExecutor(kwargs["delegate"])

    hook = _hook(
        reviewed_runtime,
        supplier,
        executor_wrapper_factory=wrapper,
    )
    plan = _plan(
        tmp_path, case_id="case-analysis", required=("workspace_isolation",)
    )
    layout = _layout(
        short_layout_root, run_id="runtime-analysis", case_id=plan.case.case_id
    )
    with hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    ) as runtime:
        assert isinstance(runtime.executor, _FixtureWrappedExecutor)
        assert set(calls[0]) == {
            "delegate",
            "run_id",
            "case_id",
            "trial_id",
            "run_root",
            "callback_collector",
        }
        assert calls[0]["delegate"] is runtime.executor.delegate
        assert calls[0]["run_id"] == layout.run_id
        assert calls[0]["case_id"] == plan.case.case_id
        assert calls[0]["run_root"] == layout.root
        assert calls[0]["callback_collector"] is _FakeCallbackCollector.instances[0]
        assert calls[0]["trial_id"].startswith(
            f"trial-kimi-{layout.run_id}-"
        )


def test_invalid_executor_wrapper_fails_closed_and_closes_services(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, _ = _one_fd_supplier()
    hook = _hook(
        reviewed_runtime,
        supplier,
        executor_wrapper_factory=lambda **_kwargs: object(),
    )
    plan = _plan(
        tmp_path, case_id="case-bad-wrapper", required=("workspace_isolation",)
    )
    layout = _layout(
        short_layout_root, run_id="runtime-wrapper", case_id=plan.case.case_id
    )
    with pytest.raises(KimiProductionRuntimeError, match="CaseExecutor") as failure:
        with hook(
            plan=plan,
            layout=layout,
            process_registry=_registry(layout),
            loopback_port=_LoopbackLease(),
        ):
            pass
    assert failure.value.close_evidence["closed"] is True
    assert _FakeBroker.instances[0].closed is True
    assert _FakeCallbackCollector.instances[0].closed is True
    assert _FakeLauncher.instances[0].closed is True


def test_runtime_factory_directly_accepts_kimi_analysis_wrapper_factory(
    tmp_path: Path,
    reviewed_runtime: _FixtureRuntime,
    short_layout_root: Path,
) -> None:
    supplier, _ = _one_fd_supplier()
    hook = _hook(
        reviewed_runtime,
        supplier,
        executor_wrapper_factory=build_kimi_analyzing_executor,
    )
    plan = _plan(
        tmp_path,
        case_id="case-real-analysis-wrapper",
        required=("workspace_isolation",),
    )
    layout = _layout(
        short_layout_root,
        run_id="runtime-analysis-api",
        case_id=plan.case.case_id,
    )
    with hook(
        plan=plan,
        layout=layout,
        process_registry=_registry(layout),
        loopback_port=_LoopbackLease(),
    ) as runtime:
        assert isinstance(runtime.executor, KimiAnalyzingExecutor)
        assert isinstance(runtime.executor.delegate, _FixtureExecutor)
