from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from infra.cross_harness.contract import CAPABILITIES
from infra.cross_harness.adapters.kimi import cli
from infra.cross_harness.adapters.kimi.runner import (
    BenchCase,
    CasePlan,
    InventoryValidation,
    KimiBenchRunner,
    StageSpec,
)


class _Result:
    def __init__(self, outcome: str = "COMPLETED") -> None:
        self.outcome = outcome

    def as_dict(self) -> dict[str, str]:
        return {"outcome": self.outcome}


class _Runner:
    def __init__(self, *, outcome: str = "COMPLETED", claim_credential: bool = False):
        self.outcome = outcome
        self.claim_credential = claim_credential
        self.runtime_preflight_hook: Any = None
        self.calls: list[tuple[str, Any, dict[str, bool]]] = []
        self.claimed_descriptor: int | None = None
        self.second_claim_error: BaseException | None = None

    def _results(self, command: str, selection: Any, execution: dict[str, bool]):
        self.calls.append((command, selection, execution))
        if self.claim_credential:
            supplier = self.runtime_preflight_hook.kwargs[
                "credential_fd_supplier"
            ]
            self.claimed_descriptor = supplier()
            try:
                supplier()
            except BaseException as exc:
                self.second_claim_error = exc
            os.close(self.claimed_descriptor)
        return (_Result(self.outcome),)

    def run_case(self, case_id: str, **execution: bool) -> _Result:
        return self._results("run-case", case_id, execution)[0]

    def run_suite(self, suite: str, **execution: bool) -> tuple[_Result, ...]:
        return self._results("run-suite", suite, execution)

    def run_all(self, **execution: bool) -> tuple[_Result, ...]:
        return self._results("run-all", None, execution)

    def resume(self, **execution: bool) -> tuple[_Result, ...]:
        return self._results("resume", None, execution)


class _Hook:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _patch_runner(monkeypatch: pytest.MonkeyPatch, runner: _Runner) -> None:
    monkeypatch.setattr(cli, "default_runner", lambda **_: runner)


def _single_formal_args(tmp_path: Path, descriptor: int) -> list[str]:
    return [
        "--repo-root",
        str(tmp_path),
        "--result-root",
        str(tmp_path / "results"),
        "run-case",
        "--run-id",
        "cli-single",
        "case-001",
        "--execute",
        "--authorize-external-model-execution",
        "--provider-url",
        "https://provider.example/v1",
        "--provider-model",
        "reviewed-model",
        "--credential-fd",
        str(descriptor),
        "--allowed-https-host",
        "provider.example",
        "--timeout-seconds",
        "91",
        "--kimi-executable",
        "/opt/reviewed/kimi",
        "--bwrap",
        "/opt/reviewed/bwrap",
    ]


@pytest.mark.parametrize(
    ("execute", "authorize"),
    ((False, False), (True, False), (False, True)),
)
def test_runtime_is_not_constructed_without_both_acknowledgements(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execute: bool,
    authorize: bool,
) -> None:
    runner = _Runner(outcome="NOT_RUN")
    _patch_runner(monkeypatch, runner)
    constructed: list[dict[str, Any]] = []
    monkeypatch.setattr(
        cli,
        "KimiProductionRuntimeHook",
        lambda **kwargs: constructed.append(kwargs),
    )
    argv = [
        "--repo-root",
        str(tmp_path),
        "--result-root",
        str(tmp_path / "results"),
        "run-case",
        "--run-id",
        "cli-dry",
        "case-001",
        # This intentionally names no live descriptor.  It must remain inert
        # unless both independent acknowledgements are present.
        "--credential-fd",
        "987654",
    ]
    if execute:
        argv.append("--execute")
    if authorize:
        argv.append("--authorize-external-model-execution")

    assert cli.main(argv) == 3
    assert constructed == []
    assert runner.runtime_preflight_hook is None
    assert runner.calls == [
        (
            "run-case",
            "case-001",
            {
                "execute": execute,
                "external_model_execution_authorized": authorize,
            },
        )
    ]


def test_formal_missing_parameters_fail_before_fd_or_runner_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    read_fd, write_fd = os.pipe()
    runner_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        cli,
        "default_runner",
        lambda **kwargs: runner_calls.append(kwargs),
    )
    try:
        code = cli.main(
            [
                "--repo-root",
                str(tmp_path),
                "run-all",
                "--run-id",
                "cli-missing",
                "--execute",
                "--authorize-external-model-execution",
                "--credential-fd",
                str(read_fd),
            ]
        )
        assert code == 2
        assert "--provider-url" in capsys.readouterr().out
        assert runner_calls == []
        # Missing ordinary parameters did not inspect, transfer, or close it.
        os.fstat(read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_invalid_provider_fails_before_invalid_descriptor_is_inspected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        cli,
        "default_runner",
        lambda **kwargs: runner_calls.append(kwargs),
    )

    code = cli.main(
        [
            "--repo-root",
            str(tmp_path),
            "run-all",
            "--run-id",
            "cli-invalid-provider",
            "--execute",
            "--authorize-external-model-execution",
            "--provider-url",
            "http://not-loopback.example/v1",
            "--provider-model",
            "reviewed-model",
            "--credential-fd",
            "987654",
        ]
    )

    assert code == 2
    assert "plain HTTP upstream must use a loopback IP literal" in capsys.readouterr().out
    assert runner_calls == []


def test_run_case_wires_exact_production_hook_and_one_shot_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    runner = _Runner(claim_credential=True)
    _patch_runner(monkeypatch, runner)
    hooks: list[_Hook] = []

    def hook_factory(**kwargs: Any) -> _Hook:
        hook = _Hook(**kwargs)
        hooks.append(hook)
        return hook

    monkeypatch.setattr(cli, "KimiProductionRuntimeHook", hook_factory)
    try:
        assert cli.main(_single_formal_args(tmp_path, read_fd)) == 0
        assert len(hooks) == 1
        hook = hooks[0]
        assert runner.runtime_preflight_hook is hook
        assert runner.claimed_descriptor == read_fd
        assert isinstance(runner.second_claim_error, cli.KimiBenchRunnerError)
        assert hook.kwargs == {
            "repo_root": tmp_path,
            "upstream_url": "https://provider.example/v1",
            "credential_fd_supplier": hook.kwargs["credential_fd_supplier"],
            "model_name": "reviewed-model",
            "allowed_https_hosts": ("provider.example",),
            "executable": Path("/opt/reviewed/kimi"),
            "bwrap_path": Path("/opt/reviewed/bwrap"),
            "timeout_seconds": 91,
            "executor_wrapper_factory": cli.build_kimi_analyzing_executor,
        }
        assert runner.calls[0][2] == {
            "execute": True,
            "external_model_execution_authorized": True,
        }
    finally:
        os.close(write_fd)


def test_run_case_closes_an_unclaimed_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    runner = _Runner()
    _patch_runner(monkeypatch, runner)
    monkeypatch.setattr(cli, "KimiProductionRuntimeHook", _Hook)

    try:
        assert cli.main(_single_formal_args(tmp_path, read_fd)) == 0
        with pytest.raises(OSError):
            os.fstat(read_fd)
    finally:
        os.close(write_fd)


@pytest.mark.parametrize(
    ("command_args", "expected_call"),
    (
        (("run-suite", "suite-a"), "run-suite"),
        (("run-all",), "run-all"),
        (("resume",), "resume"),
    ),
)
def test_multi_case_commands_require_reopened_sealed_memfd_supplier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_args: tuple[str, ...],
    expected_call: str,
) -> None:
    read_fd, write_fd = os.pipe()
    runner = _Runner()
    _patch_runner(monkeypatch, runner)
    suppliers: list[Any] = []
    hooks: list[_Hook] = []

    class FakeReopenedSupplier:
        def __init__(self, source_fd: int) -> None:
            self.source_fd = source_fd
            suppliers.append(self)

        def __call__(self) -> int:  # pragma: no cover - fake runner never starts a trial.
            raise AssertionError("no real trial is permitted in this test")

    def hook_factory(**kwargs: Any) -> _Hook:
        hook = _Hook(**kwargs)
        hooks.append(hook)
        return hook

    monkeypatch.setattr(
        cli, "ReopenedSealedMemfdCredentialSupplier", FakeReopenedSupplier
    )
    monkeypatch.setattr(cli, "KimiProductionRuntimeHook", hook_factory)
    argv = [
        "--repo-root",
        str(tmp_path),
        "--result-root",
        str(tmp_path / "results"),
        *command_args,
        "--run-id",
        "cli-batch",
        "--execute",
        "--authorize-external-model-execution",
        "--provider-url",
        "http://127.0.0.1:8765/v1",
        "--provider-model",
        "reviewed-model",
        "--credential-fd",
        str(read_fd),
    ]

    try:
        assert cli.main(argv) == 0
        assert len(suppliers) == 1
        assert suppliers[0].source_fd == read_fd
        assert hooks[0].kwargs["credential_fd_supplier"] is suppliers[0]
        assert hooks[0].kwargs["executor_wrapper_factory"] is (
            cli.build_kimi_analyzing_executor
        )
        assert runner.calls[0][0] == expected_call
        # The reusable source belongs to the CLI and is closed after the batch,
        # including a zero-selection resume.
        with pytest.raises(OSError):
            os.fstat(read_fd)
    finally:
        os.close(write_fd)


def test_execution_parser_exposes_reviewed_runtime_flags() -> None:
    args = cli.build_parser().parse_args(
        [
            "run-all",
            "--run-id",
            "parser-check",
            "--provider-url",
            "https://provider.example/v1",
            "--provider-model",
            "model-a",
            "--credential-fd",
            "9",
            "--allowed-https-host",
            "provider.example",
            "--allowed-https-host",
            "backup.example",
            "--timeout-seconds",
            "45",
            "--kimi-executable",
            "/opt/kimi",
            "--bwrap",
            "/opt/bwrap",
        ]
    )

    assert args.provider_url == "https://provider.example/v1"
    assert args.provider_model == "model-a"
    assert args.credential_fd == 9
    assert args.allowed_https_host == ["provider.example", "backup.example"]
    assert args.timeout_seconds == 45
    assert args.kimi_executable == Path("/opt/kimi")
    assert args.bwrap == Path("/opt/bwrap")


def test_cli_actual_runner_gate_closes_unclaimed_fd_before_port_or_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    case_dir = repo / "runs" / "active" / "fixture" / "case-001"
    (case_dir / "workspace").mkdir(parents=True)
    (case_dir / "case_meta.json").write_text(
        '{"case_id":"cli_gate_case"}\n', encoding="utf-8"
    )
    case = BenchCase(
        case_id="cli_gate_case",
        suite="fixture",
        case_dir=case_dir,
        case_meta_sha256="0" * 64,
        stages=(StageSpec(0, "trigger"),),
    )

    class Inventory:
        def list_cases(self):
            return (case,)

        def validate(self):
            return InventoryValidation(True, 1, {"fixture": 1})

    class Builder:
        def build(self, selected, _layout):
            return CasePlan(
                case=selected,
                required_capabilities=(
                    "headless_execution",
                    "workspace_isolation",
                    "control_isolation",
                ),
                binding_kind="neutral",
                stages=selected.stages,
                launch_eligible=True,
            )

    class MatrixItem:
        def __init__(self, capability: str, status: str) -> None:
            self.capability = capability
            self.status = status
            self.evidence = (f"fixture:cli-gate:{capability}",)

    class ProbeResult:
        status = "UNVALIDATED"
        required_capabilities = (
            "headless_execution",
            "workspace_isolation",
            "control_isolation",
        )
        evidence = ("fixture:cli-gate:aggregate",)
        reasons = (
            "workspace isolation requires live attestation",
            "matched-control receipts are absent",
        )

    class CapabilitySource:
        def probe_capabilities(self, _required):
            states = {capability: "SUPPORTED" for capability in CAPABILITIES}
            states["workspace_isolation"] = "UNVALIDATED"
            states["control_isolation"] = "UNVALIDATED"
            self.last_capability_matrix = {
                capability: MatrixItem(capability, states[capability])
                for capability in CAPABILITIES
            }
            return ProbeResult()

    class ForbiddenPortLease:
        def __init__(self):
            raise AssertionError("precredential gate allocated a loopback port")

    runner = KimiBenchRunner(
        repo_root=repo,
        result_root=tmp_path / "results",
        run_id="cli-gate",
        inventory=Inventory(),
        plan_builder=Builder(),
        capability_source=CapabilitySource(),
        port_lease_factory=ForbiddenPortLease,
    )
    monkeypatch.setattr(cli, "default_runner", lambda **_: runner)
    hooks: list[Any] = []

    class ProductionLikeHook:
        dynamically_provable_capabilities = ("workspace_isolation",)

        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            self.calls = 0
            hooks.append(self)

        def __call__(self, **_kwargs: Any):
            self.calls += 1
            raise AssertionError("precredential gate started the runtime hook")

    monkeypatch.setattr(cli, "KimiProductionRuntimeHook", ProductionLikeHook)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        os.write(write_fd, b"inert-cli-gate-fixture")
    finally:
        os.close(write_fd)

    code = cli.main(
        [
            "--repo-root",
            str(repo),
            "--result-root",
            str(tmp_path / "results"),
            "run-case",
            "--run-id",
            "cli-gate",
            case.case_id,
            "--execute",
            "--authorize-external-model-execution",
            "--provider-url",
            "http://127.0.0.1:18999/v1",
            "--provider-model",
            "inert-model",
            "--credential-fd",
            str(read_fd),
        ]
    )

    assert code == 3
    assert len(hooks) == 1
    assert hooks[0].calls == 0
    with pytest.raises(OSError):
        os.fstat(read_fd)


def test_plan_controls_cli_writes_only_static_schedule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "default_runner", lambda **_: object())
    calls: list[tuple[str, dict[str, Any]]] = []
    schedule = {
        "schedule_payload_sha256": "a" * 64,
        "counts": {
            "case_count": 328,
            "control_trial_count": 1312,
        },
    }

    def build(**kwargs: Any) -> dict[str, Any]:
        calls.append(("build", kwargs))
        return schedule

    def write(document: dict[str, Any], **kwargs: Any) -> Path:
        assert document is schedule
        calls.append(("write", kwargs))
        return tmp_path / "matched-control-schedule.json"

    monkeypatch.setattr(cli, "build_production_matched_control_schedule", build)
    monkeypatch.setattr(cli, "write_production_matched_control_schedule", write)
    monkeypatch.setattr(
        cli,
        "KimiProductionRuntimeHook",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("static control planning constructed a runtime hook")
        ),
    )

    code = cli.main(
        [
            "--repo-root",
            str(tmp_path / "repo"),
            "--result-root",
            str(tmp_path / "results"),
            "plan-controls",
            "--run-id",
            "cli-controls",
            "--attempt",
            "2",
        ]
    )

    assert code == 0
    assert calls[0][0] == "build"
    assert calls[0][1]["run_id"] == "cli-controls"
    assert calls[0][1]["attempt"] == 2
    assert calls[1][0] == "write"
    output = capsys.readouterr().out
    assert '"mode": "MATCHED_CONTROL_SCHEDULE_ONLY"' in output
    assert '"attack_execution_started": false' in output
    assert '"external_model_execution_started": false' in output
    assert '"scoring_status": "NOT_PRODUCED"' in output


@pytest.mark.parametrize(
    ("allowed", "expected_code"),
    ((False, 3), (True, 0)),
)
def test_check_control_gate_cli_never_launches_attack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    allowed: bool,
    expected_code: int,
) -> None:
    monkeypatch.setattr(cli, "default_runner", lambda **_: object())
    constructed: list[dict[str, Any]] = []
    evaluated: list[dict[str, Any]] = []

    class Decision:
        attack_execution_allowed = allowed

        def as_dict(self) -> dict[str, Any]:
            return {
                "harness_id": "kimi",
                "status": (
                    "CONTROL_GATE_SATISFIED"
                    if allowed
                    else "BLOCKED_PENDING_CONTROL_EXECUTION"
                ),
                "attack_execution_allowed": allowed,
                "formal_conformance_allowed": False,
                "analysis_release_allowed": False,
                "paper_result_allowed": False,
                "capability_upgrade_performed": False,
                "scoring_status": "NOT_PRODUCED",
            }

    class Gate:
        def __init__(self, **kwargs: Any) -> None:
            constructed.append(kwargs)

        def evaluate(self, **kwargs: Any) -> Decision:
            evaluated.append(kwargs)
            return Decision()

    monkeypatch.setattr(cli, "ProductionMatchedControlGate", Gate)
    monkeypatch.setattr(
        cli,
        "KimiProductionRuntimeHook",
        lambda **_: (_ for _ in ()).throw(
            AssertionError("control gate inspection constructed a runtime hook")
        ),
    )
    schedule_path = tmp_path / "schedule.json"
    receipt_path = tmp_path / "receipt.json"
    code = cli.main(
        [
            "--repo-root",
            str(tmp_path / "repo"),
            "check-control-gate",
            "case-001",
            "--schedule",
            str(schedule_path),
            "--receipt",
            str(receipt_path),
        ]
    )

    assert code == expected_code
    assert constructed == [
        {"schedule_path": schedule_path, "repo_root": tmp_path / "repo"}
    ]
    assert evaluated == [
        {"case_id": "case-001", "receipt_paths": (receipt_path,)}
    ]
    output = capsys.readouterr().out
    assert '"formal_conformance_allowed": false' in output
    assert '"scoring_status": "NOT_PRODUCED"' in output
