"""Command-line interface for the Kimi-only 328-case runner.

The command surface remains dry-run by default.  Production runtime wiring is
created only when both execution acknowledgements are present; credentials are
accepted only as inherited file descriptors and never as argv text.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from typing import Any, Sequence

from .analysis_pipeline import build_kimi_analyzing_executor
from .audit import KimiStaticAuditError, run_static_materialization_audit
from .lifecycle import KimiLifecycleError
from .matched_control_scheduler import (
    KimiMatchedControlScheduleError,
    ProductionMatchedControlGate,
    build_production_matched_control_schedule,
    write_production_matched_control_schedule,
)
from .provider_broker import UpstreamEndpoint
from .runner import KimiBenchRunnerError, default_runner
from .runtime_factory import (
    KimiProductionRuntimeError,
    KimiProductionRuntimeHook,
    ReopenedSealedMemfdCredentialSupplier,
)


_DEFAULT_KIMI_EXECUTABLE = Path("/usr/local/bin/kimi")
_DEFAULT_BWRAP_EXECUTABLE = Path("/usr/bin/bwrap")
_DEFAULT_TIMEOUT_SECONDS = 300


class _OneShotCredentialFDSupplier:
    """Transfer one inherited credential descriptor to exactly one trial."""

    def __init__(self, descriptor: int) -> None:
        if (
            not isinstance(descriptor, int)
            or isinstance(descriptor, bool)
            or descriptor < 3
        ):
            raise ValueError("--credential-fd must identify a descriptor >= 3")
        self._descriptor: int | None = descriptor
        self._lock = threading.Lock()

    def __call__(self) -> int:
        with self._lock:
            if self._descriptor is None:
                raise KimiBenchRunnerError(
                    "single-case credential descriptor was already claimed"
                )
            descriptor = self._descriptor
            self._descriptor = None
            return descriptor

    def close_unclaimed(self) -> None:
        """Close only a descriptor which was never transferred to the runtime."""

        with self._lock:
            descriptor = self._descriptor
            self._descriptor = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _add_run_id(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run-local identifier; every Kimi resource includes this value.",
    )


def _add_execution_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Request real execution. Omit for the default dry-run.",
    )
    parser.add_argument(
        "--authorize-external-model-execution",
        action="store_true",
        help=(
            "Independent acknowledgement that a credentialed/paid external model "
            "run is authorized. This flag alone never starts execution."
        ),
    )
    parser.add_argument(
        "--provider-url",
        help=(
            "Reviewed provider endpoint. Required only for formally authorized "
            "execution; HTTPS hosts also require --allowed-https-host."
        ),
    )
    parser.add_argument(
        "--provider-model",
        help="Provider model identifier; required only for formal execution.",
    )
    parser.add_argument(
        "--credential-fd",
        type=int,
        help=(
            "Inherited close-on-exec credential FD (never a credential value). "
            "A multi-case command requires a fully sealed memfd."
        ),
    )
    parser.add_argument(
        "--allowed-https-host",
        action="append",
        default=[],
        help="Exact HTTPS provider DNS host allowlist entry; repeat as needed.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-stage timeout (default: {_DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--kimi-executable",
        type=Path,
        default=_DEFAULT_KIMI_EXECUTABLE,
        help=f"Reviewed Kimi executable (default: {_DEFAULT_KIMI_EXECUTABLE}).",
    )
    parser.add_argument(
        "--bwrap",
        type=Path,
        default=_DEFAULT_BWRAP_EXECUTABLE,
        help=f"bubblewrap executable (default: {_DEFAULT_BWRAP_EXECUTABLE}).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kimi-bench",
        description=(
            "Kimi-only Safety Bench scheduler. Commands are dry-run by default; "
            "formal execution additionally requires explicit provider and "
            "credential-FD configuration."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Safety Bench repository root (read-only canonical source).",
    )
    parser.add_argument(
        "--result-root",
        type=Path,
        default=Path(tempfile.gettempdir()) / "sb-kimi",
        help=(
            "External Kimi result root; the short default preserves Linux AF_UNIX "
            "socket headroom and paths inside the repository are rejected."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List active cases read-only.")
    list_parser.add_argument("--suite")

    subparsers.add_parser("validate", help="Validate the frozen 328-case inventory.")

    plan_parser = subparsers.add_parser("plan", help="Write a dry execution plan.")
    _add_run_id(plan_parser)
    selection = plan_parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--case", dest="case_id")
    selection.add_argument("--suite")
    selection.add_argument("--all", action="store_true")

    audit_parser = subparsers.add_parser(
        "audit-materialization",
        help=(
            "Materialize all 328 cases locally and verify hashes without "
            "launching Kimi or a model provider."
        ),
    )
    _add_run_id(audit_parser)

    controls_parser = subparsers.add_parser(
        "plan-controls",
        help=(
            "Write the immutable 328 x 4 matched-control schedule without "
            "launching Kimi, a provider, or an analyzer."
        ),
    )
    _add_run_id(controls_parser)
    controls_parser.add_argument(
        "--attempt",
        type=int,
        default=1,
        help="Attack attempt identity used only for run-local resource planning.",
    )

    gate_parser = subparsers.add_parser(
        "check-control-gate",
        help=(
            "Validate immutable post-close control receipts for one case; this "
            "never launches an attack or produces a score."
        ),
    )
    gate_parser.add_argument("case_id")
    gate_parser.add_argument("--schedule", type=Path, required=True)
    gate_parser.add_argument(
        "--receipt",
        action="append",
        type=Path,
        default=[],
        help="Exact control receipt path; repeat up to four times.",
    )

    case_parser = subparsers.add_parser("run-case", help="Schedule one active case.")
    _add_run_id(case_parser)
    case_parser.add_argument("case_id")
    _add_execution_flags(case_parser)

    suite_parser = subparsers.add_parser("run-suite", help="Schedule one active suite.")
    _add_run_id(suite_parser)
    suite_parser.add_argument("suite")
    _add_execution_flags(suite_parser)

    all_parser = subparsers.add_parser("run-all", help="Schedule all 328 active cases.")
    _add_run_id(all_parser)
    _add_execution_flags(all_parser)

    resume_parser = subparsers.add_parser(
        "resume",
        help=(
            "Re-plan only queued, dry-run, or explicitly retry-eligible transient "
            "failures from run-local state."
        ),
    )
    _add_run_id(resume_parser)
    _add_execution_flags(resume_parser)
    return parser


def _print(document: Any) -> None:
    print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))


def _result_exit_code(results: Sequence[Any]) -> int:
    outcomes = {result.outcome for result in results}
    if "EXECUTION_INVALID" in outcomes:
        return 4
    if "MODEL_PROTOCOL_INCOMPLETE" in outcomes:
        return 6
    if "NOT_RUN" in outcomes:
        return 3
    return 0


def _formal_execution_requested(args: argparse.Namespace) -> bool:
    return bool(
        args.execute and args.authorize_external_model_execution
    )


def _validated_production_config(args: argparse.Namespace) -> dict[str, Any]:
    """Validate every non-FD production argument before inspecting the FD."""

    missing: list[str] = []
    if not isinstance(args.provider_url, str) or not args.provider_url.strip():
        missing.append("--provider-url")
    if not isinstance(args.provider_model, str) or not args.provider_model.strip():
        missing.append("--provider-model")
    if args.credential_fd is None:
        missing.append("--credential-fd")
    if missing:
        raise ValueError(
            "formally authorized execution requires: " + ", ".join(missing)
        )

    assert isinstance(args.provider_url, str)
    assert isinstance(args.provider_model, str)
    provider_url = args.provider_url.strip()
    provider_model = args.provider_model.strip()
    if provider_url != args.provider_url or "\0" in provider_url:
        raise ValueError("--provider-url must be a trimmed non-NUL value")
    if provider_model != args.provider_model or "\0" in provider_model:
        raise ValueError("--provider-model must be a trimmed non-NUL value")
    if (
        not isinstance(args.credential_fd, int)
        or isinstance(args.credential_fd, bool)
        or args.credential_fd < 3
    ):
        raise ValueError("--credential-fd must identify a descriptor >= 3")
    if (
        not isinstance(args.timeout_seconds, int)
        or isinstance(args.timeout_seconds, bool)
        or args.timeout_seconds < 1
    ):
        raise ValueError("--timeout-seconds must be positive")
    allowed_hosts = tuple(args.allowed_https_host)
    if any(
        not isinstance(host, str)
        or not host
        or host != host.strip()
        or "\0" in host
        for host in allowed_hosts
    ):
        raise ValueError("--allowed-https-host values must be trimmed and non-empty")
    if not isinstance(args.kimi_executable, Path) or not isinstance(args.bwrap, Path):
        raise ValueError("runtime executable arguments must be filesystem paths")

    # This performs shape/allowlist validation only: no DNS lookup, connection,
    # file-descriptor operation, or credential access is possible here.
    try:
        UpstreamEndpoint.parse(
            provider_url,
            allowed_https_hosts=allowed_hosts,
        )
    except (RuntimeError, ValueError, UnicodeError) as exc:
        raise ValueError(f"invalid --provider-url configuration: {exc}") from exc

    return {
        "upstream_url": provider_url,
        "model_name": provider_model,
        "credential_fd": args.credential_fd,
        "allowed_https_hosts": allowed_hosts,
        "timeout_seconds": args.timeout_seconds,
        "executable": args.kimi_executable,
        "bwrap_path": args.bwrap,
    }


def _attach_production_runtime(
    *,
    runner: Any,
    repo_root: Path,
    config: dict[str, Any],
    multiple_cases: bool,
) -> tuple[_OneShotCredentialFDSupplier | None, int | None]:
    """Attach the reviewed hook and return the caller-owned FD cleanup state."""

    source_fd = int(config["credential_fd"])
    one_shot: _OneShotCredentialFDSupplier | None = None
    reusable_source: int | None = None
    try:
        if multiple_cases:
            supplier = ReopenedSealedMemfdCredentialSupplier(source_fd)
            reusable_source = source_fd
        else:
            one_shot = _OneShotCredentialFDSupplier(source_fd)
            supplier = one_shot
        hook = KimiProductionRuntimeHook(
            repo_root=repo_root,
            upstream_url=config["upstream_url"],
            credential_fd_supplier=supplier,
            model_name=config["model_name"],
            allowed_https_hosts=config["allowed_https_hosts"],
            executable=config["executable"],
            bwrap_path=config["bwrap_path"],
            timeout_seconds=config["timeout_seconds"],
            executor_wrapper_factory=build_kimi_analyzing_executor,
        )
        runner.runtime_preflight_hook = hook
        return one_shot, reusable_source
    except BaseException:
        if one_shot is not None:
            one_shot.close_unclaimed()
        else:
            _close_descriptor(source_fd)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # list/validate do not persist state and therefore use a synthetic safe run id.
    run_id = getattr(args, "run_id", "static-inspection")
    one_shot_supplier: _OneShotCredentialFDSupplier | None = None
    reusable_source_fd: int | None = None
    try:
        production_config = None
        if args.command in {"run-case", "run-suite", "run-all", "resume"} and (
            _formal_execution_requested(args)
        ):
            # Validate all ordinary parameters before constructing a supplier;
            # in particular, a missing/invalid configuration cannot inspect,
            # read, seek, duplicate, or close --credential-fd.
            production_config = _validated_production_config(args)
        runner = default_runner(
            repo_root=args.repo_root,
            result_root=args.result_root,
            run_id=run_id,
        )
        if args.command == "list":
            cases = runner.list_cases(suite=args.suite)
            _print(
                {
                    "harness_id": "kimi",
                    "count": len(cases),
                    "cases": [case.as_dict() for case in cases],
                }
            )
            return 0
        if args.command == "validate":
            validation = runner.validate_inventory()
            _print(validation.as_dict())
            return 0 if validation.valid else 2
        if args.command == "plan":
            if args.case_id:
                plans = (runner.plan_case(args.case_id),)
            elif args.suite:
                plans = runner.plan_suite(args.suite)
            else:
                plans = runner.plan_all()
            _print(
                {
                    "harness_id": "kimi",
                    "run_id": run_id,
                    "execution": "DRY_RUN_PLAN_ONLY",
                    "scoring_status": "NOT_PRODUCED",
                    "plan_path": str(runner.layout.plan_path),
                    "plans": [plan.as_dict() for plan in plans],
                }
            )
            return 0
        if args.command == "audit-materialization":
            audit = run_static_materialization_audit(
                repo_root=args.repo_root,
                result_root=args.result_root,
                run_id=run_id,
            )
            _print(
                {
                    "harness_id": "kimi",
                    "run_id": run_id,
                    "mode": audit["mode"],
                    "valid": audit["valid"],
                    "case_count_succeeded": audit["case_count_succeeded"],
                    "case_count_failed": audit["case_count_failed"],
                    "stage_count_materialized": audit[
                        "stage_count_materialized"
                    ],
                    "plan_dispositions": audit["plan_dispositions"],
                    "canonical_hashes_unchanged": audit[
                        "canonical_hashes_unchanged"
                    ],
                    "summary_path": audit["summary_path"],
                    "audit_payload_sha256": audit["audit_payload_sha256"],
                    "scoring_status": "NOT_PRODUCED",
                }
            )
            return 0 if audit["valid"] else 5
        if args.command == "plan-controls":
            schedule = build_production_matched_control_schedule(
                repo_root=args.repo_root,
                batch_root=args.result_root,
                run_id=run_id,
                attempt=args.attempt,
            )
            schedule_path = write_production_matched_control_schedule(
                schedule,
                repo_root=args.repo_root,
            )
            _print(
                {
                    "harness_id": "kimi",
                    "run_id": run_id,
                    "mode": "MATCHED_CONTROL_SCHEDULE_ONLY",
                    "schedule_path": str(schedule_path),
                    "schedule_payload_sha256": schedule[
                        "schedule_payload_sha256"
                    ],
                    "counts": schedule["counts"],
                    "attack_execution_started": False,
                    "external_model_execution_started": False,
                    "capability_upgrade_performed": False,
                    "scoring_status": "NOT_PRODUCED",
                }
            )
            return 0
        if args.command == "check-control-gate":
            gate = ProductionMatchedControlGate(
                schedule_path=args.schedule,
                repo_root=args.repo_root,
            )
            decision = gate.evaluate(
                case_id=args.case_id,
                receipt_paths=tuple(args.receipt),
            )
            _print(decision.as_dict())
            return 0 if decision.attack_execution_allowed else 3
        if production_config is not None:
            one_shot_supplier, reusable_source_fd = _attach_production_runtime(
                runner=runner,
                repo_root=args.repo_root,
                config=production_config,
                multiple_cases=args.command != "run-case",
            )
        execution = {
            "execute": bool(args.execute),
            "external_model_execution_authorized": bool(
                args.authorize_external_model_execution
            ),
        }
        if args.command == "run-case":
            results = (runner.run_case(args.case_id, **execution),)
        elif args.command == "run-suite":
            results = runner.run_suite(args.suite, **execution)
        elif args.command == "run-all":
            results = runner.run_all(**execution)
        elif args.command == "resume":
            results = runner.resume(**execution)
        else:  # pragma: no cover - argparse makes this unreachable.
            raise KimiBenchRunnerError(f"unknown command: {args.command}")
        _print(
            {
                "harness_id": "kimi",
                "run_id": run_id,
                "results": [result.as_dict() for result in results],
                "scoring_status": "NOT_PRODUCED",
            }
        )
        return _result_exit_code(results)
    except (
        KimiBenchRunnerError,
        KimiLifecycleError,
        KimiProductionRuntimeError,
        KimiMatchedControlScheduleError,
        KimiStaticAuditError,
        ValueError,
    ) as exc:
        _print(
            {
                "harness_id": "kimi",
                "error": type(exc).__name__,
                "detail": str(exc),
                "scoring_status": "NOT_PRODUCED",
            }
        )
        return 2
    finally:
        if one_shot_supplier is not None:
            one_shot_supplier.close_unclaimed()
        _close_descriptor(reusable_source_fd)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
