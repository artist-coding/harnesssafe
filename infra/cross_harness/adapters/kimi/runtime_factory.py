"""Production-only, per-trial runtime wiring for the Kimi 328-case runner.

The runner deliberately starts this context *before* materialization.  This
module therefore owns the narrow bootstrap which can turn one otherwise
``UNVALIDATED`` adapter capability into a directly attested runtime fact:

* ``workspace_isolation`` is upgraded only after the live bubblewrap self-test;

``control_isolation`` is intentionally *not* upgraded by that self-test.  The
capability means attack/control intervention-only equivalence in the deferred
Kimi matched-control workflow, not merely independent provider/callback or
filesystem boundaries.  It is not required by the current attack-only Kimi
inventory.  A formal matched-control scheduler has not yet bound a
``KimiMatchedControlBoundary`` to every production trial, so the static probe's
``UNVALIDATED`` state must survive runtime construction.

No credential value is accepted by this API.  A caller supplies one already
open, close-on-exec descriptor for each case/trial.  The descriptor is passed
straight to :class:`RunScopedProviderBroker` and closed in the parent as soon
as the worker is ready.  Pipes are one-shot.  A sealed memfd may back a batch
only through :class:`ReopenedSealedMemfdCredentialSupplier`, which performs a
fresh ``open(/proc/self/fd/<source>)`` for every case and proves offset zero;
``dup`` and other shared-open-file-description reuse fail closed.

This module materializes, executes, and captures evidence only.  It contains
no analyzer, oracle, N0--N5b, verdict, or scoring integration.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, Callable, Mapping, Sequence

from infra.cross_harness.adapter import HarnessIdentity
from infra.cross_harness.contract import CAPABILITIES

from .adapter import KimiHarnessAdapter
from .bench_materializer import sha256_file
from .callback_collector import RunScopedCallbackCollector
from .capabilities import CapabilityEvidence
from .controllers import (
    KimiAcpCompactionController,
    KimiExactSessionController,
    KimiSubagentArtifactController,
)
from .execution_observer import KimiDirectEvidenceObserver
from .executor import (
    ATTESTATION_SCHEMA_NAME,
    ATTESTATION_SCHEMA_VERSION,
    KimiStageExecutor,
)
from .isolated_launcher import LinuxBubblewrapLauncher
from .lifecycle import (
    CaseRunLayout,
    KimiLifecycleError,
    LoopbackPortLease,
    OwnedProcessRegistry,
    ProcessSnapshot,
    case_attempt_component,
    case_identity_digest,
    inspect_process,
    production_service_paths,
    validate_bench_run_id,
)
from .materializer import tree_sha256
from .provider_broker import RunScopedProviderBroker, UpstreamEndpoint
from .runner import (
    BenchMaterializerBridge,
    CapabilityDecision,
    CasePlan,
    RuntimePreflight,
)
from .trace import KimiBenchEventIRNormalizer


EXPECTED_KIMI_VERSION = "0.26.0"
EXPECTED_KIMI_ENTRYPOINT_SHA256 = (
    "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
)
EXPECTED_KIMI_PACKAGE_TREE_SHA256 = (
    "80c3e12b49172bd98b3f42184835568957964e2f3b77657afb091c52ca2282aa"
)
EXPECTED_NODE_SHA256 = (
    "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CAPABILITY_STATES = frozenset({"SUPPORTED", "UNSUPPORTED", "UNVALIDATED"})
_DYNAMIC_ISOLATION_CAPABILITIES = ("workspace_isolation",)
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
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


class KimiProductionRuntimeError(RuntimeError):
    """A production trial could not preserve an evidence or isolation gate."""

    def __init__(
        self,
        message: str,
        *,
        close_evidence: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.close_evidence = dict(close_evidence or {})
        self._kimi_runtime_close_evidence = dict(self.close_evidence)


def _require_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _canonical_sha256(document: Mapping[str, Any], omitted: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {key: value for key, value in document.items() if key != omitted},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _forbidden_keys(value: Any, prefix: str = "runtime_close") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{prefix}.{key}"
            if str(key).casefold() in _FORBIDDEN_EVIDENCE_KEYS:
                found.append(child_path)
            found.extend(_forbidden_keys(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            found.extend(_forbidden_keys(child, f"{prefix}[{index}]"))
    return found


@dataclass(frozen=True)
class ReviewedKimiRuntimePins:
    """Exact reviewed bytes mounted by the production bubblewrap launcher."""

    version: str = EXPECTED_KIMI_VERSION
    package_root: Path = Path(
        "/usr/local/lib/node_modules/@moonshot-ai/kimi-code"
    )
    package_tree_sha256: str = EXPECTED_KIMI_PACKAGE_TREE_SHA256
    entrypoint_path: Path = Path(
        "/usr/local/lib/node_modules/@moonshot-ai/kimi-code/dist/main.mjs"
    )
    entrypoint_sha256: str = EXPECTED_KIMI_ENTRYPOINT_SHA256
    node_path: Path = Path("/usr/local/bin/node")
    node_sha256: str = EXPECTED_NODE_SHA256

    def __post_init__(self) -> None:
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("reviewed Kimi version must be non-empty")
        for value, label in (
            (self.package_tree_sha256, "Kimi package tree"),
            (self.entrypoint_sha256, "Kimi entrypoint"),
            (self.node_sha256, "Node executable"),
        ):
            _require_sha256(value, label)
        object.__setattr__(self, "package_root", Path(self.package_root).absolute())
        object.__setattr__(self, "entrypoint_path", Path(self.entrypoint_path).absolute())
        object.__setattr__(self, "node_path", Path(self.node_path).absolute())


CredentialFDSupplier = Callable[[], int]
ProcessIdentityProbe = Callable[[int], ProcessSnapshot | None]


def _credential_transport(
    descriptor: int, *, require_offset_zero: bool = True
) -> tuple[str, tuple[int, int, int]]:
    """Classify an FD without reading or seeking through credential bytes."""

    try:
        metadata = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    except OSError as exc:
        raise KimiProductionRuntimeError(
            "credential supplier returned an unavailable descriptor"
        ) from exc
    if flags & fcntl.FD_CLOEXEC == 0:
        raise KimiProductionRuntimeError(
            "credential descriptor must be close-on-exec"
        )
    identity = (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))
    if stat.S_ISFIFO(metadata.st_mode):
        return "pipe_fd", identity
    if stat.S_ISREG(metadata.st_mode):
        try:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
            offset = os.lseek(descriptor, 0, os.SEEK_CUR)
        except OSError as exc:
            raise KimiProductionRuntimeError(
                "regular credential descriptor is not a sealed memfd"
            ) from exc
        required = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        if (
            "memfd:" not in target
            or seals & required != required
            or (require_offset_zero and offset != 0)
            or metadata.st_size < 1
        ):
            raise KimiProductionRuntimeError(
                "sealed memfd credential requires all write/size seals and offset zero"
            )
        return "sealed_memfd", identity
    raise KimiProductionRuntimeError(
        "credential descriptor must be a one-shot pipe or sealed memfd"
    )


class ReopenedSealedMemfdCredentialSupplier:
    """Safely reopen one caller-owned sealed memfd for a multi-case batch.

    The source descriptor is never read, duplicated, or handed to the broker.
    Linux ``open`` on its procfs descriptor link creates an independent open
    file description whose offset begins at zero.  The caller retains ownership
    of ``source_fd`` and must close it after the batch.
    """

    def __init__(self, source_fd: int) -> None:
        if (
            not isinstance(source_fd, int)
            or isinstance(source_fd, bool)
            or source_fd < 3
        ):
            raise ValueError("sealed memfd source_fd must be >= 3")
        transport, identity = _credential_transport(
            source_fd, require_offset_zero=False
        )
        if transport != "sealed_memfd":
            raise ValueError("reusable credential source must be a sealed memfd")
        self.source_fd = source_fd
        self.source_identity = identity
        self._lock = threading.Lock()

    def __call__(self) -> int:
        with self._lock:
            transport, identity = _credential_transport(
                self.source_fd, require_offset_zero=False
            )
            if transport != "sealed_memfd" or identity != self.source_identity:
                raise KimiProductionRuntimeError(
                    "sealed memfd credential source identity drifted"
                )
            try:
                descriptor = os.open(
                    f"/proc/self/fd/{self.source_fd}",
                    os.O_RDONLY | os.O_CLOEXEC,
                )
            except OSError as exc:
                raise KimiProductionRuntimeError(
                    "could not independently reopen sealed memfd credential"
                ) from exc
            try:
                reopened_transport, reopened_identity = _credential_transport(
                    descriptor
                )
                if (
                    reopened_transport != "sealed_memfd"
                    or reopened_identity != self.source_identity
                ):
                    raise KimiProductionRuntimeError(
                        "reopened sealed memfd identity drifted"
                    )
            except BaseException:
                os.close(descriptor)
                raise
            return descriptor


def _validate_layout(
    *,
    plan: CasePlan,
    layout: CaseRunLayout,
    process_registry: OwnedProcessRegistry,
    loopback_port: LoopbackPortLease,
) -> Path:
    run_id = validate_bench_run_id(layout.run_id)
    if plan.case.case_id != layout.case_id:
        raise KimiProductionRuntimeError("runtime plan/case layout identity drifted")
    root = Path(layout.root).absolute()
    expected_case_digest = case_identity_digest(plan.case.case_id)
    expected_case_component = case_attempt_component(
        plan.case.case_id, attempt=layout.attempt
    )
    if (
        not root.is_dir()
        or root.is_symlink()
        or root.resolve(strict=True) != root
        or root.parent.name != f"kimi-{run_id}"
        or root.name != expected_case_component
        or layout.case_digest != expected_case_digest
        or any(
            part.casefold() in {".claude", ".codex", ".kimi-code"}
            for part in root.parts
        )
    ):
        raise KimiProductionRuntimeError(
            "runtime case root lacks exact Kimi/run ownership"
        )
    if any(root.iterdir()):
        raise KimiProductionRuntimeError(
            "runtime preflight requires the runner's empty per-attempt case root"
        )
    os.chmod(root, 0o700)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise KimiProductionRuntimeError("runtime case root is not private")
    for owned in layout.owned_paths():
        candidate = Path(owned).absolute()
        if candidate != root and not _is_relative_to(candidate, root):
            raise KimiProductionRuntimeError("case layout path escapes runtime root")
    if (
        getattr(process_registry, "run_id", None) != run_id
        or Path(getattr(process_registry, "record_path", Path("/"))).absolute()
        != Path(layout.pid_record).absolute()
    ):
        raise KimiProductionRuntimeError("process registry is not bound to this case")
    if (
        getattr(loopback_port, "host", None) != "127.0.0.1"
        or getattr(loopback_port, "active", None) is not True
    ):
        raise KimiProductionRuntimeError("loopback callback port is not actively leased")
    port = getattr(loopback_port, "port", None)
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise KimiProductionRuntimeError("loopback callback port is unsafe")
    return root


def _validate_runtime_pins(
    pins: ReviewedKimiRuntimePins,
    identity: HarnessIdentity,
) -> tuple[Path, Path, Path]:
    try:
        package = pins.package_root.resolve(strict=True)
        entrypoint = pins.entrypoint_path.resolve(strict=True)
        node = pins.node_path.resolve(strict=True)
        detected = Path(identity.executable).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise KimiProductionRuntimeError(
            "reviewed Kimi/Node runtime paths are unavailable"
        ) from exc
    flags = identity.feature_flags
    resolved_flag = flags.get("resolved_executable")
    binary_sha = flags.get("binary_sha256")
    if (
        identity.harness_id != "kimi"
        or identity.version != pins.version
        or detected != entrypoint
        or resolved_flag != str(entrypoint)
        or binary_sha != pins.entrypoint_sha256
        or package.is_symlink()
        or not package.is_dir()
        or entrypoint != package / "dist" / "main.mjs"
        or entrypoint.is_symlink()
        or not entrypoint.is_file()
        or not os.access(entrypoint, os.X_OK)
        or node.is_symlink()
        or not node.is_file()
        or not os.access(node, os.X_OK)
        or not hmac.compare_digest(tree_sha256(package), pins.package_tree_sha256)
        or not hmac.compare_digest(sha256_file(entrypoint), pins.entrypoint_sha256)
        or not hmac.compare_digest(sha256_file(node), pins.node_sha256)
    ):
        raise KimiProductionRuntimeError(
            "detected Kimi identity does not match the reviewed runtime pins"
        )
    return package, entrypoint, node


def _validate_launcher_attestation(path: Path, *, run_id: str, root: Path) -> str:
    candidate = Path(path).absolute()
    if (
        candidate.is_symlink()
        or not candidate.is_file()
        or not _is_relative_to(candidate.resolve(strict=True), root)
    ):
        raise KimiProductionRuntimeError("launcher attestation escaped the trial root")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KimiProductionRuntimeError("launcher attestation is malformed") from exc
    expected = {
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
    }
    if not isinstance(document, Mapping) or set(document) != expected:
        raise KimiProductionRuntimeError("launcher attestation field set drifted")
    isolation = document.get("isolation")
    broker = document.get("credential_broker")
    claimed = document.get("attestation_payload_sha256")
    if (
        document.get("schema_name") != ATTESTATION_SCHEMA_NAME
        or document.get("schema_version") != ATTESTATION_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("run_id") != run_id
        or Path(str(document.get("run_root"))).resolve() != root
        or document.get("launcher_id")
        != "linux-bubblewrap-run-local-provider-callback-v1"
        or not isinstance(isolation, Mapping)
        or isolation.get("enforced") is not True
        or isolation.get("host_user_state_mounted") is not False
        or isolation.get("other_harness_state_mounted") is not False
        or isolation.get("network_egress") != "run_local_broker_only"
        or not isinstance(broker, Mapping)
        or broker.get("run_id") != run_id
        or broker.get("run_local") is not True
        or broker.get("verified") is not True
        or broker.get("external_credentials_in_kimi_env") is not False
        or broker.get("external_credentials_in_tool_child_env") is not False
        or broker.get("external_credentials_persisted") is not False
        or not isinstance(document.get("evidence"), list)
        or not isinstance(claimed, str)
        or _SHA256_RE.fullmatch(claimed) is None
        or not hmac.compare_digest(
            claimed, _canonical_sha256(document, "attestation_payload_sha256")
        )
    ):
        raise KimiProductionRuntimeError(
            "launcher attestation did not prove the required isolation boundaries"
        )
    return sha256_file(candidate)


def _validate_launcher_snapshot(
    value: Any,
    *,
    run_id: str,
    closed: bool,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "run_id",
        "owned_process_count",
        "active_processes",
        "attested_context_count",
        "spawned_stage_count",
    }:
        raise KimiProductionRuntimeError("launcher resource snapshot is malformed")
    counts: dict[str, int] = {}
    for key in (
        "owned_process_count",
        "attested_context_count",
        "spawned_stage_count",
    ):
        item = value.get(key)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise KimiProductionRuntimeError("launcher resource count is malformed")
        counts[key] = item
    active = value.get("active_processes")
    if (
        value.get("run_id") != run_id
        or not isinstance(active, list)
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"pid", "returncode"}
            or not isinstance(item.get("pid"), int)
            or isinstance(item.get("pid"), bool)
            or item.get("pid") <= 1
            or item.get("returncode") is not None
            for item in active
        )
    ):
        raise KimiProductionRuntimeError("launcher resource identity drifted")
    if len(active) > counts["owned_process_count"]:
        raise KimiProductionRuntimeError("launcher active process count is impossible")
    if closed and (
        active
        or counts["owned_process_count"] != 0
        or counts["attested_context_count"] != 0
        or counts["spawned_stage_count"] != 0
    ):
        raise KimiProductionRuntimeError("launcher retained trial resources after close")
    return {
        "run_id": run_id,
        **counts,
        "active_processes": [dict(item) for item in active],
    }


def _process_closed_evidence(
    service: Any,
    *,
    process_probe: ProcessIdentityProbe,
    label: str,
) -> dict[str, Any]:
    pid = getattr(service, "pid", None)
    start_time = getattr(service, "start_time", None)
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 1
        or not isinstance(start_time, str)
        or not start_time
    ):
        raise KimiProductionRuntimeError(f"{label} process identity is malformed")
    observed = process_probe(pid)
    if observed is not None and observed.start_time == start_time:
        raise KimiProductionRuntimeError(f"{label} process remained alive after close")
    return {
        "pid": pid,
        "start_time": start_time,
        "absent_or_pid_reused": True,
        "observed_replacement_start_time": (
            observed.start_time if observed is not None else None
        ),
    }


class KimiProductionRuntimeHook:
    """Callable ``runner.RuntimePreflightHook`` for one FD-isolated trial at a time."""

    # The runner may use this immutable declaration for a credential- and
    # socket-free preliminary gate.  It is intentionally narrower than all
    # UNVALIDATED capabilities: only a live launcher self-test can change this
    # capability's state in the current implementation.
    dynamically_provable_capabilities = _DYNAMIC_ISOLATION_CAPABILITIES

    def __init__(
        self,
        *,
        repo_root: Path,
        upstream_url: str,
        credential_fd_supplier: CredentialFDSupplier,
        model_name: str,
        allowed_https_hosts: Sequence[str] = (),
        executable: Path | str = "/usr/local/bin/kimi",
        bwrap_path: Path | str = "/usr/bin/bwrap",
        timeout_seconds: int = 300,
        path_environment: str = "/usr/local/bin:/usr/bin:/bin",
        runtime_pins: ReviewedKimiRuntimePins | None = None,
        canary_token: str | None = None,
        shared_materializer: Callable[..., Any] | None = None,
        forbidden_host_paths: Sequence[Path | str] = (),
        adapter_factory: Callable[..., Any] = KimiHarnessAdapter,
        broker_factory: Callable[..., Any] = RunScopedProviderBroker,
        callback_collector_factory: Callable[..., Any] = RunScopedCallbackCollector,
        launcher_factory: Callable[..., Any] = LinuxBubblewrapLauncher,
        normalizer_factory: Callable[..., Any] = KimiBenchEventIRNormalizer,
        direct_observer_factory: Callable[..., Any] = KimiDirectEvidenceObserver,
        executor_factory: Callable[..., Any] = KimiStageExecutor,
        executor_wrapper_factory: Callable[..., Any] | None = None,
        materializer_factory: Callable[..., Any] = BenchMaterializerBridge,
        process_identity_probe: ProcessIdentityProbe = inspect_process,
    ) -> None:
        self.repo_root = Path(repo_root).resolve(strict=True)
        if self.repo_root == Path("/") or not self.repo_root.is_dir():
            raise ValueError("repo_root must be a concrete repository directory")
        if not callable(credential_fd_supplier):
            raise ValueError("credential_fd_supplier must be callable")
        if not isinstance(model_name, str) or not model_name.strip() or "\0" in model_name:
            raise ValueError("model_name must be non-empty")
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds < 1
        ):
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(path_environment, str) or not path_environment:
            raise ValueError("path_environment must be non-empty")
        # Parse now without DNS or network activity.  The real broker repeats
        # this validation before it receives the credential descriptor.
        UpstreamEndpoint.parse(
            upstream_url, allowed_https_hosts=allowed_https_hosts
        )
        self.upstream_url = upstream_url
        self.allowed_https_hosts = tuple(allowed_https_hosts)
        self.credential_fd_supplier = credential_fd_supplier
        self.model_name = model_name
        self.executable = Path(executable).absolute()
        self.bwrap_path = Path(bwrap_path).absolute()
        self.timeout_seconds = timeout_seconds
        self.path_environment = path_environment
        self.runtime_pins = runtime_pins or ReviewedKimiRuntimePins()
        self.canary_token = canary_token
        self.shared_materializer = shared_materializer
        self.forbidden_host_paths = tuple(Path(item).absolute() for item in forbidden_host_paths)
        self.adapter_factory = adapter_factory
        self.broker_factory = broker_factory
        self.callback_collector_factory = callback_collector_factory
        self.launcher_factory = launcher_factory
        self.normalizer_factory = normalizer_factory
        self.direct_observer_factory = direct_observer_factory
        self.executor_factory = executor_factory
        if executor_wrapper_factory is not None and not callable(
            executor_wrapper_factory
        ):
            raise ValueError("executor_wrapper_factory must be callable or None")
        self.executor_wrapper_factory = executor_wrapper_factory
        self.materializer_factory = materializer_factory
        self.process_identity_probe = process_identity_probe
        self._credential_lock = threading.Lock()
        self._claimed_credential_objects: dict[tuple[int, int, int], str] = {}

    def _claim_credential_fd(self) -> tuple[int, str]:
        descriptor = self.credential_fd_supplier()
        if (
            not isinstance(descriptor, int)
            or isinstance(descriptor, bool)
            or descriptor < 3
        ):
            raise KimiProductionRuntimeError(
                "credential supplier must return an open descriptor >= 3"
            )
        try:
            transport, identity = _credential_transport(descriptor)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        with self._credential_lock:
            prior = self._claimed_credential_objects.get(identity)
            controlled_reopen = type(self.credential_fd_supplier) is (
                ReopenedSealedMemfdCredentialSupplier
            )
            if prior is not None and not (
                transport == "sealed_memfd"
                and prior == "sealed_memfd"
                and controlled_reopen
                and self.credential_fd_supplier.source_identity == identity
            ):
                os.close(descriptor)
                raise KimiProductionRuntimeError(
                    "credential pipe or unproved shared-offset memfd reuse across "
                    "Kimi cases is forbidden"
                )
            self._claimed_credential_objects[identity] = transport
        return descriptor, transport

    def __call__(
        self,
        *,
        plan: CasePlan,
        layout: CaseRunLayout,
        process_registry: OwnedProcessRegistry,
        loopback_port: LoopbackPortLease,
    ) -> AbstractContextManager[RuntimePreflight]:
        return _TrialRuntimeContext(
            hook=self,
            plan=plan,
            layout=layout,
            process_registry=process_registry,
            loopback_port=loopback_port,
        )


class _TrialRuntimeContext(AbstractContextManager[RuntimePreflight]):
    def __init__(
        self,
        *,
        hook: KimiProductionRuntimeHook,
        plan: CasePlan,
        layout: CaseRunLayout,
        process_registry: OwnedProcessRegistry,
        loopback_port: LoopbackPortLease,
    ) -> None:
        self.hook = hook
        self.plan = plan
        self.layout = layout
        self.process_registry = process_registry
        self.loopback_port = loopback_port
        self.root: Path | None = None
        self.adapter: Any = None
        self.identity: HarnessIdentity | None = None
        self.broker: Any = None
        self.callback_collector: Any = None
        self.launcher: Any = None
        self.runtime: RuntimePreflight | None = None
        self.close_evidence: dict[str, Any] = {}
        self._credential_fd: int | None = None
        self._credential_transport: str | None = None
        self._precredential_blockers: tuple[str, ...] = ()
        self._closed = False

    def _identity_and_matrix(
        self, identity_service: Path
    ) -> tuple[HarnessIdentity, dict[str, CapabilityEvidence], Path, Path, Path]:
        safe_environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        }
        self.adapter = self.hook.adapter_factory(
            run_id=self.layout.run_id,
            state_root=identity_service,
            executable=self.hook.executable,
            base_environment=safe_environment,
        )
        identity = self.adapter.detect_identity()
        if not isinstance(identity, HarnessIdentity):
            raise KimiProductionRuntimeError("adapter returned an invalid Kimi identity")
        package, entrypoint, node = _validate_runtime_pins(
            self.hook.runtime_pins, identity
        )
        probe = self.adapter.probe_capabilities(self.plan.required_capabilities)
        if tuple(getattr(probe, "required_capabilities", ())) != tuple(
            self.plan.required_capabilities
        ):
            raise KimiProductionRuntimeError(
                "adapter changed the required capability set"
            )
        matrix = getattr(self.adapter, "last_capability_matrix", None)
        if not isinstance(matrix, Mapping) or set(matrix) != set(CAPABILITIES):
            raise KimiProductionRuntimeError(
                "adapter did not return the complete Contract-v1 capability matrix"
            )
        normalized: dict[str, CapabilityEvidence] = {}
        for capability in CAPABILITIES:
            item = matrix[capability]
            if (
                not isinstance(item, CapabilityEvidence)
                or item.capability != capability
                or item.status not in _CAPABILITY_STATES
                or not item.evidence
            ):
                raise KimiProductionRuntimeError(
                    f"adapter capability evidence is invalid: {capability}"
                )
            normalized[capability] = item
        return identity, normalized, package, entrypoint, node

    def _precredential_decision(
        self,
        matrix: Mapping[str, CapabilityEvidence],
    ) -> tuple[
        CapabilityDecision,
        dict[str, str],
        dict[str, tuple[str, ...]],
    ] | None:
        """Stop before credential access when runtime cannot close the gate.

        A live launcher can directly upgrade only the capabilities in
        ``_DYNAMIC_ISOLATION_CAPABILITIES``.  Starting a credential broker or
        bubblewrap self-test cannot change an already-UNSUPPORTED requirement,
        nor can it prove native durable memory or matched-control equivalence.
        In those cases the complete static matrix is already decisive and must
        be returned without claiming, reading, closing, or forwarding a
        credential descriptor.
        """

        blockers = tuple(
            capability
            for capability in self.plan.required_capabilities
            if matrix[capability].status == "UNSUPPORTED"
            or (
                matrix[capability].status == "UNVALIDATED"
                and capability not in _DYNAMIC_ISOLATION_CAPABILITIES
            )
        )
        if not blockers:
            return None
        states = {
            capability: matrix[capability].status for capability in CAPABILITIES
        }
        evidence = {
            capability: tuple(matrix[capability].evidence)
            for capability in CAPABILITIES
        }
        required_states = [states[item] for item in self.plan.required_capabilities]
        status = (
            "UNSUPPORTED"
            if "UNSUPPORTED" in required_states
            else "UNVALIDATED"
        )
        selected_evidence = tuple(
            dict.fromkeys(
                locator
                for capability in self.plan.required_capabilities
                for locator in evidence[capability]
            )
        )
        reasons = tuple(
            f"{capability}: {matrix[capability].detail}"
            for capability in self.plan.required_capabilities
            if states[capability] != "SUPPORTED"
        )
        self._precredential_blockers = blockers
        return (
            CapabilityDecision(
                status=status,
                required_capabilities=self.plan.required_capabilities,
                evidence=selected_evidence,
                reasons=reasons,
                capability_states=states,
                capability_evidence=evidence,
            ),
            states,
            evidence,
        )

    def _build_capability_decision(
        self,
        *,
        matrix: Mapping[str, CapabilityEvidence],
        attestation_path: Path,
        attestation_sha256: str,
    ) -> tuple[CapabilityDecision, dict[str, str], dict[str, tuple[str, ...]]]:
        states = {capability: matrix[capability].status for capability in CAPABILITIES}
        evidence = {
            capability: tuple(matrix[capability].evidence)
            for capability in CAPABILITIES
        }
        isolation_locator = (
            f"{attestation_path}#sha256={attestation_sha256}"
        )
        for capability in _DYNAMIC_ISOLATION_CAPABILITIES:
            if states[capability] != "UNSUPPORTED":
                states[capability] = "SUPPORTED"
                evidence[capability] = tuple(
                    dict.fromkeys((*evidence[capability], isolation_locator))
                )
        # Control equivalence and native durable memory are deliberately
        # outside this adapter-owned upgrade.  An attested filesystem/provider
        # boundary is neither a per-case matched intervention nor native memory
        # proof.
        for capability in (
            "control_isolation",
            "durable_memory_write",
            "durable_memory_retrieval",
        ):
            if states[capability] != matrix[capability].status:
                raise AssertionError(
                    f"{capability} state was unexpectedly changed"
                )

        required_states = [states[item] for item in self.plan.required_capabilities]
        status = (
            "UNSUPPORTED"
            if "UNSUPPORTED" in required_states
            else "UNVALIDATED"
            if "UNVALIDATED" in required_states
            else "SUPPORTED"
        )
        selected_evidence = tuple(
            dict.fromkeys(
                locator
                for capability in self.plan.required_capabilities
                for locator in evidence[capability]
            )
        )
        reasons = tuple(
            f"{capability}: {matrix[capability].detail}"
            for capability in self.plan.required_capabilities
            if states[capability] != "SUPPORTED"
        )
        decision = CapabilityDecision(
            status=status,
            required_capabilities=self.plan.required_capabilities,
            evidence=selected_evidence,
            reasons=reasons,
            capability_states=states,
            capability_evidence=evidence,
        )
        return decision, states, evidence

    def __enter__(self) -> RuntimePreflight:
        try:
            root = _validate_layout(
                plan=self.plan,
                layout=self.layout,
                process_registry=self.process_registry,
                loopback_port=self.loopback_port,
            )
            self.root = root
            identity_service = root / f"identity-service-kimi-{self.layout.run_id}"
            identity_service.mkdir(mode=0o700)
            identity, matrix, package, entrypoint, node = self._identity_and_matrix(
                identity_service
            )
            self.identity = identity

            blocked = self._precredential_decision(matrix)
            if blocked is not None:
                decision, states, capability_evidence = blocked
                self.runtime = RuntimePreflight(
                    capability=decision,
                    capability_states=states,
                    capability_evidence=capability_evidence,
                    callback_url=f"http://127.0.0.1:{self.loopback_port.port}",
                    preexisting_service_paths=(identity_service,),
                    materializer=None,
                    executor=None,
                    close_evidence=self.close_evidence,
                )
                return self.runtime

            case_digest = case_identity_digest(self.plan.case.case_id)
            trial_id = f"trial-kimi-{self.layout.run_id}-{case_digest}"
            try:
                expected_provider_socket, expected_callback_socket = (
                    production_service_paths(
                        root,
                        run_id=self.layout.run_id,
                        case_id=self.plan.case.case_id,
                        trial_id=trial_id,
                    )
                )
            except KimiLifecycleError as exc:
                raise KimiProductionRuntimeError(
                    "validated Kimi provider/callback socket layout is unavailable: "
                    f"{exc}"
                ) from exc
            self._credential_fd, self._credential_transport = (
                self.hook._claim_credential_fd()
            )
            try:
                self.broker = self.hook.broker_factory(
                    ownership_root=root,
                    run_id=self.layout.run_id,
                    case_id=self.plan.case.case_id,
                    trial_id=trial_id,
                    upstream_url=self.hook.upstream_url,
                    credential_fd=self._credential_fd,
                    allowed_https_hosts=self.hook.allowed_https_hosts,
                )
            finally:
                if self._credential_fd is not None:
                    try:
                        os.close(self._credential_fd)
                    finally:
                        self._credential_fd = None

            self.callback_collector = self.hook.callback_collector_factory(
                ownership_root=root,
                run_id=self.layout.run_id,
                case_id=self.plan.case.case_id,
                trial_id=trial_id,
            )
            if (
                Path(self.broker.socket_path).absolute()
                != expected_provider_socket
                or Path(self.callback_collector.socket_path).absolute()
                != expected_callback_socket
            ):
                raise KimiProductionRuntimeError(
                    "provider/callback socket path differs from the validated short layout"
                )
            forbidden = tuple(
                dict.fromkeys(
                    (
                        self.hook.repo_root.parent,
                        *self.hook.forbidden_host_paths,
                    )
                )
            )
            self.launcher = self.hook.launcher_factory(
                broker=self.broker,
                callback_collector=self.callback_collector,
                run_id=self.layout.run_id,
                ownership_root=root,
                model_name=self.hook.model_name,
                reviewed_broker_implementation_path=(
                    self.broker.implementation_path
                ),
                reviewed_broker_implementation_sha256=(
                    self.broker.implementation_sha256
                ),
                reviewed_broker_process_executable_path=(
                    self.broker.process_executable_path
                ),
                reviewed_broker_process_executable_sha256=(
                    self.broker.process_executable_sha256
                ),
                reviewed_kimi_package_root=package,
                reviewed_kimi_package_tree_sha256=(
                    self.hook.runtime_pins.package_tree_sha256
                ),
                reviewed_kimi_entrypoint_path=entrypoint,
                reviewed_kimi_entrypoint_sha256=(
                    self.hook.runtime_pins.entrypoint_sha256
                ),
                reviewed_node_executable_path=node,
                reviewed_node_executable_sha256=self.hook.runtime_pins.node_sha256,
                bwrap_path=self.hook.bwrap_path,
                forbidden_paths=forbidden,
            )
            attestation_path = Path(
                self.launcher.attest(run_id=self.layout.run_id, run_root=root)
            )
            attestation_sha = _validate_launcher_attestation(
                attestation_path, run_id=self.layout.run_id, root=root
            )
            snapshot = _validate_launcher_snapshot(
                self.launcher.resource_snapshot(),
                run_id=self.layout.run_id,
                closed=False,
            )
            if (
                snapshot["attested_context_count"] != 1
                or snapshot["owned_process_count"] != 0
                or snapshot["spawned_stage_count"] != 0
                or snapshot["active_processes"]
            ):
                raise KimiProductionRuntimeError(
                    "new launcher attestation has unexpected trial resources"
                )

            decision, states, capability_evidence = self._build_capability_decision(
                matrix=matrix,
                attestation_path=attestation_path,
                attestation_sha256=attestation_sha,
            )
            normalizer = self.hook.normalizer_factory(identity=identity)
            direct_observer = self.hook.direct_observer_factory(self.broker)
            raw_executor = self.hook.executor_factory(
                launcher=self.launcher,
                event_ir_normalizer=normalizer,
                executable=entrypoint,
                executable_sha256=self.hook.runtime_pins.entrypoint_sha256,
                timeout_seconds=self.hook.timeout_seconds,
                path_environment=self.hook.path_environment,
                resume_controller=KimiExactSessionController(),
                compact_controller=KimiAcpCompactionController(),
                subagent_controller=KimiSubagentArtifactController(),
                direct_evidence_observer=direct_observer,
            )
            executor = raw_executor
            if self.hook.executor_wrapper_factory is not None:
                executor = self.hook.executor_wrapper_factory(
                    delegate=raw_executor,
                    run_id=self.layout.run_id,
                    case_id=self.plan.case.case_id,
                    trial_id=trial_id,
                    run_root=root,
                    callback_collector=self.callback_collector,
                )
                if not callable(getattr(executor, "execute", None)):
                    raise KimiProductionRuntimeError(
                        "executor wrapper factory did not return a CaseExecutor"
                    )
            materializer_kwargs: dict[str, Any] = {
                "repo_root": self.hook.repo_root,
                "canary_token": self.hook.canary_token,
            }
            if self.hook.shared_materializer is not None:
                materializer_kwargs["shared_materializer"] = (
                    self.hook.shared_materializer
                )
            materializer = self.hook.materializer_factory(**materializer_kwargs)

            children = tuple(sorted(root.iterdir(), key=lambda item: item.name))
            expected_children = {
                identity_service,
                Path(self.broker.root).absolute(),
                Path(self.callback_collector.root).absolute(),
                attestation_path.parent.absolute(),
            }
            if set(children) != expected_children:
                raise KimiProductionRuntimeError(
                    "preflight created undeclared case-root resources"
                )
            for child in children:
                metadata = child.lstat()
                if (
                    child.is_symlink()
                    or not child.is_dir()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or metadata.st_uid != os.geteuid()
                ):
                    raise KimiProductionRuntimeError(
                        "preflight service root is not private and runner-owned"
                    )

            callback_url = (
                f"http://127.0.0.1:{self.loopback_port.port}"
            )
            self.runtime = RuntimePreflight(
                capability=decision,
                capability_states=states,
                capability_evidence=capability_evidence,
                callback_url=callback_url,
                preexisting_service_paths=children,
                materializer=materializer,
                executor=executor,
                close_evidence=self.close_evidence,
            )
            return self.runtime
        except BaseException as startup_error:
            try:
                self._close(startup_failed=True)
            except BaseException as close_error:
                raise KimiProductionRuntimeError(
                    "Kimi runtime startup failed and exact cleanup also failed: "
                    f"{type(close_error).__name__}: {close_error}",
                    close_evidence=self.close_evidence,
                ) from startup_error
            try:
                setattr(startup_error, "close_evidence", dict(self.close_evidence))
                setattr(
                    startup_error,
                    "_kimi_runtime_close_evidence",
                    dict(self.close_evidence),
                )
            except Exception:
                pass
            raise

    @staticmethod
    def _attestation_reference(service: Any, label: str) -> dict[str, Any]:
        path = Path(getattr(service, "attestation_path", Path("/"))).absolute()
        if path.is_symlink() or not path.is_file():
            raise KimiProductionRuntimeError(f"{label} attestation is unavailable")
        return {
            "path": str(path),
            "sha256": sha256_file(path),
            "pid": getattr(service, "pid", None),
            "start_time": getattr(service, "start_time", None),
        }

    def _close(self, *, startup_failed: bool) -> None:
        if self._closed:
            return
        self._closed = True
        errors: list[str] = []
        evidence: dict[str, Any] = {
            "schema_name": "safety_bench_kimi_runtime_close_evidence",
            "schema_version": 1,
            "harness_id": "kimi",
            "run_id": self.layout.run_id,
            "case_id": self.plan.case.case_id,
            "startup_failed": startup_failed,
            "closed_at": datetime.now(timezone.utc).isoformat(),
            "closed": False,
            "credential_transport": self._credential_transport,
            "credential_descriptor_open_in_parent": self._credential_fd is not None,
        }
        if self._precredential_blockers:
            evidence["precredential_capability_gate"] = {
                "blocked": True,
                "blocking_capabilities": list(self._precredential_blockers),
                "credential_supplier_called": False,
                "provider_callback_launcher_started": False,
            }
        if self._credential_fd is not None:
            try:
                os.close(self._credential_fd)
            except OSError as exc:
                errors.append(f"credential_fd:{type(exc).__name__}")
            finally:
                self._credential_fd = None
                evidence["credential_descriptor_open_in_parent"] = False

        launcher_before: dict[str, Any] | None = None
        if self.launcher is not None:
            try:
                launcher_before = _validate_launcher_snapshot(
                    self.launcher.resource_snapshot(),
                    run_id=self.layout.run_id,
                    closed=False,
                )
                evidence["launcher_before_close"] = launcher_before
            except BaseException as exc:
                errors.append(f"launcher_snapshot_before:{type(exc).__name__}")
            try:
                self.launcher.close()
                evidence["launcher_after_close"] = _validate_launcher_snapshot(
                    self.launcher.resource_snapshot(),
                    run_id=self.layout.run_id,
                    closed=True,
                )
            except BaseException as exc:
                errors.append(f"launcher_close:{type(exc).__name__}")

        if self.broker is not None:
            try:
                evidence["provider_broker_attestation"] = (
                    self._attestation_reference(self.broker, "provider broker")
                )
                leases = self.broker.active_lease_count
                evidence["provider_broker_active_leases_before_close"] = leases
                if leases != 0:
                    raise KimiProductionRuntimeError(
                        "provider broker retained an active trial lease"
                    )
            except BaseException as exc:
                errors.append(f"provider_broker_preclose:{type(exc).__name__}")

        if self.callback_collector is not None:
            try:
                evidence["callback_collector_attestation"] = (
                    self._attestation_reference(
                        self.callback_collector, "callback collector"
                    )
                )
                leases = self.callback_collector.active_lease_count
                evidence["callback_collector_active_leases_before_close"] = leases
                if leases != 0:
                    raise KimiProductionRuntimeError(
                        "callback collector retained an active trial lease"
                    )
                manifest_path = Path(
                    self.callback_collector.evidence_manifest_path
                ).absolute()
                spawned = (
                    launcher_before["spawned_stage_count"]
                    if launcher_before is not None
                    else 0
                )
                if manifest_path.exists():
                    manifest = self.callback_collector.verify_evidence_manifest()
                    completed = manifest.get("completed_stage_connections")
                    if (
                        not isinstance(completed, list)
                        or len(completed) != spawned
                        or any(
                            not isinstance(item, Mapping)
                            or not isinstance(item.get("stage_index"), int)
                            or isinstance(item.get("stage_index"), bool)
                            or item.get("stage_index") < 0
                            or item.get("outcome") != "completed"
                            for item in completed
                        )
                        or len(
                            {
                                int(item["stage_index"])
                                for item in completed
                                if isinstance(item, Mapping)
                            }
                        )
                        != spawned
                    ):
                        raise KimiProductionRuntimeError(
                            "callback manifest does not exactly cover spawned stages"
                        )
                    evidence["callback_manifest"] = {
                        "status": "verified",
                        "path": str(manifest_path),
                        "sha256": sha256_file(manifest_path),
                        "line_count": manifest.get("line_count"),
                        "spawned_stage_count": spawned,
                        "completed_stage_indices": sorted(
                            int(item["stage_index"]) for item in completed
                        ),
                    }
                elif spawned:
                    raise KimiProductionRuntimeError(
                        "spawned stages have no callback evidence manifest"
                    )
                else:
                    evidence["callback_manifest"] = {
                        "status": "not_created_no_stage_spawned",
                        "path": str(manifest_path),
                        "spawned_stage_count": 0,
                    }
            except BaseException as exc:
                errors.append(f"callback_collector_preclose:{type(exc).__name__}")

        for label, service in (
            ("callback_collector", self.callback_collector),
            ("provider_broker", self.broker),
        ):
            if service is None:
                continue
            try:
                service.close()
                evidence[f"{label}_process"] = _process_closed_evidence(
                    service,
                    process_probe=self.hook.process_identity_probe,
                    label=label.replace("_", " "),
                )
            except BaseException as exc:
                errors.append(f"{label}_close:{type(exc).__name__}")

        evidence["errors"] = errors
        evidence["closed"] = not errors
        forbidden = _forbidden_keys(evidence)
        if forbidden:
            errors.append("forbidden_scoring_evidence_key")
            evidence["closed"] = False
            evidence["errors"] = errors
        try:
            json.dumps(evidence, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            errors.append("non_json_serializable_close_evidence")
            evidence = {
                "schema_name": "safety_bench_kimi_runtime_close_evidence",
                "schema_version": 1,
                "harness_id": "kimi",
                "run_id": self.layout.run_id,
                "case_id": self.plan.case.case_id,
                "closed": False,
                "errors": errors,
            }
        self.close_evidence.clear()
        self.close_evidence.update(evidence)
        if errors:
            raise KimiProductionRuntimeError(
                "Kimi runtime cleanup failed closed: " + ", ".join(errors),
                close_evidence=evidence,
            )

    def __exit__(self, *_: object) -> bool:
        self._close(startup_failed=False)
        return False


__all__ = [
    "EXPECTED_KIMI_ENTRYPOINT_SHA256",
    "EXPECTED_KIMI_PACKAGE_TREE_SHA256",
    "EXPECTED_KIMI_VERSION",
    "EXPECTED_NODE_SHA256",
    "KimiProductionRuntimeError",
    "KimiProductionRuntimeHook",
    "ReopenedSealedMemfdCredentialSupplier",
    "ReviewedKimiRuntimePins",
]
