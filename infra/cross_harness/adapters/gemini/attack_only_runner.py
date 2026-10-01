"""Formal Gemini CLI 328-case attack-only execution support.

This module is intentionally separate from the scored Cross-Harness adapter and
from the matched-control qualification runner.  It executes one attack trial per
case, never runs controls, and never writes N0--N5b scoring.  A case becomes
``ATTACK_COMPLETED`` only after every declared attack stage exits successfully
and the Gemini raw traces normalize to the required Event IR.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlparse

from ...adapter import HarnessIdentity
from ...bindings.gemini import load_gemini_all_bindings
from .adapter import GeminiHarnessAdapter
from .capabilities import aggregate_required_capabilities, capability_matrix
from .launcher import build_gemini_bwrap_command, build_gemini_launch_spec
from .materializer import (
    binding_document_sha256,
    load_materialization_manifest,
    sha256_file,
)
from .openai_compat_proxy import OpenAICompatibleVertexProxy
from .vertex_auth_proxy import ServiceAccountTokenProvider, VertexQualificationProxy


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CONFORMANCE = (
    REPO_ROOT
    / "tests/cross_harness/gemini/fixtures/gemini_cli_0_51_0_capability_conformance.json"
)
DEFAULT_INVENTORY = REPO_ROOT / "infra/cross_harness/bindings/gemini/active_328_v1.json"
DEFAULT_MODEL = "gemini-3.5-flash"
DEFAULT_LOCATION = "global"
DEFAULT_PROVIDER_KIND = "openai-compatible"
DEFAULT_API_BASE_URL = "https://api.evomap.ai/v1"
DEFAULT_API_KEY_ENV = "EVOMAP_API_KEY"
DEFAULT_VERTEX_SHIM_PROJECT = "safety-bench-proxy"
DEFAULT_TIMEOUT_SECONDS = 360
DEFAULT_MAX_PROVIDER_REQUESTS_PER_STAGE = 40
DEFAULT_HONEYPOT_HOST = "127.0.0.1"
DEFAULT_HONEYPOT_PORT = 18765
DEFAULT_CALLBACK_URL = f"http://{DEFAULT_HONEYPOT_HOST}:{DEFAULT_HONEYPOT_PORT}"
GEMINI_CLI_VERSION = "0.51.0"
PROTOCOL_SCHEMA_VERSION = 1


class GeminiAttackOnlyError(RuntimeError):
    """The attack-only runner failed a protocol or execution invariant."""


class _CaseExecutionFailure(RuntimeError):
    def __init__(self, reason: str, *, failure_type: str) -> None:
        super().__init__(reason)
        self.failure_type = failure_type


class _GeminiProviderProxy(Protocol):
    base_url: str
    project: str
    location: str

    def begin_scope(self, label: str, *, max_provider_requests: int = 12) -> None: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GeminiAttackOnlyError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _jsonl_line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


@contextmanager
def _stage_honeypot(
    *,
    enabled: bool,
    host: str,
    port: int,
    log_path: Path,
    stderr_path: Path,
    startup_timeout_seconds: float = 2.0,
) -> Iterator[None]:
    """Run the local loopback honeypot for one stage.

    The honeypot is evidence collection only.  It logs real HTTP requests and
    never creates analyzer evidence by itself.
    """

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_handle = None
    process: subprocess.Popen[str] | None = None
    if enabled:
        honeypot_script = REPO_ROOT / "infra" / "honeypot.py"
        stderr_handle = stderr_path.open("w", encoding="utf-8")
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(honeypot_script),
                    "--host",
                    host,
                    "--port",
                    str(port),
                    "--log",
                    str(log_path),
                ],
                cwd=str(REPO_ROOT),
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
            )
            deadline = time.time() + startup_timeout_seconds
            while time.time() < deadline:
                if process.poll() is not None:
                    raise _CaseExecutionFailure(
                        f"stage honeypot exited before launch; stderr_sha256={sha256_file(stderr_path)}",
                        failure_type="honeypot_startup",
                    )
                if log_path.is_file():
                    break
                time.sleep(0.05)
            if process.poll() is not None:
                raise _CaseExecutionFailure(
                    f"stage honeypot exited before launch; stderr_sha256={sha256_file(stderr_path)}",
                    failure_type="honeypot_startup",
                )
            yield
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if stderr_handle is not None:
                stderr_handle.close()
    else:
        stderr_path.write_text("", encoding="utf-8")
        yield


def _batch_report_path(work_root: Path, *, dry_run: bool) -> Path:
    if dry_run:
        return work_root / "attack-only-dry-run-report.json"
    return work_root / "attack-only-batch-report.json"


def _load_secret_from_dotenv(*, repo_root: Path, key: str) -> str:
    """Load a single secret from a git-ignored local .env file.

    This deliberately supports only simple KEY=VALUE lines.  It never logs,
    returns metadata about, or writes the secret value.
    """

    env_path = repo_root / ".env"
    if not env_path.is_file():
        return ""
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() != key:
            continue
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        return value
    return ""


def _validate_honeypot_configuration(
    *, enabled: bool, callback_url: str, honeypot_host: str, honeypot_port: int
) -> None:
    if not enabled:
        return
    parsed = urlparse(callback_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise GeminiAttackOnlyError(
            "--enable-honeypot requires an http loopback callback URL"
        )
    if parsed.port != honeypot_port:
        raise GeminiAttackOnlyError(
            "--callback-url port must match --honeypot-port when honeypot is enabled"
        )
    if honeypot_host not in {"127.0.0.1", "localhost"}:
        raise GeminiAttackOnlyError(
            "--honeypot-host must be loopback when honeypot is enabled"
        )


def attack_only_protocol(
    *,
    repo_root: Path | None = None,
    conformance_path: Path | None = None,
    model: str = DEFAULT_MODEL,
    location: str = DEFAULT_LOCATION,
    provider_kind: str = DEFAULT_PROVIDER_KIND,
    api_base_url: str = DEFAULT_API_BASE_URL,
) -> dict[str, Any]:
    root = (repo_root or REPO_ROOT).resolve()
    conformance = (conformance_path or DEFAULT_CONFORMANCE).resolve()
    inventory = _read_json(
        root / "infra/cross_harness/bindings/gemini/active_328_v1.json"
    )
    protocol = {
        "schema_name": "safety_bench_gemini_attack_only_protocol",
        "schema_version": PROTOCOL_SCHEMA_VERSION,
        "harness_id": "gemini",
        "gemini_cli_version": _conformance_identity(conformance).version,
        "model": model,
        "provider": {
            "kind": provider_kind,
            "api_base_url": api_base_url if provider_kind == "openai-compatible" else None,
            "vertex_shim_location": location,
            "upstream_credential_recorded": False,
        },
        "case_scope": "active_328",
        "case_count": 328,
        "trial_policy": {
            "attack_trials_per_case": 1,
            "controls_required": False,
            "matched_controls_generated": False,
            "retry_policy": "transient execution retry is external to this single-trial record",
        },
        "completion_gate": {
            "ATTACK_COMPLETED": (
                "all attack stages exit 0 and final-stage normalization contains every "
                "binding-declared expected Event IR type"
            ),
            "NOT_RUN": "case is not capability-ready or environment preflight is unverified",
            "BLOCKED": "adapter binding semantics are unresolved before execution",
            "FAILED": "a ready case was invoked but materialization, launch, process, or trace validation failed",
        },
        "scoring": {
            "status_during_execution": "NOT_PRODUCED",
            "only_attack_completed_enters_shared_analyzer": True,
            "failed_or_not_run_never_maps_to_SAFE_or_N0": True,
        },
        "source_contract": inventory["source_contract"],
        "inventory_content_sha256": inventory["inventory_content_sha256"],
        "conformance_path": str(
            conformance.relative_to(root)
            if conformance.is_relative_to(root)
            else conformance
        ),
        "conformance_sha256": sha256_file(conformance),
    }
    protocol["protocol_sha256"] = _canonical_json_sha256(protocol)
    return protocol


def _conformance_identity(conformance_path: Path) -> HarnessIdentity:
    document = _read_json(conformance_path)
    return HarnessIdentity(
        harness_id="gemini",
        version=str(document["harness_version"]),
        executable="/version-pinned/evidence-only/gemini",
        feature_flags={
            "binary_sha256": document["executable_sha256"],
            "headless_prompt": True,
            "stream_json": True,
            "resume": True,
            "session_id": True,
        },
    )


def build_attack_readiness(
    *,
    repo_root: Path | None = None,
    conformance_path: Path | None = None,
    model: str = DEFAULT_MODEL,
    location: str = DEFAULT_LOCATION,
    provider_kind: str = DEFAULT_PROVIDER_KIND,
    api_base_url: str = DEFAULT_API_BASE_URL,
) -> dict[str, Any]:
    root = (repo_root or REPO_ROOT).resolve()
    conformance = (conformance_path or DEFAULT_CONFORMANCE).resolve()
    inventory = _read_json(
        root / "infra/cross_harness/bindings/gemini/active_328_v1.json"
    )
    protocol = attack_only_protocol(
        repo_root=root,
        conformance_path=conformance,
        model=model,
        location=location,
        provider_kind=provider_kind,
        api_base_url=api_base_url,
    )
    matrix = capability_matrix(
        identity=_conformance_identity(conformance), conformance_path=conformance
    )
    rows: list[dict[str, Any]] = []
    for row in inventory["cases"]:
        aggregate, evidence, reasons = aggregate_required_capabilities(
            row["required_capabilities"], matrix
        )
        capability_status = {
            capability: matrix[capability].status
            for capability in row["required_capabilities"]
        }
        if row["disposition"] == "BLOCKED":
            attack_status = "BLOCKED"
            blocking_reasons = list(row["blocking_reasons"])
        elif aggregate == "SUPPORTED":
            attack_status = "ATTACK_READY"
            blocking_reasons = []
        else:
            attack_status = "NOT_RUN"
            blocking_reasons = [*row["blocking_reasons"], *reasons]
        rows.append(
            {
                "manifest_index": row["manifest_index"],
                "suite": row["suite"],
                "case_id": row["case_id"],
                "case_dir": row["case_dir"],
                "stage_count": row["stage_count"],
                "case_meta_sha256": row["case_meta_sha256"],
                "binding_version": row["binding_version"],
                "binding_kind": row["binding_kind"],
                "comparison_group": row["comparison_group"],
                "required_capabilities": row["required_capabilities"],
                "required_capability_status": capability_status,
                "capability_aggregate_status": aggregate,
                "capability_evidence": list(evidence),
                "attack_status": attack_status,
                "blocking_reasons": list(dict.fromkeys(blocking_reasons)),
                "execution_outcome": "NOT_RUN",
                "scoring_status": "NOT_PRODUCED",
            }
        )
    summary = {
        "case_count": len(rows),
        "stage_count": sum(row["stage_count"] for row in rows),
        "attack_status_counts": dict(Counter(row["attack_status"] for row in rows)),
        "attack_ready_stage_count": sum(
            row["stage_count"] for row in rows if row["attack_status"] == "ATTACK_READY"
        ),
        "not_run_blocker_group_counts": dict(
            Counter(
                " + ".join(
                    capability
                    for capability, status in row["required_capability_status"].items()
                    if status != "SUPPORTED"
                )
                for row in rows
                if row["attack_status"] == "NOT_RUN"
            )
        ),
        "scoring_status": "NOT_PRODUCED",
    }
    document = {
        "schema_name": "safety_bench_gemini_attack_only_readiness",
        "schema_version": 1,
        "generated_at": _now(),
        "protocol": protocol,
        "summary": summary,
        "cases": rows,
    }
    document["readiness_sha256"] = _canonical_json_sha256(document)
    return document


def _case_dir_map(repo_root: Path) -> dict[str, Path]:
    inventory = _read_json(
        repo_root / "infra/cross_harness/bindings/gemini/active_328_v1.json"
    )
    return {
        row["case_id"]: (repo_root / row["case_dir"]).resolve()
        for row in inventory["cases"]
    }


def _safe_case_dir_name(index: int, case_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", case_id)[:96].strip("._-")
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:12]
    return f"{index:03d}-{slug}-{digest}"


def _case_run_id(index: int, case_id: str) -> str:
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]
    return f"g328-{index:03d}-{digest}"


def _assistant_content_sha256(trace_path: Path) -> str:
    deltas: list[str] = []
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.get("type") == "message" and record.get("role") == "assistant":
            content = record.get("content")
            if isinstance(content, str):
                deltas.append(content)
    return hashlib.sha256("".join(deltas).encode("utf-8")).hexdigest()


def _not_invoked_outcome(
    *,
    status: str,
    case_row: Mapping[str, Any],
    protocol: Mapping[str, Any],
    case_run_dir: Path,
    reasons: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema_name": "safety_bench_gemini_attack_only_case_outcome",
        "schema_version": 1,
        "case_id": case_row["case_id"],
        "case_meta_sha256": case_row["case_meta_sha256"],
        "attack_status": status,
        "execution_outcome": status,
        "failure_type": "pre_execution_gate",
        "blocking_reasons": list(reasons),
        "stage_count_completed": 0,
        "stage_count_total": case_row["stage_count"],
        "stages": [],
        "run_kind": "attack",
        "controls_run": 0,
        "scoring_status": "NOT_PRODUCED",
        "safe_or_n0_prohibited": True,
        "protocol_sha256": protocol["protocol_sha256"],
        "raw_trace_root": str(case_run_dir),
        "started_at": None,
        "finished_at": _now(),
    }


def _existing_completed(
    path: Path, *, protocol_sha256: str, case_meta_sha256: str
) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        document = _read_json(path)
    except Exception:
        return None
    if (
        document.get("attack_status") == "ATTACK_COMPLETED"
        and document.get("protocol_sha256") == protocol_sha256
        and document.get("case_meta_sha256") == case_meta_sha256
    ):
        document = dict(document)
        document["idempotent_reuse"] = True
        return document
    return None


def _case_outcome_path(work_root: Path, case_row: Mapping[str, Any]) -> Path:
    return (
        work_root
        / "cases"
        / _safe_case_dir_name(int(case_row["manifest_index"]), str(case_row["case_id"]))
        / "attack-outcome.json"
    )


def _is_completed_outcome(
    work_root: Path, *, protocol: Mapping[str, Any], case_row: Mapping[str, Any]
) -> bool:
    return (
        _existing_completed(
            _case_outcome_path(work_root, case_row),
            protocol_sha256=str(protocol["protocol_sha256"]),
            case_meta_sha256=str(case_row["case_meta_sha256"]),
        )
        is not None
    )


def _load_case_ids_from_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        case_ids = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    else:
        if isinstance(value, list):
            case_ids = value
        elif isinstance(value, Mapping) and isinstance(value.get("case_ids"), list):
            case_ids = value["case_ids"]
        elif isinstance(value, Mapping) and isinstance(value.get("cases"), list):
            raw_cases = value["cases"]
            case_ids = [
                item["case_id"] if isinstance(item, Mapping) else item
                for item in raw_cases
            ]
        else:
            raise GeminiAttackOnlyError(
                "case-id file must be a newline list, JSON list, or JSON object "
                "with case_ids/cases"
            )
    if not all(isinstance(case_id, str) and case_id.strip() for case_id in case_ids):
        raise GeminiAttackOnlyError("case-id file contains an invalid case_id")
    return list(dict.fromkeys(str(case_id).strip() for case_id in case_ids))


def _artifact_status(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    workspace = Path(str(manifest["workspace_dir"]))
    result: dict[str, dict[str, Any]] = {}
    for name, relative in dict(manifest.get("artifact_bindings", {})).items():
        path = workspace / str(relative)
        result[str(name)] = {
            "path": str(relative),
            "present": path.is_file(),
            "sha256": sha256_file(path) if path.is_file() else None,
        }
    return result


def _case_proxy_environment(
    *, proxy: _GeminiProviderProxy, case_run_dir: Path
) -> dict[str, str]:
    """Create per-case placeholder ADC inside the bubblewrap-bound run tree."""

    client_dir = case_run_dir / "provider-client"
    client_dir.mkdir(parents=True, exist_ok=True)
    subject_path = client_dir / "placeholder-subject.txt"
    adc_path = client_dir / "placeholder-external-account.json"
    subject_path.write_text("safety-bench-placeholder-subject\n", encoding="utf-8")
    adc = {
        "type": "external_account",
        "audience": (
            "//iam.googleapis.com/projects/0/locations/global/"
            "workloadIdentityPools/safety-bench/providers/loopback"
        ),
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": proxy.base_url + "/qualification-sts",
        "credential_source": {
            "file": str(subject_path),
            "format": {"type": "text"},
        },
    }
    adc_path.write_text(
        json.dumps(adc, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "GOOGLE_APPLICATION_CREDENTIALS": str(adc_path),
        "GOOGLE_CLOUD_PROJECT": proxy.project,
        "GOOGLE_CLOUD_LOCATION": proxy.location,
        "GOOGLE_GENAI_USE_VERTEXAI": "true",
        "GOOGLE_VERTEX_BASE_URL": proxy.base_url,
    }


def execute_attack_case(
    *,
    case_row: Mapping[str, Any],
    binding: Mapping[str, Any],
    case_dir: Path,
    work_root: Path,
    protocol: Mapping[str, Any],
    proxy: _GeminiProviderProxy,
    executable: str,
    conformance_path: Path,
    timeout_seconds: int,
    max_provider_requests_per_stage: int,
    enable_honeypot: bool = False,
    callback_url: str = DEFAULT_CALLBACK_URL,
    honeypot_host: str = DEFAULT_HONEYPOT_HOST,
    honeypot_port: int = DEFAULT_HONEYPOT_PORT,
    skip_completed: bool = True,
) -> dict[str, Any]:
    case_run_dir = work_root / "cases" / _safe_case_dir_name(
        int(case_row["manifest_index"]), str(case_row["case_id"])
    )
    outcome_path = case_run_dir / "attack-outcome.json"
    if skip_completed:
        existing = _existing_completed(
            outcome_path,
            protocol_sha256=str(protocol["protocol_sha256"]),
            case_meta_sha256=str(case_row["case_meta_sha256"]),
        )
        if existing is not None:
            return existing
    if case_run_dir.exists():
        cases_root = work_root / "cases"
        if case_run_dir.parent.resolve() != cases_root.resolve():
            raise GeminiAttackOnlyError(
                f"refusing to clean unexpected case run directory: {case_run_dir}"
            )
        shutil.rmtree(case_run_dir)
    if case_row["attack_status"] != "ATTACK_READY":
        outcome = _not_invoked_outcome(
            status=str(case_row["attack_status"]),
            case_row=case_row,
            protocol=protocol,
            case_run_dir=case_run_dir,
            reasons=case_row.get("blocking_reasons", []),
        )
        _write_json(outcome_path, outcome)
        return outcome

    started = _now()
    stages: list[dict[str, Any]] = []
    honeypot_hit_count = 0
    proxy_environment = _case_proxy_environment(
        proxy=proxy,
        case_run_dir=case_run_dir,
    )
    adapter = GeminiHarnessAdapter(
        run_id=_case_run_id(int(case_row["manifest_index"]), str(case_row["case_id"])),
        run_dir=case_run_dir,
        executable=executable,
        conformance_evidence_path=conformance_path,
        model=str(protocol["model"]),
        callback_url=callback_url,
        canary_token=hashlib.sha256(
            f"{protocol['protocol_sha256']}:{case_row['case_id']}".encode("utf-8")
        ).hexdigest(),
        base_environment={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    materialized = None
    manifest: Mapping[str, Any] | None = None
    try:
        identity = adapter.detect_identity()
        if identity.version != protocol["gemini_cli_version"]:
            raise _CaseExecutionFailure(
                f"Gemini CLI version drifted: {identity.version}",
                failure_type="identity_preflight",
            )
        probe = adapter.probe_capabilities(case_row["required_capabilities"])
        if probe.status != "SUPPORTED":
            outcome = _not_invoked_outcome(
                status="NOT_RUN",
                case_row=case_row,
                protocol=protocol,
                case_run_dir=case_run_dir,
                reasons=probe.reasons,
            )
            outcome["failure_type"] = "capability_preflight"
            _write_json(outcome_path, outcome)
            return outcome
        materialized = adapter.materialize_binding(
            case_dir=case_dir,
            binding_document=binding,
            run_dir=case_run_dir,
        )
        manifest = load_materialization_manifest(materialized)
        for stage in manifest["stages"]:
            index = int(stage["index"])
            adapter.stage_index = index
            prompt = Path(stage["prompt_path"]).read_text(encoding="utf-8")
            spec = build_gemini_launch_spec(
                identity=identity,
                materialized=materialized,
                manifest=manifest,
                stage_index=index,
                prompt=prompt,
                timeout_seconds=timeout_seconds,
                base_environment=adapter.base_environment,
                model=str(protocol["model"]),
            )
            honeypot_path = spec.trace_path.with_name("honeypot.jsonl")
            honeypot_stderr_path = spec.trace_path.with_name("honeypot-stderr.txt")
            command = build_gemini_bwrap_command(
                launch_spec=spec,
                run_dir=case_run_dir,
                extra_environment=proxy_environment,
            )
            proxy.begin_scope(
                f"{case_row['case_id']}:attack:stage:{index}",
                max_provider_requests=max_provider_requests_per_stage,
            )
            try:
                with _stage_honeypot(
                    enabled=enable_honeypot,
                    host=honeypot_host,
                    port=honeypot_port,
                    log_path=honeypot_path,
                    stderr_path=honeypot_stderr_path,
                ):
                    result = subprocess.run(
                        command,
                        cwd="/",
                        env={"PATH": "/usr/bin:/bin"},
                        text=True,
                        capture_output=True,
                        timeout=timeout_seconds + 15,
                        check=False,
                    )
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8", errors="replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                spec.trace_path.write_text(stdout, encoding="utf-8")
                stderr_path = spec.trace_path.with_name("gemini-stderr.txt")
                stderr_path.write_text(stderr, encoding="utf-8")
                raise _CaseExecutionFailure(
                    f"stage {index} timed out",
                    failure_type="stage_timeout",
                ) from exc
            stage_honeypot_hits = _jsonl_line_count(honeypot_path)
            honeypot_hit_count += stage_honeypot_hits
            spec.trace_path.write_text(result.stdout, encoding="utf-8")
            stderr_path = spec.trace_path.with_name("gemini-stderr.txt")
            stderr_path.write_text(result.stderr, encoding="utf-8")
            if result.returncode != 0:
                raise _CaseExecutionFailure(
                    f"stage {index} exited {result.returncode}; stderr_sha256={sha256_file(stderr_path)}",
                    failure_type="stage_process_exit",
                )
            try:
                events = list(
                    adapter.normalize_trace(
                        identity=identity,
                        materialized=materialized,
                        raw_trace_path=spec.trace_path,
                    )
                )
            except Exception as exc:
                raise _CaseExecutionFailure(
                    f"stage {index} Event IR normalization failed: {exc}",
                    failure_type="event_ir_validation",
                ) from exc
            event_path = spec.trace_path.with_name("event-ir.jsonl")
            event_path.write_text(
                "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
                encoding="utf-8",
            )
            stages.append(
                {
                    "index": index,
                    "name": stage["name"],
                    "process_exit_code": result.returncode,
                    "raw_stream_sha256": sha256_file(spec.trace_path),
                    "stderr_sha256": sha256_file(stderr_path),
                    "assistant_content_sha256": _assistant_content_sha256(spec.trace_path),
                    "honeypot_enabled": enable_honeypot,
                    "honeypot_hit_count": stage_honeypot_hits,
                    "honeypot_path": str(honeypot_path),
                    "honeypot_sha256": sha256_file(honeypot_path),
                    "honeypot_stderr_sha256": sha256_file(honeypot_stderr_path),
                    "normalized_event_types": [event["event_type"] for event in events],
                    "normalized_event_count": len(events),
                    "event_ir_schema_valid": True,
                    "event_ir_path": str(event_path),
                    "event_ir_sha256": sha256_file(event_path),
                }
            )
        adapter.cleanup(materialized=materialized)
        outcome = {
            "schema_name": "safety_bench_gemini_attack_only_case_outcome",
            "schema_version": 1,
            "case_id": case_row["case_id"],
            "case_meta_sha256": case_row["case_meta_sha256"],
            "binding_sha256": binding_document_sha256(binding),
            "attack_status": "ATTACK_COMPLETED",
            "execution_outcome": "ATTACK_COMPLETED",
            "failure_type": None,
            "blocking_reasons": [],
            "stage_count_completed": len(stages),
            "stage_count_total": case_row["stage_count"],
            "stages": stages,
            "artifacts": _artifact_status(manifest),
            "run_kind": "attack",
            "controls_run": 0,
            "scoring_status": "NOT_PRODUCED",
            "safe_or_n0_prohibited": True,
            "protocol_sha256": protocol["protocol_sha256"],
            "raw_trace_root": str(case_run_dir),
            "callback_url": callback_url,
            "honeypot_enabled": enable_honeypot,
            "honeypot_hit_count": honeypot_hit_count,
            "started_at": started,
            "finished_at": _now(),
        }
    except _CaseExecutionFailure as exc:
        outcome = {
            "schema_name": "safety_bench_gemini_attack_only_case_outcome",
            "schema_version": 1,
            "case_id": case_row["case_id"],
            "case_meta_sha256": case_row["case_meta_sha256"],
            "binding_sha256": binding_document_sha256(binding),
            "attack_status": "FAILED",
            "execution_outcome": "FAILED",
            "failure_type": exc.failure_type,
            "blocking_reasons": [str(exc)],
            "stage_count_completed": len(stages),
            "stage_count_total": case_row["stage_count"],
            "stages": stages,
            "run_kind": "attack",
            "controls_run": 0,
            "scoring_status": "NOT_PRODUCED",
            "safe_or_n0_prohibited": True,
            "protocol_sha256": protocol["protocol_sha256"],
            "raw_trace_root": str(case_run_dir),
            "callback_url": callback_url,
            "honeypot_enabled": enable_honeypot,
            "honeypot_hit_count": honeypot_hit_count,
            "started_at": started,
            "finished_at": _now(),
        }
    except Exception as exc:
        outcome = {
            "schema_name": "safety_bench_gemini_attack_only_case_outcome",
            "schema_version": 1,
            "case_id": case_row["case_id"],
            "case_meta_sha256": case_row["case_meta_sha256"],
            "binding_sha256": binding_document_sha256(binding),
            "attack_status": "FAILED",
            "execution_outcome": "FAILED",
            "failure_type": "runner_exception",
            "blocking_reasons": [str(exc)],
            "stage_count_completed": len(stages),
            "stage_count_total": case_row["stage_count"],
            "stages": stages,
            "run_kind": "attack",
            "controls_run": 0,
            "scoring_status": "NOT_PRODUCED",
            "safe_or_n0_prohibited": True,
            "protocol_sha256": protocol["protocol_sha256"],
            "raw_trace_root": str(case_run_dir),
            "callback_url": callback_url,
            "honeypot_enabled": enable_honeypot,
            "honeypot_hit_count": honeypot_hit_count,
            "started_at": started,
            "finished_at": _now(),
        }
    _write_json(outcome_path, outcome)
    return outcome


def execute_attack_batch(
    *,
    credential_file: Path | None,
    project: str | None,
    api_key_env: str = DEFAULT_API_KEY_ENV,
    api_base_url: str = DEFAULT_API_BASE_URL,
    provider_kind: str = DEFAULT_PROVIDER_KIND,
    output_root: Path | None = None,
    repo_root: Path | None = None,
    conformance_path: Path | None = None,
    executable: str = "/usr/local/bin/gemini",
    model: str = DEFAULT_MODEL,
    location: str = DEFAULT_LOCATION,
    case_set: str = "ready",
    case_ids: Sequence[str] = (),
    case_id_file: Path | None = None,
    offset: int = 0,
    pending_only: bool = False,
    limit: int | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_provider_requests: int = 20_000,
    max_provider_requests_per_stage: int = DEFAULT_MAX_PROVIDER_REQUESTS_PER_STAGE,
    cost_cap_usd: float = 1_000_000.0,
    enable_honeypot: bool = False,
    callback_url: str = DEFAULT_CALLBACK_URL,
    honeypot_host: str = DEFAULT_HONEYPOT_HOST,
    honeypot_port: int = DEFAULT_HONEYPOT_PORT,
    dry_run: bool = False,
) -> tuple[Path, dict[str, Any]]:
    root = (repo_root or REPO_ROOT).resolve()
    conformance = (conformance_path or DEFAULT_CONFORMANCE).resolve()
    _validate_honeypot_configuration(
        enabled=enable_honeypot,
        callback_url=callback_url,
        honeypot_host=honeypot_host,
        honeypot_port=honeypot_port,
    )
    readiness = build_attack_readiness(
        repo_root=root,
        conformance_path=conformance,
        model=model,
        location=location,
        provider_kind=provider_kind,
        api_base_url=api_base_url,
    )
    if output_root is None:
        output_root = Path(
            tempfile.mkdtemp(prefix="safety-bench-gemini-attack-", dir="/tmp")
        )
    work_root = output_root.resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    protocol = readiness["protocol"]
    rows = {row["case_id"]: row for row in readiness["cases"]}

    requested_case_ids = list(case_ids)
    if case_id_file is not None:
        requested_case_ids.extend(_load_case_ids_from_file(case_id_file))
    requested_case_ids = list(dict.fromkeys(requested_case_ids))

    if requested_case_ids:
        unknown = sorted(set(requested_case_ids) - set(rows))
        if unknown:
            raise GeminiAttackOnlyError(f"unknown case_id(s): {unknown}")
        selected = [rows[case_id] for case_id in requested_case_ids]
    elif case_set == "ready":
        selected = [
            row for row in readiness["cases"] if row["attack_status"] == "ATTACK_READY"
        ]
    elif case_set == "all":
        selected = list(readiness["cases"])
    else:
        raise GeminiAttackOnlyError("case_set must be ready or all")
    selected_before_pending = len(selected)
    if pending_only:
        selected = [
            row
            for row in selected
            if not _is_completed_outcome(work_root, protocol=protocol, case_row=row)
        ]
    if offset < 0:
        raise GeminiAttackOnlyError("offset must be non-negative")
    if offset:
        selected = selected[offset:]
    if limit is not None:
        if limit < 1:
            raise GeminiAttackOnlyError("limit must be positive")
        selected = selected[:limit]

    _write_json(work_root / "attack-readiness.json", readiness)
    bindings = load_gemini_all_bindings(repo_root=root)
    case_dirs = _case_dir_map(root)
    outcomes: list[dict[str, Any]] = []
    started = _now()

    if dry_run or not any(row["attack_status"] == "ATTACK_READY" for row in selected):
        for row in selected:
            outcomes.append(
                _not_invoked_outcome(
                    status=(
                        "NOT_RUN"
                        if row["attack_status"] == "ATTACK_READY"
                        else row["attack_status"]
                    ),
                    case_row=row,
                    protocol=protocol,
                    case_run_dir=work_root
                    / "cases"
                    / _safe_case_dir_name(int(row["manifest_index"]), row["case_id"]),
                    reasons=(
                        ["dry_run"]
                        if row["attack_status"] == "ATTACK_READY"
                        else row.get("blocking_reasons", [])
                    ),
                )
            )
        report = _batch_report(
            started=started,
            work_root=work_root,
            readiness=readiness,
            selected=selected,
            outcomes=outcomes,
            provider_evidence=None,
            dry_run=dry_run,
            selection_metadata={
                "case_set": case_set,
                "requested_case_count": len(requested_case_ids),
                "selected_before_pending_count": selected_before_pending,
                "pending_only": pending_only,
                "offset": offset,
                "limit": limit,
                "callback_url": callback_url,
                "honeypot_enabled": enable_honeypot,
                "honeypot_host": honeypot_host,
                "honeypot_port": honeypot_port,
            },
        )
        path = _batch_report_path(work_root, dry_run=dry_run)
        _write_json(path, report)
        return path, report

    try:
        work_root.relative_to(Path("/tmp"))
    except ValueError as exc:
        raise GeminiAttackOnlyError(
            "non-dry-run Gemini attack execution requires output_root under /tmp "
            "because the bubblewrap launcher binds only the run-local sandbox tree"
        ) from exc

    if provider_kind == "openai-compatible":
        api_key = os.environ.get(api_key_env, "") or _load_secret_from_dotenv(
            repo_root=root, key=api_key_env
        )
        if not api_key:
            raise GeminiAttackOnlyError(
                f"{api_key_env} must be set in the environment or in the git-ignored "
                ".env file for openai-compatible attack execution"
            )
        proxy_evidence_path = work_root / "openai-compat-proxy-evidence.json"
        proxy = OpenAICompatibleVertexProxy(
            project=project or DEFAULT_VERTEX_SHIM_PROJECT,
            location=location,
            model=model,
            api_base_url=api_base_url,
            api_key=api_key,
            evidence_path=proxy_evidence_path,
            max_provider_requests=max_provider_requests,
            timeout_seconds=timeout_seconds,
        )
    elif provider_kind == "vertex":
        if credential_file is None or project is None:
            raise GeminiAttackOnlyError(
                "credential_file and project are required for vertex attack execution"
            )
        credential_file = credential_file.resolve()
        proxy_evidence_path = work_root / "vertex-proxy-evidence.json"
        token_provider = ServiceAccountTokenProvider(
            credential_file,
            scope="https://www.googleapis.com/auth/cloud-platform",
        )
        proxy = VertexQualificationProxy(
            project=project,
            location=location,
            model=model,
            token_provider=token_provider,
            evidence_path=proxy_evidence_path,
            max_provider_requests=max_provider_requests,
            cost_cap_usd=cost_cap_usd,
        )
    else:
        raise GeminiAttackOnlyError("provider_kind must be openai-compatible or vertex")
    try:
        proxy.start(work_root / "vertex-client")
        for row in selected:
            outcomes.append(
                execute_attack_case(
                    case_row=row,
                    binding=bindings[row["case_id"]],
                    case_dir=case_dirs[row["case_id"]],
                    work_root=work_root,
                    protocol=protocol,
                    proxy=proxy,
                    executable=executable,
                    conformance_path=conformance,
                    timeout_seconds=timeout_seconds,
                    max_provider_requests_per_stage=max_provider_requests_per_stage,
                    enable_honeypot=enable_honeypot,
                    callback_url=callback_url,
                    honeypot_host=honeypot_host,
                    honeypot_port=honeypot_port,
                )
            )
    finally:
        proxy.stop()
    provider_evidence = _read_json(proxy_evidence_path)
    provider_evidence["__evidence_path"] = str(proxy_evidence_path)
    report = _batch_report(
        started=started,
        work_root=work_root,
        readiness=readiness,
        selected=selected,
        outcomes=outcomes,
        provider_evidence=provider_evidence,
        dry_run=False,
        selection_metadata={
            "case_set": case_set,
            "requested_case_count": len(requested_case_ids),
            "selected_before_pending_count": selected_before_pending,
            "pending_only": pending_only,
            "offset": offset,
            "limit": limit,
            "callback_url": callback_url,
            "honeypot_enabled": enable_honeypot,
            "honeypot_host": honeypot_host,
            "honeypot_port": honeypot_port,
        },
    )
    path = _batch_report_path(work_root, dry_run=False)
    _write_json(path, report)
    return path, report


def _batch_report(
    *,
    started: str,
    work_root: Path,
    readiness: Mapping[str, Any],
    selected: Sequence[Mapping[str, Any]],
    outcomes: Sequence[Mapping[str, Any]],
    provider_evidence: Mapping[str, Any] | None,
    dry_run: bool,
    selection_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_name": "safety_bench_gemini_attack_only_batch_report",
        "schema_version": 1,
        "started_at": started,
        "finished_at": _now(),
        "dry_run": dry_run,
        "protocol": readiness["protocol"],
        "work_root": str(work_root),
        "selection": {
            "case_count": len(selected),
            "case_ids": [row["case_id"] for row in selected],
            **dict(selection_metadata or {}),
        },
        "readiness_summary": readiness["summary"],
        "outcome_counts": dict(Counter(row["attack_status"] for row in outcomes)),
        "stage_counts": {
            "completed": sum(int(row.get("stage_count_completed", 0)) for row in outcomes),
            "planned": sum(int(row.get("stage_count_total", 0)) for row in outcomes),
        },
        "provider": (
            None
            if provider_evidence is None
            else {
                "provider_requests": provider_evidence.get("provider_requests"),
                "estimated_cost_usd": provider_evidence.get("estimated_cost_usd"),
                "evidence_schema_name": provider_evidence.get("schema_name"),
                "route": provider_evidence.get("route"),
                "evidence_path": provider_evidence.get("__evidence_path"),
            }
        ),
        "scoring_status": "NOT_PRODUCED",
        "safe_or_n0_prohibited": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="write attack-only readiness inventory")
    plan.add_argument("--output", type=Path)
    plan.add_argument("--conformance", type=Path, default=DEFAULT_CONFORMANCE)
    plan.add_argument("--model", default=DEFAULT_MODEL)
    plan.add_argument("--location", default=DEFAULT_LOCATION)
    plan.add_argument(
        "--provider-kind",
        choices=("openai-compatible", "vertex"),
        default=DEFAULT_PROVIDER_KIND,
    )
    plan.add_argument("--api-base-url", default=DEFAULT_API_BASE_URL)

    execute = sub.add_parser("execute", help="run attack-only cases")
    execute.add_argument("--credential-file", type=Path)
    execute.add_argument("--project", default=DEFAULT_VERTEX_SHIM_PROJECT)
    execute.add_argument(
        "--provider-kind",
        choices=("openai-compatible", "vertex"),
        default=DEFAULT_PROVIDER_KIND,
    )
    execute.add_argument("--api-base-url", default=DEFAULT_API_BASE_URL)
    execute.add_argument("--api-key-env", default=DEFAULT_API_KEY_ENV)
    execute.add_argument("--output-root", type=Path)
    execute.add_argument("--conformance", type=Path, default=DEFAULT_CONFORMANCE)
    execute.add_argument("--executable", default="/usr/local/bin/gemini")
    execute.add_argument("--model", default=DEFAULT_MODEL)
    execute.add_argument("--location", default=DEFAULT_LOCATION)
    execute.add_argument("--case-set", choices=("ready", "all"), default="ready")
    execute.add_argument("--case-id", action="append", dest="case_ids", default=[])
    execute.add_argument("--case-id-file", type=Path)
    execute.add_argument("--offset", type=int, default=0)
    execute.add_argument("--pending-only", action="store_true")
    execute.add_argument("--limit", type=int)
    execute.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    execute.add_argument("--max-provider-requests", type=int, default=20_000)
    execute.add_argument(
        "--max-provider-requests-per-stage",
        type=int,
        default=DEFAULT_MAX_PROVIDER_REQUESTS_PER_STAGE,
    )
    execute.add_argument("--cost-cap-usd", type=float, default=1_000_000.0)
    execute.add_argument(
        "--enable-honeypot",
        action="store_true",
        help="Start the loopback honeypot during each stage and record real callback hits.",
    )
    execute.add_argument("--callback-url", default=DEFAULT_CALLBACK_URL)
    execute.add_argument("--honeypot-host", default=DEFAULT_HONEYPOT_HOST)
    execute.add_argument("--honeypot-port", type=int, default=DEFAULT_HONEYPOT_PORT)
    execute.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "plan":
        document = build_attack_readiness(
            conformance_path=args.conformance,
            model=args.model,
            location=args.location,
            provider_kind=args.provider_kind,
            api_base_url=args.api_base_url,
        )
        if args.output:
            _write_json(args.output, document)
        print(json.dumps(document["summary"], indent=2, sort_keys=True))
        return 0
    path, report = execute_attack_batch(
        credential_file=args.credential_file,
        project=args.project,
        api_key_env=args.api_key_env,
        api_base_url=args.api_base_url,
        provider_kind=args.provider_kind,
        output_root=args.output_root,
        conformance_path=args.conformance,
        executable=args.executable,
        model=args.model,
        location=args.location,
        case_set=args.case_set,
        case_ids=tuple(args.case_ids),
        case_id_file=args.case_id_file,
        offset=args.offset,
        pending_only=args.pending_only,
        limit=args.limit,
        timeout_seconds=args.timeout_seconds,
        max_provider_requests=args.max_provider_requests,
        max_provider_requests_per_stage=args.max_provider_requests_per_stage,
        cost_cap_usd=args.cost_cap_usd,
        enable_honeypot=args.enable_honeypot,
        callback_url=args.callback_url,
        honeypot_host=args.honeypot_host,
        honeypot_port=args.honeypot_port,
        dry_run=args.dry_run,
    )
    print(
        json.dumps(
            {
                "report": str(path),
                "outcome_counts": report["outcome_counts"],
                "scoring_status": report["scoring_status"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["outcome_counts"].get("FAILED", 0) == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
