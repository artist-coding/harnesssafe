"""Reproducible, credential-free materialization audit for all 328 cases.

This module intentionally stops before Kimi launch.  It supplies an
all-SUPPORTED capability *hypothesis* only to exercise every reviewed semantic
translation and records the resulting READY/NOT_RUN disposition.  The
hypothesis is never capability evidence and never produces a score.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Mapping

from infra.cross_harness.contract import CAPABILITIES

from .bench_inventory import EXPECTED_CASE_COUNT, EXPECTED_STAGE_COUNT, load_frozen_inventory
from .bench_materializer import materialize_bench_case
from .lifecycle import RunLayout, atomic_write_json
from .materializer import sha256_file, tree_sha256


AUDIT_SCHEMA_NAME = "safety_bench_kimi_static_materialization_audit"
AUDIT_SCHEMA_VERSION = 1


class KimiStaticAuditError(RuntimeError):
    """The static audit could not preserve its fail-closed invariants."""


class _StaticCallbackPlaceholder:
    """Run-derived URL placeholder; it never creates a socket or service."""

    host = "127.0.0.1"

    def __init__(self, run_id: str) -> None:
        digest = hashlib.sha256(f"kimi-static-audit:{run_id}".encode()).digest()
        self.port = 49152 + int.from_bytes(digest[:2], "big") % 16384

    def __enter__(self) -> "_StaticCallbackPlaceholder":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _payload_sha256(document: Mapping[str, Any]) -> str:
    return _canonical_sha256(
        {
            key: value
            for key, value in document.items()
            if key != "audit_payload_sha256"
        }
    )


def _plain_empty_run_root(layout: RunLayout) -> None:
    run_dir = layout.run_dir
    if run_dir.is_symlink():
        raise KimiStaticAuditError("static audit run directory must not be a symlink")
    if run_dir.exists() and (not run_dir.is_dir() or any(run_dir.iterdir())):
        raise KimiStaticAuditError(
            "static audit refuses to reuse a non-empty Kimi run directory"
        )
    layout.initialize()


def run_static_materialization_audit(
    *,
    repo_root: Path,
    result_root: Path,
    run_id: str,
) -> dict[str, Any]:
    """Materialize all frozen cases without launching a harness or provider."""

    repo = Path(repo_root).resolve()
    layout = RunLayout(repo, Path(result_root), run_id)
    _plain_empty_run_root(layout)
    inventory = load_frozen_inventory(repo, verify_live=True)
    records = inventory.get("cases")
    if not isinstance(records, list) or len(records) != EXPECTED_CASE_COUNT:
        raise KimiStaticAuditError(
            f"frozen inventory must contain exactly {EXPECTED_CASE_COUNT} cases"
        )

    capability_hypothesis = {name: "SUPPORTED" for name in CAPABILITIES}
    case_results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    dispositions: Counter[str] = Counter()
    suite_dispositions: Counter[tuple[str, str]] = Counter()
    stage_count = 0

    # The materializer requires a syntactically valid callback origin even
    # though this command starts no server and performs no request.  A port
    # derived from run_id avoids a shared fixed-port identity without needing
    # socket permission in a read/write-only audit environment.
    with _StaticCallbackPlaceholder(run_id) as lease:
        callback_url = f"http://{lease.host}:{lease.port}"
        for ordinal, record in enumerate(records):
            if not isinstance(record, Mapping):
                failures.append(
                    {
                        "index": ordinal,
                        "error": "inventory record is not an object",
                    }
                )
                break
            case_id = str(record.get("case_id") or "")
            suite = str(record.get("suite") or "")
            raw_case_dir = record.get("case_dir")
            if not case_id or not suite or not isinstance(raw_case_dir, str):
                failures.append(
                    {
                        "index": ordinal,
                        "case_id": case_id,
                        "error": "inventory case identity is incomplete",
                    }
                )
                break
            canonical = (repo / raw_case_dir).resolve()
            before = tree_sha256(canonical)
            case_layout = layout.for_case(case_id)
            try:
                materialized = materialize_bench_case(
                    repo_root=repo,
                    case_dir=canonical,
                    run_dir=case_layout.root,
                    run_id=run_id,
                    callback_url=callback_url,
                    capability_states=capability_hypothesis,
                    expected_suite_id=suite,
                )
                after = tree_sha256(canonical)
                if not hmac.compare_digest(before, after):
                    raise KimiStaticAuditError(
                        "canonical case changed during static materialization"
                    )
                disposition = str(materialized.get("disposition") or "")
                if disposition not in {"READY", "NOT_RUN"}:
                    raise KimiStaticAuditError(
                        f"unexpected materialization disposition: {disposition!r}"
                    )
                stages = materialized.get("stages")
                if not isinstance(stages, list) or not stages:
                    raise KimiStaticAuditError("materialization returned no stages")
                manifest_path = Path(str(materialized.get("manifest_path") or ""))
                manifest_path = layout.assert_owned(manifest_path)
                if manifest_path.is_symlink() or not manifest_path.is_file():
                    raise KimiStaticAuditError(
                        "materialization manifest is not a regular run-local file"
                    )
                dispositions[disposition] += 1
                suite_dispositions[(suite, disposition)] += 1
                stage_count += len(stages)
                materialized_record = materialized.get("materialized")
                if not isinstance(materialized_record, Mapping):
                    raise KimiStaticAuditError(
                        "materialization omitted its artifact provenance"
                    )
                semantic = materialized.get("semantic_binding")
                case_results.append(
                    {
                        "index": ordinal,
                        "case_id": case_id,
                        "suite": suite,
                        "disposition": disposition,
                        "disposition_reasons": list(
                            materialized.get("disposition_reasons") or []
                        ),
                        "stage_count": len(stages),
                        "canonical_tree_sha256_before": before,
                        "canonical_tree_sha256_after": after,
                        "canonical_unchanged": True,
                        "materialized_tree_sha256": str(
                            materialized_record.get("tree_sha256") or ""
                        ),
                        "manifest_path": str(manifest_path),
                        "manifest_sha256": sha256_file(manifest_path),
                        "semantic_binding": (
                            dict(semantic) if isinstance(semantic, Mapping) else None
                        ),
                    }
                )
            except Exception as exc:
                after = tree_sha256(canonical)
                failures.append(
                    {
                        "index": ordinal,
                        "case_id": case_id,
                        "suite": suite,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "canonical_tree_sha256_before": before,
                        "canonical_tree_sha256_after": after,
                        "canonical_unchanged": hmac.compare_digest(before, after),
                    }
                )
                # Do not continue after any materializer or provenance failure.
                break

    valid = (
        not failures
        and len(case_results) == EXPECTED_CASE_COUNT
        and stage_count == EXPECTED_STAGE_COUNT
        and all(item["canonical_unchanged"] for item in case_results)
    )
    summary_path = layout.run_dir / f"audit-kimi-{run_id}.json"
    document: dict[str, Any] = {
        "schema_name": AUDIT_SCHEMA_NAME,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "harness_id": "kimi",
        "run_id": run_id,
        "mode": "static_materialization_only",
        "valid": valid,
        "formal_runtime_readiness_claimed": False,
        "scoring_status": "NOT_PRODUCED",
        "external_model_started": False,
        "credentials_used": False,
        "network_request_made": False,
        "network_service_started": False,
        "callback_url_is_materialization_placeholder_only": True,
        "capability_hypothesis": (
            "all Contract v1 capabilities supplied as SUPPORTED for semantic "
            "audit only; this is not runtime evidence"
        ),
        "inventory_content_sha256": str(
            inventory.get("inventory_content_sha256") or ""
        ),
        "case_count_expected": EXPECTED_CASE_COUNT,
        "case_count_succeeded": len(case_results),
        "case_count_failed": len(failures),
        "stage_count_expected": EXPECTED_STAGE_COUNT,
        "stage_count_materialized": stage_count,
        "plan_dispositions": dict(sorted(dispositions.items())),
        "suite_dispositions": [
            {"suite": suite, "disposition": disposition, "count": count}
            for (suite, disposition), count in sorted(suite_dispositions.items())
        ],
        "canonical_hashes_unchanged": bool(
            valid and len(case_results) == EXPECTED_CASE_COUNT
        ),
        "cases": case_results,
        "failures": failures,
        "summary_path": str(summary_path),
    }
    document["audit_payload_sha256"] = _payload_sha256(document)
    atomic_write_json(summary_path, document, run_id=run_id)
    return document


def load_static_materialization_audit(path: Path) -> dict[str, Any]:
    """Load and self-check an audit summary without upgrading its claims."""

    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KimiStaticAuditError("static audit summary is malformed") from exc
    if not isinstance(document, dict):
        raise KimiStaticAuditError("static audit summary must be an object")
    if (
        document.get("schema_name") != AUDIT_SCHEMA_NAME
        or document.get("schema_version") != AUDIT_SCHEMA_VERSION
        or document.get("harness_id") != "kimi"
        or document.get("mode") != "static_materialization_only"
        or document.get("formal_runtime_readiness_claimed") is not False
        or document.get("scoring_status") != "NOT_PRODUCED"
    ):
        raise KimiStaticAuditError("static audit summary identity is invalid")
    claimed = document.get("audit_payload_sha256")
    if not isinstance(claimed, str) or not hmac.compare_digest(
        claimed, _payload_sha256(document)
    ):
        raise KimiStaticAuditError("static audit summary self-hash mismatch")
    return document


__all__ = [
    "AUDIT_SCHEMA_NAME",
    "AUDIT_SCHEMA_VERSION",
    "KimiStaticAuditError",
    "load_static_materialization_audit",
    "run_static_materialization_audit",
]
