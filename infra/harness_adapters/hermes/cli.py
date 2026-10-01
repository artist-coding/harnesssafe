from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Mapping, Sequence

from .events import (
    EventProvenance,
    normalize_compaction_for_analyzer,
    normalize_session,
    normalize_delegation_for_analyzer,
    read_compacted_summary_text,
    read_compression_evidence,
    read_delegation_evidence,
    read_delegation_trace,
    read_session_lineage,
    validate_session_lineage,
    write_session_snapshot,
    write_event_ir,
)
from .launch import LaunchContext, UnsupportedCapabilityError, build_launch_spec
from .probe import detect_identity, probe_capabilities


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def launch_spec_from_request(payload: Mapping[str, object]) -> dict[str, object]:
    stage = _mapping(payload.get("stage"), "stage")
    context_raw = _mapping(payload.get("context"), "context")
    binding_path = Path(str(payload.get("binding_path") or ""))
    if not binding_path.is_file():
        raise ValueError(f"Hermes binding is missing: {binding_path}")
    binding = json.loads(binding_path.read_text(encoding="utf-8-sig"))
    if binding.get("harness") != "hermes":
        raise ValueError("selected binding is not for Hermes")
    if binding.get("disposition") == "BLOCKED":
        reasons = ", ".join(str(item) for item in binding.get("blocking_reasons", []))
        raise UnsupportedCapabilityError(f"Hermes binding is BLOCKED: {reasons}")

    probe_executable = Path(str(context_raw.get("probe_executable") or ""))
    source_root = Path(str(context_raw.get("source_root") or ""))
    identity = detect_identity(
        probe_executable,
        _run,
        source_root=source_root,
        git_run=_run,
    )
    capabilities = probe_capabilities(identity, _run)
    for required in binding.get("required_capabilities", []):
        name = str(required)
        if name == "shared_artifact":
            continue
        evidence = getattr(capabilities, name, None)
        if evidence is None or not evidence.supported:
            reason = getattr(evidence, "reason", "unknown capability")
            raise UnsupportedCapabilityError(
                f"unsupported Hermes capability {name}: {reason}"
            )

    context = LaunchContext(
        hermes_python=Path(str(context_raw["hermes_python"])),
        hermes_launcher=Path(str(context_raw["hermes_launcher"])),
        hermes_home=Path(str(context_raw["hermes_home"])),
        workspace_dir=Path(str(context_raw["workspace_dir"])),
        model=str(context_raw.get("model") or ""),
        provider_base_url=str(context_raw["provider_base_url"]),
        timeout_sec=int(context_raw["timeout_sec"]),
        secret_env={str(name): "" for name in context_raw.get("secret_env_names", [])},
        provider_id=str(context_raw.get("provider_id") or "coding-plan"),
        provider_display_name=str(
            context_raw.get("provider_display_name") or "DashScope Coding Plan"
        ),
        provider_key_env=str(context_raw.get("provider_key_env") or "OPENAI_API_KEY"),
        provider_api_mode=str(context_raw.get("provider_api_mode") or ""),
        session_id=str(context_raw.get("session_id") or ""),
        delegation_auto_approve=bool(
            context_raw.get("delegation_auto_approve", False)
        ),
    )
    spec = build_launch_spec(stage, context, capabilities)
    identity_record = asdict(identity)
    identity_record["executable"] = str(identity.executable)
    identity_record["pinned"] = identity.pinned
    return {
        **spec.to_dict(),
        "identity": identity_record,
        "capabilities": asdict(capabilities),
        "binding_disposition": binding.get("disposition"),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safety Bench Hermes adapter")
    subparsers = parser.add_subparsers(dest="command", required=True)
    launch = subparsers.add_parser("launch-spec")
    launch.add_argument("--request", type=Path, required=True)
    capture = subparsers.add_parser("capture-session")
    capture.add_argument("--state-db", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--session-id", default="")
    capture.add_argument("--parent-session-id", default="")
    normalize = subparsers.add_parser("normalize")
    normalize.add_argument("--session", type=Path, required=True)
    normalize.add_argument("--output", type=Path, required=True)
    normalize.add_argument("--stage-name", required=True)
    normalize.add_argument("--stage-index", type=int, required=True)
    normalize.add_argument("--session-id-override", default="")
    normalize.add_argument("--message-start-index", type=int, default=0)
    lineage = subparsers.add_parser("session-lineage")
    lineage.add_argument("--state-db", type=Path, required=True)
    lineage.add_argument("--seed-session-id", required=True)
    lineage.add_argument("--requested-session-id", required=True)
    lineage.add_argument("--resumed-session-id", required=True)
    lineage.add_argument("--session-action", choices=("resume", "compact"), required=True)
    lineage.add_argument("--output", type=Path, required=True)
    delegation = subparsers.add_parser("delegation-evidence")
    delegation.add_argument("--state-db", type=Path, required=True)
    delegation.add_argument("--parent-session-id", required=True)
    delegation.add_argument("--output", type=Path, required=True)
    delegation_events = subparsers.add_parser("delegation-event-ir")
    delegation_events.add_argument("--state-db", type=Path, required=True)
    delegation_events.add_argument("--parent-session", type=Path, required=True)
    delegation_events.add_argument("--parent-session-id", required=True)
    delegation_events.add_argument("--producer-name", required=True)
    delegation_events.add_argument("--stage-name", required=True)
    delegation_events.add_argument("--stage-index", type=int, required=True)
    delegation_events.add_argument("--output", type=Path, required=True)
    compaction_events = subparsers.add_parser("compaction-event-ir")
    compaction_events.add_argument("--state-db", type=Path, required=True)
    compaction_events.add_argument("--parent-session-id", required=True)
    compaction_events.add_argument("--child-session-id", required=True)
    compaction_events.add_argument("--stage-name", required=True)
    compaction_events.add_argument("--stage-index", type=int, required=True)
    compaction_events.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "launch-spec":
            payload = json.loads(args.request.read_text(encoding="utf-8-sig"))
            result = launch_spec_from_request(_mapping(payload, "request"))
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if args.command == "capture-session":
            captured_session_id = write_session_snapshot(
                args.state_db,
                args.output,
                session_id=args.session_id,
                parent_session_id=args.parent_session_id,
            )
            print(captured_session_id)
            return 0
        if args.command == "session-lineage":
            lineage = read_session_lineage(
                args.state_db,
                seed_session_id=args.seed_session_id,
                requested_session_id=args.requested_session_id,
                resumed_session_id=args.resumed_session_id,
            )
            validation = validate_session_lineage(lineage)
            if not validation.valid:
                raise ValueError(validation.reason)
            record: dict[str, object] = {
                "schema_version": "hermes-session-lineage-v1",
                "lineage": asdict(lineage),
                "lineage_valid": True,
                "session_action": args.session_action,
            }
            if args.session_action == "compact":
                record["compression"] = asdict(
                    read_compression_evidence(
                        args.state_db,
                        parent_session_id=args.requested_session_id,
                        compacted_session_id=args.resumed_session_id,
                    )
                )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return 0
        if args.command == "delegation-evidence":
            evidence = read_delegation_evidence(
                args.state_db,
                parent_session_id=args.parent_session_id,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(asdict(evidence), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return 0
        if args.command == "compaction-event-ir":
            evidence = read_compression_evidence(
                args.state_db,
                parent_session_id=args.parent_session_id,
                compacted_session_id=args.child_session_id,
            )
            summary_text = read_compacted_summary_text(
                args.state_db,
                compacted_session_id=args.child_session_id,
            )
            records = normalize_compaction_for_analyzer(
                evidence,
                summary_text=summary_text,
                provenance=EventProvenance(
                    stage_name=args.stage_name,
                    stage_index=args.stage_index,
                    source_path=args.state_db,
                ),
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                "".join(
                    json.dumps(record, ensure_ascii=False) + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )
            return 0
        if args.command == "delegation-event-ir":
            parent = json.loads(args.parent_session.read_text(encoding="utf-8-sig"))
            parent_calls = []
            for message in parent.get("messages", []):
                if not isinstance(message, dict):
                    continue
                for call in message.get("tool_calls") or []:
                    if not isinstance(call, dict):
                        continue
                    function = call.get("function")
                    function = function if isinstance(function, dict) else {}
                    if str(call.get("name") or function.get("name") or "") == "delegate_task":
                        parent_calls.append(str(call.get("id") or ""))
            if len(parent_calls) != 1 or not parent_calls[0]:
                raise ValueError(
                    f"Hermes delegation projection requires exactly one delegate_task call; found {len(parent_calls)}"
                )
            child_id, child_messages = read_delegation_trace(
                args.state_db,
                parent_session_id=args.parent_session_id,
            )
            events = normalize_delegation_for_analyzer(
                parent_session_id=args.parent_session_id,
                child_session_id=child_id,
                parent_call_id=parent_calls[0],
                producer_name=args.producer_name,
                child_messages=child_messages,
                provenance=EventProvenance(
                    stage_name=args.stage_name,
                    stage_index=args.stage_index,
                    source_path=args.state_db,
                ),
            )
            write_event_ir(events, args.output)
            return 0
        raw = json.loads(args.session.read_text(encoding="utf-8-sig"))
        events = normalize_session(
            _mapping(raw, "session"),
            EventProvenance(
                stage_name=args.stage_name,
                stage_index=args.stage_index,
                source_path=args.session,
            ),
            session_id_override=args.session_id_override,
            message_start_index=args.message_start_index,
        )
        write_event_ir(events, args.output)
        return 0
    except UnsupportedCapabilityError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
