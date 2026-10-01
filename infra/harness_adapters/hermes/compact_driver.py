from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path


_AUDIT_FILENAME = "compaction_scaffold.json"
_SHORT_TRANSCRIPT_MESSAGE_COUNT = 4
_SHORT_TRANSCRIPT_SCAFFOLD = (
    {
        "role": "user",
        "content": "[Context boundary padding 1/2; no action requested.]",
    },
    {
        "role": "assistant",
        "content": "[Context boundary padding 1/2 acknowledged.]",
    },
    {
        "role": "user",
        "content": "[Context boundary padding 2/2; no action requested.]",
    },
    {
        "role": "assistant",
        "content": "[Context boundary padding 2/2 acknowledged.]",
    },
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Headless Hermes native compaction")
    parser.add_argument("--hermes-source", type=Path, required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--toolsets", default="")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--focus", default="")
    parser.add_argument("--audit-path", type=Path)
    return parser


def _message_sha256(message: object) -> str:
    canonical = json.dumps(
        message,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _contains_all_hashes(expected: list[str], actual: list[str]) -> bool:
    expected_counts = Counter(expected)
    actual_counts = Counter(actual)
    return all(actual_counts[value] >= count for value, count in expected_counts.items())


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source = args.hermes_source.resolve()
    if not (source / "cli.py").is_file():
        print(f"Hermes source root is invalid: {source}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(source))

    from cli import HermesCLI

    toolsets = [item for item in args.toolsets.split(",") if item]
    cli = HermesCLI(
        model=args.model,
        toolsets=toolsets,
        max_turns=args.max_turns,
        verbose=False,
        compact=True,
        resume=args.session_id,
    )
    if not cli._init_agent():
        print("Hermes agent initialization failed during compaction", file=sys.stderr)
        return 2
    parent_session_id = cli.session_id
    original_history = deepcopy(cli.conversation_history)
    original_hashes = [_message_sha256(message) for message in original_history]
    scaffold: list[dict[str, str]] = []
    if len(original_history) == _SHORT_TRANSCRIPT_MESSAGE_COUNT:
        # The pinned compressor requires head + three tail messages + one
        # compressible message. Two complete no-op exchanges are the smallest
        # valid tail that also moves the original tool-call group into the
        # native summary window instead of leaving the carrier uncompressed.
        scaffold = deepcopy(list(_SHORT_TRANSCRIPT_SCAFFOLD))
        cli.conversation_history.extend(scaffold)
        cli.agent._flush_messages_to_session_db(
            cli.conversation_history,
            original_history,
        )
        flushed_count = getattr(
            cli.agent, "_last_flushed_db_idx", len(cli.conversation_history)
        )
        if flushed_count != len(cli.conversation_history):
            print("Hermes compaction scaffold was not persisted to the parent", file=sys.stderr)
            return 2

    parent_message_count = len(cli.conversation_history)
    compressor = cli.agent.context_compressor
    original_generate_summary = compressor._generate_summary
    native_summary_messages: list[dict[str, object]] = []

    def _record_native_summary_input(messages, *summary_args, **summary_kwargs):
        native_summary_messages.extend(deepcopy(messages))
        return original_generate_summary(messages, *summary_args, **summary_kwargs)

    compressor._generate_summary = _record_native_summary_input
    command = "/compress" + (f" {args.focus}" if args.focus else "")
    try:
        cli._manual_compress(command)
    finally:
        compressor._generate_summary = original_generate_summary
    if cli.session_id == parent_session_id:
        print("Hermes native compaction did not rotate the session", file=sys.stderr)
        return 2
    child_message_count = len(cli.conversation_history)
    if parent_message_count <= child_message_count:
        print("Hermes native compaction did not reduce the in-memory transcript", file=sys.stderr)
        return 2
    if not native_summary_messages:
        print("Hermes native compaction did not invoke summary generation", file=sys.stderr)
        return 2
    if getattr(compressor, "_last_summary_error", None) or getattr(
        compressor, "_last_summary_fallback_used", False
    ):
        print("Hermes native compaction used fallback summary content", file=sys.stderr)
        return 2

    save_session_log = getattr(cli.agent, "_save_session_log", None)
    if not callable(save_session_log):
        print("Hermes child snapshot writer is unavailable", file=sys.stderr)
        return 2
    save_session_log(cli.conversation_history)

    native_summary_hashes = [
        _message_sha256(message) for message in native_summary_messages
    ]
    all_original_summarized = _contains_all_hashes(
        original_hashes, native_summary_hashes
    )
    if scaffold and not all_original_summarized:
        print(
            "Hermes short-session carrier remained outside the native summary window",
            file=sys.stderr,
        )
        return 2

    audit_path = args.audit_path
    if audit_path is None:
        hermes_home = os.environ.get("HERMES_HOME", "").strip()
        if not hermes_home:
            print("HERMES_HOME is required for compaction audit evidence", file=sys.stderr)
            return 2
        audit_path = Path(hermes_home) / _AUDIT_FILENAME
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit = {
        "schema_version": 1,
        "runtime_mode": "hermes_compaction",
        "native_method": "HermesCLI._manual_compress",
        "parent_session_id": parent_session_id,
        "child_session_id": cli.session_id,
        "original_message_count": len(original_history),
        "scaffold_message_count": len(scaffold),
        "parent_message_count": parent_message_count,
        "child_message_count": child_message_count,
        "native_summary_input_message_count": len(native_summary_messages),
        "original_message_sha256": original_hashes,
        "scaffold_message_sha256": [
            _message_sha256(message) for message in scaffold
        ],
        "native_summary_input_message_sha256": native_summary_hashes,
        "all_original_messages_entered_native_summary": all_original_summarized,
        "native_summary_fallback_used": False,
    }
    audit_path.write_text(
        json.dumps(audit, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"session_id: {cli.session_id}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
