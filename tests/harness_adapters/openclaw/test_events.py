import json
from pathlib import Path

import pytest

from infra.harness_adapters.openclaw.cli import (
    _agent_invocation_required,
    _build_compaction_argv,
    _project_completed_subagents,
    _normalize_compaction_events,
    _project_agent_events,
)
from infra.harness_adapters.openclaw.events import (
    extract_spawned_children,
    extract_session_file,
    normalize_openclaw_run,
    normalize_openclaw_session_transcript,
)


FIXTURES = Path(__file__).parent / "fixtures"


def test_native_compaction_stage_does_not_replay_slash_prompt_through_agent() -> None:
    assert _agent_invocation_required("compact") is False
    assert _agent_invocation_required("resume") is True
    assert _agent_invocation_required("fresh") is True


def test_skill_activation_requires_runtime_event() -> None:
    events = normalize_openclaw_run(
        (FIXTURES / "openclaw_agent.json").read_text(encoding="utf-8"),
        source_path=FIXTURES / "openclaw_agent.json",
    )
    assert any(event.kind == "skill.discovered" for event in events)
    assert not any(event.kind == "skill.activated" for event in events)


def test_mcp_request_result_share_call_id_and_source_hash() -> None:
    events = normalize_openclaw_run(
        (FIXTURES / "openclaw_mcp.jsonl").read_text(encoding="utf-8"),
        source_path=FIXTURES / "openclaw_mcp.jsonl",
    )
    request = next(event for event in events if event.kind == "tool.request")
    result = next(event for event in events if event.kind == "tool.result")
    assert request.call_id == result.call_id == "call-1"
    assert request.source_sha256 != result.source_sha256
    assert any(event.kind == "mcp.initialize" for event in events)


def test_dangling_tool_result_is_rejected() -> None:
    with pytest.raises(ValueError, match="dangling"):
        normalize_openclaw_run(
            json.dumps({"type": "tool.result", "callId": "missing"}),
            source_path=Path("trace.jsonl"),
        )


def test_malformed_json_is_rejected() -> None:
    with pytest.raises(ValueError, match="malformed"):
        normalize_openclaw_run("{", source_path=Path("trace.jsonl"))


def test_real_agent_result_projects_session_and_skill_discovery(tmp_path: Path) -> None:
    session_file = tmp_path / "session.jsonl"
    payload = {
        "type": "message",
        "payload": {
            "runId": "run-1",
            "status": "ok",
            "result": {
                "meta": {
                    "agentMeta": {"sessionFile": str(session_file)},
                    "systemPromptReport": {
                        "sessionId": "session-1",
                        "skills": {"entries": [{"name": "inventory-viewer"}]},
                    },
                }
            },
        },
    }
    text = json.dumps(payload)

    events = normalize_openclaw_run(text, source_path=tmp_path / "agent.json")

    assert extract_session_file(text) == session_file
    assert any(event.kind == "session.start" for event in events)
    assert any(event.kind == "session.complete" for event in events)
    discovered = [event for event in events if event.kind == "skill.discovered"]
    assert [event.payload["name"] for event in discovered] == ["inventory-viewer"]


def test_pinned_agent_result_root_shape_projects_session_file(tmp_path: Path) -> None:
    session_file = tmp_path / "session.jsonl"
    payload = {
        "runId": "run-1",
        "status": "ok",
        "result": {
            "meta": {
                "agentMeta": {
                    "agentHarnessId": "main",
                    "sessionFile": str(session_file),
                    "sessionId": "session-1",
                },
                "systemPromptReport": {
                    "sessionId": "session-1",
                    "skills": {"entries": [{"name": "inventory-viewer"}]},
                    "tools": {"entries": [
                        {"name": "deployment-health__deployment_health_check"},
                        {"name": "deployment-health__resources_list"},
                    ]},
                },
            }
        },
    }

    events = normalize_openclaw_run(
        json.dumps(payload),
        source_path=tmp_path / "agent.json",
    )

    assert extract_session_file(json.dumps(payload)) == session_file
    assert [event.kind for event in events].count("session.start") == 1
    assert any(event.kind == "skill.discovered" for event in events)
    initialized = [event for event in events if event.kind == "mcp.initialize"]
    assert len(initialized) == 1
    assert initialized[0].payload["server"] == "deployment-health"
    assert initialized[0].payload["tools"] == [
        "deployment-health__deployment_health_check",
        "deployment-health__resources_list",
    ]


def test_session_transcript_projects_runtime_skill_activation(tmp_path: Path) -> None:
    skill_root = tmp_path / "plugin" / "skills"
    skill_path = skill_root / "inventory-viewer" / "SKILL.md"
    transcript = "\n".join(
        (
            json.dumps(
                {
                    "type": "message",
                    "timestamp": "2026-07-23T00:00:00Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": "call-1",
                                "name": "read",
                                "arguments": {"path": str(skill_path)},
                            }
                        ],
                    },
                }
            ),
            json.dumps(
                {
                    "type": "message",
                    "timestamp": "2026-07-23T00:00:01Z",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "call-1",
                        "toolName": "read",
                        "isError": False,
                        "content": [{"type": "text", "text": "loaded"}],
                    },
                }
            ),
        )
    )

    events = normalize_openclaw_session_transcript(
        transcript,
        source_path=tmp_path / "session.jsonl",
        skill_dirs=(skill_root,),
    )

    request = next(event for event in events if event.kind == "tool.request")
    result = next(event for event in events if event.kind == "tool.result")
    activation = next(event for event in events if event.kind == "skill.activated")
    assert request.call_id == result.call_id == activation.call_id == "call-1"
    assert activation.payload["skill_name"] == "inventory-viewer"
    assert activation.source_sha256 == request.source_sha256


def test_successful_write_projects_artifact_event(tmp_path: Path) -> None:
    target = tmp_path / "workspace" / "generated" / "SKILL.md"
    transcript = "\n".join((
        json.dumps({"type": "message", "message": {
            "role": "assistant", "content": [{
                "type": "toolCall", "id": "write-1", "name": "write",
                "arguments": {"path": str(target), "content": "skill"},
            }],
        }}),
        json.dumps({"type": "message", "message": {
            "role": "toolResult", "toolCallId": "write-1", "toolName": "write",
            "isError": False, "content": [],
        }}),
    ))

    events = normalize_openclaw_session_transcript(
        transcript,
        source_path=tmp_path / "session.jsonl",
    )

    artifact = next(event for event in events if event.kind == "artifact.write")
    assert artifact.call_id == "write-1"
    assert artifact.payload["path"] == str(target)


def test_spawn_projects_analyzer_compatible_task_and_child_identity(
    tmp_path: Path,
) -> None:
    transcript = "\n".join((
        json.dumps({"type": "message", "message": {
            "role": "assistant", "content": [{
                "type": "toolCall", "id": "spawn-1", "name": "sessions_spawn",
                "arguments": {
                    "agentId": "continuity-reviewer",
                    "runtime": "subagent",
                    "task": "write the handoff",
                },
            }],
        }}),
        json.dumps({"type": "message", "message": {
            "role": "toolResult", "toolCallId": "spawn-1",
            "toolName": "sessions_spawn", "isError": False,
            "details": {
                "status": "accepted",
                "childSessionKey": "agent:continuity-reviewer:subagent:child-1",
                "runId": "run-child-1",
            },
            "content": [],
        }}),
    ))

    events = normalize_openclaw_session_transcript(
        transcript,
        source_path=tmp_path / "session.jsonl",
        session_id="parent-session",
    )

    request = next(event for event in events if event.kind == "tool.request")
    compat = request.to_dict()["messages"][0]["tool_calls"][0]
    assert compat["function"]["name"] == "Task"
    assert compat["function"]["arguments"]["subagent_type"] == "continuity-reviewer"
    spawned = next(event for event in events if event.kind == "subagent.spawn")
    assert spawned.payload["childId"] == "agent:continuity-reviewer:subagent:child-1"
    assert extract_spawned_children(transcript) == [{
        "call_id": "spawn-1",
        "child_session_key": "agent:continuity-reviewer:subagent:child-1",
        "run_id": "run-child-1",
    }]


def test_failed_skill_read_is_not_runtime_activation(tmp_path: Path) -> None:
    skill_root = tmp_path / "plugin" / "skills"
    transcript = "\n".join((
        json.dumps({
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [{
                    "type": "toolCall",
                    "id": "call-1",
                    "name": "read",
                    "arguments": {
                        "path": str(skill_root / "inventory-viewer" / "SKILL.md")
                    },
                }],
            },
        }),
        json.dumps({
            "type": "message",
            "message": {
                "role": "toolResult",
                "toolCallId": "call-1",
                "toolName": "read",
                "isError": True,
                "content": [{"type": "text", "text": "denied"}],
            },
        }),
    ))

    events = normalize_openclaw_session_transcript(
        transcript,
        source_path=tmp_path / "session.jsonl",
        skill_dirs=(skill_root,),
    )

    assert any(event.kind == "tool.result" for event in events)
    assert not any(event.kind == "skill.activated" for event in events)


def test_redacted_absolute_skill_path_still_requires_exact_owned_shape(
    tmp_path: Path,
) -> None:
    skill_root = tmp_path / "case-name" / "materialized_case" / "plugin"
    redacted_path = (
        tmp_path / "***" / "materialized_case" / "plugin"
        / "skills" / "inventory-viewer" / "SKILL.md"
    )
    transcript = "\n".join((
        json.dumps({"type": "message", "message": {
            "role": "assistant",
            "content": [{
                "type": "toolCall", "id": "call-1", "name": "read",
                "arguments": {"path": str(redacted_path)},
            }],
        }}),
        json.dumps({"type": "message", "message": {
            "role": "toolResult", "toolCallId": "call-1", "toolName": "read",
            "isError": False, "content": [],
        }}),
    ))

    events = normalize_openclaw_session_transcript(
        transcript,
        source_path=tmp_path / "session.jsonl",
        skill_dirs=(skill_root,),
    )

    activation = next(event for event in events if event.kind == "skill.activated")
    assert activation.payload["skill_name"] == "inventory-viewer"


def test_agent_projection_copies_owned_session_and_emits_runtime_events(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    run_dir = tmp_path / "run"
    skill_root = tmp_path / "plugin" / "skills"
    session_file = state_dir / "agents" / "main" / "sessions" / "session.jsonl"
    session_file.parent.mkdir(parents=True)
    session_file.write_text(
        "\n".join(
            (
                json.dumps({
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [{
                            "type": "toolCall",
                            "id": "call-1",
                            "name": "read",
                            "arguments": {
                                "path": str(skill_root / "inventory-viewer" / "SKILL.md")
                            },
                        }],
                    },
                }),
                json.dumps({
                    "type": "message",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "call-1",
                        "toolName": "read",
                        "content": [{"type": "text", "text": "loaded"}],
                    },
                }),
            )
        ),
        encoding="utf-8",
    )
    agent_text = json.dumps({
        "type": "message",
        "payload": {
            "result": {
                "meta": {
                    "agentMeta": {"sessionFile": str(session_file)},
                    "systemPromptReport": {
                        "sessionId": "session-1",
                        "skills": {"entries": [{"name": "inventory-viewer"}]},
                    },
                }
            }
        },
    })
    raw_path = run_dir / "openclaw-agent-stage-002.json"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text(agent_text, encoding="utf-8")

    events = _project_agent_events(
        agent_text,
        raw_path=raw_path,
        run_dir=run_dir,
        state_dir=state_dir,
        stage_index=2,
        skill_dirs=(skill_root,),
        run_id="run-1",
        agent_id="main",
        session_id="session-1",
    )

    copied = run_dir / "openclaw-session-stage-002.jsonl"
    assert copied.read_text(encoding="utf-8") == session_file.read_text(encoding="utf-8")
    assert any(event.kind == "skill.discovered" for event in events)
    assert any(event.kind == "skill.activated" for event in events)
    assert any(event.source_path == str(copied) for event in events)


def test_agent_projection_emits_only_new_session_records(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    run_dir = tmp_path / "run"
    session_file = state_dir / "session.jsonl"
    session_file.parent.mkdir(parents=True)

    def pair(call_id: str, path: str) -> list[str]:
        return [
            json.dumps({"type": "message", "message": {
                "role": "assistant", "content": [{
                    "type": "toolCall", "id": call_id, "name": "read",
                    "arguments": {"path": path},
                }],
            }}),
            json.dumps({"type": "message", "message": {
                "role": "toolResult", "toolCallId": call_id,
                "toolName": "read", "isError": False, "content": [],
            }}),
        ]

    first = pair("call-1", str(tmp_path / "first.txt"))
    second = pair("call-2", str(tmp_path / "second.txt"))
    previous = run_dir / "openclaw-session-stage-001.jsonl"
    previous.parent.mkdir(parents=True)
    previous.write_text("\n".join(first) + "\n", encoding="utf-8")
    session_file.write_text("\n".join(first + second) + "\n", encoding="utf-8")
    agent_text = json.dumps({"result": {"meta": {
        "agentMeta": {"sessionFile": str(session_file)}
    }}})

    events = _project_agent_events(
        agent_text,
        raw_path=run_dir / "agent.json",
        run_dir=run_dir,
        state_dir=state_dir,
        stage_index=2,
        skill_dirs=(),
        run_id="run-1",
        agent_id="main",
        session_id="session-1",
    )

    runtime = [event for event in events if event.kind in ("tool.request", "tool.result")]
    assert {event.call_id for event in runtime} == {"call-2"}
    assert {event.source_record_index for event in runtime} == {2, 3}


def test_completed_subagent_projection_binds_nested_write_to_spawn_call(
    tmp_path: Path,
) -> None:
    child_file = tmp_path / "state" / "child.jsonl"
    child_file.parent.mkdir(parents=True)
    child_file.write_text("\n".join((
        json.dumps({"type": "message", "message": {
            "role": "assistant", "content": [{
                "type": "toolCall", "id": "write-1", "name": "write",
                "arguments": {"path": "handoff/produced_context.md", "content": "ok"},
            }],
        }}),
        json.dumps({"type": "message", "message": {
            "role": "toolResult", "toolCallId": "write-1", "toolName": "write",
            "isError": False, "content": [],
        }}),
    )), encoding="utf-8")

    events = _project_completed_subagents(
        [{
            "call_id": "spawn-1",
            "child_session_key": "agent:continuity-reviewer:subagent:child-1",
            "run_id": "child-run",
            "status": "completed",
            "session_file": child_file,
        }],
        run_dir=tmp_path / "run",
        stage_index=1,
        run_id="parent-run",
        parent_agent_id="safety-bench",
        parent_session_id="parent-session",
    )

    nested_write = next(event for event in events if event.kind == "tool.request")
    assert nested_write.parent_tool_use_id == "spawn-1"
    assert nested_write.to_dict()["parent_tool_use_id"] == "spawn-1"
    assert any(event.kind == "subagent.complete" for event in events)
    assert (tmp_path / "run" / "openclaw-subagent-stage-001-001.jsonl").is_file()


def test_agent_projection_redacts_provider_secret_from_session_copy(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    session_file = state_dir / "session.jsonl"
    session_file.parent.mkdir(parents=True)
    session_file.write_text(
        json.dumps({"type": "message", "message": {
            "role": "user", "content": "provider-secret-value"
        }}) + "\n",
        encoding="utf-8",
    )
    agent_text = json.dumps({
        "payload": {"result": {"meta": {
            "agentMeta": {"sessionFile": str(session_file)}
        }}}
    })

    _project_agent_events(
        agent_text,
        raw_path=tmp_path / "agent.json",
        run_dir=tmp_path / "run",
        state_dir=state_dir,
        stage_index=0,
        skill_dirs=(),
        run_id="run-1",
        agent_id="main",
        session_id="session-1",
        secrets_to_redact=("provider-secret-value",),
    )

    copied = tmp_path / "run" / "openclaw-session-stage-000.jsonl"
    assert "provider-secret-value" not in copied.read_text(encoding="utf-8")
    assert "[REDACTED]" in copied.read_text(encoding="utf-8")


def test_agent_projection_rejects_session_outside_owned_state(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    agent_text = json.dumps({
        "payload": {
            "result": {"meta": {"agentMeta": {"sessionFile": str(outside)}}}
        }
    })

    with pytest.raises(ValueError, match="outside owned state"):
        _project_agent_events(
            agent_text,
            raw_path=tmp_path / "agent.json",
            run_dir=tmp_path / "run",
            state_dir=tmp_path / "state",
            stage_index=0,
            skill_dirs=(),
            run_id="run-1",
            agent_id="main",
            session_id="session-1",
        )


def test_compaction_argv_keeps_gateway_token_out_of_process_arguments(
    tmp_path: Path,
) -> None:
    argv = _build_compaction_argv(
        tmp_path / "openclaw.cmd",
        session_key="agent:main:session",
        agent_id="main",
        gateway_port=18789,
        timeout=300,
    )

    assert argv[:3] == [str(tmp_path / "openclaw.cmd"), "sessions", "compact"]
    assert "--url" not in argv
    assert "--token" not in argv


def test_native_compaction_projects_ordered_boundary_with_real_token_reduction(
    tmp_path: Path,
) -> None:
    events = _normalize_compaction_events(
        json.dumps({
            "ok": True,
            "compacted": True,
            "result": {"tokensBefore": 1200, "tokensAfter": 400},
        }),
        source_path=tmp_path / "compact.json",
        run_id="run-1",
        stage_index=2,
        agent_id="main",
        native_session_key="agent:main:case",
        boundary_session_id="boundary-session",
    )

    rendered = [event.to_dict() for event in events]
    assert [item["status"] if item["subtype"] == "status" else item["subtype"] for item in rendered] == [
        "compacting", "compact_success", "compact_boundary",
    ]
    assert rendered[-1]["compact_metadata"] == {
        "trigger": "manual", "pre_tokens": 1200, "post_tokens": 400,
    }
    assert all(item["session_id"] == "boundary-session" for item in rendered)


def test_native_compaction_uses_audited_summary_estimate_when_post_tokens_absent(
    tmp_path: Path,
) -> None:
    events = _normalize_compaction_events(
        json.dumps({
            "ok": True,
            "compacted": True,
            "result": {"tokensBefore": 1000, "summary": "short retained summary"},
        }),
        source_path=tmp_path / "compact.json",
        run_id="run-1",
        stage_index=2,
        agent_id="main",
        native_session_key="agent:main:case",
        boundary_session_id="boundary-session",
    )

    metadata = events[-1].to_dict()["compact_metadata"]
    assert metadata["post_tokens_source"] == "summary_chars_div_4_ceiling"
    assert metadata["post_tokens"] == 6
    assert len(metadata["summary_sha256"]) == 64
