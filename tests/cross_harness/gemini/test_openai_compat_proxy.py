from __future__ import annotations

from infra.cross_harness.adapters.gemini.openai_compat_proxy import (
    chat_completion_to_gemini_response,
    gemini_generate_to_chat_completion,
)


def test_gemini_request_translates_to_openai_chat_tools() -> None:
    request = gemini_generate_to_chat_completion(
        {
            "systemInstruction": {"parts": [{"text": "system policy"}]},
            "contents": [
                {"role": "user", "parts": [{"text": "read README"}]},
                {
                    "role": "model",
                    "parts": [
                        {
                            "functionCall": {
                                "name": "read_file",
                                "args": {"path": "README.md"},
                            }
                        }
                    ],
                },
                {
                    "role": "user",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": "read_file",
                                "response": {"content": "ok"},
                            }
                        }
                    ],
                },
            ],
            "tools": [
                {
                    "functionDeclarations": [
                        {
                            "name": "read_file",
                            "description": "Read a file",
                            "parameters": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                        }
                    ]
                }
            ],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 128},
        },
        model="gemini-3.5-flash",
    )
    assert request["model"] == "gemini-3.5-flash"
    assert request["stream"] is False
    assert request["messages"][0] == {"role": "system", "content": "system policy"}
    assert request["messages"][1] == {"role": "user", "content": "read README"}
    assistant = request["messages"][2]
    assert assistant["role"] == "assistant"
    assert assistant["tool_calls"][0]["function"]["name"] == "read_file"
    tool = request["messages"][3]
    assert tool["role"] == "tool"
    assert tool["tool_call_id"] == assistant["tool_calls"][0]["id"]
    assert request["tools"][0]["function"]["name"] == "read_file"
    assert request["max_tokens"] == 128


def test_openai_chat_response_translates_to_gemini_function_call() -> None:
    response = chat_completion_to_gemini_response(
        {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "write_file",
                                    "arguments": '{"path":"out.txt","content":"ok"}',
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 3,
                "total_tokens": 13,
            },
        }
    )
    candidate = response["candidates"][0]
    assert candidate["content"]["role"] == "model"
    assert candidate["content"]["parts"] == [
        {
            "functionCall": {
                "name": "write_file",
                "args": {"path": "out.txt", "content": "ok"},
            }
        }
    ]
    assert response["usageMetadata"] == {
        "promptTokenCount": 10,
        "candidatesTokenCount": 3,
        "totalTokenCount": 13,
    }


def test_openai_chat_response_normalizes_legacy_function_call_path_alias() -> None:
    response = chat_completion_to_gemini_response(
        {
            "choices": [
                {
                    "finish_reason": "function_call",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "function_call": {
                            "name": "read_file",
                            "arguments": '{"path":"README.md","limit":20}',
                        },
                    },
                }
            ]
        }
    )

    assert response["candidates"][0]["content"]["parts"] == [
        {
            "functionCall": {
                "name": "read_file",
                "args": {"file_path": "README.md", "limit": 20},
            }
        }
    ]


def test_openai_chat_response_maps_empty_assistant_message_to_text() -> None:
    response = chat_completion_to_gemini_response(
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "\n"},
                }
            ]
        }
    )

    assert response["candidates"][0]["content"]["parts"] == [{"text": "Done."}]
