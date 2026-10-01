"""Execution support is explicit; discovery never implies scoring eligibility."""
from .common import ARMS

ADAPTERS = {
    "codex": {"platform": "win32", "profiles": ["default_permission", "max_permission"], "arms": list(ARMS), "scoring": "shared_v3"},
    "claude": {"platform": "win32", "profiles": ["default_permission", "max_permission"], "arms": list(ARMS), "scoring": "shared_v3"},
    "hermes": {"platform": "win32", "profiles": ["max_permission"], "arms": list(ARMS), "scoring": "shared_v3"},
    "openclaw": {"platform": "win32", "profiles": ["max_permission"], "arms": list(ARMS), "scoring": "shared_v3"},
    "gemini": {"platform": "linux", "profiles": ["adapter_default"], "arms": ["attack"], "scoring": "gemini_bridge_then_shared_v3"},
    "opencode": {"platform": "linux", "profiles": ["adapter_default"], "arms": ["attack"], "scoring": "native_capture_only"},
    "kimi": {"platform": "linux", "profiles": ["adapter_default"], "arms": ["attack"], "scoring": "diagnostic_only; reviewed runtime 0.26.0"},
}
PROVIDER_FIELDS = {
    "codex": {"codex_provider"},
    "claude": {"claude_base_url", "claude_api_key_env", "claude_auth_token_env"},
    "hermes": {"base_url", "provider_id", "api_key_env", "api_mode"},
    "openclaw": {"base_url", "provider_id", "api_key_env", "api"},
    "gemini": {"api_base_url", "api_key_env", "project", "location", "provider_kind"},
    "opencode": {"profile"},
    "kimi": {"provider_url", "credential_env"},
}
RUNTIME_FIELDS = {
    "codex": set(), "claude": set(),
    "hermes": {"source_root", "python_executable", "git_bash", "conformance"},
    "openclaw": {"node_executable", "expected_node_version", "allow_not_run_smoke", "conformance"},
    "gemini": {"conformance"}, "opencode": {"conformance"}, "kimi": set(),
}
REQUIRED_PROVIDER = {
    "codex": set(), "claude": set(),
    "hermes": PROVIDER_FIELDS["hermes"], "openclaw": PROVIDER_FIELDS["openclaw"],
    "gemini": PROVIDER_FIELDS["gemini"], "opencode": {"profile"}, "kimi": PROVIDER_FIELDS["kimi"],
}
REQUIRED_RUNTIME = {h: fields - ({"allow_not_run_smoke", "conformance"} if h in {"hermes", "openclaw"} else set()) for h, fields in RUNTIME_FIELDS.items()}
