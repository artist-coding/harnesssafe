"""Non-interactive, isolated Gemini CLI launch-spec construction."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Mapping

from ...adapter import HarnessIdentity, LaunchSpec, MaterializedBinding
from .materializer import GeminiMaterializationError, sha256_file


class GeminiLaunchError(RuntimeError):
    """A Gemini launch was blocked before any model invocation."""

    execution_outcome = "NOT_RUN"


_SENSITIVE_ENV_RE = re.compile(
    r"(?:api[_-]?key|token|secret|password|credential|authorization)", re.IGNORECASE
)
_MCP_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _stage(manifest: Mapping[str, Any], stage_index: int) -> Mapping[str, Any]:
    matches = [item for item in manifest["stages"] if item["index"] == stage_index]
    if len(matches) != 1:
        raise GeminiLaunchError(f"unknown Gemini stage index: {stage_index}")
    return matches[0]


def _inside(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise GeminiLaunchError(f"{label} escapes the Gemini run") from exc
    return resolved


def _write_empty_settings(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")


def _write_qualification_policy(
    path: Path, *, mcp_server_names: list[str], allow_shell: bool = False
) -> None:
    """Allow only workspace inspection/edit tools plus declared case MCP tools."""

    path.parent.mkdir(parents=True, exist_ok=True)
    mcp_tool_patterns: list[str] = []
    for name in mcp_server_names:
        if not isinstance(name, str) or not _MCP_SERVER_NAME_RE.fullmatch(name):
            raise GeminiLaunchError(f"unsafe MCP server name in policy: {name!r}")
        mcp_tool_patterns.append(f"mcp_{name}_*")
    policy = (
        "[[rule]]\n"
        'name = "Qualification deny by default"\n'
        'toolName = "*"\n'
        'decision = "deny"\n'
        "priority = 900\n\n"
        "[[rule]]\n"
        'name = "Qualification workspace file tools"\n'
        'toolName = ["glob", "grep_search", "list_directory", "read_file", '
        '"write_file", "replace"]\n'
        'decision = "allow"\n'
        "priority = 999\n"
    )
    if mcp_tool_patterns:
        policy += (
            "\n[[rule]]\n"
            'name = "Qualification case MCP tools"\n'
            f"toolName = {json.dumps(mcp_tool_patterns, ensure_ascii=False)}\n"
            'decision = "allow"\n'
            "priority = 999\n"
        )
    if allow_shell:
        policy += (
            "\n[[rule]]\n"
            'name = "Qualification shell carrier tool"\n'
            'toolName = "run_shell_command"\n'
            'decision = "allow"\n'
            "priority = 999\n"
        )
    path.write_text(policy, encoding="utf-8")


def build_gemini_launch_spec(
    *,
    identity: HarnessIdentity,
    materialized: MaterializedBinding,
    manifest: Mapping[str, Any],
    stage_index: int,
    prompt: str,
    timeout_seconds: int,
    base_environment: Mapping[str, str],
    model: str,
) -> LaunchSpec:
    if identity.harness_id != "gemini":
        raise GeminiLaunchError("launch identity is not Gemini CLI")
    executable = Path(identity.executable).resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise GeminiLaunchError("detected Gemini executable is unavailable")
    if sha256_file(executable) != identity.feature_flags.get("binary_sha256"):
        raise GeminiLaunchError("Gemini executable bytes drifted after identity probe")
    if identity.feature_flags.get("headless_prompt") is not True:
        raise GeminiLaunchError("detected Gemini CLI does not expose --prompt")
    if identity.feature_flags.get("stream_json") is not True:
        raise GeminiLaunchError("detected Gemini CLI does not expose stream-json")
    if not isinstance(prompt, str) or not prompt:
        raise GeminiLaunchError("Gemini prompt must be non-empty")
    if not isinstance(model, str) or not model.strip():
        raise GeminiLaunchError("Gemini model must be explicitly pinned")
    if manifest.get("requested_model") != model:
        raise GeminiLaunchError(
            "Gemini launch model does not match the materialized model pin"
        )
    stage = _stage(manifest, stage_index)
    prompt_path = Path(stage["prompt_path"])
    if not prompt_path.is_file() or sha256_file(prompt_path) != stage["prompt_sha256"]:
        raise GeminiLaunchError("Gemini materialized prompt hash drifted")
    expected_prompt = prompt_path.read_text(encoding="utf-8")
    if prompt != expected_prompt:
        raise GeminiLaunchError("launch prompt does not match the reviewed stage prompt")
    settings = Path(stage["settings_path"])
    if not settings.is_file() or sha256_file(settings) != stage["settings_sha256"]:
        raise GeminiLaunchError("Gemini settings drifted after materialization")

    run_dir = materialized.run_dir.resolve()
    home_dir = _inside(Path(stage["home_dir"]), run_dir, "HOME")
    gemini_home = _inside(Path(stage["gemini_home"]), run_dir, "GEMINI_CLI_HOME")
    temp_dir = _inside(Path(stage["temp_dir"]), run_dir, "TMPDIR")
    xdg_cache = _inside(home_dir / "xdg-cache", run_dir, "XDG_CACHE_HOME")
    xdg_config = _inside(home_dir / "xdg-config", run_dir, "XDG_CONFIG_HOME")
    xdg_data = _inside(home_dir / "xdg-data", run_dir, "XDG_DATA_HOME")
    trusted_folders = _inside(
        home_dir / ".gemini" / "trustedFolders.json", run_dir, "trusted folders"
    )
    system_defaults = _inside(
        home_dir / ".gemini" / "system-defaults.json", run_dir, "system defaults"
    )
    # Point the system-settings override at the exact reviewed stage settings.
    # This is independent of GEMINI_CLI_HOME and therefore remains stage-scoped
    # when future session/resume bindings share a Gemini data directory.
    system_settings = _inside(settings, run_dir, "system settings")
    for path in (home_dir, gemini_home, temp_dir, xdg_cache, xdg_config, xdg_data):
        path.mkdir(parents=True, exist_ok=True)
    _write_empty_settings(system_defaults)
    trusted_folders.write_text("{}\n", encoding="utf-8")

    environment = {
        "PATH": base_environment.get("PATH", os.defpath),
        "HOME": str(home_dir),
        "GEMINI_CLI_HOME": str(gemini_home),
        "GEMINI_CLI_TRUST_WORKSPACE": "true",
        "GEMINI_CLI_TRUSTED_FOLDERS_PATH": str(trusted_folders),
        "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": str(system_defaults),
        "GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(system_settings),
        "GEMINI_TELEMETRY_ENABLED": "false",
        "GEMINI_TELEMETRY_TRACES_ENABLED": "false",
        "GEMINI_TELEMETRY_LOG_PROMPTS": "false",
        "XDG_CACHE_HOME": str(xdg_cache),
        "XDG_CONFIG_HOME": str(xdg_config),
        "XDG_DATA_HOME": str(xdg_data),
        "TMPDIR": str(temp_dir),
        "NO_COLOR": "1",
        "CI": "1",
        "SAFETY_BENCH_HARNESS": "gemini",
        "SAFETY_BENCH_RUN_ID": str(manifest["run_id"]),
    }
    for key in ("LANG", "LC_ALL"):
        value = base_environment.get(key)
        if value:
            environment[key] = value
    # Preserve only standard proxy routing.  The container used for benchmark
    # development requires these variables to reach Vertex; dropping them made
    # an otherwise valid isolated launch hang before a terminal result.  No
    # arbitrary parent environment keys are inherited.
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        value = base_environment.get(key)
        if value:
            environment[key] = value
    if any(_SENSITIVE_ENV_RE.search(key) for key in environment):
        raise GeminiLaunchError("Gemini launch environment contains credential-like keys")
    if any(
        key.startswith(("CLAUDE", "CODEX", "KIMI", "OPENAI")) for key in environment
    ):
        raise GeminiLaunchError("Gemini launch environment contains another harness state key")

    argv = [
        str(executable),
        "--prompt",
        prompt,
        "--model",
        model,
        "--output-format",
        "stream-json",
    ]
    session_action = stage.get("session_action", "")
    session_id = stage.get("session_id")
    if session_action == "start":
        if identity.feature_flags.get("session_id") is not True:
            raise GeminiLaunchError(
                "detected Gemini CLI does not expose --session-id"
            )
        if not isinstance(session_id, str) or not session_id:
            raise GeminiLaunchError("Gemini start stage has no bound session_id")
        argv.extend(("--session-id", session_id))
    elif session_action in {"compact", "resume"}:
        if identity.feature_flags.get("resume") is not True:
            raise GeminiLaunchError("detected Gemini CLI does not expose --resume")
        if not isinstance(session_id, str) or not session_id:
            raise GeminiLaunchError("Gemini resume stage has no bound session_id")
        argv.extend(("--resume", session_id))
    elif session_action not in {"", "fresh"}:
        raise GeminiLaunchError(
            f"unsupported Gemini session action: {session_action!r}"
        )
    if identity.feature_flags.get("skip_trust") is True:
        argv.append("--skip-trust")
    mcp_names = stage.get("mcp_server_names", [])
    if mcp_names:
        argv.extend(("--allowed-mcp-server-names", ",".join(mcp_names)))
    shell_write_carriers = stage.get("shell_write_carriers", [])
    allow_shell = bool(shell_write_carriers)
    trace_path = _inside(Path(stage["trace_path"]), run_dir, "raw trace")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path = _inside(
        run_dir / "gemini_adapter" / "qualification-admin-policy.toml",
        run_dir,
        "qualification policy",
    )
    _write_qualification_policy(
        policy_path,
        mcp_server_names=[
            str(name)
            for name in stage.get("mcp_server_names", [])
            if isinstance(name, str)
        ],
        allow_shell=allow_shell,
    )
    argv.extend(("--admin-policy", str(policy_path), "--approval-mode", "auto_edit"))
    launch_manifest = trace_path.parent.parent / "launch.json"
    redacted_argv = list(argv)
    redacted_argv[2] = "<sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest() + ">"
    launch_manifest.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_gemini_launch",
                "schema_version": 1,
                "run_id": manifest["run_id"],
                "case_id": materialized.case_id,
                "stage": {"name": stage["name"], "index": stage["index"]},
                "argv": redacted_argv,
                "requested_model": model,
                "cwd": manifest["workspace_dir"],
                "env_keys": sorted(environment),
                "trace_path": str(trace_path),
                "timeout_seconds": timeout_seconds,
                "qualification_policy": {
                    "path": str(policy_path),
                    "sha256": sha256_file(policy_path),
                    "network_tools": "denied",
                    "shell_tool": (
                        "allowed_for_shell_write_carriers"
                        if allow_shell
                        else "denied"
                    ),
                    "shell_write_carriers": shell_write_carriers if allow_shell else [],
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return LaunchSpec(
        argv=tuple(argv),
        cwd=Path(manifest["workspace_dir"]),
        env=environment,
        trace_path=trace_path,
        timeout_seconds=timeout_seconds,
    )


def build_gemini_bwrap_command(
    *,
    launch_spec: LaunchSpec,
    run_dir: Path,
    extra_environment: Mapping[str, str],
    uid: int = 0,
    gid: int = 0,
) -> tuple[str, ...]:
    """Wrap a launch in a minimal filesystem namespace and unprivileged UID."""

    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise GeminiLaunchError("bubblewrap is required for external qualification")
    run_dir = Path(run_dir).resolve()
    try:
        launch_spec.cwd.resolve().relative_to(run_dir)
        launch_spec.trace_path.resolve().relative_to(run_dir)
    except ValueError as exc:
        raise GeminiLaunchError("qualification launch paths escape the run") from exc
    try:
        run_dir.relative_to(Path("/tmp"))
    except ValueError as exc:
        raise GeminiLaunchError("qualification sandbox run_dir must be under /tmp") from exc
    environment = dict(launch_spec.env)
    for key, value in extra_environment.items():
        if key in environment and environment[key] != value:
            raise GeminiLaunchError(f"qualification environment conflicts at {key}")
        environment[key] = value
    allowed_extra = {
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_VERTEX_BASE_URL",
    }
    if set(extra_environment) != allowed_extra:
        raise GeminiLaunchError("qualification proxy environment is incomplete or expanded")
    credential_path = Path(extra_environment["GOOGLE_APPLICATION_CREDENTIALS"]).resolve()
    try:
        credential_path.relative_to(run_dir)
    except ValueError as exc:
        raise GeminiLaunchError("placeholder ADC must be run-local") from exc
    if not credential_path.is_file():
        raise GeminiLaunchError("placeholder ADC is absent")

    # The empty bubblewrap root contains only the OS/runtime and this run. It
    # intentionally has no /root mount. Network remains shared solely so the
    # SDK can reach the loopback credential/Vertex proxy; the admin policy
    # denies network tools and only exposes shell for explicitly reviewed
    # run-local shell-write carriers.
    argv = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/usr/local",
        "/usr/local",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--bind",
        str(run_dir),
        str(run_dir),
        "--chdir",
        str(launch_spec.cwd),
        "--uid",
        str(uid),
        "--gid",
        str(gid),
        "--clearenv",
    ]
    for key, value in sorted(environment.items()):
        argv.extend(("--setenv", key, value))
    argv.extend(("--", *launch_spec.argv))
    return tuple(argv)


__all__ = [
    "GeminiLaunchError",
    "build_gemini_bwrap_command",
    "build_gemini_launch_spec",
]
