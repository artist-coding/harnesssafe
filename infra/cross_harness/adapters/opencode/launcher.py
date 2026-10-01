"""OpenCode non-interactive launch specification."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import shlex
from typing import Mapping

from ...adapter import LaunchSpec, MaterializedBinding
from .materializer import (
    OpenCodeMaterializationError,
    load_materialization_manifest,
)


class OpenCodeLaunchError(RuntimeError):
    """A safe, non-interactive OpenCode launch could not be built."""


_SHELL_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _write_secret_env_loader(
    *,
    isolated_run: Path,
    trace_path: Path,
    environment: Mapping[str, str],
    secret_env_names: tuple[str, ...],
) -> Path | None:
    selected = tuple(name for name in secret_env_names if name in environment)
    if not selected:
        return None
    for name in selected:
        if _SHELL_ENV_NAME_RE.fullmatch(name) is None:
            raise OpenCodeLaunchError(
                f"credential environment variable is not shell-safe: {name}"
            )
    secret_dir = isolated_run / "opencode-state" / "launch-secrets"
    secret_dir.mkdir(parents=True, exist_ok=True)
    secret_dir.chmod(0o700)
    loader_path = secret_dir / f"{trace_path.stem}.env.sh"
    loader_path.write_text(
        "".join(
            f"export {name}={shlex.quote(environment[name])}\n"
            for name in selected
        ),
        encoding="utf-8",
    )
    loader_path.chmod(0o600)
    return loader_path


def _selected_stage(
    manifest: Mapping[str, object], stage_index: int
) -> Mapping[str, object]:
    stages = manifest.get("stages")
    if not isinstance(stages, list):
        raise OpenCodeLaunchError("materialization manifest has no stages")
    for stage in stages:
        if isinstance(stage, Mapping) and stage.get("index") == stage_index:
            return stage
    raise OpenCodeLaunchError(
        f"materialization manifest has no stage {stage_index}"
    )


def build_opencode_launch_spec(
    *,
    materialized: MaterializedBinding,
    executable: str,
    prompt: str,
    timeout_seconds: int,
    stage_index: int,
    session_id: str | None,
    base_environment: Mapping[str, str],
    credential_environment_names: tuple[str, ...] = (),
) -> LaunchSpec:
    if not isinstance(prompt, str) or not prompt.strip() or "\0" in prompt:
        raise OpenCodeLaunchError("prompt must be non-empty and contain no NUL")
    if timeout_seconds < 1:
        raise OpenCodeLaunchError("timeout_seconds must be positive")
    try:
        manifest = load_materialization_manifest(materialized)
    except OpenCodeMaterializationError as exc:
        raise OpenCodeLaunchError(str(exc)) from exc
    stage = _selected_stage(manifest, stage_index)
    workspace = Path(str(manifest["workspace_dir"])).resolve()
    config_path = Path(str(stage["config_path"])).resolve()
    config_dir = Path(str(manifest["config_surface_dir"])).resolve()
    hook_log = Path(str(manifest["hook_log_path"])).resolve()
    if not workspace.is_dir():
        raise OpenCodeLaunchError("materialized workspace does not exist")
    if not config_path.is_file():
        raise OpenCodeLaunchError("stage OpenCode config does not exist")
    if not config_dir.is_dir():
        raise OpenCodeLaunchError("run-local OpenCode config surface is missing")

    isolated = materialized.run_dir / "opencode-state"
    isolated_home = isolated / "home"
    xdg_config = isolated / "xdg-config"
    xdg_data = isolated / "xdg-data"
    xdg_cache = isolated / "xdg-cache"
    temp_dir = isolated / "tmp"
    for path in (
        isolated_home,
        xdg_config,
        xdg_data,
        xdg_cache,
        temp_dir,
        hook_log.parent,
    ):
        path.mkdir(parents=True, exist_ok=True)

    environment = {
        "PATH": base_environment.get("PATH", os.defpath),
        "HOME": str(isolated_home),
        "XDG_CONFIG_HOME": str(xdg_config),
        "XDG_DATA_HOME": str(xdg_data),
        "XDG_CACHE_HOME": str(xdg_cache),
        "TMPDIR": str(temp_dir),
        "CI": "1",
        "NO_COLOR": "1",
        "OPENCODE_CLIENT": "safety-bench",
        "OPENCODE_CONFIG": str(config_path),
        "OPENCODE_CONFIG_DIR": str(config_dir),
        "OPENCODE_DISABLE_AUTOUPDATE": "1",
        "OPENCODE_DISABLE_PRUNE": "1",
        "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
        "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
        "OPENCODE_DISABLE_MODELS_FETCH": "1",
        "OPENCODE_DISABLE_CLAUDE_CODE": "1",
        "OPENCODE_ENABLE_EXA": "0",
        "SAFETY_BENCH_OPENCODE_HOOK_LOG": str(hook_log),
        "TAR_OPTIONS": "--no-same-owner",
    }
    for name in ("LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        value = base_environment.get(name)
        if value:
            environment[name] = value
    for name in credential_environment_names:
        if not isinstance(name, str) or not name.strip():
            raise OpenCodeLaunchError(
                "credential environment names must be non-empty strings"
            )
        value = base_environment.get(name)
        if value is None:
            raise OpenCodeLaunchError(
                f"required credential environment variable is missing: {name}"
            )
        environment[name] = value

    trace_path = (
        materialized.run_dir
        / "raw"
        / f"stage-{stage_index:02d}-opencode.jsonl"
    )
    argv = [
        executable,
        "run",
        "--format",
        "json",
        "--model",
        str(manifest["model"]),
        "--dir",
        str(workspace),
    ]
    action = stage.get("session_action", "fresh")
    if action in {"resume", "continue"}:
        if not session_id:
            raise OpenCodeLaunchError(
                f"stage {stage_index} requires a captured OpenCode session id"
            )
        argv.extend(["--session", session_id])
    elif action not in {"fresh", "new"}:
        raise OpenCodeLaunchError(
            f"stage {stage_index} has unsupported session_action {action!r}"
        )
    argv.append(prompt)
    return LaunchSpec(
        argv=tuple(argv),
        cwd=workspace,
        env=environment,
        trace_path=trace_path,
        timeout_seconds=timeout_seconds,
        secret_env_names=credential_environment_names,
    )


def _mounted_tool_parent(name: str, host_path: str) -> str | None:
    found = shutil.which(name, path=host_path)
    if found is None:
        return None
    resolved = Path(found).resolve()
    try:
        resolved.relative_to(Path("/usr"))
    except ValueError:
        return None
    return str(resolved.parent)


def build_opencode_bwrap_command(
    *,
    launch_spec: LaunchSpec,
    run_dir: Path,
    executable: Path,
    uid: int = 0,
    gid: int = 0,
) -> tuple[str, ...]:
    """Wrap OpenCode in a minimal run-local filesystem namespace.

    Network remains shared so the process can reach the explicitly configured
    provider proxy and benchmark honeypot.  The filesystem contains only the
    read-only OS/runtime, the exact OpenCode binary, and one writable run tree.
    """

    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise OpenCodeLaunchError(
            "bubblewrap is required for OpenCode benchmark execution"
        )
    isolated_run = Path(run_dir).resolve()
    try:
        isolated_run.relative_to(Path("/tmp"))
        launch_spec.cwd.resolve().relative_to(isolated_run)
        launch_spec.trace_path.resolve().relative_to(isolated_run)
    except ValueError as exc:
        raise OpenCodeLaunchError(
            "OpenCode sandbox run_dir, cwd, and trace must stay under /tmp"
        ) from exc
    resolved_executable = Path(executable).resolve()
    if (
        not resolved_executable.is_file()
        or not os.access(resolved_executable, os.X_OK)
    ):
        raise OpenCodeLaunchError(
            f"OpenCode sandbox executable is invalid: {resolved_executable}"
        )
    if Path(launch_spec.argv[0]).resolve() != resolved_executable:
        raise OpenCodeLaunchError(
            "OpenCode launch executable changed before sandbox construction"
        )
    if uid < 0 or gid < 0:
        raise OpenCodeLaunchError("sandbox uid/gid must be non-negative")

    sandbox_executable = "/opt/safety-bench/opencode"
    environment = dict(launch_spec.env)
    secret_env_names = tuple(launch_spec.secret_env_names)
    for name in secret_env_names:
        environment.pop(name, None)
    sandbox_path = ["/usr/local/bin", "/usr/bin", "/bin"]
    rg_parent = _mounted_tool_parent("rg", environment.get("PATH", ""))
    if rg_parent is not None and rg_parent not in sandbox_path:
        sandbox_path.insert(0, rg_parent)
    environment["PATH"] = ":".join(sandbox_path)
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
        "--dir",
        "/opt",
        "--dir",
        "/opt/safety-bench",
        "--dir",
        "/etc",
        "--dir",
        "/etc/ssl",
        "--ro-bind",
        str(resolved_executable),
        sandbox_executable,
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--bind",
        str(isolated_run),
        str(isolated_run),
        "--chdir",
        str(launch_spec.cwd),
        "--uid",
        str(uid),
        "--gid",
        str(gid),
        "--clearenv",
    ]
    for certificate_path in (
        Path("/etc/ssl/certs"),
        Path("/etc/resolv.conf"),
        Path("/etc/hosts"),
    ):
        if certificate_path.exists():
            argv.extend(
                (
                    "--ro-bind",
                    str(certificate_path),
                    str(certificate_path),
                )
            )
    secret_loader = _write_secret_env_loader(
        isolated_run=isolated_run,
        trace_path=launch_spec.trace_path,
        environment=launch_spec.env,
        secret_env_names=secret_env_names,
    )
    for key, value in sorted(environment.items()):
        argv.extend(("--setenv", key, value))
    if secret_loader is None:
        argv.extend(("--", sandbox_executable, *launch_spec.argv[1:]))
    else:
        argv.extend(
            (
                "--",
                "/bin/sh",
                "-c",
                '. "$1"; rm -f "$1"; shift; exec "$@"',
                "opencode-secret-loader",
                str(secret_loader),
                sandbox_executable,
                *launch_spec.argv[1:],
            )
        )
    return tuple(argv)


__all__ = [
    "OpenCodeLaunchError",
    "build_opencode_bwrap_command",
    "build_opencode_launch_spec",
]
