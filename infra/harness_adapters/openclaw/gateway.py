from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import OpenClawPaths, io_path, runtime_environment


@dataclass(frozen=True)
class GatewaySpec:
    argv: tuple[str, ...]
    environment: dict[str, str]
    ownership_path: Path
    launch_nonce: str


@dataclass(frozen=True)
class OwnershipManifest:
    gateway_pid: int
    launch_nonce: str
    path: Path

    def write(self) -> None:
        target = io_path(self.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"gateway_pid": self.gateway_pid, "launch_nonce": self.launch_nonce}, indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    launch_nonce: str


@dataclass(frozen=True)
class CleanupResult:
    terminated: tuple[int, ...]
    refused: tuple[int, ...]


def build_gateway_spec(
    executable: Path,
    paths: OpenClawPaths,
    *,
    gateway_token: str = "",
    stage_index: int = 0,
) -> GatewaySpec:
    env = runtime_environment(paths)
    if gateway_token:
        env[paths.gateway_token_env] = gateway_token
    return GatewaySpec(
        (
            str(executable),
            "gateway",
            "run",
            "--port",
            str(paths.gateway_port),
            "--bind",
            "loopback",
            "--auth",
            "token",
            "--verbose",
        ),
        env,
        paths.run_dir
        / f"openclaw-gateway-stage-{stage_index:03d}-ownership.json",
        paths.run_nonce,
    )


def cleanup_owned_processes(
    manifest: OwnershipManifest,
    observed: ProcessIdentity,
    *,
    terminate: Callable[[int], bool] | None = None,
) -> CleanupResult:
    if observed.pid != manifest.gateway_pid or observed.launch_nonce != manifest.launch_nonce:
        return CleanupResult((), (observed.pid,))
    if terminate is None:
        return CleanupResult((), (observed.pid,))
    return CleanupResult((observed.pid,), ()) if terminate(observed.pid) else CleanupResult((), (observed.pid,))
