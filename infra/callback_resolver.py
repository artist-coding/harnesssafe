"""Resolve a honeypot callback URL reachable from a harness environment."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable, Iterable


ProbeFn = Callable[[str, str, float], bool]


@dataclass(frozen=True)
class CallbackResolution:
    callback_url: str
    callback_probe_ok: bool
    callback_probe_method: str
    callback_candidates: list[str]


def _unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _local_ipv4_hosts() -> list[str]:
    hosts: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            hosts.add(info[4][0])
    except OSError:
        pass
    return sorted(h for h in hosts if not h.startswith("127."))


def _wsl_gateway_hosts() -> list[str]:
    hosts: list[str] = []
    try:
        proc = subprocess.run(
            [
                "wsl.exe",
                "sh",
                "-lc",
                (
                    "ip route show default 2>/dev/null | "
                    "sed -n 's/^default via \\([^ ]*\\).*/\\1/p' | head -1; "
                    "grep -m1 '^nameserver ' /etc/resolv.conf 2>/dev/null | cut -d' ' -f2"
                ),
            ],
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="ignore",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", line) and line not in hosts:
            hosts.append(line)
    return hosts


def candidate_callback_urls(
    port: int,
    extra_hosts: Iterable[str] = (),
    include_host_network: bool = True,
    include_wsl: bool = True,
) -> list[str]:
    hosts: list[str] = ["127.0.0.1", "localhost", "host.docker.internal"]
    hosts.extend(extra_hosts)
    if include_host_network:
        hosts.extend(_local_ipv4_hosts())
    if include_wsl:
        hosts.extend(_wsl_gateway_hosts())
    return [f"http://{host}:{port}" for host in _unique(hosts)]


def host_http_probe(url: str, harness: str, timeout_sec: float = 2.0) -> bool:
    probe_url = f"{url.rstrip('/')}/__callback_probe?harness={harness}"
    try:
        with urllib.request.urlopen(probe_url, timeout=timeout_sec) as response:
            return 200 <= response.status < 500
    except Exception:
        return False


def wsl_http_probe(url: str, harness: str, timeout_sec: float = 2.0) -> bool:
    probe_url = f"{url.rstrip('/')}/__callback_probe?harness={harness}"
    try:
        proc = subprocess.run(
            ["wsl.exe", "sh", "-lc", f"curl -fsS --max-time {int(max(1, timeout_sec))} {json.dumps(probe_url)} >/dev/null"],
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_sec + 2,
            check=False,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def default_probe(url: str, harness: str, timeout_sec: float = 2.0) -> bool:
    if harness.lower() == "hermes":
        return wsl_http_probe(url, harness, timeout_sec) or host_http_probe(url, harness, timeout_sec)
    return host_http_probe(url, harness, timeout_sec)


def resolve_callback_url(
    harness: str,
    port: int,
    candidates: list[str] | None = None,
    probe: ProbeFn = default_probe,
    timeout_sec: float = 2.0,
) -> CallbackResolution:
    candidate_list = candidates or candidate_callback_urls(port)
    for url in candidate_list:
        if probe(url, harness, timeout_sec):
            return CallbackResolution(
                callback_url=url.rstrip("/"),
                callback_probe_ok=True,
                callback_probe_method=harness,
                callback_candidates=candidate_list,
            )
    fallback = candidate_list[0] if candidate_list else f"http://127.0.0.1:{port}"
    return CallbackResolution(
        callback_url=fallback.rstrip("/"),
        callback_probe_ok=False,
        callback_probe_method=harness,
        callback_candidates=candidate_list,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--extra-host", action="append", default=[])
    args = ap.parse_args()

    candidates = candidate_callback_urls(args.port, extra_hosts=args.extra_host)
    resolution = resolve_callback_url(args.harness, args.port, candidates=candidates)
    print(json.dumps(asdict(resolution), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
