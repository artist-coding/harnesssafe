"""Check whether the local checkout is ready for paper-scale experiments."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from infra.check_active_case_integrity import validate_active_cases
except ModuleNotFoundError:  # direct `python infra/check_paper_readiness.py`
    from check_active_case_integrity import validate_active_cases


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
MANIFEST = RUNS / "manifest.json"

# ``all`` is the canonical runnable-coverage scope. ``core`` remains accepted
# as a backwards-compatible alias because older run labels and scripts used it
# as a compatibility selector. Both select every active manifest case;
# formal metrics use only the separately declared eligible subset.
CASE_SETS = ["all", "core", "extended", "exploratory"]
ACTIVE_CASE_COUNT = 328
FORMAL_METRIC_CASE_COUNT = 328
DIAGNOSTIC_CASE_COUNT = ACTIVE_CASE_COUNT - FORMAL_METRIC_CASE_COUNT
# Backwards-compatible import used by older audit helpers; this denotes active
# runnable coverage, not the formal ASR denominator.
FORMAL_CASE_COUNT = ACTIVE_CASE_COUNT
REQUIRED_RUNNERS = [
    "infra/check_active_case_integrity.py",
    "infra/audit_paper_suite.py",
    "infra/run_harness_case.ps1",
    "infra/run_paper_baseline_matrix.ps1",
    "infra/run_paper_control_matrix.ps1",
    "infra/plan_control_smoke.py",
    "infra/run_control_smoke.py",
    "infra/plan_paper_experiment_matrix.py",
    "infra/check_paper_matrix_progress.py",
    "infra/export_paper_run_queue.py",
    "infra/run_paper_queue.py",
    "infra/estimate_paper_run_budget.py",
    "infra/report_paper_submission_gaps.py",
    "infra/check_paper_live_status.py",
    "infra/run_paper_preflight.ps1",
    "infra/report_active_run.py",
    "infra/check_paper_results.py",
    "infra/check_paper_numbers.py",
    "infra/check_paper_case_studies.py",
    "infra/check_paper_manuscript.py",
    "infra/generate_benchmark_card.py",
    "infra/generate_paper_appendix.py",
    "infra/generate_oracle_coverage_report.py",
    "infra/generate_threat_model_card.py",
    "infra/generate_statistical_analysis.py",
    "infra/generate_claim_evidence_map.py",
    "infra/generate_control_integrity_report.py",
    "infra/generate_paper_figures.py",
    "infra/check_paper_bibliography.py",
    "infra/generate_submission_package_manifest.py",
    "infra/check_paper_artifact_gate.py",
    "infra/check_paper_claims.py",
    "infra/check_public_artifact_safety.py",
    "infra/check_paper_suite_lock.py",
    "infra/check_release_metadata.py",
    "infra/export_paper_tables.py",
    "infra/export_case_study_evidence.py",
    "infra/build_repro_bundle.py",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def include_case_in_set(meta: dict[str, Any], case_set: str) -> bool:
    if case_set in {"all", "core"}:
        return True
    if case_set == "extended":
        return meta.get("reporting_track") == "extended_benchmark"
    if case_set == "exploratory":
        return meta.get("reporting_track") == "exploratory_case_study"
    raise ValueError(f"unknown case_set: {case_set}")


def count_case_sets(root: Path = ROOT) -> dict[str, int]:
    runs = root / "runs"
    manifest = load_json(runs / "manifest.json")
    counts = {name: 0 for name in CASE_SETS}
    for suite in manifest.get("suites", {}).values():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            meta_path = runs / str(entry["case_dir"]) / "case_meta.json"
            meta = load_json(meta_path)
            for case_set in CASE_SETS:
                if include_case_in_set(meta, case_set):
                    counts[case_set] += 1
    return counts


def count_metric_eligibility(root: Path = ROOT) -> dict[str, Any]:
    runs = root / "runs"
    manifest = load_json(runs / "manifest.json")
    eligible = 0
    diagnostic = 0
    inconsistent: list[str] = []
    for suite in manifest.get("suites", {}).values():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            case_dir = str(entry["case_dir"])
            meta = load_json(runs / case_dir / "case_meta.json")
            runtime = meta.get("boundary_runtime_contract")
            runtime_eligible = not (
                isinstance(runtime, dict) and runtime.get("metric_eligible") is False
            )
            excluded = bool(meta.get("attack_success_metric_excluded"))
            formal = (
                meta.get("oracle_strength") == "hard_trace_oracle"
                and bool(meta.get("main_table_eligible"))
                and not excluded
                and runtime_eligible
            )
            eligible += int(formal)
            diagnostic += int(excluded)
            if excluded:
                if (
                    meta.get("main_table_eligible") is not False
                    or runtime_eligible
                    or not isinstance(runtime, dict)
                    or runtime.get("status") != "diagnostic_pending_session_provenance"
                ):
                    inconsistent.append(case_dir)
            elif not formal:
                inconsistent.append(case_dir)
    return {
        "formal_metric_eligible": eligible,
        "diagnostic": diagnostic,
        "inconsistent": inconsistent,
    }


def command_version(command: str) -> dict[str, Any]:
    executable = shutil.which(command)
    if not executable:
        return {"available": False, "version": "", "error": "not found"}
    suffix = Path(executable).suffix.lower()
    if suffix in {".bat", ".cmd"}:
        args = [os.environ.get("COMSPEC", "cmd.exe"), "/c", executable, "--version"]
    else:
        args = [executable, "--version"]
    try:
        proc = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        return {"available": False, "version": "", "error": "not found"}
    except subprocess.TimeoutExpired:
        return {"available": False, "version": "", "error": "version command timed out"}
    except OSError as exc:
        return {"available": False, "version": "", "error": str(exc)}

    output = (proc.stdout or proc.stderr or "").strip()
    return {
        "available": proc.returncode == 0,
        "version": output.splitlines()[0] if output else "",
        "error": "" if proc.returncode == 0 else output,
    }


def api_keys_file(root: Path = ROOT, environ: dict[str, str] | None = None) -> Path:
    env = environ if environ is not None else os.environ
    override = env.get("SAFETY_BENCH_API_KEYS_FILE", "").strip()
    if override:
        path = Path(override)
        return path if path.is_absolute() else root / path
    return root / "bench_state" / "secrets" / "api_keys.json"


def load_api_keys(root: Path = ROOT, environ: dict[str, str] | None = None) -> tuple[Path, dict[str, Any]]:
    path = api_keys_file(root, environ)
    if not path.is_file():
        return path, {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return path, {}
    return path, data if isinstance(data, dict) else {}


def json_path_value(data: dict[str, Any], dotted: str) -> str:
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return ""
        cur = cur[part]
    return cur.strip() if isinstance(cur, str) else ""


def api_key_value(root: Path, environ: dict[str, str], keys: list[str]) -> tuple[str, str]:
    path, data = load_api_keys(root, environ)
    for key in keys:
        value = json_path_value(data, key)
        if value:
            source = f"{path}:{key}"
            try:
                source = f"{path.relative_to(root).as_posix()}:{key}"
            except ValueError:
                pass
            return value, source
    return "", ""


def dashscope_credential(root: Path = ROOT, environ: dict[str, str] | None = None) -> dict[str, Any]:
    env = environ if environ is not None else os.environ
    api_value, api_source = api_key_value(
        root,
        env,
        [
            "providers.dashscope.coding_api_key",
            "providers.dashscope.api_key",
            "dashscope.coding_api_key",
            "dashscope.api_key",
            "dashscope_coding_api_key",
            "DASHSCOPE_CODING_API_KEY",
            "env.DASHSCOPE_CODING_API_KEY",
        ],
    )
    if api_value:
        return {
            "available": True,
            "source": api_source,
            "openai_api_key_ignored": bool(env.get("OPENAI_API_KEY")),
        }
    secret_path = root / "bench_state" / "secrets" / "codex" / "api_key.txt"
    if secret_path.is_file() and secret_path.read_text(encoding="utf-8-sig").strip():
        return {
            "available": True,
            "source": "bench_state/secrets/codex/api_key.txt",
            "openai_api_key_ignored": bool(env.get("OPENAI_API_KEY")),
        }
    if env.get("DASHSCOPE_CODING_API_KEY", "").strip():
        return {
            "available": True,
            "source": "DASHSCOPE_CODING_API_KEY",
            "openai_api_key_ignored": bool(env.get("OPENAI_API_KEY")),
        }
    return {
        "available": False,
        "source": "",
        "openai_api_key_ignored": bool(env.get("OPENAI_API_KEY")),
    }


def claude_runtime_auth(root: Path = ROOT, environ: dict[str, str] | None = None) -> dict[str, Any]:
    env = environ if environ is not None else os.environ
    sources: list[str] = []
    for name in [
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "KIMI_API_KEY",
        "MOONSHOT_API_KEY",
    ]:
        if env.get(name, "").strip():
            sources.append(name)
    api_value, api_source = api_key_value(
        root,
        env,
        [
            "providers.kimi.anthropic_api_key",
            "providers.kimi.api_key",
            "providers.moonshot.api_key",
            "kimi.anthropic_api_key",
            "kimi.api_key",
            "moonshot.api_key",
            "kimi_api_key",
            "moonshot_api_key",
            "env.ANTHROPIC_API_KEY",
            "env.KIMI_API_KEY",
            "env.MOONSHOT_API_KEY",
            "ANTHROPIC_API_KEY",
            "KIMI_API_KEY",
            "MOONSHOT_API_KEY",
        ],
    )
    if api_value:
        sources.append(api_source)
    for rel in [
        "bench_state/secrets/claude/kimi_api_key.txt",
        "bench_state/secrets/claude/moonshot_api_key.txt",
        "bench_state/secrets/claude/anthropic_api_key.txt",
        "bench_state/secrets/claude/api_key.txt",
    ]:
        secret_path = root / rel
        if secret_path.is_file() and secret_path.read_text(encoding="utf-8-sig").strip():
            sources.append(rel)
    local_settings = root / "bench_state" / "secrets" / "claude" / "settings.json"
    if local_settings.is_file():
        sources.append("bench_state/secrets/claude/settings.json")
    return {"available": bool(sources), "sources": list(dict.fromkeys(sources))}


def runner_files(root: Path = ROOT) -> dict[str, bool]:
    return {rel: (root / rel).is_file() for rel in REQUIRED_RUNNERS}


def local_proxy_readiness(
    environ: dict[str, str] | None = None,
    *,
    target_host: str = "",
    connect: Any = socket.create_connection,
) -> dict[str, Any]:
    """Fail closed when the configured HTTPS proxy is a dead loopback socket.

    Remote proxies and direct connections are not actively probed here.  A
    loopback proxy is deterministic and safe to test without sending any
    benchmark traffic or credential.
    """

    env = environ if environ is not None else os.environ
    no_proxy = [
        item.strip().split(":", 1)[0].casefold()
        for item in str(env.get("NO_PROXY") or env.get("no_proxy") or "").split(",")
        if item.strip()
    ]
    target = target_host.strip().casefold()
    bypassed = bool(
        target
        and any(
            item == "*"
            or target == item.lstrip(".")
            or (item.startswith(".") and target.endswith(item))
            for item in no_proxy
        )
    )
    source = next(
        (
            name
            for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy")
            if str(env.get(name) or "").strip()
        ),
        "",
    )
    if not source:
        return {
            "configured": False,
            "source": "",
            "loopback": False,
            "host": "",
            "port": 0,
            "listening": None,
            "ready": True,
            "bypassed_for_target": bypassed,
            "error": "",
        }
    raw = str(env.get(source) or "").strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = str(parsed.hostname or "")
    port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    loopback = host.casefold() in {"127.0.0.1", "localhost", "::1"}
    if bypassed:
        return {
            "configured": True,
            "source": source,
            "loopback": loopback,
            "host": host,
            "port": port,
            "listening": None,
            "ready": True,
            "bypassed_for_target": True,
            "error": "configured proxy is bypassed for the runtime endpoint",
        }
    if not loopback:
        return {
            "configured": True,
            "source": source,
            "loopback": False,
            "host": host,
            "port": port,
            "listening": None,
            "ready": True,
            "bypassed_for_target": False,
            "error": "remote proxy is not actively probed by static readiness",
        }
    try:
        sock = connect((host, port), timeout=0.5)
    except OSError as exc:
        return {
            "configured": True,
            "source": source,
            "loopback": True,
            "host": host,
            "port": port,
            "listening": False,
            "ready": False,
            "bypassed_for_target": False,
            "error": type(exc).__name__,
        }
    try:
        sock.close()
    finally:
        pass
    return {
        "configured": True,
        "source": source,
        "loopback": True,
        "host": host,
        "port": port,
        "listening": True,
        "ready": True,
        "bypassed_for_target": False,
        "error": "",
    }


def claude_runtime_endpoint_host(
    root: Path = ROOT,
    environ: dict[str, str] | None = None,
) -> str:
    env = environ if environ is not None else os.environ
    for name in ("ANTHROPIC_BASE_URL", "KIMI_BASE_URL", "MOONSHOT_BASE_URL"):
        value = str(env.get(name) or "").strip()
        if value:
            return str(urlparse(value).hostname or "")
    _, data = load_api_keys(root, env)
    for key in (
        "providers.kimi.base_url",
        "providers.moonshot.base_url",
        "kimi.base_url",
        "moonshot.base_url",
    ):
        value = json_path_value(data, key)
        if value:
            return str(urlparse(value).hostname or "")
    return ""


def build_readiness(
    require_kimi: bool = True,
    root: Path = ROOT,
    require_codex_kimi: bool = False,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = environ if environ is not None else os.environ
    integrity_problems = validate_active_cases(root)
    counts = count_case_sets(root)
    metric_eligibility = count_metric_eligibility(root)
    tools = {
        "claude": command_version("claude"),
        "codex": command_version("codex"),
    }
    credentials = {
        "dashscope_kimi": dashscope_credential(root, env),
        "claude_runtime_auth": claude_runtime_auth(root, env),
    }
    network = {
        "runtime_endpoint_host": claude_runtime_endpoint_host(root, env),
    }
    network["configured_proxy"] = local_proxy_readiness(
        env,
        target_host=network["runtime_endpoint_host"],
    )
    runners = runner_files(root)

    blockers: list[str] = []
    warnings: list[str] = []
    if integrity_problems:
        blockers.append(f"active case integrity has {len(integrity_problems)} problem(s)")
    if counts.get("core") != ACTIVE_CASE_COUNT or counts.get("all") != ACTIVE_CASE_COUNT:
        blockers.append(
            f"unexpected case counts: core={counts.get('core')} all={counts.get('all')}"
        )
    if (
        metric_eligibility["formal_metric_eligible"] != FORMAL_METRIC_CASE_COUNT
        or metric_eligibility["diagnostic"] != DIAGNOSTIC_CASE_COUNT
        or metric_eligibility["inconsistent"]
    ):
        blockers.append(
            "unexpected formal eligibility split: "
            f"eligible={metric_eligibility['formal_metric_eligible']} "
            f"diagnostic={metric_eligibility['diagnostic']} "
            f"inconsistent={len(metric_eligibility['inconsistent'])}"
        )
    for rel, exists in runners.items():
        if not exists:
            blockers.append(f"missing runner file: {rel}")
    if not tools["claude"]["available"]:
        blockers.append("claude CLI is unavailable")
    if require_codex_kimi and not tools["codex"]["available"]:
        blockers.append("codex CLI is unavailable")
    if require_codex_kimi and not credentials["dashscope_kimi"]["available"]:
        blockers.append(
            "Codex Kimi K2.6 path is requested but no DashScope coding key is configured"
        )
    if require_codex_kimi and credentials["dashscope_kimi"]["openai_api_key_ignored"]:
        warnings.append("OPENAI_API_KEY is present but ignored for the Kimi/DashScope baseline")
    if require_kimi and not credentials["claude_runtime_auth"]["available"]:
        blockers.append("Claude + Kimi runtime auth source is required but was not detected")
    elif not credentials["claude_runtime_auth"]["available"]:
        warnings.append("Claude auth source was not detected by static readiness checks")
    if require_kimi and network["configured_proxy"]["ready"] is not True:
        proxy = network["configured_proxy"]
        blockers.append(
            "configured local proxy is not listening: "
            f"{proxy['source']}={proxy['host']}:{proxy['port']}"
        )

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "baseline": {
            "name": "claude_code_kimi_k2.6",
            "harness": "claude",
            "model": "kimi-k2.6",
            "model_source": "Claude Code runtime default",
            "codex_in_current_scope": bool(require_codex_kimi),
        },
        "ready": not blockers,
        "require_kimi": bool(require_kimi),
        "require_codex_kimi": bool(require_codex_kimi),
        "case_counts": counts,
        "metric_eligibility": metric_eligibility,
        "integrity": {
            "ok": not integrity_problems,
            "problem_count": len(integrity_problems),
            "problems_preview": integrity_problems[:20],
        },
        "tools": tools,
        "credentials": credentials,
        "network": network,
        "runners": runners,
        "blockers": blockers,
        "warnings": warnings,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Readiness Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- ready: `{str(report['ready']).lower()}`",
        f"- root: `{report['root']}`",
        f"- baseline: `{report.get('baseline', {}).get('name', 'claude_code_kimi_k2.6')}`",
        f"- baseline_model_source: `{report.get('baseline', {}).get('model_source', 'Claude Code runtime default')}`",
        f"- require_codex_kimi: `{str(report.get('require_codex_kimi', False)).lower()}`",
        f"- runnable_coverage_cases: `{report.get('case_counts', {}).get('all', 0)}`",
        f"- formal_metric_cases: `{report.get('metric_eligibility', {}).get('formal_metric_eligible', 0)}`",
        f"- diagnostic_cases: `{report.get('metric_eligibility', {}).get('diagnostic', 0)}`",
        "",
        "## Case Counts",
        "",
        "| Set | Count |",
        "| --- | ---: |",
    ]
    for name in CASE_SETS:
        lines.append(f"| {name} | {report['case_counts'].get(name, 0)} |")

    lines += [
        "",
        "## Tools",
        "",
        "| Tool | Available | Version | Error |",
        "| --- | --- | --- | --- |",
    ]
    for name, tool in report["tools"].items():
        lines.append(
            f"| {name} | {str(tool['available']).lower()} | "
            f"{tool.get('version', '')} | {tool.get('error', '')} |"
        )

    dashscope = report["credentials"]["dashscope_kimi"]
    claude_auth = report["credentials"]["claude_runtime_auth"]
    lines += [
        "",
        "## Credentials",
        "",
        f"- dashscope_kimi_optional_codex_path: available=`{str(dashscope['available']).lower()}`, source=`{dashscope['source'] or 'n/a'}`",
        f"- OPENAI_API_KEY ignored for optional Codex/DashScope path: `{str(dashscope['openai_api_key_ignored']).lower()}`",
        f"- claude_runtime_auth: available=`{str(claude_auth['available']).lower()}`, sources=`{', '.join(claude_auth['sources']) or 'n/a'}`",
        f"- configured_proxy_ready: `{str(report.get('network', {}).get('configured_proxy', {}).get('ready')).lower()}`",
        f"- configured_proxy_source: `{report.get('network', {}).get('configured_proxy', {}).get('source') or 'n/a'}`",
        "",
        "## Runners",
        "",
        "| File | Exists |",
        "| --- | --- |",
    ]
    for rel, exists in report["runners"].items():
        lines.append(f"| {rel} | {str(exists).lower()} |")

    lines += ["", "## Blockers", ""]
    if report["blockers"]:
        lines.extend(f"- {item}" for item in report["blockers"])
    else:
        lines.append("- none")

    lines += ["", "## Warnings", ""]
    if report["warnings"]:
        lines.extend(f"- {item}" for item in report["warnings"])
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper experiment readiness.")
    parser.add_argument(
        "--no-require-kimi",
        action="store_true",
        help="Legacy compatibility flag; the current default Kimi baseline is Claude Code runtime configured and does not require DashScope.",
    )
    parser.add_argument(
        "--require-codex-kimi",
        action="store_true",
        help="Also require the optional Codex/DashScope Kimi path. Not used for the current Claude Code + Kimi K2.6 baseline.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--json-out", default="", help="optional path to write the JSON report")
    args = parser.parse_args()

    report = build_readiness(
        require_kimi=not args.no_require_kimi,
        require_codex_kimi=args.require_codex_kimi,
    )
    if args.json_out:
        path = Path(args.json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_markdown(report))
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
