from __future__ import annotations
import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from .common import ROOT, ARMS, ExperimentError, case_catalog, write_json, read_json
from .config import load_config, validate_config
from .registry import ADAPTERS
from .engine import create_plan, run_plan
from .runtime import resolve_executable, runtime_snapshot, probe, adapter_environment
from .reporting import make_report, compare_experiments

def parser():
    p = argparse.ArgumentParser(prog="python -m harnesssafe", description="Frozen experiments over existing HarnessSafe adapters. Plan/report/test do not call a model.")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("adapters", help="Show platform, control and scoring support for all seven harnesses")
    cases = sub.add_parser("cases", help="List all frozen active cases")
    cases.add_argument("--suite")
    cases.add_argument("--json", action="store_true")
    init = sub.add_parser("init", help="Create a config pinned to an installed CLI (--version only)")
    init.add_argument("--harness", choices=list(ADAPTERS), required=True)
    init.add_argument("--model", required=True)
    init.add_argument("--name", required=True)
    init.add_argument("--executable")
    init.add_argument("--expected-version", help="Pin exact --version output without probing; useful for offline plans")
    init.add_argument("--provider-config", type=Path, help="Secret-free provider settings JSON")
    init.add_argument("--runtime-config", type=Path, help="Native runtime paths/conformance settings JSON")
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--smoke", action="store_true", help="Select one case per family")
    init.add_argument("--controls", action="store_true", help="Plan the attack and all four matched controls")
    init.add_argument("--repeats", type=int, default=1)
    init.add_argument("--permission-profile", choices=["default_permission", "max_permission", "adapter_default"])
    doctor = sub.add_parser("doctor", help="Check CLI identity, supported flags and dependencies; no model calls")
    doctor.add_argument("--config", type=Path, required=True)
    plan = sub.add_parser("plan", help="Freeze config, case selection, code and fixture hashes offline")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    run = sub.add_parser("run", help="Execute the frozen plan using the real CLI (may incur provider charges)")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--resume", action="store_true", help="Continue only untouched jobs; never rerun attempted trials")
    run.add_argument("--limit", type=int, help="Maximum new jobs this invocation")
    report = sub.add_parser("report", help="Verify evidence and generate JSON, CSV and Markdown offline")
    report.add_argument("--plan", type=Path, required=True)
    compare = sub.add_parser("compare", help="Compare experiments on saved common eligible support")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    compare.add_argument("--out", type=Path, required=True)
    compare.add_argument("--arm", choices=ARMS, default="attack")
    return p

def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "adapters":
            print(json.dumps(ADAPTERS, indent=2, ensure_ascii=False))
            return 0
        if args.command == "cases":
            cases = [c for c in case_catalog() if not args.suite or c["suite"] == args.suite]
            if not cases:
                raise ExperimentError("No cases match this suite")
            if args.json:
                print(json.dumps(cases, ensure_ascii=False, indent=2))
            else:
                for c in cases:
                    print(f"{c['family']:4} {c['case_id']}")
                print(f"{len(cases)} cases")
            return 0
        if args.command == "init":
            if args.output.exists():
                raise ExperimentError("Config already exists; choose a new filename")
            cfg = {"schema_version": 1, "name": args.name, "harness": args.harness, "model": args.model,
                   "executable": args.executable or args.harness, "expected_version": "probe-pending",
                   "permission_profile": args.permission_profile or ADAPTERS[args.harness]["profiles"][0], "selection": {"smoke": args.smoke},
                   "arms": list(ARMS) if args.controls else ["attack"], "repeats": args.repeats,
                   "provider": read_json(args.provider_config) if args.provider_config else {},
                   "runtime": read_json(args.runtime_config) if args.runtime_config else {}}
            # Resolve runtime/provider document paths against their source file.
            for section, source in (("provider", args.provider_config), ("runtime", args.runtime_config)):
                if source:
                    for key in ("profile", "conformance", "source_root", "python_executable", "git_bash", "node_executable"):
                        if key in cfg[section]:
                            value = Path(cfg[section][key]).expanduser()
                            if not value.is_absolute():
                                cfg[section][key] = str((source.resolve().parent / value).resolve())
            cfg = validate_config(cfg)
            if args.expected_version:
                cfg["expected_version"] = args.expected_version
            else:
                executable = resolve_executable(cfg)
                cfg["executable"] = str(executable)
                env = os.environ.copy()
                env.update(adapter_environment(cfg))
                if cfg["harness"] == "openclaw":
                    env["PATH"] = str(Path(cfg["runtime"]["node_executable"]).parent) + os.pathsep + env.get("PATH", "")
                cfg["expected_version"] = probe(executable, env=env)
            cfg = validate_config(cfg)
            write_json(args.output, cfg)
            result = {"config": str(args.output), "cli_version": cfg["expected_version"]}
        elif args.command == "doctor":
            result = runtime_snapshot(load_config(args.config))
        elif args.command == "plan":
            plan = create_plan(args.config, args.out)
            result = {"plan": str(args.out / "plan.json"), "cases": len(plan["cases"]),
                      "jobs": len(plan["jobs"]), "plan_sha256": plan["plan_sha256"]}
        elif args.command == "run":
            result = run_plan(args.plan, args.resume, args.limit)
            make_report(args.plan)
        elif args.command == "report":
            result = make_report(args.plan)["summaries"]
        else:
            comparison = compare_experiments(args.baseline, args.candidate, args.out, args.arm)
            result = {"output": str(args.out), "common_trials": comparison["common_support"]["trial_count"],
                      "delta": comparison["delta"], "transition_counts": comparison["transition_counts"]}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 3 if args.command == "run" and result.get("invalid_or_interrupted_jobs", 0) else 0
    except (ExperimentError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"HarnessSafe: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. Attempted trials are retained; --resume continues untouched jobs.", file=sys.stderr)
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
