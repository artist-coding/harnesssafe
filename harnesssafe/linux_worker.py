"""One native Linux job, with a durable evidence snapshot and explicit score status.

Temporary native paths are retained: original attestations refer to them. Reports
verify the copied regular-file evidence, never depend on those temporary paths.
"""
from __future__ import annotations
import argparse
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from .common import ExperimentError, file_hash, read_json, write_json
from .config import validate_config
from .engine import empty_row

def snapshot_tree(source: Path, target: Path) -> None:
    """Do not follow fixture/user symlinks or copy live sockets."""
    for directory, dirs, files in os.walk(source, followlinks=False):
        current = Path(directory)
        dirs[:] = [name for name in dirs if not (current / name).is_symlink()]
        for name in files:
            path = current / name
            if path.is_symlink() or not path.is_file():
                continue
            dest = target / path.relative_to(source)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)

def capture_row(request: dict, outcome: dict) -> dict:
    case, job = request["case"], request["job"]
    if outcome.get("case_id") != case["case_id"]:
        raise ExperimentError("Native outcome case identity mismatch")
    status = outcome.get("attack_status", outcome.get("outcome", "MISSING"))
    completed = status in {"ATTACK_COMPLETED", "COMPLETED"}
    failure = status in {"FAILED", "EXECUTION_INVALID", "MISSING"}
    execution = "capture_complete_unscored" if completed else "execution_invalid" if failure else "model_protocol_incomplete" if status == "MODEL_PROTOCOL_INCOMPLETE" else "not_experimentable"
    row = empty_row(case, job, execution, "native_scoring_not_produced" if completed else "native_status:" + status)
    row.update(native_status=status, scoring_status="NOT_PRODUCED",
               native_stage_count_completed=outcome.get("stage_count_completed"),
               native_stage_count_total=outcome.get("stage_count_total"))
    return row

def validate_gemini_evidence(case_root: Path, outcome: dict) -> None:
    stages = outcome.get("stages", [])
    count = outcome.get("stage_count_total")
    if type(count) is not int or count < 1 or outcome.get("stage_count_completed") != count or len(stages) != count:
        raise ExperimentError("Gemini completion lacks complete stage evidence")
    for stage in stages:
        if stage.get("process_exit_code") != 0 or stage.get("event_ir_schema_valid") is not True:
            raise ExperimentError("Gemini stage did not complete successfully")
        event_path = Path(stage["event_ir_path"])
        if not event_path.resolve().is_relative_to(case_root.resolve()):
            raise ExperimentError("Gemini event evidence escaped the native case root")
        for path, expected in ((event_path, stage["event_ir_sha256"]),
                               (event_path.with_name("gemini-stream.jsonl"), stage["raw_stream_sha256"])):
            if file_hash(path) != expected:
                raise ExperimentError("Gemini raw evidence hash mismatch")

def score_gemini(request: dict, case_root: Path, outcome: dict, work: Path) -> dict:
    from infra.cross_harness.adapters.gemini.score_attack_only_results import _prepare_one_case
    from infra.analyze_trace import reanalyze_results_tree
    from .engine import normalize_native
    root, cfg = Path(request["root"]), request["config"]
    canonical = root / "runs" / request["case"]["case_dir"] / "case_meta.json"
    if file_hash(canonical) != outcome.get("case_meta_sha256"):
        raise ExperimentError("Gemini canonical case identity/hash mismatch")
    validate_gemini_evidence(case_root, outcome)
    prepared = _prepare_one_case(source_case_root=case_root, output_cases_root=work / "derived",
                                 label="managed", require_completed=True)
    run = Path(prepared["run_dir"])
    # The legacy scorer uses paper-time model/trial labels. Replace metadata
    # before analysis, never replace trace events or eligibility decisions.
    for path in [run / "case.json", *sorted((run / "stages").glob("*/case.json"))]:
        meta = read_json(path)
        meta.update(model=cfg["model"], secondary_model=cfg["model"],
                    harness_version=cfg["expected_version"], trial_index=request["job"]["trial"],
                    permission_profile=cfg["permission_profile"])
        write_json(path, meta)
    reanalyze_results_tree(run)
    row = normalize_native(request["case"], request["job"], cfg, run, 0, root, use_linux_bridge=False)
    row["scoring_bridge"] = "inherited_gemini_event_ir_to_shared_analyzer"
    row["scoring_status"] = "FORMAL_V3" if row["evaluation_eligible"] else "ANALYZED_INELIGIBLE"
    return row

def execute_native(request: dict, work: Path) -> dict:
    cfg = dict(request["config"])
    cfg["executable"] = os.environ.get(cfg["harness"].upper() + "_BIN", cfg["executable"])
    request = {**request, "config": cfg}
    harness, provider, runtime = cfg["harness"], cfg["provider"], cfg["runtime"]
    root = Path(request["root"])
    case_id = request["case"]["case_id"]
    if harness == "gemini":
        from infra.cross_harness.adapters.gemini.attack_only_runner import execute_attack_batch
        execute_attack_batch(credential_file=None, repo_root=root, output_root=work,
            project=provider["project"], location=provider["location"],
            provider_kind=provider["provider_kind"], api_base_url=provider["api_base_url"],
            api_key_env=provider["api_key_env"], model=cfg["model"], executable=cfg["executable"],
            conformance_path=Path(runtime["conformance"]), case_ids=[case_id],
            timeout_seconds=cfg["timeout_seconds"], enable_honeypot=True)
    elif harness == "opencode":
        from infra.cross_harness.adapters.opencode.active_attack_runner import execute_active_batch
        execute_active_batch(repo_root=root, work_root=work, executable=cfg["executable"],
            provider_profile_path=Path(provider["profile"]), conformance_path=Path(runtime["conformance"]),
            environ=os.environ, case_ids=[case_id], timeout_seconds=cfg["timeout_seconds"])
    elif harness == "kimi":
        return execute_kimi(request, work)
    else:
        raise ExperimentError("Unknown Linux harness")
    paths = list((work / "cases").glob("*/attack-outcome.json"))
    if len(paths) != 1:
        raise ExperimentError("Native scheduler did not emit exactly one case outcome")
    outcome = read_json(paths[0])
    row = capture_row(request, outcome)
    if harness == "gemini" and outcome.get("attack_status") == "ATTACK_COMPLETED":
        row = score_gemini(request, paths[0].parent, outcome, work)
    return row

def execute_kimi(request: dict, work: Path) -> dict:
    from infra.cross_harness.adapters.kimi.cli import main
    cfg = request["config"]
    provider = cfg["provider"]
    # Secret bytes exist only in an anonymous FD; never in config/argv/evidence.
    credential = os.environ.pop(provider["credential_env"], "")
    if not credential:
        raise ExperimentError("Configured Kimi credential environment variable is empty")
    import fcntl
    descriptor = os.memfd_create("harnesssafe-credential", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(descriptor, credential.encode())
        del credential
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        args = ["--repo-root", request["root"], "--result-root", str(work),
                "run-case", request["case"]["case_id"], "--run-id", "m",
                "--execute", "--authorize-external-model-execution",
                "--provider-url", provider["provider_url"], "--provider-model", cfg["model"],
                "--credential-fd", str(descriptor), "--kimi-executable", cfg["executable"],
                "--timeout-seconds", str(cfg["timeout_seconds"])]
        endpoint = urlparse(provider["provider_url"])
        if endpoint.scheme == "https":
            args += ["--allowed-https-host", endpoint.hostname]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(args)
        (work / "native-stdout.json").write_text(output.getvalue(), encoding="utf-8")
        payload = json.loads(output.getvalue())
        results = payload.get("results", [])
        if len(results) != 1:
            raise ExperimentError(f"Kimi did not emit one case result (exit {code})")
        row = capture_row(request, results[0])
        row["native_returncode"] = code
        # Existing Kimi analyzer outputs remain diagnostic, never formal v3.
        row["scoring_status"] = "DIAGNOSTIC_ONLY"
        return row
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass  # Native credential supplier owns and may already close it.

def run_request(request: dict) -> int:
    request["config"] = validate_config(request["config"])
    if sys.platform != "linux":
        raise ExperimentError("This worker requires native Linux")
    raw = Path(request["raw_root"]) / "native"
    raw.mkdir(parents=True, exist_ok=False)
    # Short native roots preserve Kimi AF_UNIX headroom and satisfy /tmp gates.
    work = Path(tempfile.mkdtemp(prefix="hs-", dir="/tmp"))
    write_json(raw / "native-location.json", {"source_root": str(work), "retained": True})
    row = empty_row(request["case"], request["job"], "execution_invalid", "worker_failed")
    try:
        row = execute_native(request, work)
    except Exception as exc:
        row = empty_row(request["case"], request["job"], "execution_invalid",
                        "native_worker_error:" + type(exc).__name__)
    finally:
        snapshot_tree(work, raw / "evidence")
        write_json(raw / "managed-result.json", {"case_id": request["case"]["case_id"],
                   "job": request["job"], "row": row})
    return 1 if row["execution_outcome"] == "execution_invalid" else 0

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_request(read_json(args.request))

if __name__ == "__main__":
    raise SystemExit(main())
