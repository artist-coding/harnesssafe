import json
import subprocess
import sys
from pathlib import Path
import pytest
from harnesssafe.common import ROOT, ExperimentError, case_catalog, write_json
from harnesssafe.config import validate_config, select_cases
from harnesssafe.engine import create_plan, load_plan, run_plan, read_rows, normalize_native, experiment_lock
from harnesssafe.reporting import make_report, compare_experiments, shared_support, summarize
from harnesssafe.runtime import command_for

@pytest.fixture
def project(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("")
    suites = {}
    for suite, name in [("F1_memory_runtime", "a"), ("v2_skill_runtime", "b")]:
        directory = f"active/{suite}/{name}"
        suites[suite] = {"status": "active", "cases": [{"case_dir": directory, "attack_id": "test", "variant": name}]}
        write_json(root / "runs" / directory / "case_meta.json",
                   {"case_id": name, "main_table_eligible": True, "checkpoint_contract": {"test": True}})
    write_json(root / "runs/manifest.json", {"suites": suites})
    cfg = {"name": "baseline", "harness": "codex", "model": "fixture-model",
           "executable": "fake-cli", "expected_version": "fake 1.0", "permission_profile": "default_permission"}
    config = tmp_path / "config.json"
    write_json(config, cfg)
    return root, config, cfg

def runtime(cfg, root):
    return {"executable": "fake-cli", "powershell": "fake-pwsh", "cli_version": cfg["expected_version"]}

def fake_execute(args, cfg, exe, log, root):
    raw = Path(args[args.index("-ResultsRoot") + 1]) / "native-run"
    raw.mkdir()
    (raw / "trace.jsonl").write_text('{"synthetic": true}\n')
    return 0

def fake_normalize(case, job, cfg, raw, code, root):
    from harnesssafe.engine import empty_row
    row = empty_row(case, job)
    row.update(execution_outcome="scored", evaluation_eligible=True, progress_node="N1",
               attack_success=False, css=80, exclusion_reasons=[])
    return row

def execute(plan, root, **kwargs):
    return run_plan(plan, root=root, inspect_runtime=runtime, execute=fake_execute, normalize=fake_normalize, **kwargs)

def test_real_frozen_catalog_is_328_unique_cases_and_seven_smoke_cases():
    cases = case_catalog()
    assert len(cases) == len({c["case_id"] for c in cases}) == 328
    selected = select_cases(cases, {"suites": [], "case_ids": [], "smoke": True})
    assert len(selected) == len({c["family"] for c in selected}) == 7

def test_offline_plan_report_resume_and_complete_inventory(project, tmp_path):
    root, config, _ = project
    folder = tmp_path / "experiment"
    plan = create_plan(config, folder, root)
    assert len(plan["jobs"]) == 2
    assert make_report(folder)["summaries"]["attack"]["asr"] is None
    first = execute(folder, root, limit=1)
    assert first["launched"] == 1
    summary = make_report(folder)["summaries"]["attack"]
    assert summary["inventory_trials"] == 2
    assert summary["eligible_trials"] == 1
    assert summary["coverage"] == 0.5
    with pytest.raises(ExperimentError, match="resume"):
        execute(folder, root)
    assert execute(folder, root, resume=True)["launched"] == 1
    assert execute(folder, root, resume=True)["launched"] == 0
    assert make_report(folder)["summaries"]["attack"]["eligible_trials"] == 2
    assert (folder / "results.csv").exists()
    assert not list((root / "runs").rglob("results"))

def test_failure_and_interruption_are_retained_never_counted_as_safe(project, tmp_path):
    root, config, _ = project
    folder = tmp_path / "experiment"
    plan = create_plan(config, folder, root)
    def fail(*args):
        raise OSError("simulated launch failure")
    run_plan(folder, root=root, inspect_runtime=runtime, execute=fail, normalize=fake_normalize)
    rows = read_rows(plan, folder)
    assert all(not r["evaluation_eligible"] and r["progress_node"] is None for r in rows)
    assert summarize(rows)["asr"] is None
    assert execute(folder, root, resume=True)["launched"] == 0

def test_crashed_started_job_is_not_repeated(project, tmp_path):
    root, config, _ = project
    folder = tmp_path / "experiment"
    plan = create_plan(config, folder, root)
    write_json(folder / "jobs" / plan["jobs"][0]["job_id"] / "started.json", {"synthetic_crash": True})
    assert execute(folder, root, resume=True)["launched"] == 1
    rows = read_rows(plan, folder)
    assert rows[0]["execution_outcome"] == "interrupted"
    assert rows[1]["evaluation_eligible"]

def test_benchmark_mutation_stops_execution(project, tmp_path):
    root, config, _ = project
    folder = tmp_path / "experiment"
    create_plan(config, folder, root)
    (root / "runs/active/F1_memory_runtime/a/new-file.txt").write_text("drift")
    with pytest.raises(ExperimentError, match="changed after planning"):
        execute(folder, root)
    assert not (folder / "environment.json").exists()

def test_plan_edit_and_evidence_edit_are_detected(project, tmp_path):
    root, config, _ = project
    folder = tmp_path / "experiment"
    plan = create_plan(config, folder, root)
    execute(folder, root)
    trace = next((folder / "jobs").rglob("trace.jsonl"))
    trace.write_text("changed")
    with pytest.raises(ExperimentError, match="Evidence changed"):
        make_report(folder)
    plan["config"]["model"] = "edited"
    write_json(folder / "plan.json", plan)
    with pytest.raises(ExperimentError, match="Plan integrity"):
        load_plan(folder)

def test_cli_update_mid_batch_stops_remaining_jobs(project, tmp_path):
    root, config, _ = project
    folder = tmp_path / "experiment"
    create_plan(config, folder, root)
    counter = 0
    def changing_runtime(cfg, root):
        nonlocal counter
        counter += 1
        return {**runtime(cfg, root), "cli_version": "v1" if counter < 3 else "v2"}
    with pytest.raises(ExperimentError, match="changed during"):
        run_plan(folder, root=root, inspect_runtime=changing_runtime, execute=fake_execute, normalize=fake_normalize)
    assert len(list((folder / "jobs").glob("*/receipt.json"))) == 1

def test_native_adapter_results_are_evaluated_by_existing_v3_contract(project, tmp_path):
    root, _, cfg = project
    case = case_catalog(root)[0]
    meta_path = root / "runs" / case["case_dir"] / "case_meta.json"
    # This mirrors the legacy valid-run contract accepted by Evaluation Record v3.
    meta = {"case_id": "a", "main_table_eligible": True}
    write_json(meta_path, meta)
    raw = tmp_path / "native"
    write_json(raw / "case.json", {**meta, "harness": "codex", "model": "fixture-model"})
    write_json(raw / "codex_exit.json", {"exit_code": 0, "timed_out": False})
    write_json(raw / "run_validity.json", {"schema_version": 1, "valid": True, "status": "completed"})
    write_json(raw / "oracle.json", {"oracles": {}, "evaluation": {
        "progress_node": "N1", "verdict": "EXPOSED", "progress_score": 20, "attack_success": False}})
    job = {"job_id": "unit", "arm": "attack", "trial": 1}
    row = normalize_native(case, job, validate_config(cfg), raw, 0, root)
    assert row["native_evaluation_record"]["schema_version"] == 3
    assert row["evaluation_eligible"]
    assert row["progress_node"] == "N1" and row["css"] == 80
    failed = normalize_native(case, job, validate_config(cfg), raw, 1, root)
    assert not failed["evaluation_eligible"] and failed["css"] is None

def test_controls_repeats_and_argument_boundaries(project, tmp_path):
    root, config, cfg = project
    cfg.update(arms=["attack", "clean_control"], repeats=2, model="model name")
    write_json(config, cfg)
    plan = create_plan(config, tmp_path / "experiment", root)
    assert len(plan["jobs"]) == 8
    control = next(j for j in plan["jobs"] if j["arm"] == "clean_control")
    args = command_for(plan["config"], plan["cases"][0], control, tmp_path / "path with spaces",
                       "label", root, "powershell with spaces.exe")
    assert args[0] == "powershell with spaces.exe"
    assert args[args.index("-Model") + 1] == "model name"
    assert args[args.index("-ControlType") + 1] == "clean_control"
    assert "-DangerouslySkipPermissions" not in args
    assert args[args.index("-PermissionProfile") + 1] == "default_permission"

def test_compare_freezes_membership_and_rejects_protocol_drift(project, tmp_path):
    root, config, cfg = project
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    create_plan(config, baseline, root)
    execute(baseline, root)
    cfg.update(name="candidate", expected_version="fake 2.0")
    write_json(config, cfg)
    create_plan(config, candidate, root)
    execute(candidate, root, limit=1)
    comparison = compare_experiments(baseline, candidate, tmp_path / "comparison")
    assert comparison["common_support"]["case_count"] == 1
    assert comparison["common_support"]["membership"][0]["case_id"] == "a"
    assert comparison["delta"]["css_standardized"] is None
    assert comparison["candidate_inventory"]["coverage"] == .5
    cfg["permission_profile"] = "max_permission"
    write_json(config, cfg)
    other = tmp_path / "different-permission"
    create_plan(config, other, root)
    with pytest.raises(ExperimentError, match="permission_profile"):
        compare_experiments(baseline, other, tmp_path / "bad")

def test_standardization_uses_fixed_family_weights_and_exact_common_trials():
    def row(case, family, node, ok=True):
        return {"case_id": case, "family": family, "trial": 1, "evaluation_eligible": ok,
                "progress_node": node, "execution_outcome": "scored" if ok else "execution_invalid"}
    a = [row("a", "F1", "N0"), row("b", "F2", "N5b"), row("c", "F1", "N0")]
    b = [row("a", "F1", "N1"), row("b", "F2", "N4"), row("c", "F1", None, False)]
    result = shared_support({"old": a, "new": b}, {"F1": 3, "F2": 1})
    assert result["trial_count"] == 2
    assert result["scores"]["old"]["css_standardized"] == 75
    assert result["scores"]["new"]["css_standardized"] == 65
    assert result["scores"]["old"]["asr"] == .5
    assert result["scores"]["new"]["asr"] == 0

@pytest.mark.parametrize("field,value", [
    ("timeout_seconds", True), ("repeats", 0), ("selection", {"case_ids": ["a", "a"]}),
    ("provider", {"api_key": "never-store-a-key"}), ("provider", {"claude_base_url": "https://user:password@example.invalid"}),
    ("arms", ["unknown"]), ("unknown_flag", "value"),
])
def test_invalid_or_secret_bearing_configs_are_rejected(project, field, value):
    _, _, cfg = project
    with pytest.raises(ExperimentError):
        validate_config({**cfg, field: value})

def test_execution_lock_prevents_concurrent_runs(tmp_path):
    with experiment_lock(tmp_path / "lock"):
        with pytest.raises(ExperimentError, match="execution lock"):
            with experiment_lock(tmp_path / "lock"):
                pass

def test_cli_help_is_available_without_harness_or_credentials():
    result = subprocess.run([sys.executable, "-m", "harnesssafe", "--help"], cwd=ROOT,
                            text=True, capture_output=True)
    assert result.returncode == 0
    assert "compare" in result.stdout and "plan" in result.stdout


def test_dependency_versions_must_satisfy_frozen_requirements(tmp_path):
    from harnesssafe.runtime import validate_dependency_versions
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("pandas>=2,<3\nJinja2>=3.1,<4\n")
    validate_dependency_versions({"pandas": "2.3.3", "Jinja2": "3.1.6"}, requirements)
    with pytest.raises(ExperimentError, match="Dependency mismatch"):
        validate_dependency_versions({"pandas": "3.0.1", "Jinja2": "3.1.6"}, requirements)
    with pytest.raises(ExperimentError, match="Dependency mismatch"):
        validate_dependency_versions({"pandas": "2.3.3", "Jinja2": "3.0.0"}, requirements)


def test_long_path_evidence_can_be_hashed_and_read(tmp_path):
    from harnesssafe.common import write_json, read_json, file_hash
    path = tmp_path / ("long" * 40) / ("deep" * 30) / "evidence.json"
    write_json(path, {"ok": True})
    assert read_json(path) == {"ok": True}
    assert len(file_hash(path)) == 64
