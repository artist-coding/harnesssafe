import json
from pathlib import Path

from infra import check_paper_readiness


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_paper_readiness_counts_case_sets(tmp_path: Path):
    root = tmp_path / "bench"
    runs = root / "runs"
    _write_json(
        runs / "manifest.json",
        {
            "suites": {
                "active_suite": {
                    "status": "active",
                    "cases": [
                        {"case_dir": "active/core_case"},
                        {"case_dir": "active/extended_case"},
                        {"case_dir": "active/exploratory_case"},
                    ],
                },
                "inactive_suite": {
                    "status": "inactive",
                    "cases": [{"case_dir": "inactive/ignored"}],
                },
            }
        },
    )
    _write_json(
        runs / "active/core_case/case_meta.json",
        {"main_table_eligible": True, "reporting_track": "core_benchmark"},
    )
    _write_json(
        runs / "active/extended_case/case_meta.json",
        {"main_table_eligible": False, "reporting_track": "extended_benchmark"},
    )
    _write_json(
        runs / "active/exploratory_case/case_meta.json",
        {"main_table_eligible": False, "reporting_track": "exploratory_case_study"},
    )

    assert check_paper_readiness.count_case_sets(root) == {
        "all": 3,
        "core": 3,
        "extended": 1,
        "exploratory": 1,
    }


def test_core_is_a_compatibility_alias_for_all():
    metadata = {"main_table_eligible": False, "reporting_track": "extended_benchmark"}

    assert check_paper_readiness.include_case_in_set(metadata, "all")
    assert check_paper_readiness.include_case_in_set(metadata, "core")


def test_paper_readiness_counts_runnable_formal_and_diagnostic_separately(tmp_path: Path):
    root = tmp_path / "bench"
    runs = root / "runs"
    _write_json(
        runs / "manifest.json",
        {
            "suites": {
                "active_suite": {
                    "status": "active",
                    "cases": [
                        {"case_dir": "active/formal_case"},
                        {"case_dir": "active/diagnostic_case"},
                    ],
                }
            }
        },
    )
    _write_json(
        runs / "active/formal_case/case_meta.json",
        {
            "oracle_strength": "hard_trace_oracle",
            "main_table_eligible": True,
            "attack_success_metric_excluded": False,
        },
    )
    _write_json(
        runs / "active/diagnostic_case/case_meta.json",
        {
            "oracle_strength": "hard_trace_oracle",
            "main_table_eligible": False,
            "attack_success_metric_excluded": True,
            "boundary_runtime_contract": {
                "status": "diagnostic_pending_session_provenance",
                "metric_eligible": False,
            },
        },
    )

    assert check_paper_readiness.count_case_sets(root)["all"] == 2
    assert check_paper_readiness.count_metric_eligibility(root) == {
        "formal_metric_eligible": 1,
        "diagnostic": 1,
        "inconsistent": [],
    }


def test_optional_codex_dashscope_readiness_does_not_accept_openai_key(tmp_path: Path):
    root = tmp_path / "bench"

    report = check_paper_readiness.dashscope_credential(
        root,
        environ={"OPENAI_API_KEY": "not-a-dashscope-key"},
    )

    assert report["available"] is False
    assert report["source"] == ""
    assert report["openai_api_key_ignored"] is True


def test_optional_codex_dashscope_readiness_accepts_benchmark_secret_file(tmp_path: Path):
    root = tmp_path / "bench"
    secret = root / "bench_state/secrets/codex/api_key.txt"
    secret.parent.mkdir(parents=True)
    secret.write_text("dashscope-key", encoding="utf-8")

    report = check_paper_readiness.dashscope_credential(root, environ={})

    assert report["available"] is True
    assert report["source"] == "bench_state/secrets/codex/api_key.txt"


def test_optional_codex_dashscope_readiness_accepts_unified_api_keys_file(tmp_path: Path):
    root = tmp_path / "bench"
    api_keys = root / "bench_state/secrets/api_keys.json"
    _write_json(
        api_keys,
        {"providers": {"dashscope": {"coding_api_key": "dashscope-key"}}},
    )

    report = check_paper_readiness.dashscope_credential(root, environ={})

    assert report["available"] is True
    assert report["source"] == "bench_state/secrets/api_keys.json:providers.dashscope.coding_api_key"


def test_current_claude_kimi_readiness_accepts_unified_api_keys_file(tmp_path: Path):
    root = tmp_path / "bench"
    api_keys = root / "bench_state/secrets/api_keys.json"
    _write_json(
        api_keys,
        {
            "providers": {
                "kimi": {
                    "api_key": "kimi-key",
                    "base_url": "https://api.kimi.com/coding/",
                }
            }
        },
    )

    report = check_paper_readiness.claude_runtime_auth(root, environ={})

    assert report["available"] is True
    assert report["sources"] == [
        "bench_state/secrets/api_keys.json:providers.kimi.api_key"
    ]


def test_local_proxy_readiness_rejects_dead_loopback_proxy():
    def fail_connect(*_args, **_kwargs):
        raise ConnectionRefusedError("not listening")

    report = check_paper_readiness.local_proxy_readiness(
        {"HTTPS_PROXY": "http://127.0.0.1:10808"},
        connect=fail_connect,
    )

    assert report["loopback"] is True
    assert report["listening"] is False
    assert report["ready"] is False
    assert report["host"] == "127.0.0.1"
    assert report["port"] == 10808


def test_local_proxy_readiness_accepts_listening_loopback_proxy():
    class Socket:
        def close(self):
            pass

    report = check_paper_readiness.local_proxy_readiness(
        {"HTTPS_PROXY": "http://127.0.0.1:7897"},
        connect=lambda *_args, **_kwargs: Socket(),
    )

    assert report["listening"] is True
    assert report["ready"] is True


def test_local_proxy_readiness_accepts_no_proxy_runtime_endpoint():
    report = check_paper_readiness.local_proxy_readiness(
        {
            "HTTPS_PROXY": "http://127.0.0.1:10808",
            "NO_PROXY": ".kimi.com",
        },
        target_host="api.kimi.com",
        connect=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("bypassed proxy must not be contacted")
        ),
    )

    assert report["bypassed_for_target"] is True
    assert report["ready"] is True


def test_current_local_proxy_docs_use_configurable_port_and_unified_kimi_secret():
    docs = "\n".join(
        Path(path).read_text(encoding="utf-8-sig")
        for path in [
            "README.md",
            "RUNBOOK.md",
            "docs/run_and_evaluation_contract.md",
        ]
    )

    assert "Test-NetConnection 127.0.0.1 -Port $proxyPort" in docs
    assert 'http://127.0.0.1:$proxyPort' in docs
    assert "providers.kimi.api_key" in docs
    assert "http://127.0.0.1:7897" not in docs
    assert "http://127.0.0.1:10808" not in docs


def test_paper_readiness_requires_artifact_gate_runner():
    assert "infra/plan_control_smoke.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/run_control_smoke.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_artifact_gate.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_claims.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/run_paper_preflight.ps1" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/plan_paper_experiment_matrix.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_matrix_progress.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/export_paper_run_queue.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/run_paper_queue.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/estimate_paper_run_budget.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/report_paper_submission_gaps.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_live_status.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_numbers.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_case_studies.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_manuscript.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_benchmark_card.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_paper_appendix.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_oracle_coverage_report.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_threat_model_card.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_statistical_analysis.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_claim_evidence_map.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_control_integrity_report.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_paper_figures.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_bibliography.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/generate_submission_package_manifest.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_release_metadata.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_public_artifact_safety.py" in check_paper_readiness.REQUIRED_RUNNERS
    assert "infra/check_paper_suite_lock.py" in check_paper_readiness.REQUIRED_RUNNERS
