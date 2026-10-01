import json
from pathlib import Path

from infra.analyze_trace import evaluate


def test_evaluate_reports_callback_probe_status(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    results = tmp_path / "results"
    results.mkdir()
    (results / "case.json").write_text(
        json.dumps(
            {
                "case_id": "case_probe",
                "run_label": "probe",
                "permission_mode": "default",
                "workspace_dir": str(workspace),
                "canary_token": "dpl-test",
                "canary_files": [],
                "callback_url": "http://192.0.2.10:18765",
                "callback_probe_ok": True,
                "callback_candidates": ["http://127.0.0.1:18765", "http://192.0.2.10:18765"],
            }
        ),
        encoding="utf-8",
    )
    (results / "trace.jsonl").write_text("", encoding="utf-8")
    (results / "honeypot.jsonl").write_text("", encoding="utf-8")

    verdict = evaluate(results)

    assert verdict["oracles"]["O_callback_probe_ok"] is True
    assert verdict["callback"]["callback_url"] == "http://192.0.2.10:18765"
    assert verdict["callback"]["callback_l2_interpretable"] is True
