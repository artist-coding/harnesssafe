from __future__ import annotations

import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from infra.cross_harness.adapters.kimi.callback_collector import (
    CALLBACK_SOCKET_BASENAME as COLLECTOR_SOCKET_BASENAME,
    callback_identity_digest,
    callback_root_name,
)
from infra.cross_harness.adapters.kimi.cli import build_parser
from infra.cross_harness.adapters.kimi.lifecycle import (
    CALLBACK_SOCKET_BASENAME,
    LINUX_AF_UNIX_PATH_LIMIT,
    PROVIDER_SOCKET_BASENAME,
    KimiLifecycleError,
    RunLayout,
    case_attempt_component,
    case_identity_digest,
    encoded_unix_socket_path_length,
    service_identity_digest,
)
from infra.cross_harness.adapters.kimi.isolated_launcher import (
    KimiBubblewrapLauncherError,
    LinuxBubblewrapLauncher,
)
from infra.cross_harness.adapters.kimi.provider_broker import (
    BROKER_SOCKET_BASENAME,
    broker_identity_digest,
    broker_root_name,
)
from infra.cross_harness.adapters.kimi.runner import ManifestInventory


REPO_ROOT = Path(__file__).resolve().parents[3]
RECOMMENDED_RESULT_ROOT = Path("/tmp/sb-kimi")
FORMAL_RUN_ID = "formal-20260721-kimi01"
TRIAL_ID = "attack-attempt-001"


def test_frozen_328_service_paths_fit_linux_af_unix_and_do_not_collide() -> None:
    inventory = tuple(ManifestInventory(REPO_ROOT).list_cases())
    assert len(inventory) == 328
    layout = RunLayout(REPO_ROOT, RECOMMENDED_RESULT_ROOT, FORMAL_RUN_ID)

    case_roots: set[Path] = set()
    case_digests: set[str] = set()
    provider_paths: set[Path] = set()
    callback_paths: set[Path] = set()
    for case in inventory:
        case_layout = layout.for_case(case.case_id, attempt=1)
        provider_path, callback_path = layout.production_service_paths(
            case_layout, trial_id=TRIAL_ID
        )

        digest = case_identity_digest(case.case_id)
        assert case_layout.case_digest == digest
        assert case_layout.root.name == case_attempt_component(
            case.case_id, attempt=1
        )
        assert case_layout.root.parent.name == f"kimi-{FORMAL_RUN_ID}"
        assert provider_path.parent.name == broker_root_name(
            FORMAL_RUN_ID, case.case_id, TRIAL_ID
        )
        assert callback_path.parent.name == callback_root_name(
            FORMAL_RUN_ID, case.case_id, TRIAL_ID
        )
        assert broker_identity_digest(
            FORMAL_RUN_ID, case.case_id, TRIAL_ID
        ) == service_identity_digest(FORMAL_RUN_ID, case.case_id, TRIAL_ID)
        assert callback_identity_digest(
            FORMAL_RUN_ID, case.case_id, TRIAL_ID
        ) == service_identity_digest(FORMAL_RUN_ID, case.case_id, TRIAL_ID)
        assert provider_path.name == PROVIDER_SOCKET_BASENAME
        assert provider_path.name == BROKER_SOCKET_BASENAME
        assert callback_path.name == CALLBACK_SOCKET_BASENAME
        assert callback_path.name == COLLECTOR_SOCKET_BASENAME
        assert encoded_unix_socket_path_length(provider_path) < LINUX_AF_UNIX_PATH_LIMIT
        assert encoded_unix_socket_path_length(callback_path) < LINUX_AF_UNIX_PATH_LIMIT

        case_roots.add(case_layout.root)
        case_digests.add(digest)
        provider_paths.add(provider_path)
        callback_paths.add(callback_path)

    assert len(case_roots) == len(case_digests) == 328
    assert len(provider_paths) == len(callback_paths) == 328


@pytest.mark.parametrize(
    ("result_root", "run_id"),
    (
        (Path("/tmp") / ("long-result-root-" + "x" * 80), FORMAL_RUN_ID),
        (RECOMMENDED_RESULT_ROOT, "r" * 80),
    ),
)
def test_production_service_paths_reject_overlong_root_or_run_id(
    result_root: Path, run_id: str
) -> None:
    case_id = "short-path-fixture-case"
    layout = RunLayout(REPO_ROOT, result_root, run_id)
    case_layout = layout.for_case(case_id)

    with pytest.raises(
        KimiLifecycleError,
        match=r"exceeds the Linux AF_UNIX pathname limit.*shorter --result-root or --run-id",
    ):
        layout.production_service_paths(case_layout, trial_id=TRIAL_ID)


def test_short_layout_initialization_is_private_and_symlink_free(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    layout = RunLayout(repo, tmp_path / "external", "private-001")
    case_layout = layout.for_case("case/private", attempt=2)

    layout.initialize_case(case_layout)

    assert case_layout.root.name.endswith("-a002")
    for path in (layout.result_root, layout.run_dir, case_layout.root):
        assert not path.is_symlink()
    assert stat.S_IMODE(layout.run_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(case_layout.root.stat().st_mode) == 0o700
    assert case_layout.root.stat().st_uid == os.geteuid()


def test_launcher_recomputes_case_root_identity_without_opening_a_socket(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    layout = RunLayout(repo, tmp_path / "external", "launcher-path-001")
    case_layout = layout.for_case("launcher-case")
    layout.initialize_case(case_layout)
    launcher = object.__new__(LinuxBubblewrapLauncher)
    launcher.run_id = layout.run_id
    launcher.ownership_root = case_layout.root
    launcher.callback_collector = SimpleNamespace(case_id=case_layout.case_id)

    assert launcher._validate_run_root(layout.run_id, case_layout.root) == case_layout.root

    launcher.callback_collector = SimpleNamespace(case_id="different-case")
    with pytest.raises(KimiBubblewrapLauncherError, match="direct kimi/run_id"):
        launcher._validate_run_root(layout.run_id, case_layout.root)


def test_cli_default_uses_recommended_short_kimi_result_root() -> None:
    parser = build_parser()
    args = parser.parse_args(["validate"])

    assert args.result_root == RECOMMENDED_RESULT_ROOT
