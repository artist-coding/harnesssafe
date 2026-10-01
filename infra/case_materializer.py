"""Create per-run case copies with callback URLs and local paths injected."""

from __future__ import annotations

import json
import importlib
import os
import re
import shutil
import argparse
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

try:
    from infra import check_paper_suite_lock
    from infra.f3_producer_prompt_contract import (
        canonical_producer_lifecycle_contract,
        producer_target_path,
    )
    from infra.runtime_input_policy import ignored_copy_names
except ModuleNotFoundError:  # direct `python infra/case_materializer.py`
    import check_paper_suite_lock  # type: ignore
    from f3_producer_prompt_contract import (  # type: ignore
        canonical_producer_lifecycle_contract,
        producer_target_path,
    )
    from runtime_input_policy import ignored_copy_names  # type: ignore


TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".mdc",
    ".txt",
    ".toml",
    ".yaml",
    ".yml",
    ".py",
    ".ps1",
    ".sh",
}

LEGACY_CALLBACK_RE = re.compile(
    r"http://(?:127\.0\.0\.1|localhost):18765", re.IGNORECASE
)
LEGACY_DEPLOY_RE = re.compile(
    r"(?:[A-Za-z]:\\Users\\Test\\Desktop\\safety_bench|/mnt/c/Users/anonymous/Desktop/safety_bench)"
    r"[/\\]runs[/\\][^ \r\n\"'`<>]+?[/\\]config[/\\]deployment\.id",
    re.IGNORECASE,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
MATERIALIZATION_ATTESTATION_SCHEMA_VERSION = "1.0.0"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CASE_CONTENT_DIGEST_FIELDS = (
    "case_meta_canonical_sha256",
    "control_contracts_canonical_sha256",
    "runtime_inputs_tree_sha256",
    "case_content_sha256",
)


@dataclass(frozen=True)
class MaterializedCase:
    case_dir: Path
    workspace_dir: Path
    secret_dir: Path | None
    canary_files: list[Path]
    callback_url: str
    materialization_attestation_path: Path | None = None
    materialization_attestation: dict[str, Any] | None = None
    harness_binding_path: Path | None = None


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "CLAUDE.md",
        "AGENTS.md",
        "HERMES.md",
        ".hermes.md",
        ".cursorrules",
    }


def _ignore_case_copy(dir_name: str, names: list[str]) -> set[str]:
    return ignored_copy_names(dir_name, names)


def _filesystem_path(path: Path) -> str:
    """Return a filesystem path string that can handle deep Windows trees."""
    resolved = str(path.resolve())
    if os.name != "nt":
        return resolved
    if resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved.lstrip("\\")
    return "\\\\?\\" + resolved


def _walk_files(root: Path) -> Iterator[Path]:
    filesystem_root = _filesystem_path(root)
    for dirpath, _dirnames, filenames in os.walk(filesystem_root):
        relative_dir = os.path.relpath(dirpath, filesystem_root)
        logical_dir = root if relative_dir == "." else root / relative_dir
        for filename in filenames:
            # Keep logical paths free of the Windows extended-path prefix so
            # prompts and run metadata never expose an implementation detail.
            yield logical_dir / filename


def _path_exists(path: Path) -> bool:
    return os.path.exists(_filesystem_path(path))


def _path_is_file(path: Path) -> bool:
    return os.path.isfile(_filesystem_path(path))


def _path_is_dir(path: Path) -> bool:
    return os.path.isdir(_filesystem_path(path))


def _read_text(path: Path, *, encoding: str = "utf-8-sig", errors: str | None = None) -> str:
    with open(_filesystem_path(path), "r", encoding=encoding, errors=errors) as handle:
        return handle.read()


def _write_text(path: Path, value: str, *, encoding: str = "utf-8") -> None:
    os.makedirs(_filesystem_path(path.parent), exist_ok=True)
    with open(_filesystem_path(path), "w", encoding=encoding) as handle:
        handle.write(value)


def _iter_children(path: Path) -> list[Path]:
    try:
        with os.scandir(_filesystem_path(path)) as entries:
            return [path / entry.name for entry in entries]
    except OSError:
        return []


def _load_meta(path: Path) -> dict[str, Any]:
    if not _path_is_file(path):
        return {}
    try:
        return json.loads(_read_text(path))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_meta(path: Path, meta: dict[str, Any]) -> None:
    _write_text(path, json.dumps(meta, indent=2, ensure_ascii=False))


def _find_secret_dir(case_dir: Path) -> Path | None:
    for rel in ("config", "deploy", "canary", "workspace/config", "workspace/deploy", "workspace/canary"):
        candidate = case_dir / rel
        if _path_exists(candidate):
            return candidate
    return None


def _prepare_workspace_dir(materialized_dir: Path) -> Path:
    workspace_dir = materialized_dir / "workspace"
    workspace_seed_dir = materialized_dir / "workspace_seed"
    if not _path_is_dir(workspace_dir) and _path_is_dir(workspace_seed_dir):
        shutil.copytree(_filesystem_path(workspace_seed_dir), _filesystem_path(workspace_dir))
    return workspace_dir


def _assert_f3_producer_target_absent(
    materialized_dir: Path, meta: dict[str, Any]
) -> None:
    """Fail closed if an F3 runtime producer target is already populated."""

    if str(meta.get("family") or "") != "F3_tool_mcp_poisoning":
        return
    if str(meta.get("carrier") or "") not in {
        "workspace_file",
        "registry_cache",
        "schema_cache",
        "tool_schema_cache",
    }:
        return
    expected = canonical_producer_lifecycle_contract(meta)
    if meta.get("producer_carrier_lifecycle_contract") != expected:
        raise ValueError(
            f"{meta.get('case_id')}: F3 producer lifecycle contract is missing or drifted"
        )
    target = producer_target_path(materialized_dir, meta)
    if target is None:
        raise ValueError(f"{meta.get('case_id')}: F3 producer target is not declared")
    if _path_exists(target) or target.is_symlink():
        raise ValueError(
            f"{meta.get('case_id')}: F3 producer target must be absent before phase1: "
            f"{expected['target_path']}"
        )
    if not _path_is_dir(target.parent) or target.parent.is_symlink():
        raise ValueError(
            f"{meta.get('case_id')}: F3 producer target parent is missing or linked: "
            f"{expected['target_path']}"
        )


def _copy_if_exists(src: Path | None, dst: Path) -> bool:
    if not src or not os.path.isfile(_filesystem_path(src)):
        return False
    src_fs = _filesystem_path(src)
    dst_fs = _filesystem_path(dst)
    try:
        if os.path.exists(dst_fs) and os.path.samefile(src_fs, dst_fs):
            return True
    except OSError:
        pass
    if os.path.normcase(os.path.abspath(src_fs)) == os.path.normcase(os.path.abspath(dst_fs)):
        return True
    os.makedirs(_filesystem_path(dst.parent), exist_ok=True)
    shutil.copy2(src_fs, dst_fs)
    return True


def _memory_pool_files(memory_dir: Path) -> list[Path]:
    if not _path_is_dir(memory_dir):
        return []
    try:
        with os.scandir(_filesystem_path(memory_dir)) as entries:
            names = [
                entry.name
                for entry in entries
                if entry.is_file()
                and entry.name.startswith("memory_pool_r")
                and entry.name.endswith(".json")
            ]
    except OSError:
        return []
    return sorted(memory_dir / name for name in names)


def _git_args(args: list[str]) -> list[str]:
    return ["git", "-c", "core.longpaths=true", *args]


def _ensure_git_config_defaults(workspace_dir: Path) -> None:
    config_path = workspace_dir / ".git" / "config"
    try:
        with open(_filesystem_path(config_path), "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except OSError:
        content = ""

    additions: list[str] = []
    if "longpaths" not in content:
        additions.append("[core]\n\tlongpaths = true\n")
    if "[user]" not in content:
        additions.append("[user]\n\temail = audit-bot@example.invalid\n\tname = Audit Bot\n")
    if not additions:
        return

    with open(_filesystem_path(config_path), "a", encoding="utf-8", newline="\n") as handle:
        if content and not content.endswith("\n"):
            handle.write("\n")
        handle.write("".join(additions))


def _write_minimal_git_repo(workspace_dir: Path) -> None:
    git_dir = workspace_dir / ".git"
    for rel in ("objects/info", "objects/pack", "refs/heads", "refs/tags"):
        os.makedirs(_filesystem_path(git_dir / rel), exist_ok=True)
    head_path = git_dir / "HEAD"
    config_path = git_dir / "config"
    if not _path_exists(head_path):
        with open(_filesystem_path(head_path), "w", encoding="utf-8", newline="\n") as handle:
            handle.write("ref: refs/heads/main\n")
    if not _path_exists(config_path):
        with open(_filesystem_path(config_path), "w", encoding="utf-8", newline="\n") as handle:
            handle.write("[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n")
    _ensure_git_config_defaults(workspace_dir)


def _latest_result_memory_candidate(source_case_dir: Path, relpath: str) -> Path | None:
    results_dir = source_case_dir / "results"
    if not _path_is_dir(results_dir):
        return None
    candidates: list[Path] = []
    for run_dir in sorted(_iter_children(results_dir), key=lambda p: p.name, reverse=True):
        if not _path_is_dir(run_dir):
            continue
        for prefix in (
            "runtime_input_from_previous_round",
            "materialized_case/workspace",
        ):
            candidate = run_dir / prefix / relpath
            if _path_is_file(candidate):
                candidates.append(candidate)
    return candidates[0] if candidates else None


def _previous_case_memory_candidate(source_case_dir: Path, source_meta: dict[str, Any], relpath: str) -> Path | None:
    previous_case_id = str(source_meta.get("depends_on_case_id") or "")
    if not previous_case_id:
        return None
    previous_case_dir = source_case_dir.parent / previous_case_id
    if not _path_is_dir(previous_case_dir):
        return None
    candidate = _latest_result_memory_candidate(previous_case_dir, relpath)
    if candidate:
        return candidate
    previous_memory_dir = previous_case_dir / "workspace_seed" / ".evolution_memory"
    memory_files = _memory_pool_files(previous_memory_dir)
    if memory_files:
        return memory_files[-1]
    return None


def _ensure_memory_input_snapshot(
    source_case_dir: Path,
    materialized_dir: Path,
    workspace_dir: Path,
    source_meta: dict[str, Any],
) -> None:
    relpath = source_meta.get("input_memory_snapshot_relpath") or source_meta.get("memory_artifact_relpath")
    if not isinstance(relpath, str) or not relpath:
        return
    target = workspace_dir / relpath
    if _path_exists(target):
        return

    if _copy_if_exists(_previous_case_memory_candidate(source_case_dir, source_meta, relpath), target):
        return
    if _copy_if_exists(_latest_result_memory_candidate(source_case_dir, relpath), target):
        return

    memory_files = _memory_pool_files(workspace_dir / ".evolution_memory")
    if memory_files and _copy_if_exists(memory_files[-1], target):
        return

    control_seed = materialized_dir / "control_seed" / "safe_memory_pool.json"
    _copy_if_exists(control_seed, target)


def _initialize_git_repo(
    workspace_dir: Path,
    callback_url: str,
    deployment_path: Path | None,
    source_deployment_paths: list[str],
) -> None:
    """Initialize a per-run git repository inside the materialized workspace.

    The materialized workspace lives under the benchmark repository's results
    tree. Some agents use the nearest git root as their project boundary, so a
    nested .git directory prevents relative writes from escaping back to the
    real benchmark checkout. Cases that need a pre-populated git repo can also
    ship a .git_init template.
    """
    git_init_dir = workspace_dir / ".git_init"
    has_git_template = _path_is_dir(git_init_dir)

    manifest_path = git_init_dir / "commit_manifest.txt"
    commit_files: list[str] = []
    if _path_is_file(manifest_path):
        commit_files = [
            line.strip() for line in _read_text(manifest_path).splitlines() if line.strip()
        ]

    hooks_src = git_init_dir / "hooks"
    hooks_dst = workspace_dir / ".git" / "hooks"
    git_cwd = _filesystem_path(workspace_dir)

    try:
        if not _path_is_dir(workspace_dir / ".git"):
            try:
                subprocess.run(_git_args(["init"]), cwd=git_cwd, check=True, capture_output=True)
            except subprocess.CalledProcessError:
                if has_git_template and commit_files:
                    raise
                _write_minimal_git_repo(workspace_dir)
        _ensure_git_config_defaults(workspace_dir)

        if has_git_template and commit_files:
            subprocess.run(
                _git_args(["add", *commit_files]),
                cwd=git_cwd,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                _git_args(["commit", "-m", "initial project snapshot"]),
                cwd=git_cwd,
                check=True,
                capture_output=True,
            )

        # Install hooks after the initial commit so the commit itself does not
        # trigger them (the callback server may not be running yet).
        if _path_is_dir(hooks_src):
            os.makedirs(_filesystem_path(hooks_dst), exist_ok=True)
            for hook_src in _iter_children(hooks_src):
                if not _path_is_file(hook_src):
                    continue
                template = _read_text(hook_src, errors="replace")
                rendered = _render_text(template, callback_url, deployment_path, source_deployment_paths)
                hook_dst = hooks_dst / hook_src.name
                _write_text(hook_dst, rendered)
                # Make executable on Unix/Git Bash; ignore errors on Windows.
                try:
                    hook_dst.chmod(0o755)
                except OSError:
                    pass

        if has_git_template:
            shutil.rmtree(_filesystem_path(git_init_dir))
    except (subprocess.CalledProcessError, OSError) as exc:
        # Leave .git_init in place so debugging is possible if git is missing.
        print(f"warning: failed to initialize git repo in {workspace_dir}: {exc}", file=sys.stderr)


def _render_text(
    text: str,
    callback_url: str,
    deployment_path: Path | None,
    source_deployment_paths: list[str] | None = None,
) -> str:
    callback = callback_url.rstrip("/")
    text = text.replace("{{CALLBACK_URL}}", callback)
    text = text.replace("{{HONEYPOT_URL}}", callback)
    text = text.replace("{{HONEYPOT_BASE_URL}}", callback)
    text = LEGACY_CALLBACK_RE.sub(callback, text)
    if deployment_path is not None:
        # Use forward slashes so the replacement is safe inside JSON strings
        # (Windows backslashes would create invalid escape sequences).
        deployment = str(deployment_path).replace("\\", "/")
        text = LEGACY_DEPLOY_RE.sub(lambda _: deployment, text)
        for source_path in source_deployment_paths or []:
            if source_path:
                text = text.replace(source_path, deployment)
                # Only replace the JSON-escaped form when it differs from the
                # plain source_path. For relative paths like
                # "config/deployment.id" the escaped form is identical to the
                # plain form; running both replacements would re-substitute the
                # source_path substring inside the already-replaced absolute
                # deployment path and produce a doubled path.
                escaped_source = json.dumps(source_path, ensure_ascii=False)[1:-1]
                escaped_deployment = json.dumps(deployment, ensure_ascii=False)[1:-1]
                if escaped_source != source_path:
                    text = text.replace(escaped_source, escaped_deployment)
    return text


def _rewrite_mcp_config_paths(
    path: Path,
    materialized_dir: Path,
    deployment_path: Path | None,
) -> None:
    """Point copied MCP configs at this run's local server and canary path."""
    if not path.name.startswith("mcp") or path.suffix.lower() != ".json":
        return
    is_clean_config = path.name.lower() == "mcp_clean.json"
    try:
        doc = json.loads(_read_text(path))
    except (json.JSONDecodeError, OSError) as exc:
        if is_clean_config:
            raise ValueError(f"invalid clean MCP config {path}: {exc}") from exc
        return
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        if is_clean_config:
            raise ValueError(f"clean MCP config has no mcpServers object: {path}")
        return
    if not servers:
        if is_clean_config:
            raise ValueError(f"clean MCP config has no server declarations: {path}")
        # Some suite-lock tests use an empty MCP declaration as a hashed
        # placeholder.  With no executable server entry there are no runtime
        # paths to resolve or validate.
        return

    changed = False
    local_server = materialized_dir / "mcp_server.py"
    local_deploy = deployment_path
    clean_server = materialized_dir / "mcp_clean_server.py"
    clean_fixture = materialized_dir / "controls" / "mcp_clean_fixture.json"
    if is_clean_config:
        if not _path_is_file(clean_server):
            raise FileNotFoundError(
                f"clean MCP server is missing from materialized case: {clean_server}"
            )
        if not _path_is_file(clean_fixture):
            raise FileNotFoundError(
                f"clean MCP fixture is missing from materialized case: {clean_fixture}"
            )

    for server_name, server in servers.items():
        if not isinstance(server, dict):
            if is_clean_config:
                raise ValueError(
                    f"clean MCP server entry {server_name!r} is not an object: {path}"
                )
            continue
        args = server.get("args")
        if not isinstance(args, list):
            if is_clean_config:
                raise ValueError(
                    f"clean MCP server entry {server_name!r} has no args array: {path}"
                )
            continue

        deploy_flags = [
            idx for idx, value in enumerate(args) if value == "--deploy-path"
        ]
        for deploy_flag in deploy_flags:
            deploy_index = deploy_flag + 1
            if deploy_index >= len(args) or not isinstance(args[deploy_index], str):
                raise ValueError(
                    f"MCP server entry {server_name!r} has no path after "
                    f"--deploy-path: {path}"
                )
            if local_deploy is None or not _path_is_file(local_deploy):
                raise FileNotFoundError(
                    f"MCP deployment path is missing from materialized case: "
                    f"{local_deploy or materialized_dir / 'config' / 'deployment.id'}"
                )
            # The flag provides an unambiguous semantic binding.  Always use
            # the authoritative run-local deployment file, including when a
            # source config used a relative value or the run is reached via a
            # subst drive that does not contain a literal `/runs/` segment.
            args[deploy_index] = str(local_deploy)
            changed = True

        if is_clean_config:
            if not args or not isinstance(args[0], str):
                raise ValueError(
                    f"clean MCP server entry {server_name!r} has no script argument: {path}"
                )
            script_arg = args[0].replace("\\", "/")
            if not (
                script_arg == "mcp_clean_server.py"
                or script_arg.endswith("/mcp_clean_server.py")
            ):
                raise ValueError(
                    f"clean MCP server entry {server_name!r} does not reference "
                    f"mcp_clean_server.py in args[0]: {path}"
                )

            fixture_flags = [
                idx for idx, value in enumerate(args) if value == "--fixture-json"
            ]
            if len(fixture_flags) != 1:
                raise ValueError(
                    f"clean MCP server entry {server_name!r} must declare exactly one "
                    f"--fixture-json argument: {path}"
                )
            fixture_index = fixture_flags[0] + 1
            if fixture_index >= len(args) or not isinstance(args[fixture_index], str):
                raise ValueError(
                    f"clean MCP server entry {server_name!r} has no fixture path after "
                    f"--fixture-json: {path}"
                )
            fixture_arg = args[fixture_index].replace("\\", "/")
            if not (
                fixture_arg == "controls/mcp_clean_fixture.json"
                or fixture_arg.endswith("/controls/mcp_clean_fixture.json")
            ):
                raise ValueError(
                    f"clean MCP server entry {server_name!r} does not reference "
                    f"controls/mcp_clean_fixture.json after --fixture-json: {path}"
                )

            # These are the only clean-control arguments treated as paths.
            # Keep logical (non-\\?\) absolute paths in the config while the
            # existence checks above use the long-path-safe filesystem helper.
            args[0] = str(clean_server)
            args[fixture_index] = str(clean_fixture)
            changed = True

        if not is_clean_config and args and isinstance(args[0], str):
            script_arg = args[0].replace("\\", "/")
            if script_arg == "mcp_server.py" or script_arg.endswith("/mcp_server.py"):
                if not _path_is_file(local_server):
                    raise FileNotFoundError(
                        f"MCP server is missing from materialized case: {local_server}"
                    )
                # Normal MCP configs may be authored with source-tree-relative
                # script paths such as ../mcp_server.py.  Claude does not
                # consistently resolve those relative to the copied config
                # file, so bind the executable script to the run-local copy
                # just as clean MCP configs are bound above.
                args[0] = str(local_server)
                changed = True

        for idx, value in enumerate(args):
            if not isinstance(value, str):
                continue
            normalized = value.replace("\\", "/")
            if normalized.endswith("/mcp_server.py") and "/runs/" in normalized:
                args[idx] = str(local_server)
                changed = True
            elif (
                local_deploy is not None
                and normalized.endswith("/deployment.id")
                and "/runs/" in normalized
            ):
                args[idx] = str(local_deploy)
                changed = True

    if changed:
        _write_text(path, json.dumps(doc, indent=2, ensure_ascii=False))


def _formal_digest_bindings(
    *,
    formal_row_id: str,
    expected_case_content_sha256: str,
    expected_case_contract_sha256: str,
    expected_control_contract_sha256: str,
    expected_runtime_inputs_sha256: str,
    expected_source_manifest_sha256: str,
    expected_source_manifest_canonical_sha256: str,
    expected_runtime_code_sha256: str,
    expected_protocol_sha256: str,
    expected_runtime_input_policy_sha256: str,
    expected_runtime_revision_sha256: str,
    expected_suite_content_sha256: str,
) -> dict[str, str] | None:
    values = {
        "case_content_sha256": str(expected_case_content_sha256 or ""),
        "case_contract_digest": str(expected_case_contract_sha256 or ""),
        "control_contract_digest": str(expected_control_contract_sha256 or ""),
        "runtime_inputs_sha256": str(expected_runtime_inputs_sha256 or ""),
        "source_manifest_sha256": str(expected_source_manifest_sha256 or ""),
        "source_manifest_canonical_sha256": str(
            expected_source_manifest_canonical_sha256 or ""
        ),
        "runtime_code_sha256": str(expected_runtime_code_sha256 or ""),
        "protocol_sha256": str(expected_protocol_sha256 or ""),
        "runtime_input_policy_sha256": str(expected_runtime_input_policy_sha256 or ""),
        "runtime_revision_sha256": str(expected_runtime_revision_sha256 or ""),
        "suite_content_sha256": str(expected_suite_content_sha256 or ""),
    }
    if not formal_row_id:
        supplied = sorted(name for name, value in values.items() if value)
        if supplied:
            raise ValueError(
                "formal digest bindings cannot be supplied without formal_row_id: "
                + ", ".join(supplied)
            )
        return None
    invalid = sorted(name for name, value in values.items() if not SHA256_RE.fullmatch(value))
    if invalid:
        raise ValueError(
            "formal_row_id requires every expected digest to be a non-empty 64-hex SHA-256: "
            + ", ".join(invalid)
        )
    return {name: value.lower() for name, value in values.items()}


def _formal_case_relative_path(repo_root: Path, source_case_dir: Path) -> str:
    runs_root = (repo_root / "runs").resolve()
    try:
        relative = source_case_dir.resolve().relative_to(runs_root)
    except ValueError as exc:
        raise ValueError(
            f"formal source case must resolve below {runs_root}: {source_case_dir}"
        ) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"formal source case has an unsafe runs-relative path: {relative}")
    return relative.as_posix()


def _assert_digest(label: str, expected: str, actual: Any) -> None:
    actual_text = str(actual or "").lower()
    if expected.lower() != actual_text:
        raise ValueError(
            f"formal materialization digest mismatch for {label}: "
            f"expected={expected.lower()} actual={actual_text or '<missing>'}"
        )


def _digest_projection(record: dict[str, Any]) -> dict[str, str]:
    return {field: str(record.get(field) or "") for field in CASE_CONTENT_DIGEST_FIELDS}


def _runtime_digest_projection(record: dict[str, Any]) -> dict[str, str]:
    return {
        "runtime_code_sha256": str(record.get("runtime_code_revision_sha256") or ""),
        "protocol_sha256": str(record.get("protocol_revisions_sha256") or ""),
        "runtime_input_policy_sha256": str(record.get("runtime_input_policy_sha256") or ""),
        "runtime_revision_sha256": str(record.get("runtime_revision_sha256") or ""),
    }


def _verify_formal_suite_lock(
    *,
    repo_root: Path,
    suite_lock_path: Path,
    case_relative: str,
    source_meta: dict[str, Any],
    control_type: str,
    source_record: dict[str, Any],
    runtime_record: dict[str, Any],
    expected: dict[str, str],
    attestation_mode: str,
) -> dict[str, Any]:
    absolute_lock: Path | None
    if attestation_mode == "live_prefreeze":
        absolute_lock = None
        lock = check_paper_suite_lock.build_lock(repo_root)
    else:
        absolute_lock = suite_lock_path if suite_lock_path.is_absolute() else repo_root / suite_lock_path
        absolute_lock = absolute_lock.resolve()
        try:
            absolute_lock.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise ValueError(f"formal suite lock must resolve inside the benchmark root: {absolute_lock}") from exc
        if not absolute_lock.is_file():
            raise FileNotFoundError(f"formal suite lock is missing: {absolute_lock}")
        lock = check_paper_suite_lock.load_json(absolute_lock)
    stored_suite_digest = str(lock.get("suite_content_sha256") or "").lower()
    _assert_digest("suite_content_sha256", expected["suite_content_sha256"], stored_suite_digest)
    _assert_digest(
        "suite_lock_self_digest",
        expected["suite_content_sha256"],
        check_paper_suite_lock.lock_digest(lock),
    )
    _assert_digest(
        "suite_lock_compatibility_digest",
        expected["suite_content_sha256"],
        lock.get("case_set_sha256"),
    )
    if str(lock.get("attestation_sha256") or "") != check_paper_suite_lock.attestation_digest(lock):
        raise ValueError("formal suite lock provenance attestation digest is invalid")
    if attestation_mode == "formal_suite_lock":
        if not check_paper_suite_lock.valid_git_commit_sha(lock.get("git_commit_sha")):
            raise ValueError("formal suite lock has no valid source-freeze Git commit")
        if lock.get("git_worktree_dirty") is not False:
            raise ValueError("formal suite lock was not generated from a clean source-freeze worktree")

    manifest_path = repo_root / "runs" / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"active manifest is missing: {manifest_path}")
    manifest = check_paper_suite_lock.load_json(manifest_path)
    _assert_digest(
        "source_manifest_sha256",
        str(lock.get("source_manifest_sha256") or ""),
        check_paper_suite_lock.file_sha256(manifest_path),
    )
    _assert_digest(
        "expected.source_manifest_sha256",
        expected["source_manifest_sha256"],
        check_paper_suite_lock.file_sha256(manifest_path),
    )
    _assert_digest(
        "source_manifest_canonical_sha256",
        str(lock.get("source_manifest_canonical_sha256") or ""),
        check_paper_suite_lock.canonical_json_sha256(manifest),
    )
    _assert_digest(
        "expected.source_manifest_canonical_sha256",
        expected["source_manifest_canonical_sha256"],
        check_paper_suite_lock.canonical_json_sha256(manifest),
    )

    locked_cases = {
        str(item.get("case_dir") or ""): item
        for item in (lock.get("cases") or [])
        if isinstance(item, dict)
    }
    locked_case = locked_cases.get(case_relative)
    if locked_case is None:
        raise ValueError(f"formal source case is absent from the suite lock: {case_relative}")
    for field in CASE_CONTENT_DIGEST_FIELDS:
        _assert_digest(f"suite_lock_case.{field}", str(locked_case.get(field) or ""), source_record.get(field))
    _assert_digest(
        "case_content_sha256",
        expected["case_content_sha256"],
        source_record.get("case_content_sha256"),
    )
    _assert_digest(
        "case_contract_digest",
        expected["case_contract_digest"],
        source_record.get("case_meta_canonical_sha256"),
    )
    selected_control: dict[str, Any] | None = None
    if control_type:
        selected_control = next(
            (
                item
                for item in (source_meta.get("control_suite") or [])
                if isinstance(item, dict) and str(item.get("control_type") or "") == control_type
            ),
            None,
        )
        if selected_control is None:
            raise ValueError(f"formal control is absent from case_meta.json: {control_type}")
        actual_control_digest = check_paper_suite_lock.canonical_json_sha256(selected_control)
    else:
        actual_control_digest = str(source_record.get("control_contracts_canonical_sha256") or "")
    _assert_digest(
        "control_contract_digest",
        expected["control_contract_digest"],
        actual_control_digest,
    )
    _assert_digest(
        "runtime_inputs_sha256",
        expected["runtime_inputs_sha256"],
        source_record.get("runtime_inputs_tree_sha256"),
    )
    _assert_digest(
        "runtime_code_sha256",
        expected["runtime_code_sha256"],
        runtime_record.get("runtime_code_revision_sha256"),
    )
    _assert_digest(
        "suite_lock.runtime_code_revision_sha256",
        expected["runtime_code_sha256"],
        lock.get("runtime_code_revision_sha256"),
    )
    _assert_digest(
        "protocol_sha256",
        expected["protocol_sha256"],
        runtime_record.get("protocol_revisions_sha256"),
    )
    _assert_digest(
        "suite_lock.protocol_revisions_sha256",
        expected["protocol_sha256"],
        lock.get("protocol_revisions_sha256"),
    )
    _assert_digest(
        "runtime_revision_sha256",
        expected["runtime_revision_sha256"],
        runtime_record.get("runtime_revision_sha256"),
    )
    _assert_digest(
        "runtime_input_policy_sha256",
        expected["runtime_input_policy_sha256"],
        runtime_record.get("runtime_input_policy_sha256"),
    )
    _assert_digest(
        "suite_lock.runtime_input_policy_sha256",
        expected["runtime_input_policy_sha256"],
        lock.get("runtime_input_policy_sha256"),
    )
    _assert_digest(
        "suite_lock.runtime_revision_sha256",
        expected["runtime_revision_sha256"],
        lock.get("runtime_revision_sha256"),
    )
    return {
        "path": absolute_lock,
        "content_sha256": stored_suite_digest,
        "source_manifest_sha256": str(lock.get("source_manifest_sha256") or ""),
        "source_manifest_canonical_sha256": str(
            lock.get("source_manifest_canonical_sha256") or ""
        ),
        "case_id": str(source_meta.get("case_id") or ""),
        "control_id": str((selected_control or {}).get("control_id") or ""),
        "control_contract_digest": actual_control_digest,
    }


def _verify_copy_attestation(
    *,
    source_before: dict[str, Any],
    copied_pre_injection: dict[str, Any],
    source_after: dict[str, Any],
    runtime_before: dict[str, Any],
    runtime_after: dict[str, Any],
    expected: dict[str, str],
) -> None:
    for field in CASE_CONTENT_DIGEST_FIELDS:
        before = str(source_before.get(field) or "")
        copied = str(copied_pre_injection.get(field) or "")
        after = str(source_after.get(field) or "")
        if not before or before != copied or before != after:
            raise ValueError(
                f"formal materialization copy/source TOCTOU mismatch for {field}: "
                f"source_before={before or '<missing>'} copied={copied or '<missing>'} "
                f"source_after={after or '<missing>'}"
            )
    for field, expected_name in (
        ("runtime_code_revision_sha256", "runtime_code_sha256"),
        ("protocol_revisions_sha256", "protocol_sha256"),
        ("runtime_input_policy_sha256", "runtime_input_policy_sha256"),
        ("runtime_revision_sha256", "runtime_revision_sha256"),
    ):
        before = str(runtime_before.get(field) or "")
        after = str(runtime_after.get(field) or "")
        _assert_digest(expected_name, expected[expected_name], before)
        if before != after:
            raise ValueError(
                f"formal runtime revision changed during materialization for {field}: "
                f"before={before or '<missing>'} after={after or '<missing>'}"
            )


def _write_materialization_attestation(path: Path, payload: dict[str, Any]) -> None:
    os.makedirs(_filesystem_path(path.parent), exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    _write_text(temporary, json.dumps(payload, indent=2, ensure_ascii=False))
    os.replace(_filesystem_path(temporary), _filesystem_path(path))


def materialize_case(
    source_case_dir: str | Path,
    results_dir: str | Path,
    callback_url: str,
    canary_token: str | None = None,
    *,
    formal_row_id: str = "",
    formal_attempt: int = 1,
    formal_isolated_home_id: str = "",
    formal_matrix_id: str = "",
    formal_queue_position: int = 0,
    formal_launch_nonce: str = "",
    formal_launch_command_sha256: str = "",
    formal_launch_event_sha256: str = "",
    attestation_mode: str = "",
    control_type: str = "",
    expected_case_content_sha256: str = "",
    expected_case_contract_sha256: str = "",
    expected_control_contract_sha256: str = "",
    expected_runtime_inputs_sha256: str = "",
    expected_source_manifest_sha256: str = "",
    expected_source_manifest_canonical_sha256: str = "",
    expected_runtime_code_sha256: str = "",
    expected_protocol_sha256: str = "",
    expected_runtime_input_policy_sha256: str = "",
    expected_runtime_revision_sha256: str = "",
    expected_suite_content_sha256: str = "",
    repo_root: str | Path | None = None,
    suite_lock_path: str | Path | None = None,
    harness: str = "",
) -> MaterializedCase:
    """Copy a case into a per-run directory and inject run-specific values.

    The source case remains unchanged. The returned case directory is safe to
    hand to a harness because callback URLs and stale absolute canary paths
    have been rewritten for this run.
    """
    source_case_dir = Path(source_case_dir).resolve()
    results_dir = Path(results_dir).resolve()
    materialized_dir = results_dir / "materialized_case"
    if not _path_is_dir(source_case_dir):
        raise FileNotFoundError(f"source case directory is missing: {source_case_dir}")
    expected = _formal_digest_bindings(
        formal_row_id=formal_row_id,
        expected_case_content_sha256=expected_case_content_sha256,
        expected_case_contract_sha256=expected_case_contract_sha256,
        expected_control_contract_sha256=expected_control_contract_sha256,
        expected_runtime_inputs_sha256=expected_runtime_inputs_sha256,
        expected_source_manifest_sha256=expected_source_manifest_sha256,
        expected_source_manifest_canonical_sha256=expected_source_manifest_canonical_sha256,
        expected_runtime_code_sha256=expected_runtime_code_sha256,
        expected_protocol_sha256=expected_protocol_sha256,
        expected_runtime_input_policy_sha256=expected_runtime_input_policy_sha256,
        expected_runtime_revision_sha256=expected_runtime_revision_sha256,
        expected_suite_content_sha256=expected_suite_content_sha256,
    )
    effective_repo_root = Path(repo_root).resolve() if repo_root is not None else ROOT.resolve()
    effective_suite_lock = Path(suite_lock_path) if suite_lock_path is not None else DEFAULT_SUITE_LOCK
    if formal_row_id:
        if attestation_mode not in {"formal_suite_lock", "live_prefreeze"}:
            raise ValueError(
                "attestation_mode must be formal_suite_lock or live_prefreeze with formal_row_id"
            )
        if not formal_isolated_home_id:
            raise ValueError("formal_isolated_home_id is required with formal_row_id")
        if not 1 <= int(formal_attempt) <= 3:
            raise ValueError("formal_attempt must be in [1, 3]")
        launch_bindings = {
            "formal_matrix_id": formal_matrix_id,
            "formal_launch_nonce": formal_launch_nonce,
            "formal_launch_command_sha256": formal_launch_command_sha256,
            "formal_launch_event_sha256": formal_launch_event_sha256,
        }
        if attestation_mode == "formal_suite_lock":
            if not re.fullmatch(r"[0-9a-f]{16}", formal_matrix_id):
                raise ValueError("formal_matrix_id must be 16 lowercase hex characters")
            if int(formal_queue_position) < 1:
                raise ValueError("formal_queue_position must be positive")
            for name, value in launch_bindings.items():
                if name == "formal_matrix_id":
                    continue
                if not re.fullmatch(r"[0-9a-f]{64}", str(value or "")):
                    raise ValueError(f"{name} must be 64 lowercase hex characters")
        elif any(launch_bindings.values()) or int(formal_queue_position):
            raise ValueError("formal launch ledger bindings require attestation_mode=formal_suite_lock")
    elif formal_isolated_home_id:
        raise ValueError("formal_isolated_home_id cannot be supplied without formal_row_id")
    elif attestation_mode:
        raise ValueError("attestation_mode cannot be supplied without formal_row_id")
    elif any(
        (
            formal_matrix_id,
            int(formal_queue_position),
            formal_launch_nonce,
            formal_launch_command_sha256,
            formal_launch_event_sha256,
        )
    ):
        raise ValueError("formal launch ledger bindings cannot be supplied without formal_row_id")
    source_before: dict[str, Any] | None = None
    runtime_before: dict[str, Any] | None = None
    case_relative = ""
    suite_lock_observation: dict[str, Any] | None = None

    # Every expected binding is checked before the old materialized tree is
    # removed or a new copy is created.  A stale or partial formal invocation
    # therefore fails without handing any unverified case tree to the harness.
    if expected is not None:
        case_relative = _formal_case_relative_path(effective_repo_root, source_case_dir)
        source_before = check_paper_suite_lock.canonical_case_content_record(source_case_dir)
        source_meta_for_attestation = _load_meta(source_case_dir / "case_meta.json")
        runtime_before = check_paper_suite_lock.live_runtime_revision_record(effective_repo_root)
        suite_lock_observation = _verify_formal_suite_lock(
            repo_root=effective_repo_root,
            suite_lock_path=effective_suite_lock,
            case_relative=case_relative,
            source_meta=source_meta_for_attestation,
            control_type=control_type,
            source_record=source_before,
            runtime_record=runtime_before,
            expected=expected,
            attestation_mode=attestation_mode,
        )

    if _path_exists(materialized_dir):
        shutil.rmtree(_filesystem_path(materialized_dir))
    shutil.copytree(
        _filesystem_path(source_case_dir),
        _filesystem_path(materialized_dir),
        ignore=_ignore_case_copy,
    )

    # Validate the copied runtime tree before emitting an all-verified formal
    # attestation. A preseeded F3 producer target must never leave behind a
    # misleading success attestation, even when the run aborts immediately.
    source_meta = _load_meta(source_case_dir / "case_meta.json")
    _assert_f3_producer_target_absent(materialized_dir, source_meta)

    materialization_attestation_path: Path | None = None
    materialization_attestation: dict[str, Any] | None = None
    if expected is not None:
        assert source_before is not None
        assert runtime_before is not None
        assert suite_lock_observation is not None
        copied_pre_injection = check_paper_suite_lock.canonical_case_content_record(materialized_dir)
        source_after = check_paper_suite_lock.canonical_case_content_record(source_case_dir)
        runtime_after = check_paper_suite_lock.live_runtime_revision_record(effective_repo_root)
        _verify_copy_attestation(
            source_before=source_before,
            copied_pre_injection=copied_pre_injection,
            source_after=source_after,
            runtime_before=runtime_before,
            runtime_after=runtime_after,
            expected=expected,
        )
        materialization_attestation_path = results_dir / "materialization_attestation.json"
        absolute_suite_lock = suite_lock_observation.get("path")
        materialization_attestation = {
            "schema_version": MATERIALIZATION_ATTESTATION_SCHEMA_VERSION,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "formal_row_id": formal_row_id,
            "attestation_mode": attestation_mode,
            "formal_attempt": int(formal_attempt),
            "formal_isolated_home_id": formal_isolated_home_id,
            "source_case_dir": case_relative,
            "case_id": str(suite_lock_observation.get("case_id") or ""),
            "control_type": control_type,
            "control_id": str(suite_lock_observation.get("control_id") or ""),
            "case_contract_digest": expected["case_contract_digest"],
            "control_contract_digest": expected["control_contract_digest"],
            "runtime_inputs_tree_sha256": expected["runtime_inputs_sha256"],
            "case_content_sha256": expected["case_content_sha256"],
            "source_manifest_sha256": expected["source_manifest_sha256"],
            "source_manifest_canonical_sha256": expected[
                "source_manifest_canonical_sha256"
            ],
            "suite_content_sha256": expected["suite_content_sha256"],
            "runtime_code_revision_sha256": expected["runtime_code_sha256"],
            "protocol_revisions_sha256": expected["protocol_sha256"],
            "runtime_input_policy_sha256": expected["runtime_input_policy_sha256"],
            "runtime_revision_sha256": expected["runtime_revision_sha256"],
            "all_verified": True,
            "paths": {
                "repo_root": str(effective_repo_root),
                "source_case_dir": str(source_case_dir),
                "source_case_relative": f"runs/{case_relative}",
                "materialized_case_dir": str(materialized_dir),
                "results_dir": str(results_dir),
                "suite_lock": str(absolute_suite_lock or ""),
                "attestation": str(materialization_attestation_path),
            },
            "expected": dict(expected),
            "observed": {
                "source_before": _digest_projection(source_before),
                "copied_pre_injection": _digest_projection(copied_pre_injection),
                "source_after": _digest_projection(source_after),
                "runtime_before": _runtime_digest_projection(runtime_before),
                "runtime_after": _runtime_digest_projection(runtime_after),
                "suite_lock_content_sha256": str(
                    suite_lock_observation["content_sha256"]
                ),
            },
        }
        if attestation_mode == "formal_suite_lock":
            materialization_attestation.update(
                {
                    "formal_matrix_id": formal_matrix_id,
                    "formal_queue_position": int(formal_queue_position),
                    "formal_launch_nonce": formal_launch_nonce,
                    "formal_launch_command_sha256": formal_launch_command_sha256,
                    "formal_launch_event_sha256": formal_launch_event_sha256,
                }
            )
        # Canonical self-digest covers the complete attestation payload except
        # this field itself.  The runner separately pins the exact file bytes
        # in memory and re-hashes them after the harness exits.
        materialization_attestation["attestation_sha256"] = (
            check_paper_suite_lock.canonical_json_sha256(materialization_attestation)
        )
        _write_materialization_attestation(
            materialization_attestation_path,
            materialization_attestation,
        )

    source_deployment_paths = []
    if isinstance(source_meta.get("deploy_path"), str):
        source_deployment_paths.append(source_meta["deploy_path"])

    workspace_dir = _prepare_workspace_dir(materialized_dir)
    _ensure_memory_input_snapshot(source_case_dir, materialized_dir, workspace_dir, source_meta)
    secret_dir = _find_secret_dir(materialized_dir)
    canary_files = sorted(
        (path for path in _walk_files(materialized_dir) if path.name == "deployment.id" and _path_is_file(path)),
        key=lambda path: str(path),
    )
    source_canary_values: set[str] = set()
    for canary_file in canary_files:
        try:
            value = _read_text(canary_file).strip()
        except OSError:
            continue
        if value:
            source_canary_values.add(value)
    if canary_token is not None:
        if not canary_token or canary_token != canary_token.strip() or "\n" in canary_token or "\r" in canary_token:
            raise ValueError("canary_token must be a non-empty single-line token without surrounding whitespace")
        for canary_file in canary_files:
            _write_text(canary_file, canary_token)
    deployment_path = secret_dir / "deployment.id" if secret_dir and _path_is_file(secret_dir / "deployment.id") else None

    for path in _walk_files(materialized_dir):
        if not _path_is_file(path) or not _is_text_file(path):
            continue
        try:
            original = _read_text(path, errors="replace")
        except OSError:
            continue
        rendered = _render_text(original, callback_url, deployment_path, source_deployment_paths)
        if canary_token is not None:
            for source_canary in source_canary_values:
                rendered = rendered.replace(source_canary, canary_token)
        if rendered != original:
            _write_text(path, rendered)
        _rewrite_mcp_config_paths(path, materialized_dir, deployment_path)

    meta_path = materialized_dir / "case_meta.json"
    meta = _load_meta(meta_path)
    meta["callback_url"] = callback_url.rstrip("/")
    if deployment_path is not None:
        meta["deploy_path"] = str(deployment_path)
    if "post_url" in meta and isinstance(meta["post_url"], str):
        meta["post_url"] = _render_text(
            meta["post_url"], callback_url, deployment_path, source_deployment_paths
        )
    if "user_prompt" in meta and isinstance(meta["user_prompt"], str):
        meta["user_prompt"] = _render_text(
            meta["user_prompt"], callback_url, deployment_path, source_deployment_paths
        )
    _write_meta(meta_path, meta)

    _initialize_git_repo(
        workspace_dir,
        callback_url,
        deployment_path,
        source_deployment_paths,
    )

    harness_binding_path: Path | None = None
    if harness:
        if harness not in {"openclaw", "hermes"}:
            raise ValueError(f"unsupported materialization harness: {harness}")
        # Lazy import keeps the common materializer independent of adapter internals.
        import importlib

        adapter = importlib.import_module(
            f"infra.harness_adapters.{harness}.bindings"
            if __package__
            else f"harness_adapters.{harness}.bindings"
        )
        case_relative = _formal_case_relative_path(
            effective_repo_root, source_case_dir
        )
        inventory = adapter.load_inventory(
            effective_repo_root
            / "infra"
            / "harness_bindings"
            / harness
            / "inventory.json",
            repo_root=effective_repo_root,
        )
        binding = inventory.get(case_relative)
        if binding is None:
            raise ValueError(
                f"no {harness} binding for active case: {case_relative}"
            )
        materialized_meta = materialized_dir / "case_meta.json"
        metadata_before = materialized_meta.read_bytes()
        harness_binding_path = adapter.write_selected_binding(
            binding,
            materialized_dir,
            canonical_case_dir=source_case_dir,
        )
        if materialized_meta.read_bytes() != metadata_before:
            raise RuntimeError(
                f"{harness} binding writer changed materialized case_meta.json"
            )
    return MaterializedCase(
        case_dir=materialized_dir,
        workspace_dir=workspace_dir,
        secret_dir=secret_dir,
        canary_files=canary_files,
        callback_url=callback_url.rstrip("/"),
        materialization_attestation_path=materialization_attestation_path,
        materialization_attestation=materialization_attestation,
        harness_binding_path=harness_binding_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a per-run materialized case with callback values injected."
    )
    parser.add_argument("--case-dir", required=True)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--callback-url", required=True)
    parser.add_argument("--canary-token")
    parser.add_argument("--formal-row-id", default="")
    parser.add_argument("--formal-attempt", type=int, default=1)
    parser.add_argument("--formal-isolated-home-id", default="")
    parser.add_argument("--formal-matrix-id", default="")
    parser.add_argument("--formal-queue-position", type=int, default=0)
    parser.add_argument("--formal-launch-nonce", default="")
    parser.add_argument("--formal-launch-command-sha256", default="")
    parser.add_argument("--formal-launch-event-sha256", default="")
    parser.add_argument(
        "--attestation-mode",
        choices=("", "formal_suite_lock", "live_prefreeze"),
        default="",
    )
    parser.add_argument("--control-type", default="")
    parser.add_argument("--expected-case-content-sha256", default="")
    parser.add_argument("--expected-case-contract-sha256", default="")
    parser.add_argument("--expected-control-contract-sha256", default="")
    parser.add_argument("--expected-runtime-inputs-sha256", default="")
    parser.add_argument("--expected-source-manifest-sha256", default="")
    parser.add_argument("--expected-source-manifest-canonical-sha256", default="")
    parser.add_argument("--expected-runtime-code-sha256", default="")
    parser.add_argument("--expected-protocol-sha256", default="")
    parser.add_argument("--expected-runtime-input-policy-sha256", default="")
    parser.add_argument("--expected-runtime-revision-sha256", default="")
    parser.add_argument("--expected-suite-content-sha256", default="")
    parser.add_argument("--suite-lock", default=str(DEFAULT_SUITE_LOCK))
    parser.add_argument("--harness", default="")
    args = parser.parse_args()

    materialized = materialize_case(
        source_case_dir=args.case_dir,
        results_dir=args.results_dir,
        callback_url=args.callback_url,
        canary_token=args.canary_token,
        formal_row_id=args.formal_row_id,
        formal_attempt=args.formal_attempt,
        formal_isolated_home_id=args.formal_isolated_home_id,
        formal_matrix_id=args.formal_matrix_id,
        formal_queue_position=args.formal_queue_position,
        formal_launch_nonce=args.formal_launch_nonce,
        formal_launch_command_sha256=args.formal_launch_command_sha256,
        formal_launch_event_sha256=args.formal_launch_event_sha256,
        attestation_mode=args.attestation_mode,
        control_type=args.control_type,
        expected_case_content_sha256=args.expected_case_content_sha256,
        expected_case_contract_sha256=args.expected_case_contract_sha256,
        expected_control_contract_sha256=args.expected_control_contract_sha256,
        expected_runtime_inputs_sha256=args.expected_runtime_inputs_sha256,
        expected_source_manifest_sha256=args.expected_source_manifest_sha256,
        expected_source_manifest_canonical_sha256=args.expected_source_manifest_canonical_sha256,
        expected_runtime_code_sha256=args.expected_runtime_code_sha256,
        expected_protocol_sha256=args.expected_protocol_sha256,
        expected_runtime_input_policy_sha256=args.expected_runtime_input_policy_sha256,
        expected_runtime_revision_sha256=args.expected_runtime_revision_sha256,
        expected_suite_content_sha256=args.expected_suite_content_sha256,
        suite_lock_path=args.suite_lock,
        harness=args.harness,
    )
    payload = {
        "case_dir": str(materialized.case_dir),
        "workspace_dir": str(materialized.workspace_dir),
        "secret_dir": str(materialized.secret_dir) if materialized.secret_dir else "",
        "canary_files": [str(path) for path in materialized.canary_files],
        "callback_url": materialized.callback_url,
        "materialization_attestation_path": (
            str(materialized.materialization_attestation_path)
            if materialized.materialization_attestation_path
            else ""
        ),
        "materialization_attestation": materialized.materialization_attestation,
        "harness_binding_path": (
            str(materialized.harness_binding_path)
            if materialized.harness_binding_path
            else ""
        ),
    }
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
