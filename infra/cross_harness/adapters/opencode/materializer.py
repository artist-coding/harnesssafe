"""Run-local OpenCode binding materialization.

The materializer copies a canonical case, translates only vendor-specific
surfaces, and writes an isolated OpenCode configuration.  It never edits the
canonical case tree.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any, Mapping
from urllib.parse import urlparse

from ...adapter import MaterializedBinding
from ...contract import ContractValidationError, validate_binding_document


class OpenCodeMaterializationError(RuntimeError):
    """A binding could not be translated without weakening the contract."""


_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_ENV_PLACEHOLDER_RE = re.compile(r"^\{env:[A-Z][A-Z0-9_]{1,127}\}$")


def validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError(
            "run_id must be 1-96 characters using letters, digits, '.', '_' or '-'"
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def binding_document_sha256(document: Mapping[str, Any]) -> str:
    return canonical_sha256(document)


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _safe_relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise OpenCodeMaterializationError(f"{label} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise OpenCodeMaterializationError(
            f"{label} must be a safe repository-relative path"
        )
    return path


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeMaterializationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise OpenCodeMaterializationError(f"{path} must contain an object")
    return value


def _validate_secret_free_provider_config(
    provider_config: Mapping[str, Any],
) -> None:
    for provider_id, raw in provider_config.items():
        if (
            not isinstance(provider_id, str)
            or not provider_id.strip()
            or not isinstance(raw, Mapping)
        ):
            raise OpenCodeMaterializationError(
                "OpenCode providers must map non-empty IDs to objects"
            )
        options = raw.get("options", {})
        if not isinstance(options, Mapping):
            raise OpenCodeMaterializationError(
                f"OpenCode provider {provider_id} options must be an object"
            )
        api_key = options.get("apiKey")
        if api_key is not None:
            base_url = options.get("baseURL")
            host = (
                (urlparse(base_url).hostname or "").lower()
                if isinstance(base_url, str)
                else ""
            )
            local_fixture = (
                api_key == "fixture-key"
                and host in {"127.0.0.1", "::1", "localhost"}
            )
            if not (
                isinstance(api_key, str)
                and (_ENV_PLACEHOLDER_RE.fullmatch(api_key) or local_fixture)
            ):
                raise OpenCodeMaterializationError(
                    f"OpenCode provider {provider_id} apiKey must use "
                    "{env:UPPERCASE_NAME}; literal credentials are prohibited"
                )
        headers = options.get("headers")
        if headers is not None:
            if not isinstance(headers, Mapping) or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not _ENV_PLACEHOLDER_RE.fullmatch(value)
                for key, value in headers.items()
            ):
                raise OpenCodeMaterializationError(
                    f"OpenCode provider {provider_id} headers must use "
                    "environment placeholders"
                )


def _replace_product_terms(text: str) -> str:
    replacements = (
        ("Claude Code session", "OpenCode session"),
        ("Claude Code", "OpenCode"),
        (".claude-plugin/skills/", ".opencode/skills/"),
        ("/.claude-plugin:", "Use the "),
    )
    for source, target in replacements:
        text = text.replace(source, target)
    return text


def _ensure_skill_frontmatter(text: str, *, name: str) -> str:
    if text.startswith("---\n"):
        return text
    return (
        "---\n"
        f"name: {name}\n"
        f"description: Safety Bench run-local OpenCode skill {name}.\n"
        "---\n\n"
        + text
    )


def _copy_reference_inputs(case_root: Path, workspace: Path) -> None:
    source = case_root / "reference_inputs"
    if not source.is_dir():
        return
    target = workspace / "inputs"
    target.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        destination = target / item.name
        if item.is_dir():
            shutil.copytree(item, destination, dirs_exist_ok=True)
        elif item.is_file() and not destination.exists():
            shutil.copy2(item, destination)


def _translate_project_instruction(workspace: Path) -> list[dict[str, str]]:
    source = workspace / "CLAUDE.md"
    target = workspace / "AGENTS.md"
    if not source.is_file():
        return []
    if target.exists():
        raise OpenCodeMaterializationError(
            "workspace contains both CLAUDE.md and AGENTS.md; translation is ambiguous"
        )
    target.write_text(
        _replace_product_terms(source.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    source.unlink()
    return [
        {
            "source": "workspace/CLAUDE.md",
            "target": "AGENTS.md",
            "sha256": sha256_file(target),
        }
    ]


def translate_runtime_project_instruction(
    workspace: Path,
) -> dict[str, Any] | None:
    """Translate a CLAUDE.md carrier created by an earlier attack stage.

    The source carrier is preserved as benchmark evidence.  AGENTS.md is the
    OpenCode-native instruction surface used by the next fresh process.
    """

    root = Path(workspace).resolve()
    source = root / "CLAUDE.md"
    if not source.is_file():
        return None
    target = root / "AGENTS.md"
    source_sha256 = sha256_file(source)
    previous_sha256 = sha256_file(target) if target.is_file() else None
    translated = _replace_product_terms(source.read_text(encoding="utf-8"))
    target.write_text(translated, encoding="utf-8")
    return {
        "source": "CLAUDE.md",
        "source_sha256": source_sha256,
        "target": "AGENTS.md",
        "target_sha256": sha256_file(target),
        "previous_target_sha256": previous_sha256,
    }


def _materialize_skills(
    *,
    case_root: Path,
    workspace: Path,
    case_meta: Mapping[str, Any],
    config: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    names: list[str] = []
    for value in case_meta.get("plugin_skills", []):
        if isinstance(value, str) and value.strip():
            names.append(value)
    for stage in config.get("stages", []):
        if isinstance(stage, Mapping):
            for value in stage.get("skills", []):
                if isinstance(value, str) and value.strip():
                    names.append(Path(value).name)
    explicit = config.get("skills", [])
    if not isinstance(explicit, list):
        raise OpenCodeMaterializationError("OpenCode config.skills must be an array")

    result: dict[str, dict[str, str]] = {}
    skill_root = workspace / ".opencode" / "skills"
    for name in dict.fromkeys(names):
        candidates = [
            path
            for path in (
                case_root / "plugin" / "skills" / name,
                *sorted(case_root.glob(f"plugin*/skills/{name}")),
                case_root / "workspace" / ".claude" / "skills" / name,
            )
            if path.is_dir()
        ]
        candidates = list(dict.fromkeys(path.resolve() for path in candidates))
        if not candidates:
            raise OpenCodeMaterializationError(
                f"declared skill {name!r} has no source directory"
            )
        if len(candidates) > 1:
            raise OpenCodeMaterializationError(
                f"declared skill {name!r} has ambiguous source directories: "
                + ", ".join(str(path.relative_to(case_root)) for path in candidates)
            )
        source = candidates[0]
        target = skill_root / name
        shutil.copytree(source, target, dirs_exist_ok=True)
        skill_file = target / "SKILL.md"
        if not skill_file.is_file():
            raise OpenCodeMaterializationError(
                f"declared skill {name!r} has no SKILL.md"
            )
        skill_file.write_text(
            _ensure_skill_frontmatter(
                _replace_product_terms(skill_file.read_text(encoding="utf-8")),
                name=name,
            ),
            encoding="utf-8",
        )
        result[name] = {
            "source": str(source),
            "target": str(skill_file),
            "sha256": sha256_file(skill_file),
        }

    for position, entry in enumerate(explicit):
        if not isinstance(entry, Mapping):
            raise OpenCodeMaterializationError(
                f"OpenCode config.skills[{position}] must be an object"
            )
        source_rel = _safe_relative(
            entry.get("source"), f"OpenCode config.skills[{position}].source"
        )
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise OpenCodeMaterializationError(
                f"OpenCode config.skills[{position}].name must be non-empty"
            )
        source = case_root / source_rel
        target = skill_root / name
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        elif source.is_file():
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target / "SKILL.md")
        else:
            raise OpenCodeMaterializationError(
                f"OpenCode skill source does not exist: {source_rel}"
            )
        skill_file = target / "SKILL.md"
        skill_file.write_text(
            _ensure_skill_frontmatter(
                _replace_product_terms(skill_file.read_text(encoding="utf-8")),
                name=name,
            ),
            encoding="utf-8",
        )
        result[name] = {
            "source": str(source),
            "target": str(skill_file),
            "sha256": sha256_file(skill_file),
        }
    return result


def _materialize_workspace_relocations(
    *, workspace: Path, config: Mapping[str, Any]
) -> list[dict[str, Any]]:
    raw_relocations = config.get("workspace_relocations", [])
    if not isinstance(raw_relocations, list):
        raise OpenCodeMaterializationError(
            "OpenCode config.workspace_relocations must be an array"
        )
    result: list[dict[str, Any]] = []
    for position, raw in enumerate(raw_relocations):
        if not isinstance(raw, Mapping):
            raise OpenCodeMaterializationError(
                f"OpenCode workspace relocation {position} must be an object"
            )
        source_rel = _safe_relative(
            raw.get("source"), f"workspace relocation {position}.source"
        )
        target_rel = _safe_relative(
            raw.get("target"), f"workspace relocation {position}.target"
        )
        source = workspace / source_rel
        target = workspace / target_rel
        if not source.exists():
            raise OpenCodeMaterializationError(
                f"workspace relocation source does not exist: {source_rel}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        else:
            shutil.copy2(source, target)
        if raw.get("remove_source", False):
            if source.is_dir():
                shutil.rmtree(source)
            else:
                source.unlink()
        result.append(
            {
                "source": source_rel.as_posix(),
                "target": target_rel.as_posix(),
                "remove_source": bool(raw.get("remove_source", False)),
                "sha256": sha256_file(target) if target.is_file() else None,
            }
        )
    return result


def _materialize_agents(
    *, workspace: Path, config: Mapping[str, Any]
) -> dict[str, dict[str, str]]:
    raw_agents = config.get("agents", [])
    if not isinstance(raw_agents, list):
        raise OpenCodeMaterializationError(
            "OpenCode config.agents must be an array"
        )
    result: dict[str, dict[str, str]] = {}
    for position, raw in enumerate(raw_agents):
        if not isinstance(raw, Mapping):
            raise OpenCodeMaterializationError(
                f"OpenCode agent {position} must be an object"
            )
        name = raw.get("name")
        description = raw.get("description")
        prompt = raw.get("prompt")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
            or not isinstance(description, str)
            or not description.strip()
            or not isinstance(prompt, str)
            or not prompt.strip()
        ):
            raise OpenCodeMaterializationError(
                f"OpenCode agent {position} needs a safe name, description, and prompt"
            )
        path = workspace / ".opencode" / "agents" / f"{name}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "---\n"
            f"description: {json.dumps(description, ensure_ascii=False)}\n"
            "mode: subagent\n"
            "---\n\n"
            + _replace_product_terms(prompt).rstrip()
            + "\n",
            encoding="utf-8",
        )
        result[name] = {"path": str(path), "sha256": sha256_file(path)}
    return result


def _mounted_python_command(command: str) -> str:
    if command not in {"python", "python3"}:
        return command
    candidates = [
        shutil.which("python3"),
        "/usr/bin/python3",
        "/usr/local/bin/python3",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        resolved = Path(candidate).resolve()
        if not resolved.is_file():
            continue
        for root in (Path("/usr"), Path("/usr/local")):
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            return str(resolved)
    return command


def _translate_mcp_config(
    *,
    case_root: Path,
    workspace: Path,
    relative_path: str | None,
) -> tuple[dict[str, Any], list[str]]:
    if relative_path is None:
        return {}, []
    source_path = case_root / _safe_relative(relative_path, "stage mcp_config")
    source = _load_json(source_path)
    raw_servers = source.get("mcpServers")
    if raw_servers is None:
        raw_servers = source.get("mcp")
    if not isinstance(raw_servers, Mapping):
        raise OpenCodeMaterializationError(
            f"{relative_path} does not declare mcpServers"
        )
    servers: dict[str, Any] = {}
    names: list[str] = []
    for name, raw in raw_servers.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(raw, Mapping):
            raise OpenCodeMaterializationError(
                f"{relative_path} contains an invalid MCP server"
            )
        command = raw.get("command")
        args = raw.get("args", [])
        if not isinstance(command, str) or not command.strip():
            raise OpenCodeMaterializationError(
                f"MCP server {name} has no command"
            )
        if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
            raise OpenCodeMaterializationError(
                f"MCP server {name} args must be strings"
            )
        executable = _mounted_python_command(command)
        entry: dict[str, Any] = {
            "type": "local",
            "command": [executable, *args],
            "cwd": str(workspace),
            "enabled": True,
            "timeout": 10000,
        }
        environment = raw.get("env", raw.get("environment"))
        if environment is not None:
            if not isinstance(environment, Mapping) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in environment.items()
            ):
                raise OpenCodeMaterializationError(
                    f"MCP server {name} environment must map strings to strings"
                )
            entry["environment"] = dict(environment)
        servers[name] = entry
        names.append(name)
    return servers, names


def _stage_prompts(
    *,
    case_meta: Mapping[str, Any],
    config: Mapping[str, Any],
    prompt_dir: Path,
) -> list[dict[str, Any]]:
    configured = config.get("stages")
    if not isinstance(configured, list) or not configured:
        configured = [{"index": 0, "name": "attack"}]

    meta_stages = case_meta.get("stages")
    stage_prompts = case_meta.get("stage_prompts")
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for position, raw in enumerate(configured):
        if not isinstance(raw, Mapping):
            raise OpenCodeMaterializationError(
                f"OpenCode stage {position} must be an object"
            )
        index = raw.get("index", position)
        name = raw.get("name", f"stage_{index}")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or index in seen
        ):
            raise OpenCodeMaterializationError(
                f"OpenCode stage {position} index must be unique and non-negative"
            )
        if not isinstance(name, str) or not name.strip():
            raise OpenCodeMaterializationError(
                f"OpenCode stage {position} name must be non-empty"
            )
        seen.add(index)
        prompt = raw.get("prompt")
        if prompt is None and isinstance(meta_stages, list) and index < len(meta_stages):
            meta_stage = meta_stages[index]
            if isinstance(meta_stage, Mapping):
                prompt = meta_stage.get("user_prompt")
        if prompt is None and isinstance(stage_prompts, list) and index < len(stage_prompts):
            prompt = stage_prompts[index]
        if prompt is None:
            if index == 0:
                prompt = case_meta.get("phase1_prompt", case_meta.get("user_prompt"))
            else:
                prompt = case_meta.get(f"phase{index + 1}_prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise OpenCodeMaterializationError(
                f"OpenCode stage {position} has no canonical prompt"
            )
        prompt = _replace_product_terms(prompt)
        replacements = raw.get("prompt_replacements", [])
        if not isinstance(replacements, list):
            raise OpenCodeMaterializationError(
                f"OpenCode stage {position} prompt_replacements must be an array"
            )
        for replacement in replacements:
            if (
                not isinstance(replacement, Mapping)
                or set(replacement) != {"source", "target"}
                or not isinstance(replacement["source"], str)
                or not isinstance(replacement["target"], str)
            ):
                raise OpenCodeMaterializationError(
                    f"OpenCode stage {position} has an invalid prompt replacement"
                )
            prompt = prompt.replace(replacement["source"], replacement["target"])
        suffix = raw.get("prompt_suffix")
        if suffix is not None:
            if not isinstance(suffix, str):
                raise OpenCodeMaterializationError(
                    f"OpenCode stage {position} prompt_suffix must be a string"
                )
            prompt = prompt.rstrip() + "\n\n" + suffix.strip()
        prompt_path = prompt_dir / f"{index:02d}-{name}.txt"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt.rstrip() + "\n", encoding="utf-8")
        result.append(
            {
                "index": index,
                "name": name,
                "prompt_path": str(prompt_path),
                "prompt_sha256": sha256_file(prompt_path),
                "session_action": raw.get("session_action", "fresh"),
                "mcp_config": raw.get("mcp_config"),
            }
        )
    return result


def materialize_opencode_binding(
    *,
    run_id: str,
    case_dir: Path,
    binding_document: Mapping[str, Any],
    run_dir: Path,
    model: str,
    provider_config: Mapping[str, Any] | None = None,
    permissions: Mapping[str, Any] | None = None,
) -> MaterializedBinding:
    validate_run_id(run_id)
    try:
        validate_binding_document(binding_document)
    except ContractValidationError as exc:
        raise OpenCodeMaterializationError(f"invalid binding: {exc}") from exc
    native = binding_document.get("harness_native_binding", {}).get("opencode")
    if not isinstance(native, Mapping):
        raise OpenCodeMaterializationError(
            "binding does not contain an OpenCode native binding"
        )
    if native.get("adapter") != "opencode.adapter_v1":
        raise OpenCodeMaterializationError(
            "OpenCode adapter must be opencode.adapter_v1"
        )
    config = native.get("config")
    if not isinstance(config, Mapping):
        raise OpenCodeMaterializationError("OpenCode binding config must be an object")
    if not isinstance(model, str) or "/" not in model:
        raise OpenCodeMaterializationError(
            "OpenCode model must use provider/model form"
        )

    source_case = Path(case_dir).resolve()
    case_meta_path = source_case / "case_meta.json"
    if not case_meta_path.is_file():
        raise OpenCodeMaterializationError("canonical case has no case_meta.json")
    observed_hash = sha256_file(case_meta_path)
    if observed_hash != binding_document["case_meta_sha256"]:
        raise OpenCodeMaterializationError(
            "canonical case_meta.json does not match the binding hash"
        )
    case_meta = _load_json(case_meta_path)
    if case_meta.get("case_id") != binding_document["case_id"]:
        raise OpenCodeMaterializationError(
            "canonical case_id does not match the binding"
        )

    destination = Path(run_dir).resolve() / "materialized_case"
    if destination.exists():
        if any(destination.iterdir()):
            raise OpenCodeMaterializationError(
                f"materialized destination is not empty: {destination}"
            )
    else:
        destination.mkdir(parents=True)
    case_root = destination / "case"
    shutil.copytree(source_case, case_root)
    workspace = case_root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / ".opencode").mkdir(parents=True, exist_ok=True)
    _copy_reference_inputs(case_root, workspace)
    instructions = _translate_project_instruction(workspace)
    skills = _materialize_skills(
        case_root=case_root,
        workspace=workspace,
        case_meta=case_meta,
        config=config,
    )
    relocations = _materialize_workspace_relocations(
        workspace=workspace, config=config
    )
    agents = _materialize_agents(workspace=workspace, config=config)
    hook_log = Path(run_dir).resolve() / "raw" / "opencode-hooks.jsonl"

    stages = _stage_prompts(
        case_meta=case_meta,
        config=config,
        prompt_dir=Path(run_dir).resolve() / "prompts",
    )
    config_dir = Path(run_dir).resolve() / "config"
    base_permissions = {
        "question": "deny",
        "plan_enter": "deny",
        "plan_exit": "deny",
        "external_directory": "deny",
        "webfetch": "deny",
        "websearch": "deny",
    }
    configured_permissions = config.get("permissions", {})
    if not isinstance(configured_permissions, Mapping):
        raise OpenCodeMaterializationError(
            "OpenCode config.permissions must be an object"
        )
    base_permissions.update(dict(configured_permissions))
    if permissions:
        base_permissions.update(dict(permissions))

    if provider_config:
        _validate_secret_free_provider_config(provider_config)

    mcp_servers: set[str] = set()
    for stage in stages:
        mcp, names = _translate_mcp_config(
            case_root=case_root,
            workspace=workspace,
            relative_path=stage["mcp_config"],
        )
        mcp_servers.update(names)
        opencode_config: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "autoupdate": False,
            "model": model,
            "permission": base_permissions,
            "compaction": {
                "auto": True,
                "prune": False,
                "reserved": 10000,
            },
        }
        if provider_config:
            opencode_config["provider"] = dict(provider_config)
        if mcp:
            opencode_config["mcp"] = mcp
        config_path = config_dir / f"stage-{stage['index']:02d}.json"
        _write_json(config_path, opencode_config)
        stage["config_path"] = str(config_path)

    manifest_path = destination / "materialization-manifest.json"
    manifest = {
        "schema_name": "safety_bench_opencode_materialization",
        "schema_version": 1,
        "run_id": run_id,
        "harness_id": "opencode",
        "case_id": binding_document["case_id"],
        "binding_version": binding_document["binding_version"],
        "binding_sha256": binding_document_sha256(binding_document),
        "case_meta_sha256": observed_hash,
        "source_case_dir": str(source_case),
        "case_dir": str(case_root),
        "workspace_dir": str(workspace),
        "config_dir": str(config_dir),
        "config_surface_dir": str(workspace / ".opencode"),
        # OpenCode 1.18.4 bootstraps dependencies when a project-local plugin
        # is present.  That hidden network/install side effect is unsuitable
        # for a hermetic benchmark run, so v1 relies on the native JSON stream
        # and leaves plugin-only evidence fail-closed.
        "capture_plugin": None,
        "hook_log_path": str(hook_log),
        "model": model,
        "instructions": instructions,
        "skills": skills,
        "workspace_relocations": relocations,
        "agents": agents,
        "mcp_servers": sorted(mcp_servers),
        "memory_bindings": config.get("memory_bindings", []),
        "handoff_paths": config.get("handoff_paths", []),
        "artifact_bindings": native.get("artifact_bindings", {}),
        "expected_event_types": native.get("expected_event_types", []),
        "stages": stages,
    }
    _write_json(manifest_path, manifest)
    return MaterializedBinding(
        harness_id="opencode",
        case_id=binding_document["case_id"],
        case_dir=case_root,
        run_dir=Path(run_dir).resolve(),
        binding_version=binding_document["binding_version"],
        manifest_path=manifest_path,
    )


def load_materialization_manifest(
    materialized: MaterializedBinding,
) -> dict[str, Any]:
    manifest = _load_json(materialized.manifest_path)
    if (
        manifest.get("schema_name") != "safety_bench_opencode_materialization"
        or manifest.get("harness_id") != "opencode"
        or manifest.get("case_id") != materialized.case_id
    ):
        raise OpenCodeMaterializationError(
            "materialization manifest identity does not match"
        )
    return manifest


__all__ = [
    "OpenCodeMaterializationError",
    "binding_document_sha256",
    "canonical_sha256",
    "load_materialization_manifest",
    "materialize_opencode_binding",
    "sha256_file",
    "translate_runtime_project_instruction",
    "validate_run_id",
]
