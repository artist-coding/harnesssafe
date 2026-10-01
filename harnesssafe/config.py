from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlparse
from .common import ARMS, ExperimentError, read_json, file_hash
from .registry import ADAPTERS, PROVIDER_FIELDS, RUNTIME_FIELDS, REQUIRED_PROVIDER, REQUIRED_RUNTIME

HARNESS_ENV = {h: h.upper() + "_BIN" for h in ADAPTERS}
CONFIG_KEYS = {"schema_version", "name", "harness", "model", "executable", "expected_version",
               "permission_profile", "timeout_seconds", "selection", "arms", "repeats", "provider", "runtime"}

def load_config(path: Path) -> dict:
    cfg = validate_config(read_json(path))
    for section, key in (("provider", "profile"), ("runtime", "conformance"), ("runtime", "source_root"),
                         ("runtime", "python_executable"), ("runtime", "git_bash"), ("runtime", "node_executable")):
        if key in cfg[section]:
            value = Path(cfg[section][key]).expanduser()
            cfg[section][key] = str((path.resolve().parent / value).resolve()) if not value.is_absolute() else str(value.resolve())
    return cfg

def validate_config(raw: dict) -> dict:
    if not isinstance(raw, dict) or set(raw) - CONFIG_KEYS:
        raise ExperimentError("Unknown experiment fields; credentials and arbitrary arguments are not accepted")
    cfg = {"schema_version": 1, "permission_profile": "default_permission", "timeout_seconds": 240,
           "selection": {"suites": [], "case_ids": [], "smoke": False}, "arms": ["attack"], "repeats": 1,
           "provider": {}, "runtime": {}, **raw}
    if cfg["schema_version"] != 1:
        raise ExperimentError("Unsupported experiment schema_version")
    for field in ("name", "harness", "model", "executable", "expected_version"):
        if not isinstance(cfg.get(field), str) or not cfg[field].strip() or any(c in cfg[field] for c in "\r\n\x00"):
            raise ExperimentError(f"{field} must be a nonempty, single-line string")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", cfg["name"]):
        raise ExperimentError("name must use 1-80 letters, digits, dots, underscores or hyphens")
    if cfg["harness"] not in ADAPTERS:
        raise ExperimentError(f"Unknown harness; choose from {list(ADAPTERS)}")
    spec = ADAPTERS[cfg["harness"]]
    if "permission_profile" not in raw:
        cfg["permission_profile"] = spec["profiles"][0]
    if cfg["permission_profile"] not in spec["profiles"]:
        raise ExperimentError(f"{cfg['harness']} supports permission profiles {spec['profiles']}")
    for key, high in (("timeout_seconds", 86400), ("repeats", 100)):
        if type(cfg[key]) is not int or not 1 <= cfg[key] <= high:
            raise ExperimentError(f"{key} must be an integer in 1..{high}")
    if not isinstance(cfg["arms"], list) or not cfg["arms"] or any(not isinstance(a, str) or a not in ARMS for a in cfg["arms"]) or len(set(cfg["arms"])) != len(cfg["arms"]):
        raise ExperimentError(f"arms must be a nonempty unique list from {ARMS}")
    if set(cfg["arms"]) - set(spec["arms"]):
        raise ExperimentError(f"{cfg['harness']} native scheduler supports attack-only; controls cannot be silently dropped")
    selection = cfg["selection"]
    if not isinstance(selection, dict) or set(selection) - {"suites", "case_ids", "smoke"}:
        raise ExperimentError("selection accepts suites, case_ids and smoke")
    cfg["selection"] = {"suites": [], "case_ids": [], "smoke": False, **selection}
    for key in ("suites", "case_ids"):
        value = cfg["selection"][key]
        if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value) or len(set(value)) != len(value):
            raise ExperimentError(f"selection.{key} must contain unique nonempty strings")
    if type(cfg["selection"]["smoke"]) is not bool:
        raise ExperimentError("selection.smoke must be boolean")
    if cfg["harness"] == "codex" and not cfg["provider"]:
        cfg["provider"] = {"codex_provider": "codex_login"}
    harness = cfg["harness"]
    for section, allowed, required in (("provider", PROVIDER_FIELDS[harness], REQUIRED_PROVIDER[harness]),
                                       ("runtime", RUNTIME_FIELDS[harness], REQUIRED_RUNTIME[harness])):
        value = cfg[section]
        if not isinstance(value, dict) or set(value) - allowed:
            raise ExperimentError(f"{harness} {section} accepts only {sorted(allowed)}; never include credential values")
        missing = required - set(value)
        if missing:
            raise ExperimentError(f"{harness} {section} is missing: {sorted(missing)}")
        for key, item in value.items():
            if key == "allow_not_run_smoke":
                if type(item) is not bool:
                    raise ExperimentError("allow_not_run_smoke must be boolean")
                continue
            if not isinstance(item, str) or not item.strip() or any(c in item for c in "\r\n\x00"):
                raise ExperimentError(f"{section}.{key} must be a nonempty single-line string")
            if key.endswith("_env") and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item):
                raise ExperimentError(f"{key} must be an environment-variable name")
            if key.endswith("_url"):
                url = urlparse(item)
                if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
                    raise ExperimentError(f"{key} must be an HTTP(S) endpoint without credentials, query or fragment")
    provider = cfg["provider"]
    choices = {"codex_provider": {"minimax", "dashscope", "openai", "codex_login"},
               "api": {"openai-completions", "openai-responses"},
               "api_mode": {"chat_completions", "anthropic_messages"},
               "provider_kind": {"openai-compatible"}}
    for key, allowed in choices.items():
        if key in provider and provider[key] not in allowed:
            raise ExperimentError(f"{key} must be one of {sorted(allowed)}")
    if "provider_id" in provider and not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", provider["provider_id"]):
        raise ExperimentError("provider_id must be a lowercase provider identifier")

    return cfg

def select_cases(catalog: list[dict], selection: dict) -> list[dict]:
    unknown = set(selection["suites"]) - {c["suite"] for c in catalog}
    unknown_ids = set(selection["case_ids"]) - {c["case_id"] for c in catalog}
    if unknown or unknown_ids:
        raise ExperimentError(f"Unknown suites/cases: {sorted(unknown | unknown_ids)}")
    selected = [c for c in catalog if (not selection["suites"] or c["suite"] in selection["suites"])
                and (not selection["case_ids"] or c["case_id"] in selection["case_ids"])]
    if selection["smoke"]:
        first = {}
        for case in selected:
            first.setdefault(case["suite"], case)
        selected = list(first.values())
    if not selected:
        raise ExperimentError("Case selection is empty")
    return selected


def input_inventory(cfg: dict) -> dict:
    """Pin external non-secret provider and capability documents."""
    result = {}
    for section, key in (("provider", "profile"), ("runtime", "conformance")):
        if key in cfg.get(section, {}):
            path = Path(cfg[section][key])
            if not path.is_file():
                raise ExperimentError(f"Missing {section}.{key}: {path}")
            if key == "profile":
                from infra.cross_harness.adapters.opencode.provider import load_provider_profile
                profile = load_provider_profile(path)
                if profile.model != cfg["model"]:
                    raise ExperimentError("OpenCode model must match provider profile provider_id/model_id")
            result[f"{section}.{key}"] = {"path": str(path), "sha256": file_hash(path)}
    return result
