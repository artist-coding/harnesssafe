"""Fail-closed construction of source-matched clean plugin controls.

This module deliberately does not try to decide which prose is malicious.  The
F2 builders mix ordinary workflow text and attack instructions in the same
``SKILL.md`` files, and most active cases do not declare machine-addressable
payload spans.  A lexical "cleaner" would therefore be capable of silently
changing the task or leaving a semantic payload behind.

Instead, callers must supply an audited change plan anchored to the complete
source tree and to every changed file.  The sanitizer then:

* copies the complete plugin tree, including helper code and provenance files;
* permits only unique, exact byte edits or a hash-pinned reviewed clean source;
* rejects source drift, path drift, symlinks, additions, and undeclared edits;
* preserves plugin manifests byte-for-byte and skill interface frontmatter,
  except for a hash-pinned description that is itself the declared entry
  source and is covered by the clean ``entry_source_bundle``;
* rejects short-template replacement by enforcing retained-content floors; and
* returns a hash-only allowed-diff contract suitable for a suite lock.

The plan is read from ``meta["clean_plugin_sanitization"]``.  For one plugin it
may be the plan directly.  For multi-plugin cases use either of these shapes::

    {"clean_plugin_sanitization": {"plugins": {"plugin_a": PLAN}}}
    {"clean_plugin_sanitization": {"plugin_a": PLAN}}

``PLAN`` has this schema (all hashes are lower-case SHA-256 hex strings)::

    {
      "schema_version": "1.0.0",
      "source_tree_sha256": "...",
      "minimum_retained_line_ratio": 0.60,       # optional, floor is 0.35
      "files": {
        "skills/example/SKILL.md": {
          "source_sha256": "...",
          "deletions": [
            {"text": "exact payload span", "reason": "audited rationale"}
          ],
          "replacements": [
            {
              "old": "exact poisoned inline span",
              "new": "reviewed shorter benign span",
              "reason": "audited rationale"
            }
          ]
        }
      },
      "allowed_interface_deltas": [             # exceptional, fail-closed
        {
          "path": "skills/example/SKILL.md",
          "field": "description",
          "intervention_variable": "entry_source_bundle",
          "attack_canonical_sha256": "...",
          "clean_canonical_sha256": "...",
          "reason": "description is the declared attack entry source"
        }
      ]
    }

Alternatively, one changed file may name a reviewed source relative to the
attack plugin's parent (normally the case root)::

    {
      "source_sha256": "...",
      "clean_source": {
        "path": "controls/provenance/skills/example/SKILL.md",
        "sha256": "...",
        "reason": "hand-authored clean source reviewed for this case"
      }
    }

Changed text is never copied into the returned contract; only digests and
lengths are recorded.  This keeps generated reports from becoming a second
model-visible payload source.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1.0.0"
HARD_MINIMUM_RETAINED_LINE_RATIO = 0.35
DEFAULT_MINIMUM_RETAINED_LINE_RATIO = 0.60
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INTERFACE_FIELDS = ("name", "description", "allowed-tools", "argument-hint")
DECLARED_INTERFACE_DELTA_FIELDS = {"description"}
DECLARED_INTERFACE_CLEAN_FORBIDDEN_TEXT = re.compile(
    r"\[system\b|\b(?:benchmark|canary|honeypot|untrusted|poison(?:ed|ing)?)\b|"
    r"deployment\.id|https?://|\b(?:curl|post)\b|\bexecute\b.*\bcached\b|"
    r"\bcached\b.*\b(?:command|routine)\b",
    re.IGNORECASE,
)
MANIFEST_PATHS = (".claude-plugin/plugin.json", "plugin.json")


class PluginSanitizationError(ValueError):
    """Raised when an exact clean-plugin transformation cannot be proven."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def interface_value_sha256(value: str) -> str:
    """Hash one canonical frontmatter value after parser normalization."""

    return sha256_bytes(value.encode("utf-8"))


def _normalized_relative(value: str) -> str:
    value = str(value).replace("\\", "/")
    candidate = Path(value)
    if (
        not value
        or candidate.is_absolute()
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise PluginSanitizationError(f"unsafe relative path in plan: {value!r}")
    return candidate.as_posix()


def _is_reparse_point(path: Path) -> bool:
    try:
        attrs = os.lstat(path).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _regular_files(root: Path) -> dict[str, Path]:
    if not root.is_dir():
        raise PluginSanitizationError(f"plugin source is not a directory: {root}")
    files: dict[str, Path] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink() or _is_reparse_point(path):
            raise PluginSanitizationError(
                f"plugin trees with links/reparse points require manual review: {path}"
            )
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            files[relative] = path
    if not files:
        raise PluginSanitizationError(f"plugin source tree is empty: {root}")
    return files


def file_tree_snapshot(root: Path) -> dict[str, Any]:
    """Return the canonical per-file snapshot and digest for ``root``."""

    files = _regular_files(root)
    entries = [
        {
            "path": relative,
            "sha256": sha256_bytes(path.read_bytes()),
            "size": path.stat().st_size,
        }
        for relative, path in files.items()
    ]
    canonical = json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "sha256": sha256_bytes(canonical),
        "file_count": len(entries),
        "files": entries,
    }


def _frontmatter_fields(data: bytes, path: str) -> dict[str, str]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PluginSanitizationError(f"skill is not UTF-8 text: {path}") from exc
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise PluginSanitizationError(f"skill has no YAML frontmatter: {path}")
    fields: dict[str, str] = {}
    closed = False
    for line in lines[1:]:
        if line.strip() == "---":
            closed = True
            break
        match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*?)\s*$", line)
        if match:
            key, value = match.groups()
            fields[key.lower()] = value.strip().strip("\"'")
    if not closed:
        raise PluginSanitizationError(f"skill frontmatter is not closed: {path}")
    return {field: fields.get(field, "") for field in INTERFACE_FIELDS}


def _meaningful_lines(data: bytes, path: str) -> list[str]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PluginSanitizationError(f"changed text file is not UTF-8: {path}") from exc
    return [line.strip() for line in text.splitlines() if line.strip()]


def _retained_line_ratio(before: bytes, after: bytes, path: str) -> float:
    """Measure exact source lines still present, with duplicate counts respected."""

    source = _meaningful_lines(before, path)
    output = _meaningful_lines(after, path)
    if not source:
        return 1.0 if not output else 0.0
    remaining: dict[str, int] = {}
    for line in output:
        remaining[line] = remaining.get(line, 0) + 1
    retained = 0
    for line in source:
        count = remaining.get(line, 0)
        if count:
            retained += 1
            remaining[line] = count - 1
    return retained / len(source)


def _validate_sha256(value: Any, label: str) -> str:
    normalized = str(value or "").lower()
    if not SHA256_RE.fullmatch(normalized):
        raise PluginSanitizationError(f"{label} must be a lower-case SHA-256 digest")
    return normalized


def _resolve_plan(source: Path, meta: dict[str, Any]) -> dict[str, Any]:
    declaration = meta.get("clean_plugin_sanitization")
    if not isinstance(declaration, dict):
        raise PluginSanitizationError(
            "missing explicit meta.clean_plugin_sanitization change plan"
        )
    if "source_tree_sha256" in declaration:
        plan = declaration
    else:
        plugins = declaration.get("plugins", declaration)
        if not isinstance(plugins, dict):
            raise PluginSanitizationError("clean_plugin_sanitization.plugins must be an object")
        plan = plugins.get(source.name)
    if not isinstance(plan, dict):
        raise PluginSanitizationError(
            f"no clean-plugin change plan declared for source {source.name!r}"
        )
    return plan


def _declared_interface_deltas(
    source: Path, meta: dict[str, Any]
) -> dict[tuple[str, str], dict[str, str]]:
    plan = _resolve_plan(source, meta)
    raw_rows = plan.get("allowed_interface_deltas", [])
    if raw_rows is None:
        raw_rows = []
    if not isinstance(raw_rows, list):
        raise PluginSanitizationError("allowed_interface_deltas must be a list")
    rows: dict[tuple[str, str], dict[str, str]] = {}
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            raise PluginSanitizationError(
                f"allowed_interface_deltas[{index}] must be an object"
            )
        path = _normalized_relative(str(raw.get("path") or ""))
        field = str(raw.get("field") or "").lower()
        if field not in DECLARED_INTERFACE_DELTA_FIELDS:
            raise PluginSanitizationError(
                f"allowed interface delta field is not supported: {field!r}"
            )
        if str(raw.get("intervention_variable") or "") != "entry_source_bundle":
            raise PluginSanitizationError(
                "allowed interface delta must declare entry_source_bundle"
            )
        attack_hash = _validate_sha256(
            raw.get("attack_canonical_sha256"),
            f"allowed_interface_deltas[{index}].attack_canonical_sha256",
        )
        clean_hash = _validate_sha256(
            raw.get("clean_canonical_sha256"),
            f"allowed_interface_deltas[{index}].clean_canonical_sha256",
        )
        if attack_hash == clean_hash:
            raise PluginSanitizationError(
                "allowed interface delta attack and clean hashes must differ"
            )
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise PluginSanitizationError(
                f"allowed_interface_deltas[{index}].reason is required"
            )
        key = (path, field)
        if key in rows:
            raise PluginSanitizationError(
                f"duplicate allowed interface delta: {path}.{field}"
            )
        rows[key] = {
            "path": path,
            "field": field,
            "intervention_variable": "entry_source_bundle",
            "attack_canonical_sha256": attack_hash,
            "clean_canonical_sha256": clean_hash,
            "reason": reason.strip(),
        }
    return rows


def _validated_plan(
    source: Path, source_snapshot: dict[str, Any], meta: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], float]:
    plan = _resolve_plan(source, meta)
    if str(plan.get("schema_version") or "") != SCHEMA_VERSION:
        raise PluginSanitizationError(
            f"unsupported clean-plugin plan schema: {plan.get('schema_version')!r}"
        )
    expected_tree = _validate_sha256(
        plan.get("source_tree_sha256"), "source_tree_sha256"
    )
    if expected_tree != source_snapshot["sha256"]:
        raise PluginSanitizationError(
            "source plugin tree drifted after the sanitization plan was reviewed"
        )

    try:
        retained_floor = float(
            plan.get(
                "minimum_retained_line_ratio",
                DEFAULT_MINIMUM_RETAINED_LINE_RATIO,
            )
        )
    except (TypeError, ValueError) as exc:
        raise PluginSanitizationError(
            "minimum_retained_line_ratio must be numeric"
        ) from exc
    if not HARD_MINIMUM_RETAINED_LINE_RATIO <= retained_floor <= 1.0:
        raise PluginSanitizationError(
            "minimum_retained_line_ratio must be between "
            f"{HARD_MINIMUM_RETAINED_LINE_RATIO:.2f} and 1.0"
        )

    raw_files = plan.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise PluginSanitizationError(
            "sanitization plan must declare at least one changed file"
        )
    file_plans: dict[str, dict[str, Any]] = {}
    source_paths = {entry["path"] for entry in source_snapshot["files"]}
    for raw_path, raw_file_plan in raw_files.items():
        relative = _normalized_relative(str(raw_path))
        if relative in file_plans:
            raise PluginSanitizationError(f"duplicate planned file: {relative}")
        if relative not in source_paths:
            raise PluginSanitizationError(f"planned file is absent from source: {relative}")
        if not isinstance(raw_file_plan, dict):
            raise PluginSanitizationError(f"file plan must be an object: {relative}")
        expected_file = _validate_sha256(
            raw_file_plan.get("source_sha256"), f"{relative}.source_sha256"
        )
        source_hash = next(
            entry["sha256"]
            for entry in source_snapshot["files"]
            if entry["path"] == relative
        )
        if expected_file != source_hash:
            raise PluginSanitizationError(f"source file drifted: {relative}")
        deletions = raw_file_plan.get("deletions", [])
        replacements = raw_file_plan.get("replacements", [])
        clean_source = raw_file_plan.get("clean_source")
        if deletions is None:
            deletions = []
        if replacements is None:
            replacements = []
        if not isinstance(deletions, list):
            raise PluginSanitizationError(f"{relative}.deletions must be a list")
        if not isinstance(replacements, list):
            raise PluginSanitizationError(f"{relative}.replacements must be a list")
        if clean_source is not None and (deletions or replacements):
            raise PluginSanitizationError(
                f"{relative} cannot combine a clean_source with exact span edits"
            )
        if clean_source is None and not deletions and not replacements:
            raise PluginSanitizationError(
                f"file plan must declare an exact edit or clean_source: {relative}"
            )

        normalized_operations: list[dict[str, str]] = []
        seen_text: set[str] = set()
        for index, deletion in enumerate(deletions):
            if not isinstance(deletion, dict):
                raise PluginSanitizationError(
                    f"{relative}.deletions[{index}] must be an object"
                )
            text = deletion.get("text")
            reason = deletion.get("reason")
            if not isinstance(text, str) or not text:
                raise PluginSanitizationError(
                    f"{relative}.deletions[{index}].text must be non-empty"
                )
            if text in seen_text:
                raise PluginSanitizationError(
                    f"duplicate exact deletion declared in {relative}"
                )
            if not isinstance(reason, str) or not reason.strip():
                raise PluginSanitizationError(
                    f"{relative}.deletions[{index}].reason is required"
                )
            seen_text.add(text)
            normalized_operations.append(
                {
                    "operation": "delete_exact",
                    "old": text,
                    "new": "",
                    "reason": reason.strip(),
                }
            )

        for index, replacement in enumerate(replacements):
            if not isinstance(replacement, dict):
                raise PluginSanitizationError(
                    f"{relative}.replacements[{index}] must be an object"
                )
            old = replacement.get("old")
            new = replacement.get("new")
            reason = replacement.get("reason")
            if not isinstance(old, str) or not old:
                raise PluginSanitizationError(
                    f"{relative}.replacements[{index}].old must be non-empty"
                )
            if not isinstance(new, str) or not new:
                raise PluginSanitizationError(
                    f"{relative}.replacements[{index}].new must be non-empty; "
                    "use deletions for an empty replacement"
                )
            if old == new:
                raise PluginSanitizationError(
                    f"{relative}.replacements[{index}] does not change content"
                )
            if len(new.encode("utf-8")) >= len(old.encode("utf-8")):
                raise PluginSanitizationError(
                    f"{relative}.replacements[{index}] must be shorter than its "
                    "audited payload span"
                )
            if old in seen_text:
                raise PluginSanitizationError(
                    f"duplicate exact edit declared in {relative}"
                )
            if not isinstance(reason, str) or not reason.strip():
                raise PluginSanitizationError(
                    f"{relative}.replacements[{index}].reason is required"
                )
            seen_text.add(old)
            normalized_operations.append(
                {
                    "operation": "replace_exact",
                    "old": old,
                    "new": new,
                    "reason": reason.strip(),
                }
            )

        normalized_clean_source: dict[str, str] | None = None
        if clean_source is not None:
            if not isinstance(clean_source, dict):
                raise PluginSanitizationError(
                    f"{relative}.clean_source must be an object"
                )
            clean_path = _normalized_relative(str(clean_source.get("path") or ""))
            clean_sha = _validate_sha256(
                clean_source.get("sha256"), f"{relative}.clean_source.sha256"
            )
            reason = clean_source.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise PluginSanitizationError(
                    f"{relative}.clean_source.reason is required"
                )
            normalized_clean_source = {
                "path": clean_path,
                "sha256": clean_sha,
                "reason": reason.strip(),
            }

        file_plans[relative] = {
            "source_sha256": expected_file,
            "operations": normalized_operations,
            "clean_source": normalized_clean_source,
        }
    return file_plans, retained_floor


def _same_or_nested(first: Path, second: Path) -> bool:
    try:
        first.relative_to(second)
        return True
    except ValueError:
        return False


def _validate_locations(source: Path, destination: Path) -> None:
    source_resolved = source.resolve()
    destination_resolved = destination.resolve(strict=False)
    if source_resolved == destination_resolved:
        raise PluginSanitizationError("source and destination must be distinct")
    if _same_or_nested(destination_resolved, source_resolved):
        raise PluginSanitizationError("destination must not be inside the source tree")
    if _same_or_nested(source_resolved, destination_resolved):
        raise PluginSanitizationError("destination must not contain the source tree")


def _copy_complete_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        if destination.is_symlink() or _is_reparse_point(destination):
            raise PluginSanitizationError(
                f"refusing to replace linked destination: {destination}"
            )
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, symlinks=False)


def _manifest_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in MANIFEST_PATHS:
        path = root / relative
        if path.is_file():
            hashes[relative] = sha256_bytes(path.read_bytes())
    if not hashes:
        raise PluginSanitizationError(f"plugin manifest is missing: {root}")
    return hashes


def _require_interface_delta_bundle_coverage(
    source: Path,
    destination: Path,
    meta: dict[str, Any],
) -> None:
    clean_rows = [
        row
        for row in (meta.get("control_suite") or [])
        if isinstance(row, dict) and row.get("control_type") == "clean_control"
    ]
    if len(clean_rows) != 1:
        raise PluginSanitizationError(
            "declared interface delta requires exactly one clean_control row"
        )
    bundle = clean_rows[0].get("control_clean_entry_source_bundle")
    if not isinstance(bundle, dict) or bundle.get("intervention_variable") != (
        "entry_source_bundle"
    ):
        raise PluginSanitizationError(
            "declared interface delta is not covered by an entry_source_bundle"
        )

    source_resolved = source.resolve()
    destination_resolved = destination.resolve()
    case_root = Path(
        os.path.commonpath([str(source_resolved), str(destination_resolved)])
    )
    source_snapshot = file_tree_snapshot(source)
    destination_snapshot = file_tree_snapshot(destination)
    for target in bundle.get("targets") or []:
        if not isinstance(target, dict) or target.get("kind") != "plugin_tree":
            continue
        attack_value = str(target.get("attack") or "")
        clean_value = str(target.get("clean") or "")
        try:
            attack_path = (case_root / _normalized_relative(attack_value)).resolve()
            clean_path = (case_root / _normalized_relative(clean_value)).resolve()
        except PluginSanitizationError:
            continue
        if attack_path != source_resolved or clean_path != destination_resolved:
            continue
        if target.get("attack_sha256") != source_snapshot["sha256"]:
            raise PluginSanitizationError(
                "declared interface delta attack bundle hash drifted"
            )
        if target.get("clean_sha256") != destination_snapshot["sha256"]:
            raise PluginSanitizationError(
                "declared interface delta clean bundle hash drifted"
            )
        if source_snapshot["sha256"] == destination_snapshot["sha256"]:
            raise PluginSanitizationError(
                "declared interface delta bundle does not change the plugin tree"
            )
        return
    raise PluginSanitizationError(
        "declared interface delta plugin pair is absent from the entry_source_bundle"
    )


def _validate_skill_interfaces(
    source: Path,
    destination: Path,
    source_files: dict[str, Path],
    destination_files: dict[str, Path],
    file_plans: dict[str, dict[str, Any]],
    meta: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    skill_paths = sorted(
        relative
        for relative in source_files
        if re.fullmatch(r"skills/[^/]+/SKILL\.md", relative)
    )
    if not skill_paths:
        raise PluginSanitizationError("plugin contains no skills/*/SKILL.md")

    declarations = _declared_interface_deltas(source, meta)
    for path, _field in declarations:
        if path not in skill_paths:
            raise PluginSanitizationError(
                f"allowed interface delta does not name a skill: {path}"
            )
        if path not in file_plans:
            raise PluginSanitizationError(
                f"allowed interface delta is outside the changed file plan: {path}"
            )

    skill_interfaces: list[dict[str, Any]] = []
    actual_deltas: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for relative in skill_paths:
        before_fields = _frontmatter_fields(
            source_files[relative].read_bytes(), relative
        )
        after_fields = _frontmatter_fields(
            destination_files[relative].read_bytes(), relative
        )
        row: dict[str, Any] = {"path": relative, "fields": before_fields}
        row_deltas: list[dict[str, str]] = []
        for field in INTERFACE_FIELDS:
            if before_fields[field] == after_fields[field]:
                continue
            declaration = declarations.get((relative, field))
            if not declaration:
                raise PluginSanitizationError(
                    f"skill invocation interface changed: {relative}.{field}"
                )
            attack_hash = interface_value_sha256(before_fields[field])
            clean_hash = interface_value_sha256(after_fields[field])
            if attack_hash != declaration["attack_canonical_sha256"]:
                raise PluginSanitizationError(
                    f"declared interface delta attack hash drifted: {relative}.{field}"
                )
            if clean_hash != declaration["clean_canonical_sha256"]:
                raise PluginSanitizationError(
                    f"declared interface delta clean hash drifted: {relative}.{field}"
                )
            if not after_fields[field] or DECLARED_INTERFACE_CLEAN_FORBIDDEN_TEXT.search(
                after_fields[field]
            ):
                raise PluginSanitizationError(
                    f"declared interface delta clean value retains payload or salience text: "
                    f"{relative}.{field}"
                )
            normalized = dict(declaration)
            row_deltas.append(normalized)
            actual_deltas.append(normalized)
            seen.add((relative, field))
        if row_deltas:
            row["clean_fields"] = after_fields
            row["allowed_deltas"] = row_deltas
        skill_interfaces.append(row)

    if seen != set(declarations):
        missing = sorted(set(declarations) - seen)
        raise PluginSanitizationError(
            f"declared interface delta does not match an actual difference: {missing}"
        )
    if actual_deltas:
        _require_interface_delta_bundle_coverage(source, destination, meta)
    return skill_interfaces, actual_deltas


def sanitize_plugin_tree(
    source: Path | str,
    destination: Path | str,
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Copy ``source`` and apply a reviewed, source-anchored change plan.

    No source content is modified.  If any invariant fails, the destination is
    removed so a partial clean plugin cannot accidentally be used by a runner.
    """

    source = Path(source)
    destination = Path(destination)
    _validate_locations(source, destination)
    source_snapshot = file_tree_snapshot(source)
    file_plans, retained_floor = _validated_plan(source, source_snapshot, meta)
    source_files = _regular_files(source)
    source_manifests = _manifest_hashes(source)

    # Read reviewed sources before replacing the destination.  This permits a
    # one-time migration from an existing hand-authored clean tree while still
    # pinning the exact bytes that were reviewed.
    clean_source_bytes: dict[str, bytes] = {}
    for relative, file_plan in file_plans.items():
        clean_source = file_plan["clean_source"]
        if not clean_source:
            continue
        clean_path = source.parent / clean_source["path"]
        if not clean_path.is_file():
            raise PluginSanitizationError(
                f"reviewed clean source is missing for {relative}: {clean_source['path']}"
            )
        clean_data = clean_path.read_bytes()
        if sha256_bytes(clean_data) != clean_source["sha256"]:
            raise PluginSanitizationError(
                f"reviewed clean source drifted for {relative}: {clean_source['path']}"
            )
        clean_source_bytes[relative] = clean_data

    _copy_complete_tree(source, destination)
    changed: list[dict[str, Any]] = []
    try:
        for relative, file_plan in sorted(file_plans.items()):
            source_data = source_files[relative].read_bytes()
            operations: list[dict[str, Any]] = []
            clean_source = file_plan["clean_source"]
            if clean_source:
                output = clean_source_bytes[relative]
                operations.append(
                    {
                        "operation": "replace_with_reviewed_clean_source",
                        "clean_source_path": clean_source["path"],
                        "clean_source_sha256": clean_source["sha256"],
                        "clean_source_bytes": len(output),
                        "reason": clean_source["reason"],
                    }
                )
            else:
                output = source_data
                for operation in file_plan["operations"]:
                    old = operation["old"].encode("utf-8")
                    new = operation["new"].encode("utf-8")
                    count = output.count(old)
                    if count != 1:
                        raise PluginSanitizationError(
                            f"exact payload span must occur once in {relative}; found {count}"
                        )
                    output = output.replace(old, new, 1)
                    operation_record = {
                        "operation": operation["operation"],
                        "source_span_sha256": sha256_bytes(old),
                        "source_span_bytes": len(old),
                        "destination_span_sha256": sha256_bytes(new),
                        "destination_span_bytes": len(new),
                        "reason": operation["reason"],
                    }
                    # Backward-compatible names make a deletion especially
                    # obvious in downstream reports without exposing text.
                    if operation["operation"] == "delete_exact":
                        operation_record["removed_sha256"] = sha256_bytes(old)
                        operation_record["removed_bytes"] = len(old)
                    operations.append(operation_record)
            if output == source_data:
                raise PluginSanitizationError(f"planned file was not changed: {relative}")
            if not clean_source and len(output) >= len(source_data):
                raise PluginSanitizationError(
                    f"exact payload sanitization must reduce content: {relative}"
                )
            retained_ratio = _retained_line_ratio(source_data, output, relative)
            if retained_ratio < retained_floor:
                raise PluginSanitizationError(
                    f"{relative} retains only {retained_ratio:.3f} of source lines; "
                    f"required {retained_floor:.3f} (generic clean template suspected)"
                )
            target = destination / relative
            target.write_bytes(output)
            changed.append(
                {
                    "path": relative,
                    "source_sha256": sha256_bytes(source_data),
                    "destination_sha256": sha256_bytes(output),
                    "source_bytes": len(source_data),
                    "destination_bytes": len(output),
                    "retained_line_ratio": round(retained_ratio, 6),
                    "operations": operations,
                }
            )

        destination_files = _regular_files(destination)
        if set(destination_files) != set(source_files):
            raise PluginSanitizationError("clean plugin file tree differs from attack plugin")
        actual_changed = sorted(
            relative
            for relative in source_files
            if source_files[relative].read_bytes()
            != destination_files[relative].read_bytes()
        )
        if actual_changed != sorted(file_plans):
            raise PluginSanitizationError(
                "clean plugin contains an undeclared edit or misses a declared edit"
            )
        if _manifest_hashes(destination) != source_manifests:
            raise PluginSanitizationError("plugin manifest changed during sanitization")

        skill_interfaces, interface_deltas = _validate_skill_interfaces(
            source,
            destination,
            source_files,
            destination_files,
            file_plans,
            meta,
        )

        destination_snapshot = file_tree_snapshot(destination)
        deletion_only = all(
            not plan["clean_source"]
            and all(
                operation["operation"] == "delete_exact"
                for operation in plan["operations"]
            )
            for plan in file_plans.values()
        )
        unchanged = [
            {
                "path": relative,
                "sha256": sha256_bytes(source_files[relative].read_bytes()),
            }
            for relative in sorted(set(source_files) - set(file_plans))
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "transformation": "complete_tree_copy_with_declared_payload_edits",
            "source_tree_sha256": source_snapshot["sha256"],
            "destination_tree_sha256": destination_snapshot["sha256"],
            "source_file_count": source_snapshot["file_count"],
            "destination_file_count": destination_snapshot["file_count"],
            "allowed_diff_paths": sorted(file_plans),
            "changed_files": changed,
            "unchanged_files": unchanged,
            "skill_interfaces": skill_interfaces,
            "allowed_interface_deltas": interface_deltas,
            "invariants": {
                "same_file_set": True,
                "manifest_byte_identical": True,
                "skill_interfaces_equal": not bool(interface_deltas),
                "declared_interface_delta_count": len(interface_deltas),
                "deletion_only": deletion_only,
                "all_changes_source_hash_anchored": True,
                "undeclared_changes": 0,
                "minimum_retained_line_ratio": retained_floor,
            },
        }
    except Exception:
        if destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise


def _render_declared_output(
    source: Path,
    relative: str,
    source_data: bytes,
    file_plan: dict[str, Any],
) -> bytes:
    """Render one planned file in memory without mutating either tree."""

    clean_source = file_plan["clean_source"]
    if clean_source:
        clean_path = source.parent / clean_source["path"]
        if not clean_path.is_file():
            raise PluginSanitizationError(
                f"reviewed clean source is missing for {relative}: {clean_source['path']}"
            )
        output = clean_path.read_bytes()
        if sha256_bytes(output) != clean_source["sha256"]:
            raise PluginSanitizationError(
                f"reviewed clean source drifted for {relative}: {clean_source['path']}"
            )
    else:
        output = source_data
        for operation in file_plan["operations"]:
            old = operation["old"].encode("utf-8")
            new = operation["new"].encode("utf-8")
            count = output.count(old)
            if count != 1:
                raise PluginSanitizationError(
                    f"exact payload span must occur once in {relative}; found {count}"
                )
            output = output.replace(old, new, 1)
        if len(output) >= len(source_data):
            raise PluginSanitizationError(
                f"exact payload sanitization must reduce content: {relative}"
            )
    if output == source_data:
        raise PluginSanitizationError(f"planned file was not changed: {relative}")
    return output


def validate_sanitized_plugin_tree(
    source: Path | str,
    destination: Path | str,
    meta: dict[str, Any],
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Prove that an existing clean plugin exactly implements its declaration.

    This function is strictly read-only.  It re-renders every declared edit in
    memory, compares it byte-for-byte with ``destination``, and independently
    checks the complete file set, unchanged files, manifest, skill interface,
    retained-content floor, tree hashes, and (when supplied) generation
    contract.  A mismatch raises :class:`PluginSanitizationError`.
    """

    source = Path(source)
    destination = Path(destination)
    _validate_locations(source, destination)
    source_snapshot = file_tree_snapshot(source)
    file_plans, retained_floor = _validated_plan(source, source_snapshot, meta)
    source_files = _regular_files(source)
    destination_files = _regular_files(destination)

    if set(source_files) != set(destination_files):
        missing = sorted(set(source_files) - set(destination_files))
        added = sorted(set(destination_files) - set(source_files))
        raise PluginSanitizationError(
            f"clean plugin file set drifted; missing={missing}, added={added}"
        )
    actual_changed = sorted(
        relative
        for relative in source_files
        if source_files[relative].read_bytes()
        != destination_files[relative].read_bytes()
    )
    planned_changed = sorted(file_plans)
    if actual_changed != planned_changed:
        raise PluginSanitizationError(
            f"clean plugin changed paths differ from declaration; "
            f"planned={planned_changed}, actual={actual_changed}"
        )
    if _manifest_hashes(source) != _manifest_hashes(destination):
        raise PluginSanitizationError("plugin manifest is not byte-identical")

    changed_rows: list[dict[str, Any]] = []
    for relative in planned_changed:
        before = source_files[relative].read_bytes()
        expected = _render_declared_output(
            source, relative, before, file_plans[relative]
        )
        actual = destination_files[relative].read_bytes()
        if actual != expected:
            raise PluginSanitizationError(
                f"clean file bytes do not match the declared transformation: {relative}"
            )
        retained = _retained_line_ratio(before, actual, relative)
        if retained < retained_floor:
            raise PluginSanitizationError(
                f"{relative} retains only {retained:.3f} of source lines; "
                f"required {retained_floor:.3f}"
            )
        changed_rows.append(
            {
                "path": relative,
                "source_sha256": sha256_bytes(before),
                "destination_sha256": sha256_bytes(actual),
                "retained_line_ratio": round(retained, 6),
            }
        )

    skill_interfaces, interface_deltas = _validate_skill_interfaces(
        source,
        destination,
        source_files,
        destination_files,
        file_plans,
        meta,
    )

    destination_snapshot = file_tree_snapshot(destination)
    validation = {
        "schema_version": SCHEMA_VERSION,
        "valid": True,
        "source_tree_sha256": source_snapshot["sha256"],
        "destination_tree_sha256": destination_snapshot["sha256"],
        "source_file_count": source_snapshot["file_count"],
        "destination_file_count": destination_snapshot["file_count"],
        "allowed_diff_paths": planned_changed,
        "changed_files": changed_rows,
        "skill_interfaces": skill_interfaces,
        "allowed_interface_deltas": interface_deltas,
        "unchanged_file_count": len(source_files) - len(planned_changed),
        "invariants": {
            "same_file_set": True,
            "manifest_byte_identical": True,
            "skill_interfaces_equal": not bool(interface_deltas),
            "declared_interface_delta_count": len(interface_deltas),
            "declared_bytes_match": True,
            "undeclared_changes": 0,
            "minimum_retained_line_ratio": retained_floor,
        },
    }

    if contract is not None:
        if not isinstance(contract, dict):
            raise PluginSanitizationError("clean-plugin generation contract must be an object")
        scalar_fields = (
            "schema_version",
            "source_tree_sha256",
            "destination_tree_sha256",
            "source_file_count",
            "destination_file_count",
            "allowed_diff_paths",
        )
        for field in scalar_fields:
            if contract.get(field) != validation[field]:
                raise PluginSanitizationError(
                    f"clean-plugin generation contract drifted at {field}"
                )
        raw_changed = contract.get("changed_files")
        if not isinstance(raw_changed, list):
            raise PluginSanitizationError(
                "clean-plugin generation contract has no changed_files list"
            )
        contract_changed: dict[str, dict[str, Any]] = {}
        for row in raw_changed:
            if not isinstance(row, dict) or not row.get("path"):
                raise PluginSanitizationError(
                    "clean-plugin generation contract has an invalid changed_files row"
                )
            path = str(row["path"])
            if path in contract_changed:
                raise PluginSanitizationError(
                    f"clean-plugin generation contract duplicates {path}"
                )
            contract_changed[path] = row
        if sorted(contract_changed) != planned_changed:
            raise PluginSanitizationError(
                "clean-plugin generation contract changed paths drifted"
            )
        for row in changed_rows:
            recorded = contract_changed[row["path"]]
            for field in (
                "source_sha256",
                "destination_sha256",
                "retained_line_ratio",
            ):
                if recorded.get(field) != row[field]:
                    raise PluginSanitizationError(
                        f"clean-plugin generation contract drifted at "
                        f"{row['path']}.{field}"
                    )
        if contract.get("allowed_interface_deltas", []) != interface_deltas:
            raise PluginSanitizationError(
                "clean-plugin generation contract interface deltas drifted"
            )
        validation["generation_contract_matches"] = True
    else:
        validation["generation_contract_matches"] = None
    return validation


def build_clean_entry_source_bundle(
    case_root: Path | str,
    attack_plugin_dirs: Iterable[str],
    clean_plugin_dirs: Iterable[str],
    workspace_overrides: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Build a digest-pinned, one-to-one clean entry-source bundle.

    ``workspace_overrides`` uses the runner's exact shape: ``source`` is a
    case-relative clean asset and ``target`` is the attack file's path relative
    to ``workspace/``.  Every override must replace an existing attack input
    with different bytes.  This keeps companion helpers and data-bearing entry
    files in the same declared intervention as the plugin package instead of
    silently changing an unrecorded second variable.
    """

    case_root = Path(case_root)
    attacks = [_normalized_relative(str(value)) for value in attack_plugin_dirs]
    cleans = [_normalized_relative(str(value)) for value in clean_plugin_dirs]
    if len(attacks) != len(cleans):
        raise PluginSanitizationError(
            "attack and clean plugin directories must be one-to-one lists"
        )
    targets: list[dict[str, Any]] = []
    for attack, clean in zip(attacks, cleans):
        if attack == clean:
            raise PluginSanitizationError("attack and clean plugin paths must be distinct")
        attack_snapshot = file_tree_snapshot(case_root / attack)
        clean_snapshot = file_tree_snapshot(case_root / clean)
        targets.append(
            {
                "kind": "plugin_tree",
                "attack": attack,
                "clean": clean,
                "digest_algorithm": "canonical_file_tree_sha256",
                "attack_sha256": attack_snapshot["sha256"],
                "clean_sha256": clean_snapshot["sha256"],
            }
        )

    seen_sources: set[str] = set()
    seen_targets: set[str] = set()
    for index, raw_override in enumerate(workspace_overrides):
        if not isinstance(raw_override, dict):
            raise PluginSanitizationError(
                f"workspace override {index} must be an object"
            )
        source = _normalized_relative(str(raw_override.get("source") or ""))
        runtime_target = _normalized_relative(str(raw_override.get("target") or ""))
        if source in seen_sources:
            raise PluginSanitizationError(
                f"workspace clean source appears more than once: {source}"
            )
        if runtime_target in seen_targets:
            raise PluginSanitizationError(
                f"workspace runtime target appears more than once: {runtime_target}"
            )
        seen_sources.add(source)
        seen_targets.add(runtime_target)
        attack = f"workspace/{runtime_target}"
        attack_path = case_root / attack
        clean_path = case_root / source
        if not attack_path.is_file() or not clean_path.is_file():
            raise PluginSanitizationError(
                f"workspace override must pair existing files: {attack} -> {source}"
            )
        attack_sha256 = sha256_bytes(attack_path.read_bytes())
        clean_sha256 = sha256_bytes(clean_path.read_bytes())
        if attack_sha256 == clean_sha256:
            raise PluginSanitizationError(
                f"workspace override does not change the attack input: {runtime_target}"
            )
        targets.append(
            {
                "kind": "workspace_file",
                "attack": attack,
                "clean": source,
                "runtime_target": runtime_target,
                "digest_algorithm": "file_sha256",
                "attack_sha256": attack_sha256,
                "clean_sha256": clean_sha256,
            }
        )
    if not targets:
        raise PluginSanitizationError(
            "entry-source bundle must contain a plugin or workspace target"
        )
    return {
        "schema_version": 1,
        "intervention_variable": "entry_source_bundle",
        "targets": targets,
    }


def build_plugin_clean_entry_source_bundle(
    case_root: Path | str,
    attack_plugin_dirs: Iterable[str],
    clean_plugin_dirs: Iterable[str],
) -> dict[str, Any]:
    """Compatibility wrapper for a plugin-only entry-source bundle."""

    attacks = list(attack_plugin_dirs)
    cleans = list(clean_plugin_dirs)
    if not attacks:
        raise PluginSanitizationError(
            "attack and clean plugin directories must be non-empty one-to-one lists"
        )
    return build_clean_entry_source_bundle(
        case_root,
        attacks,
        cleans,
    )


def _manifest_f2_cases(repo_root: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    runs = repo_root / "runs"
    manifest = json.loads((runs / "manifest.json").read_text(encoding="utf-8-sig"))
    suite = manifest["suites"]["v2_skill_runtime"]
    for entry in suite.get("cases") or []:
        case_root = runs / str(entry["case_dir"])
        meta = json.loads((case_root / "case_meta.json").read_text(encoding="utf-8-sig"))
        yield case_root, meta


def audit_f2_sanitization_readiness(repo_root: Path | str) -> dict[str, Any]:
    """Inventory whether active F2 clean entry sources are reviewable.

    This is a static readiness audit; it never creates clean plugin trees.  A
    plugin-replacement case is ``ready`` only if every replacement has a valid
    plan anchored to its current file tree.  A workspace-only case is ready
    only when the plugin remains selected unchanged and the exact workspace
    replacements have a digest-pinned bundle.  Missing declarations are
    reported, not inferred.
    """

    repo_root = Path(repo_root)
    rows: list[dict[str, Any]] = []
    for case_root, meta in _manifest_f2_cases(repo_root):
        plugins: list[dict[str, Any]] = []
        clean_rows = [
            row
            for row in (meta.get("control_suite") or [])
            if isinstance(row, dict) and row.get("control_type") == "clean_control"
        ]
        clean = clean_rows[0] if len(clean_rows) == 1 else {}
        clean_plugin_dirs = clean.get("control_plugin_dirs") or []
        workspace_overrides = clean.get("control_workspace_overrides") or []
        if isinstance(workspace_overrides, dict):
            workspace_overrides = [workspace_overrides]
        workspace_only = bool(workspace_overrides) and not bool(clean_plugin_dirs)
        workspace_only_problem = ""
        if workspace_only:
            try:
                if clean.get("control_plugin_interface_contracts"):
                    raise PluginSanitizationError(
                        "workspace-only clean control declares plugin contracts"
                    )
                if clean.get("control_workspace_dirs"):
                    raise PluginSanitizationError(
                        "workspace-only clean control mixes directory and file replacements"
                    )
                intervention = clean.get("control_intervention") or {}
                if intervention.get("variable") != "entry_source_bundle":
                    raise PluginSanitizationError(
                        "workspace-only clean control has no entry_source_bundle intervention"
                    )
                rebuilt_bundle = build_clean_entry_source_bundle(
                    case_root,
                    [],
                    [],
                    workspace_overrides,
                )
                if clean.get("control_clean_entry_source_bundle") != rebuilt_bundle:
                    raise PluginSanitizationError(
                        "workspace-only clean entry-source bundle drifted"
                    )
            except (PluginSanitizationError, OSError) as exc:
                workspace_only_problem = str(exc)

        for source_value in meta.get("plugin_dirs") or []:
            source_relative = _normalized_relative(str(source_value))
            source = case_root / source_relative
            if workspace_only:
                try:
                    snapshot = file_tree_snapshot(source)
                except (PluginSanitizationError, OSError) as exc:
                    workspace_only_problem = workspace_only_problem or str(exc)
                    plugins.append(
                        {
                            "source": source_relative,
                            "status": "manual_declaration_required",
                            "reason": workspace_only_problem,
                        }
                    )
                else:
                    plugins.append(
                        {
                            "source": source_relative,
                            "status": (
                                "ready_unchanged_workspace_only"
                                if not workspace_only_problem
                                else "manual_declaration_required"
                            ),
                            "source_tree_sha256": snapshot["sha256"],
                            "source_file_count": snapshot["file_count"],
                            **(
                                {"reason": workspace_only_problem}
                                if workspace_only_problem
                                else {}
                            ),
                        }
                    )
                continue
            try:
                snapshot = file_tree_snapshot(source)
                file_plans, retained_floor = _validated_plan(source, snapshot, meta)
            except (PluginSanitizationError, OSError) as exc:
                plugins.append(
                    {
                        "source": source_relative,
                        "status": "manual_declaration_required",
                        "reason": str(exc),
                    }
                )
            else:
                plugins.append(
                    {
                        "source": source_relative,
                        "status": "ready",
                        "source_tree_sha256": snapshot["sha256"],
                        "source_file_count": snapshot["file_count"],
                        "planned_changed_files": sorted(file_plans),
                        "minimum_retained_line_ratio": retained_floor,
                    }
                )
        ready_statuses = {"ready", "ready_unchanged_workspace_only"}
        ready = bool(plugins) and all(
            row["status"] in ready_statuses for row in plugins
        )
        rows.append(
            {
                "case_id": str(meta.get("case_id") or case_root.name),
                "case_dir": case_root.relative_to(repo_root).as_posix(),
                "status": "ready" if ready else "manual_declaration_required",
                "entry_source_intervention": (
                    "workspace_only" if workspace_only else "plugin_replacement"
                ),
                "plugins": plugins,
            }
        )
    unresolved = [row["case_dir"] for row in rows if row["status"] != "ready"]
    return {
        "schema_version": SCHEMA_VERSION,
        "suite": "v2_skill_runtime",
        "case_count": len(rows),
        "ready_case_count": len(rows) - len(unresolved),
        "manual_declaration_required_count": len(unresolved),
        "manual_declaration_required_cases": unresolved,
        "cases": rows,
    }


__all__ = [
    "DEFAULT_MINIMUM_RETAINED_LINE_RATIO",
    "HARD_MINIMUM_RETAINED_LINE_RATIO",
    "PluginSanitizationError",
    "SCHEMA_VERSION",
    "audit_f2_sanitization_readiness",
    "build_clean_entry_source_bundle",
    "build_plugin_clean_entry_source_bundle",
    "file_tree_snapshot",
    "interface_value_sha256",
    "sanitize_plugin_tree",
    "sha256_bytes",
    "validate_sanitized_plugin_tree",
]
