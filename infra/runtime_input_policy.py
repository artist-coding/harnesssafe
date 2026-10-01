"""Shared definition of materializable case inputs.

The suite lock and the case materializer must use the same exclusion policy.
Anything copied into ``materialized_case`` is a runtime input and therefore
must be content-locked.  In particular, generic project directories such as
``workspace/cache`` and ``workspace/tmp`` are not assumed to be disposable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


# These names have an unambiguous generated-output meaning and are never
# copied into a materialized case, wherever they appear in the source tree.
EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        "results",
        "results_mk18",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

EXCLUDED_FILE_NAMES = frozenset({".DS_Store", "Thumbs.db"})
EXCLUDED_FILE_SUFFIXES = frozenset({".pyc", ".pyo", ".tmp", ".temp", ".swp", ".swo"})
EDITOR_BACKUP_SUFFIX = "~"


def excluded_directory_name(name: str) -> bool:
    return name.casefold() in {item.casefold() for item in EXCLUDED_DIRECTORY_NAMES}


def excluded_file_name(name: str) -> bool:
    lowered = name.casefold()
    return (
        name in EXCLUDED_FILE_NAMES
        or any(lowered.endswith(suffix.casefold()) for suffix in EXCLUDED_FILE_SUFFIXES)
        or name.endswith(EDITOR_BACKUP_SUFFIX)
    )


def ignored_copy_names(directory: str | Path, names: Iterable[str]) -> set[str]:
    """Return exactly the entries that the materializer must not copy."""

    base = Path(directory)
    ignored: set[str] = set()
    for name in names:
        candidate = base / name
        if candidate.is_dir():
            if excluded_directory_name(name):
                ignored.add(name)
        elif excluded_file_name(name):
            ignored.add(name)
    return ignored


def policy_record() -> dict[str, object]:
    """Serializable policy embedded in the suite lock."""

    return {
        "directory_names": sorted(EXCLUDED_DIRECTORY_NAMES),
        "file_names": sorted(EXCLUDED_FILE_NAMES),
        "file_suffixes": sorted(EXCLUDED_FILE_SUFFIXES),
        "editor_backup_suffix": EDITOR_BACKUP_SUFFIX,
        "generic_cache_and_tmp_directories_are_runtime_inputs": True,
        "materializer_and_lock_share_policy": True,
        "case_meta_locked_separately": True,
    }
