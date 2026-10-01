"""Wrapper builder module for F2 Skill Runtime persistence upgrade.

This module intentionally contains no upgraded cases. All 14 cases from the
original builder (baseline + existing core) remain unchanged, so there is no
need to import or re-export any builder definitions here.

The orchestration script ``infra/build_v2_skill_runtime_new_cases.py`` expects
to import ``BUILDERS`` from this module, hence the empty dictionary.
"""
from __future__ import annotations

from typing import Any

BUILDERS: dict[str, Any] = {}
