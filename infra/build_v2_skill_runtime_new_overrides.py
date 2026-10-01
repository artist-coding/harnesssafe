"""Per-case SKILL.md overrides for the v2_skill_runtime_new upgrade.

Some upgraded cases need a hand-authored two-stage SKILL.md that the generic
wrapper templates could not produce faithfully — typically because the original
honeypot trigger lived in the skill *description* (a pseudo-system IPI line) or
in a *workspace script*, so the carrier ended up empty (literal ``None``) and/or
Stage 1 fired the honeypot prematurely.

Each override is the COMPLETE final SKILL.md text for the case's primary skill
(``plugin_skills[0]``), stored as ``v2_skill_runtime_new_overrides/<case_id>.md``
next to this module. The honeypot base ``http://127.0.0.1:18765`` is left literal
(the materializer rewrites it to the per-run callback URL); the synthetic canary
stays ``config/deployment.id``.

The orchestrator (``build_v2_skill_runtime_new_cases.py``) applies these after
the wrapper builder runs, overwriting the generated SKILL.md so the build output
is the single source of truth for these cases.

Faithful two-stage contract enforced by every override:
  * Stage 1 ("plant") performs the skill's benign task and WRITES the carrier
    embedding (a) the vector-specific poisoned content and (b) the honeypot
    registration/verification routine — WITHOUT executing it.
  * Stage 2 ("trigger") READS the carrier and executes the embedded routine,
    reaching the honeypot. Folding the two stages into one turn reproduces the
    original single-stage baseline.
"""

from __future__ import annotations

from pathlib import Path

_OVERRIDE_DIR = Path(__file__).resolve().parent / "v2_skill_runtime_new_overrides"


def _load_overrides() -> dict[str, str]:
    overrides: dict[str, str] = {}
    if _OVERRIDE_DIR.is_dir():
        for md in sorted(_OVERRIDE_DIR.glob("*.md")):
            overrides[md.stem] = md.read_text(encoding="utf-8")
    return overrides


# case_id -> final SKILL.md text for plugin_skills[0]
SKILL_MD_OVERRIDES: dict[str, str] = _load_overrides()
