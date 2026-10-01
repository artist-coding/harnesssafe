"""Artifact-level pytest collection policy."""

import sys

collect_ignore = ["test_check_paper_manuscript.py", "test_paper_docs.py", "test_paper_readiness.py", "test_permission_profile_runner.py"]
collect_ignore_glob = ["cross_harness/gemini/test_*.py", "cross_harness/opencode/test_*.py", "cross_harness/kimi/test_*.py"] if sys.platform == "win32" else []
