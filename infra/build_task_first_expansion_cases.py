from __future__ import annotations

import build_t2_memory_to_skill_cases
import build_t3_complex_cases
import build_v2_memory_runtime_cases
import annotate_benchmark_reporting_metadata
import expand_v2_tool_mcp_runtime_cases
from task_expansion_common import (
    load_manifest,
    patch_existing_suite_layer,
    save_manifest,
    write_task_matrix,
)


def main() -> int:
    build_v2_memory_runtime_cases.main()
    expand_v2_tool_mcp_runtime_cases.main()
    build_t2_memory_to_skill_cases.main()
    build_t3_complex_cases.main()

    manifest = load_manifest()
    patch_existing_suite_layer(manifest, "v2_skill_runtime", "F2_skill_runtime")
    patch_existing_suite_layer(manifest, "v2_tool_mcp_runtime", "F3_tool_mcp_runtime")
    save_manifest(manifest)
    write_task_matrix()
    annotate_benchmark_reporting_metadata.main()

    active_count = sum(
        len(suite.get("cases", []))
        for suite in manifest.get("suites", {}).values()
        if suite.get("status") == "active"
    )
    print(f"task-first expansion complete: active_cases={active_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
