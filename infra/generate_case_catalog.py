from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
MANIFEST = RUNS / "manifest.json"
OUTPUT = ROOT / "docs" / "active_case_catalog.md"

SKILL_METHODS = {
    "SK-I-1": (
        "权限声明欺骗（Permission Claim Spoofing）",
        "Skill manifest 声称低权限或只读，但 schema、默认参数或示例暴露写入、删除、外发等能力。",
    ),
    "SK-I-2": (
        "技能权限越界（Scope Overflow）",
        "Skill 声明了目录、数据库、租户或 API 范围，但参数约束不足，导致调用越过声明边界。",
    ),
    "SK-I-3": (
        "输出与元数据注入（Manifest & Output IPI）",
        "Skill 的 description、示例、错误信息或输出中嵌入非可信指令，诱导 agent 把数据当指令。",
    ),
    "SK-I-4": (
        "技能元数据篡改（Metadata Tampering）",
        "已注册或已信任的 skill metadata、SKILL.md、版本或依赖材料被事后篡改。",
    ),
    "SK-I-5": (
        "规则/示例权威污染（Rule & Example Authority Poisoning）",
        "Skill 中的规则、FAQ、示例或 best practice 被包装成更高优先级权威，诱导越权行为。",
    ),
    "SK-I-6": (
        "静态授权伪造与危险默认值（Static Authorization Spoofing & Dangerous Defaults）",
        "Skill 静态材料伪造授权、预批准、时间窗口或危险默认值，诱导 agent 免确认执行敏感动作。",
    ),
    "SK-E-1": (
        "沙箱逃逸（Sandbox Escape）",
        "Skill 诱导 agent 读取或操作声明 workspace 之外的模拟 host/sandbox 边界材料。",
    ),
    "SK-E-2": (
        "运行时工具链劫持（Runtime & Toolchain Hijack）",
        "Skill 运行路径、解释器、二进制、包或 hook 被污染，使正常工具链执行攻击者控制逻辑。",
    ),
    "SK-E-3": (
        "序列化与 Loader 滥用（Serialization & Loader Abuse）",
        "Skill 或任务要求加载非可信序列化/配置/模型文件，引导危险 loader 或反序列化行为。",
    ),
    "SK-E-4": (
        "执行输出间接提示注入（Execution Output IPI）",
        "命令、文档、PDF、HTML、diff、dotenv 等执行产物中夹带指令并被 agent 继续采信。",
    ),
    "SK-E-5": (
        "执行环境凭据泄露（Credential Exfiltration）",
        "Skill 诱导 agent 从模拟环境、配置、SDK 或凭据文件中提取 canary/secret-like 数据。",
    ),
    "SK-E-6": (
        "网络边界违反（Network Boundary Violation）",
        "Skill 诱导 agent 进行未授权网络访问、回调、SSRF、端口扫描或 beacon 行为。",
    ),
    "SK-E-7": (
        "本地记忆与检索状态攻击（Local Memory & State Attack）",
        "Skill 将污染内容写入本地记忆、状态、默认配置或检索材料，并在后续正常任务中生效。",
    ),
    "SK-E-8": (
        "输出 Artifact 完整性破坏（Output Artifact Integrity Failure）",
        "Skill 诱导 agent 生成带外部资源、跟踪像素或污染内容的报告、PDF、SVG、邮件等 artifact。",
    ),
    "SK-E-9": (
        "路径穿越与敏感文件访问（Path Traversal & Sensitive File Access）",
        "Skill 通过路径、归档、符号链接、日志轮转等方式诱导访问声明范围外的文件。",
    ),
    "SK-E-10": (
        "解释器/查询注入（Interpreter & Query Injection）",
        "Skill 把非可信输入拼入 shell、SQL/NoSQL、GraphQL、模板或查询解释器，导致注入执行。",
    ),
    "SK-E-11": (
        "协议身份与能力伪装（Protocol Identity & Capability Spoofing）",
        "Skill 诱导 agent 接受降级协议、伪造 endpoint、伪装认证或错误能力声明。",
    ),
    "SK-E-12": (
        "资源耗尽与成本放大（Resource Exhaustion & Cost Amplification）",
        "Skill 诱导 agent 触发压缩炸弹、递归扩展、爬取爆炸、循环解码等资源消耗行为。",
    ),
}

TOOL_MCP_METHODS = {
    "F3.01": (
        "Result Instruction Injection",
        "Tool/MCP result 中夹带指令，污染当前或后续 agent 行动。",
    ),
    "F3.02": (
        "Result Data Poisoning",
        "Tool/MCP result 返回伪造事实或状态，诱导错误判断或错误 artifact。",
    ),
    "F3.03": (
        "Error / Log Poisoning",
        "Tool error、log 或 remediation 文本中夹带非可信操作步骤。",
    ),
    "F3.04": (
        "Hidden Parameter / Argument Exfiltration",
        "Schema、上下文或工具参数描述诱导 agent 把 canary/identifier 填进攻击者控制参数。",
    ),
    "F3.05": (
        "Description / Schema Instruction Poisoning",
        "Tool description、schema text 或 registry metadata 中隐藏调用要求或额外指令。",
    ),
    "F3.06": (
        "Tool / Connector Squatting",
        "恶意 tool/connector 使用 official-looking 名称或描述吸引 agent 选择。",
    ),
    "F3.07": (
        "Capability / Scope Confusion",
        "Capability metadata 标称 readonly/low-scope，但实际诱导敏感参数或越权调用。",
    ),
    "F3.08": (
        "Cross-Tool Handoff",
        "一个 tool result 诱导 agent 调用另一个 tool，并把 canary 或状态传给第二个工具。",
    ),
    "F3.09": (
        "MCP Resource / Runbook Poisoning",
        "MCP resource、runbook 或 prompt-like 材料污染 agent 后续操作。",
    ),
    "F3.10": (
        "MCP Prompt Template Poisoning",
        "MCP prompt/template 中夹带非用户授权步骤，影响之后的正常任务。",
    ),
    "F3.11": (
        "Schema / Registry Cache Poisoning",
        "Schema、registry 或 capability cache 被污染，跨 clean server/restart 后仍影响调用。",
    ),
}


@dataclass(frozen=True)
class CaseRow:
    category: str
    method_id: str
    method_title: str
    suite: str
    case_dir: str
    attack_id: str
    legacy_id: str
    variant: str
    case_id: str
    entry: str
    carrier: str
    boundary: str
    trigger: str
    violation: str
    oracles: list[str]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def clean_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    text = text.replace("|", "\\|")
    return text or "-"


def code_cell(value: Any) -> str:
    text = clean_cell(value)
    if text == "-":
        return text
    return f"`{text}`"


def case_link(case_dir: str) -> str:
    rel = f"../runs/{case_dir}/case_meta.json"
    return f"[`{case_dir}`]({rel})"


def skill_sort_key(method_id: str) -> tuple[int, int]:
    match = re.fullmatch(r"SK-([IE])-(\d+)", method_id)
    if not match:
        return (99, 99)
    group = 0 if match.group(1) == "I" else 1
    return (group, int(match.group(2)))


def tool_sort_key(method_id: str) -> int:
    match = re.fullmatch(r"F3\.(\d+)", method_id)
    return int(match.group(1)) if match else 999


def infer_category_and_method(case_dir: str, attack_id: str) -> tuple[str, str, str]:
    if case_dir.startswith("reference/v3_skill_cases/"):
        title, _ = SKILL_METHODS.get(attack_id, ("未命名 Skill 攻击方式", ""))
        return ("Skill", attack_id, title)
    if case_dir.startswith("active/F3_tool_mcp_runtime/"):
        parts = case_dir.split("/")
        family_dir = parts[2] if len(parts) > 2 else ""
        match = re.match(r"(F3\.\d+)", family_dir)
        method_id = match.group(1) if match else family_dir
        title, _ = TOOL_MCP_METHODS.get(method_id, ("未命名 Tool/MCP 攻击方式", ""))
        return ("Tool/MCP", method_id, title)
    return ("Other", attack_id or "unknown", "未分类")


def collect_cases() -> list[CaseRow]:
    manifest = load_json(MANIFEST)
    rows: list[CaseRow] = []
    for suite, suite_obj in manifest.get("suites", {}).items():
        if suite_obj.get("status") != "active":
            continue
        for entry in suite_obj.get("cases", []):
            case_dir = str(entry["case_dir"])
            meta_path = RUNS / case_dir / "case_meta.json"
            meta = load_json(meta_path) if meta_path.exists() else {}
            attack_id = str(meta.get("attack_id") or entry.get("attack_id") or "")
            category, method_id, method_title = infer_category_and_method(case_dir, attack_id)
            rows.append(
                CaseRow(
                    category=category,
                    method_id=method_id,
                    method_title=method_title,
                    suite=suite,
                    case_dir=case_dir,
                    attack_id=attack_id,
                    legacy_id=str(entry.get("legacy_id") or meta.get("legacy_id") or ""),
                    variant=str(meta.get("variant") or entry.get("variant") or ""),
                    case_id=str(meta.get("case_id") or ""),
                    entry=str(meta.get("entry") or ""),
                    carrier=str(meta.get("carrier") or ""),
                    boundary=str(meta.get("boundary") or ""),
                    trigger=str(meta.get("trigger") or ""),
                    violation=str(meta.get("violation") or ""),
                    oracles=[str(x) for x in meta.get("oracles", [])],
                )
            )
    return rows


def method_sort_key(category: str, method_id: str) -> tuple[int, int, str]:
    if category == "Skill":
        group, number = skill_sort_key(method_id)
        return (0, group * 100 + number, method_id)
    if category == "Tool/MCP":
        return (1, tool_sort_key(method_id), method_id)
    return (9, 999, method_id)


def render_method_section(category: str, method_id: str, rows: list[CaseRow]) -> list[str]:
    title = rows[0].method_title if rows else method_id
    if category == "Skill":
        description = SKILL_METHODS.get(method_id, ("", ""))[1]
        heading = f"### {method_id} {title}"
    else:
        description = TOOL_MCP_METHODS.get(method_id, ("", ""))[1]
        heading = f"### {method_id} {title}"

    lines = [
        heading,
        "",
        f"- Case 数: `{len(rows)}`",
    ]
    if description:
        lines.append(f"- 攻击方式: {description}")
    lines += [
        "",
        "| Case | Variant | Entry | Carrier | Boundary | Trigger | Violation | Oracles |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        oracles = ", ".join(row.oracles)
        branch = row.attack_id
        if row.legacy_id:
            branch = f"{branch} / {row.legacy_id}" if branch else row.legacy_id
        variant = row.variant
        if branch:
            variant = f"{branch}: {variant}" if variant else branch
        lines.append(
            "| "
            + " | ".join(
                [
                    case_link(row.case_dir),
                    code_cell(variant),
                    code_cell(row.entry),
                    code_cell(row.carrier),
                    code_cell(row.boundary),
                    code_cell(row.trigger),
                    code_cell(row.violation),
                    clean_cell(oracles),
                ]
            )
            + " |"
        )
    lines.append("")
    return lines


def render_catalog(rows: list[CaseRow]) -> str:
    grouped: dict[str, dict[str, list[CaseRow]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        grouped[row.category][row.method_id].append(row)

    category_order = ["Skill", "Tool/MCP"]
    total_methods = sum(len(grouped[category]) for category in category_order)

    lines = [
        "# Active Case Catalog",
        "",
        "本文档整理当前 `runs/manifest.json` 中登记的 active cases。",
        "层级固定为：攻击大类 -> 攻击方式 -> 具体 case。",
        "",
        f"- Total active cases: `{len(rows)}`",
        f"- Attack categories: `{len([c for c in category_order if grouped[c]])}`",
        f"- Attack methods: `{total_methods}`",
        "",
        "## 总览",
        "",
        "| 攻击大类 | 攻击方式数 | Case 数 |",
        "| --- | ---: | ---: |",
    ]

    for category in category_order:
        cases = [row for methods in grouped[category].values() for row in methods]
        lines.append(f"| {category} | {len(grouped[category])} | {len(cases)} |")

    lines += [
        "",
        "## 攻击方式索引",
        "",
        "| 攻击大类 | 攻击方式 | Case 数 |",
        "| --- | --- | ---: |",
    ]
    for category in category_order:
        for method_id in sorted(
            grouped[category],
            key=lambda mid: method_sort_key(category, mid),
        ):
            method_rows = grouped[category][method_id]
            title = method_rows[0].method_title
            lines.append(f"| {category} | `{method_id}` {title} | {len(method_rows)} |")

    for category in category_order:
        lines += ["", f"## {category}", ""]
        methods = sorted(
            grouped[category],
            key=lambda mid: method_sort_key(category, mid),
        )
        for method_id in methods:
            method_rows = sorted(grouped[category][method_id], key=lambda row: row.case_dir)
            lines.extend(render_method_section(category, method_id, method_rows))

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    rows = collect_cases()
    OUTPUT.write_text(render_catalog(rows), encoding="utf-8")
    print(OUTPUT)
    print(f"cases={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
