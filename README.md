<p align="center">
  <img src="docs/assets/harnesssafe-banner.svg" width="100%" alt="HarnessSafe — 328 个冻结案例，7 种 harness 适配，一套可复现实验流程">
</p>

<p align="center">
  <strong>让 agent harness 的每一次更新，都能回到同一套安全实验。</strong><br>
  固定案例与协议，保留运行证据，比较版本变化。
</p>

<p align="center">
  <a href="https://arxiv.org/abs/2608.06984"><img src="https://img.shields.io/badge/arXiv-2608.06984-B31B1B?logo=arxiv&amp;logoColor=white" alt="Paper: arXiv 2608.06984"></a>
  <a href="https://artist-coding.github.io/"><img src="https://img.shields.io/badge/Project-Website-168B77" alt="HarnessSafe project website"></a>
</p>

<p align="center">
  <strong><a href="https://arxiv.org/abs/2608.06984">arXiv 论文</a> · <a href="https://arxiv.org/pdf/2608.06984">论文 PDF</a> · <a href="https://artist-coding.github.io/">项目网站</a></strong>
</p>

<p align="center">
  <a href="https://github.com/artist-coding/harnesssafe/actions/workflows/tests.yml"><img src="https://github.com/artist-coding/harnesssafe/actions/workflows/tests.yml/badge.svg" alt="Offline framework checks"></a>
  <a href="requirements.txt"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&amp;logoColor=white" alt="Python 3.10+"></a>
  <a href="runs/manifest.json"><img src="https://img.shields.io/badge/Frozen_cases-328-168B77" alt="328 frozen cases"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/Code-Apache--2.0-526B86" alt="Code license: Apache 2.0"></a>
  <a href="LICENSES.md"><img src="https://img.shields.io/badge/Case_definitions-CC_BY_4.0-526B86" alt="Case definitions: CC BY 4.0"></a>
</p>

<p align="center">
  <a href="#paper">论文与引用</a> ·
  <a href="#overview">项目概览</a> ·
  <a href="#adapters">支持范围</a> ·
  <a href="#benchmark">测试案例</a> ·
  <a href="#quickstart">快速开始</a> ·
  <a href="#compare">版本复测</a> ·
  <a href="#docs">文档</a>
</p>

---

<a id="overview"></a>

## 为什么做 HarnessSafe

Agent 的安全表现取决于模型，也取决于它所处的运行环境：记忆如何保存、技能如何加载、工具结果如何解释，以及上下文如何在压缩和子代理之间传递。

**HarnessSafe 为这些运行机制提供一套可重复执行的安全实验框架。** 当 Codex、Claude Code 或其他 harness 更新后，可以在固定案例和配置下重新测试，检查攻击结果、覆盖率与防护表现的变化。

| 你想验证什么 | HarnessSafe 提供什么 |
| --- | --- |
| 升级后，安全表现有没有变化？ | 固定案例、版本记录、共同有效样本上的逐项比较 |
| 同一次实验能否重新检查？ | 配置与源码哈希、运行证据、可校验的试验收据 |
| 中断后如何继续，避免重复计算？ | 固定试验清单；续跑只处理尚未尝试的试验 |
| 失败或不支持的案例会不会被算作安全？ | 完整状态与排除原因；未评分不会自动变成 N0 |
| 不同 harness 能否使用统一入口？ | 七种适配器共用配置、计划、运行与报告命令 |

### 一条实验流程

```mermaid
flowchart LR
    A["配置与版本检查<br/>init · doctor"] --> B["冻结实验计划<br/>plan"]
    B --> C["调用原生适配器<br/>run"]
    C --> D["保存证据与执行状态"]
    D --> E["生成报告<br/>report"]
    E --> F["比较版本<br/>compare"]

    classDef default fill:#eef8f6,stroke:#328879,color:#163f3a;
```

<a id="paper"></a>

## 论文与引用

**HarnessSafe: Evaluating Safety Across Persistent Carriers in Agent Harnesses**

Xiao Zhang · Yusheng Wang · Yuhao Fei · Dongyuan Li · Zian Liang · Liuyu Xiang · Hongxun Gu · Zhaofeng He

论文提出 **Persistent-Risk Lifecycle**，将持久风险描述为从攻击入口、载体留存、跨边界传播到后续触发与可观察违规的完整过程；在七类机制的 328 个案例上，使用 **N0–N5b 阶段评估与 CSS** 分析不同 harness–模型配置的风险遏制表现。

**[arXiv 论文](https://arxiv.org/abs/2608.06984) · [论文 PDF](https://arxiv.org/pdf/2608.06984) · [项目网站](https://artist-coding.github.io/) · [BibTeX 引用](paper/CITATION.bib)**

论文于 **2026 年 8 月 7 日**发布于 arXiv。论文中的历史结果与当前框架的新实验结果需分别报告。

<details>
<summary><strong>引用 HarnessSafe</strong></summary>

```bibtex
@misc{zhang2026harnesssafe,
  title = {{HarnessSafe}: Evaluating Safety Across Persistent Carriers in Agent Harnesses},
  author = {Xiao Zhang and Yusheng Wang and Yuhao Fei and Dongyuan Li and Zian Liang and Liuyu Xiang and Hongxun Gu and Zhaofeng He},
  year = {2026},
  eprint = {2608.06984},
  archivePrefix = {arXiv},
  primaryClass = {cs.CR},
  doi = {10.48550/arXiv.2608.06984},
  url = {https://arxiv.org/abs/2608.06984}
}
```

</details>

<a id="adapters"></a>

## 七种 harness，一套管理入口

“已接入”表示具备统一的实验管理入口；执行平台、控制组与正式评分能力如下。具体安装与版本要求见 [适配器文档](docs/adapters.md)。

| Harness | 原生执行平台 | 支持的实验组 | 当前评分路径 |
| --- | --- | --- | --- |
| **Codex CLI** | Windows | 攻击组 + 4 种控制组 | 共享 Evaluation Record v3 |
| **Claude Code** | Windows | 攻击组 + 4 种控制组 | 共享 Evaluation Record v3 |
| **Hermes Agent** | Windows | 攻击组 + 4 种控制组 | 共享 Evaluation Record v3 |
| **OpenClaw** | Windows | 攻击组 + 4 种控制组 | 共享 Evaluation Record v3 |
| **Gemini CLI** | Linux | 攻击组 | 已有分析桥接 → 共享 v3 资格判断 |
| **OpenCode** | Linux | 攻击组 | 原始证据采集；正式评分待接入 |
| **Kimi Code** | Linux | 攻击组 | 诊断分析；暂不进入正式指标 |

> **版本兼容性有明确边界。** Hermes/OpenClaw 新版本需要对应能力证明；Gemini/OpenCode 的证明须匹配目标版本与可执行文件。Kimi 的原生协议目前绑定已验证的 **0.26.0** 运行时。CLI 接口发生变化时仍可能需要更新适配器。

查看本地能力清单：

```bash
python -m harnesssafe adapters
```

<a id="benchmark"></a>

## 328 个冻结案例，覆盖七类机制

| 家族 | 测试机制 | 案例数 |
| --- | --- | ---: |
| **F1** | 持久记忆与后续任务中的污染传播 | 72 |
| **F2** | 技能加载、技能内容与执行行为 | 84 |
| **F3** | 工具 / MCP 接口与返回内容 | 70 |
| **T2** | 记忆内容向技能转化的跨机制传播 | 36 |
| **T3-S** | 子代理委派与结果回传 | 30 |
| **T3-C** | 上下文压缩与会话恢复 | 30 |
| **T3-A** | 共享产物与供应链传播 | 6 |
| **合计** | | **328** |

案例清单见 [runs/manifest.json](runs/manifest.json)。`--smoke` 固定选择每个家族的第一个案例，共 **7 例**，用于检查运行通路；省略该选项可规划全部案例。

支持控制组的适配器可增加 `clean_control`、`no_persist_control`、`no_trigger_control` 与 `cleanup_control`，并通过 `--repeats` 预先声明重复次数。

<a id="quickstart"></a>

## 快速开始

需要 **Python 3.10+**。真实执行还需安装目标 harness：Windows 入口需要 PowerShell 7，Linux 入口需要 bubblewrap；Git Bash、Node 和版本证明等额外要求见 [配置说明](docs/adapters.md)。

### 1. 安装框架

```bash
git clone https://github.com/artist-coding/harnesssafe.git
cd harnesssafe
python -m venv .venv
```

<details>
<summary><strong>Windows / PowerShell</strong></summary>

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

</details>

<details>
<summary><strong>Linux / Bash</strong></summary>

```bash
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

</details>

### 2. 先体验离线计划与报告

不需要 harness CLI 或模型凭据，就可以查看案例、规划试验并生成报告：

```bash
python -m harnesssafe cases
python -m harnesssafe plan --config examples/experiments/codex.json --out artifacts/preview
python -m harnesssafe report --plan artifacts/preview
```

打开 `artifacts/preview/report.md` 查看输出。示例配置包含占位符，**这一步不会运行模型**；未执行试验的指标显示为 `N/A`。

### 3. 运行第一次真实实验

下面以 **Windows 上的 Codex CLI** 为例。先安装并完成 CLI 的登录，替换 `YOUR_MODEL_ID`；新建独立配置与实验目录：

```bash
python -m harnesssafe init --harness codex --model YOUR_MODEL_ID --name codex-before --smoke --output experiments/codex-before.json
python -m harnesssafe doctor --config experiments/codex-before.json
python -m harnesssafe plan --config experiments/codex-before.json --out artifacts/codex-before
```

确认配置后，先执行一个试验，再继续剩余试验：

```bash
python -m harnesssafe run --plan artifacts/codex-before --limit 1
python -m harnesssafe run --plan artifacts/codex-before --resume
python -m harnesssafe report --plan artifacts/codex-before
```

**只有 `run` 会调用模型，并可能产生费用。** `--resume` 不重跑已经尝试过的失败或中断试验。其他 harness 从 [七种配置模板](examples/README.md) 开始，使用同一套后续命令。

<a id="compare"></a>

## 更新 CLI 后，用相同条件复测

保留框架代码、模型、案例、权限、超时与重复次数，安装目标 CLI 版本后创建另一份实验。也可以通过 `--executable` 指定独立安装的版本。

```bash
python -m harnesssafe init --harness codex --model YOUR_MODEL_ID --name codex-after --smoke --output experiments/codex-after.json
python -m harnesssafe doctor --config experiments/codex-after.json
python -m harnesssafe plan --config experiments/codex-after.json --out artifacts/codex-after
python -m harnesssafe run --plan artifacts/codex-after
python -m harnesssafe compare artifacts/codex-before artifacts/codex-after --out artifacts/codex-comparison
```

比较报告回答三个问题：

- **覆盖是否改变？** 各版本的有效试验数、覆盖率和执行状态分布。
- **共同案例上有何变化？** 逐案例、逐重复编号的阶段变化与指标差值。
- **分数使用了哪些样本？** 精确成员清单和哈希保存在 `common-support.json`。

改变模型、provider 或运行条件时，报告会标记为配置比较，避免将多个因素的变化归因于 CLI 版本。

### 如何阅读指标

| 指标 | 含义 |
| --- | --- |
| **Coverage** | 正式有效试验数 ÷ 计划试验数 |
| **ASR** | 正式有效试验中到达 N5a / N5b 的攻击比例；越低越好 |
| **Conditional CSS** | 有效试验的平均安全权重；越高越好 |
| **Standardized CSS** | 在共同有效样本上按完整基准的固定家族权重计算 |

未运行、失败、不支持和未评分的记录会保留在清单中，并从正式评分中排除。没有有效样本，或标准化 CSS 所需的家族缺失时，结果为 `N/A`。权重与完整定义见 [实验协议](docs/experiments.md)。

## 每次实验留下什么

```text
artifacts/codex-before/
├── plan.json               # 配置、案例、实验组与重复次数
├── source-lock.json        # 源码与冻结案例的哈希
├── environment.json        # 实际运行时身份（开始执行后生成）
├── inputs/                 # 配置引用的外部证明与 profile 副本（如有）
├── jobs/
│   └── <job_id>/           # 原生证据、启动记录和完成收据
├── results.jsonl           # 完整试验清单
├── results.csv             # 表格格式输出
├── report.json
├── report.md
└── common-support.json     # 共同有效样本成员
```

源码、案例、CLI 或外部能力证明发生变化时，框架会阻止继续混入旧实验。生成报告时会复核已记录证据的完整性。

<a id="docs"></a>

## 文档与开发

| 文档 | 内容 |
| --- | --- |
| [配置示例](examples/README.md) | 七种 harness 的配置起点 |
| [适配器状态](docs/adapters.md) | 平台要求、版本资格、控制组和评分限制 |
| [实验协议](docs/experiments.md) | 试验语义、指标、共同样本与恢复策略 |
| [开发说明](docs/development.md) | 模块职责和离线验证方法 |
| [验证记录](docs/local-validation.md) | 本地检查结果与实机验证范围 |
| [公开发布范围](docs/publication.md) | 模板归档处理、测试夹具和排除的本地产物 |

运行离线框架测试：

```bash
python -m pytest -q tests/framework
```

欢迎通过 [Issues](https://github.com/artist-coding/harnesssafe/issues) 提交版本兼容性问题与改进建议。报告兼容性问题时，请附上 harness/CLI 版本、操作系统、模型标识和脱敏后的错误信息。适配器扩展、协议变更和评分实现需配套可验证证据。

## 当前范围与许可证

本仓库提供实验代码、冻结案例和复测工作流。**真实模型实验、Linux 原生运行验证和正式评分覆盖，以各适配器的验证记录为准**；离线 CI 通过不等于所有真实 harness 通路均已验证。固定实验过程也不保证远程模型每次输出完全相同。

源码采用 [Apache 2.0](LICENSE)，案例定义与文档按 [许可证映射](LICENSES.md) 使用 CC BY 4.0。来源记录见 [provenance/upstream.json](provenance/upstream.json)，引用信息见 [CITATION.cff](CITATION.cff)，论文作者与发表日期依据 [arXiv 公开记录](https://arxiv.org/abs/2608.06984)维护。

旧版构建归档的公开副本仅保留模板，原始运行日志与凭据不进入仓库。历史论文结果与当前 CLI 的新实验结果需分别报告。高权限实验应在专用、已获授权的测试环境中运行。
