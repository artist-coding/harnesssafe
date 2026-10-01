# HarnessSafe

用于复测 agent harness 版本的本地实验框架。复用 328 个冻结案例和已有适配器，增加统一配置、版本预检、固定计划、断点续跑、证据校验和升级比较。

**Codex CLI、Claude Code、Hermes Agent、OpenClaw、Gemini CLI、OpenCode、Kimi Code** 均已接入统一命令。前四种使用现有 Windows 运行器，后三种使用现有 Linux 运行器。评分与控制组支持存在差异，见 [适配器状态](docs/adapters.md)。

## 安装和离线检查

需要 Python 3.10+。执行 Windows 适配器还需要 PowerShell 7；Linux 适配器需要 bubblewrap。每个 harness 需独立安装。以下命令在项目根目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m harnesssafe adapters
python -m harnesssafe cases
python -m pytest -q tests/framework
```

Linux 使用 `source .venv/bin/activate` 激活虚拟环境。doctor 会拒绝不符合 requirements.txt 范围的依赖。

## 一套流程复测七种 harness

Codex/Claude 可以直接 init；其余适配器从 [七种配置模板](examples/README.md) 填写原生运行时/provider 参数，或通过 init 的 --provider-config 与 --runtime-config 导入。

```text
python -m harnesssafe init --harness codex --model YOUR_MODEL_ID --name codex-before --smoke --output experiments/codex-before.json
python -m harnesssafe doctor --config experiments/codex-before.json
python -m harnesssafe plan --config experiments/codex-before.json --out artifacts/codex-before
```

init 默认只查询本地 CLI 版本；doctor 检查平台、版本、CLI 契约与依赖；plan 完全离线。这三个命令不调用模型。下面的 run 才执行真实实验并使用模型：

```text
python -m harnesssafe run --plan artifacts/codex-before --limit 1
python -m harnesssafe run --plan artifacts/codex-before --resume
python -m harnesssafe report --plan artifacts/codex-before
```

smoke 固定选择每个家族按 manifest 顺序的第一个案例，共 7 例，只用于验证通路。省略 --smoke 可选择全部 328 例。其他 harness 使用相同 doctor/plan/run/report 命令，只替换配置文件与实验目录。

Codex/Claude 默认 default_permission；Hermes/OpenClaw 的原生入口仅支持 max_permission。Linux 原生配置标记为 adapter_default，不与 Windows 权限档位混用。isolated_home 隔离 agent 状态，不是操作系统安全边界；高权限基准应在专用测试环境运行。

## CLI 更新后再测

重新 init 或复制配置，固定相同模型、案例选择、权限和超时，填写新 CLI 的精确版本。--executable 可以指定单独安装的版本。Hermes/OpenClaw 新版本需要身份绑定的能力证明；Gemini/OpenCode 的证明必须与目标版本及可执行文件匹配。Kimi 原生协议目前仍严格绑定已验证的 0.26.0 运行时。

```text
python -m harnesssafe doctor --config experiments/codex-after.json
python -m harnesssafe plan --config experiments/codex-after.json --out artifacts/codex-after
python -m harnesssafe run --plan artifacts/codex-after
python -m harnesssafe compare artifacts/codex-before artifacts/codex-after --out artifacts/codex-comparison
```

报告保存覆盖率、正式 ASR、共同样本 ASR、固定家族权重 CSS、逐案例变化，以及精确共同样本清单。CLI 参数或协议发生不兼容变化时需更新适配器，不承诺任意未来版本都无需适配。框架不会自动升级 CLI。

## 评分边界

Windows 四个适配器复用共享 Evaluation Record v3。Gemini 接入已有分析桥接后，再由共享 v3 判断资格。OpenCode 当前统一入口保留原始证据，尚不产出正式评分；Kimi 的已有分析仍是诊断用途。执行完成本身不代表 evaluation_eligible=true。

不支持、失败、未完成、未运行和未评分都不能记作 N0 或安全。缺少有效共同样本时 ASR/CSS 为 N/A。Linux 的当前统一调度仅支持 attack，配置 controls 会明确报错。

## 输出与复现

- plan.json、source-lock.json：配置、案例集、实验臂、重复次数、代码与案例哈希；外部 provider/conformance 文件有哈希和 inputs/ 副本。
- environment.json：实际 CLI/运行时身份、帮助指纹、Python 和依赖版本。
- jobs/<job_id>/：调用、原生输出、日志和证据收据。
- results.jsonl、results.csv：完整计划清单，保留失败与未运行项。
- report.json、report.md、common-support.json：指标和共同样本成员。

--resume 只运行尚未尝试的试验；重复测量应预先用 --repeats 声明。计划后修改案例、代码或外部证明会阻止继续执行。Linux 短路径原生目录和证据副本的关系见适配器文档。

artifacts/、bench_state/ 和凭据目录已被 .gitignore 排除。原始运行日志留在本地，不应直接上传为公开结果包。

[实验协议](docs/experiments.md) · [适配器状态](docs/adapters.md) · [开发说明](docs/development.md) · [本地验证](docs/local-validation.md)

## 来源和许可证

来源与原压缩包 SHA-256 在 provenance/upstream.json。历史结果仍在原匿名投稿压缩包中，不作为当前 CLI 的新结果。本框架不重建缺失的历史 CSS 成员或对照实验记录。

代码 Apache-2.0；案例定义和文档按照 LICENSES.md 使用 CC BY 4.0。CITATION.cff 暂保留匿名投稿信息，公开发布时更新作者和项目地址。本仓库提供可复现实验代码；真实模型与 Linux 真机验证状态见本地验证记录。旧版构建归档仅保留模板，公开文件清单见 [发布说明](docs/publication.md)。
