# 七种适配器的统一入口

七种 harness 现在共用 `init → doctor → plan → run → report → compare`。用 `python -m harnesssafe adapters` 查看机器可读能力清单。统一管理入口已经接入；真实模型通路是否可用，仍由对应平台、安装版本和原生适配器的能力检查决定。

| Harness | 执行平台 | 实验臂 | 当前评分路径 |
| --- | --- | --- | --- |
| Codex CLI | Windows / PowerShell 7 | attack + 四种 controls | 原生 runner → 共享 Evaluation Record v3 |
| Claude Code | Windows / PowerShell 7 / Git Bash | attack + 四种 controls | 原生 runner → 共享 v3 |
| Hermes Agent | Windows / PowerShell 7 / Git Bash | attack + 四种 controls | 原生 runner → 共享 v3 |
| OpenClaw | Windows / PowerShell 7 / 指定 Node | attack + 四种 controls | 原生 runner → 共享 v3 |
| Gemini CLI | Linux / bubblewrap | attack | 原生批量入口 → 已有 Gemini 分析桥接 → 共享 v3 资格判断 |
| OpenCode | Linux / bubblewrap | attack | 原生证据采集；尚无接入本项目的正式评分桥接 |
| Kimi Code | Linux / bubblewrap / credential FD | attack | 已有分析仅作诊断；尚不进入正式 v3 指标 |

所有计划都保留完整案例清单。不支持、未验证、失败、中断和未评分不能记作 N0 或安全。Gemini 的桥接不强制升级记录资格，只有共享 v3 验证通过的行才进入正式指标。其已有 honeypot 合成逻辑仍在来源证明里标注，未增加新的确认规则。

## 配置方式

`examples/experiments/` 提供七个完整配置模板。替换模型、版本、路径和 provider 地址后使用。模板不包含密钥；占位地址不可用于模型运行。以下以完整配置文件为例，命令适用于全部 harness：

```text
python -m harnesssafe doctor --config experiments/my-harness.json
python -m harnesssafe plan --config experiments/my-harness.json --out artifacts/my-harness
python -m harnesssafe run --plan artifacts/my-harness --limit 1
python -m harnesssafe run --plan artifacts/my-harness --resume
python -m harnesssafe report --plan artifacts/my-harness
```

也可以用 init 读取 provider/runtime 两个 JSON 对象，并从已安装 CLI 查询精确版本：

```text
python -m harnesssafe init --harness hermes --model YOUR_MODEL_ID --name hermes-before --executable C:/tools/hermes/venv/Scripts/hermes.exe --provider-config experiments/hermes-provider.json --runtime-config experiments/hermes-runtime.json --smoke --output experiments/hermes-before.json
```

provider/runtime JSON 的内容分别取自完整模板的同名对象。运行时路径建议写绝对路径；完整配置中的相对路径以该配置文件所在目录为基准。init 的 `--expected-version` 可离线填写精确的 `--version` 输出；这不绕过 run 的版本检查。

## Windows 附加配置

Codex/Claude 保持已有配置。Hermes/OpenClaw 的原生入口仅支持 max_permission；框架不会把它标为 default_permission。

Hermes 的 runtime 指定 source_root、python_executable、git_bash，executable 指向同一安装的 Hermes CLI。doctor 检查 CLI 与 Python launcher 的版本一致，并记录源码指纹。provider 显式指定 base_url、provider_id、api_key_env、api_mode；支持 chat_completions 或 anthropic_messages。显式配置不再从模型名推测 provider，不读取个人 Hermes dotenv 来替代这份配置。

OpenClaw 的 runtime 指定 node_executable 和 expected_node_version。指定的 Node 同时用于 CLI 探测和执行；原先写死的 Node/OpenClaw 版本在统一入口中由实验配置锁定。原生入口仍保留旧默认值以兼容旧脚本。原有 BLOCKED/NOT_RUN 能力门槛仍有效；需要探索 NOT_RUN 时才能显式设置 allow_not_run_smoke=true，该选项不会将案例直接标为正式有效。

## Linux 附加配置

Linux worker 直接调用已有 Python 原生入口；不在 Windows 上模拟 Linux 成功。Gemini/OpenCode 的 conformance 文件必须来自目标版本的真实能力测试，身份中的版本与可执行文件 SHA-256 必须吻合。框架不会制造 SUPPORTED 证明。CLI 更新后需要重新验证能力并提供对应证明。

Gemini 目前统一支持已有的 openai-compatible provider 路径，需要项目/位置标签、API 地址和密钥环境变量名。启用原生 honeypot 收集。OpenCode 读取原有严格 provider profile；配置的 model 必须与 profile 的 provider_id/model_id 一致。profile 和 conformance 的内容哈希进入 plan，副本保存在 inputs/，执行中变化会阻止继续。

原生执行使用独立的短路径 /tmp/hs-*，满足原有 /tmp 和 Kimi Unix socket 长度要求。原目录保留，位置记录在每个 job 的 raw/native/native-location.json。收据另外校验复制到实验目录的普通证据文件；复制过程不跟随符号链接，也不复制 socket。报告不依赖 /tmp 原目录继续存在。中断时可能只保留原目录和启动记录，应保留它们用于排查。原始运行文件是本地私有产物，不能直接作为公开数据包。

Kimi 凭据从配置指定的环境变量进入匿名 sealed memfd，不写入配置或命令行，并在 native runtime 启动前从 worker 环境移除。保留原生执行授权标志和全部运行时门槛。当前原生执行与分析都绑定已验证的 Kimi 0.26.0、精确 Node/包文件哈希和安装路径；未知更新会被拒绝，需要先验证并扩展原生协议支持。不能仅修改 expected_version 就宣称兼容。

## 验证状态与来源

本机完成离线框架测试及 Windows 可执行的原生回归；没有运行真实模型。Linux 进程、bubblewrap、FD 和 provider 联通仍需要 Linux 环境验证。CI 配置含 Windows/Linux 离线框架测试；提交前没有远程 CI 运行记录。

冻结案例与 checkpoint contract 未修改。新增管理层调用原有评分逻辑。原生 Windows runner 增加外置 ResultsRoot、可配置 OpenClaw 运行时，以及显式 Hermes provider/探测路径。原 adapter_manifest.json 的实现哈希描述匿名投稿原版；新实验以 source-lock.json 的当前实现哈希为准。

## Hermes/OpenClaw 的新版本能力证明

这两个原生适配器仍内置旧版本资格：Hermes 0.16.0 + 原源码提交，OpenClaw 2026.7.1-2。新版可以在 runtime 中增加 conformance 文件路径。证明格式为 examples/conformance/ 下的 JSON；模板全部标为 UNVALIDATED，不会放行模型运行。

证明绑定原生版本与 launcher_sha256；Hermes 还绑定 source_commit，OpenClaw 绑定 package_sha256（package.json 字节哈希）。OpenClaw 新版应使用本地 npm 项目 node_modules/.bin 下的 CLI，使原生探测能找到相邻 openclaw/package.json。每项 capability 需要目标版本实际执行的证据引用；填写 SUPPORTED 但 executed=false 或缺少证据会被拒绝。

doctor 目前要求模板列出的原生能力全部通过，并同时核验必需 CLI 参数。单独改 expected_version、帮助文本或证明版本号不能替代真实能力验证。格式和身份校验不替用户验证证据内容的真实性；能力证明必须由目标运行时的实际测试产出。完整证明与哈希会随实验保存。

新版本支持新增在原有 probe 上，旧模型的 pinned 属性保持原义，不会把新版本伪装为论文时版本。Gemini 的原生 protocol 和执行版本校验也已改为采用其 conformance 中的目标版本。
