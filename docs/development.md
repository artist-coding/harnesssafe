# 开发与验证

在项目根目录运行：

```text
python -m pytest -q tests/framework
python -m pytest -q
```

tests/framework 使用合成执行器覆盖七种入口的配置、计划、执行、续跑、报告、版本比较、身份/证明变化与证据漂移。测试直接绑定原生函数签名并检查共享 v3 评分桥接，不调用模型。Hermes/OpenClaw 额外测试新版本证明、错误身份、未执行能力与缺失 CLI 参数。

GitHub Actions 包含 Windows/Linux 框架测试及 Windows 原生适配器与评分回归；Linux FD/socket 专项只在 Linux 执行。当前实际验证环境为本机 Windows，远程 CI 尚未运行。CI 不放凭据，不调用真实模型。

| 模块 | 职责 |
| --- | --- |
| harnesssafe/registry.py | 七种适配器的平台、实验臂和配置能力 |
| harnesssafe/common.py | 案例索引、哈希、文件读写 |
| harnesssafe/config.py | 严格配置、外部输入和案例选择 |
| harnesssafe/runtime.py | CLI/依赖预检、命令与进程 |
| harnesssafe/linux_worker.py | 原生 Linux 调度、Gemini 评分桥接与证据副本 |
| harnesssafe/engine.py | 计划、锁、执行、收据、恢复 |
| harnesssafe/reporting.py | 指标、共同样本和比较 |
| harnesssafe/__main__.py | 用户命令行 |
| infra/harness_adapters/version_conformance.py | Hermes/OpenClaw 新版本能力证明 |
| infra/、runs/active/、schemas/ | 原有适配器、评分协议、冻结案例 |

CLI 升级比较要求双方使用同一框架源码版本。修改实现后创建新实验，不修改旧 plan/receipt 绕过检查。框架记录身份，不负责归档第三方可执行文件。

新增版本兼容性必须有原生证据；离线 fake CLI 测试不能代替真实 smoke 或能力证明。Kimi 执行、Event IR 与分析共同绑定原生 0.26.0 版本，修改一处常量不足以支持更新。OpenCode 的正式评分桥接是独立待完成工作，不能从 ATTACK_COMPLETED 推出 N0 或正式结果。

历史匿名投稿文档保存在 docs/original-artifact-README.md。
