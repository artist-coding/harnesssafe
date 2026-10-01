# 实验配置模板

experiments/ 下的七个 JSON 是结构完整的模板，不是已经通过 doctor 的本机配置。复制到自己的 experiments/ 后，填写模型、精确 CLI 版本、安装路径和 API 地址。配置只能存密钥环境变量名，不能存密钥值。

OpenCode 的 model 应等于 provider profile 的 provider_id/model_id；profiles/opencode.json 提供原生 profile 格式。Gemini/OpenCode 需要目标可执行文件对应的真实 conformance 证明，本目录不提供伪造的 SUPPORTED 证明。

默认 smoke 选择七个家族各一例。Linux 原生入口目前仅支持 attack；Windows 的 controls 可以通过 init --controls 生成。运行前先执行 doctor；完整步骤和能力差异见 ../docs/adapters.md。

Hermes/OpenClaw 超出内置旧版本时，可在完整配置的 runtime 中增加 conformance 路径。conformance/ 下只提供全部 UNVALIDATED 的格式模板；必须用目标版本的真实能力测试结果替换，不能把模板当作已验证的证明。
