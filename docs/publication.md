# GitHub 发布范围

公开仓库包含七种 harness 的统一管理代码、原生适配器、328 个冻结实验案例、测试、配置示例及文档。登录凭据、agent home、真实模型输出、artifacts/、bench_state/、虚拟环境和缓存不进入 Git。

旧版构建来源 runs/archive/legacy_v2_memory_evolution.zip 原本还包含历史运行输出。公开版删除了 3,487 个 results/ 文件，保留 322 个构建模板文件；保留内容逐字节一致。原始 ZIP 已留在本地忽略目录，未加入任何 Git 提交。详细哈希与保留成员清单见 provenance/public-legacy-archive.json。328 个 active 案例未更改。

案例中的 MOCK SSH 密钥、AWS EXAMPLEKEY、测试 token 和回环 HTTPS 服务私钥属于静态测试夹具，按原样保留；它们不是账户凭据。不要在其他服务中复用这些公开测试密钥。

.gitattributes 禁用自动换行转换，防止 Windows/Linux checkout 改写冻结案例和能力绑定的文件哈希。

本仓库是持续开发代码发布，不是已经完成所有 harness 实机验证的论文结果发布。OpenCode/Kimi 正式评分限制、Kimi 的原生版本锁定和真实模型验证状态见 adapters.md 与 local-validation.md。CITATION.cff 的原匿名作者信息保留，未将 GitHub 维护者冒认为原论文作者。
