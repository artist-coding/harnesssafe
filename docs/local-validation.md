# 本地交付验证（2026-10-01）

本次将统一入口扩展到七种 harness。实际验证环境为 Windows；没有运行真实模型。

- 最终全量离线回归：`python -m pytest -q`，**1,282 passed / 3 skipped**，218.88 秒。
- 框架专项：73 passed / 2 skipped；两项依赖 Linux 的 FD/socket 检查在本机跳过。
- Windows pytest 收集策略不包含原生 Gemini/OpenCode/Kimi Linux 测试目录；全量通过不代表 Linux 真机已验证。
- 原生 Windows runner 与版本探测 PowerShell 脚本：AST 解析均为 0 错误。
- 对照原压缩包核验 4,040 个保留文件，没有缺失；328 个案例及其文件无改动。
- 修改的原版文件仅四个：run_harness_case.ps1、Hermes/OpenClaw probe.py、Gemini attack_only_runner.py；新增管理层不混入原版哈希声明。
- 七种 harness 各实际生成一份七例离线计划和报告，共 49 个未运行试验；有效行均为 0、ASR 为 N/A。
- 离线验证产物：artifacts/seven-adapter-offline/，配置包含占位身份与 UNVALIDATED 证明，不用于真实运行。
- 此前只读探测到 Codex CLI 0.145.0、Claude Code 2.1.133；没有升级任何 CLI。
- 未验证真实 provider 连接、账户额度、模型可用性和 Linux 原生进程；没有上传网站或远程仓库。

逐文件核验见 provenance/source-audit.json；机器可读验证摘要见 provenance/local_validation.json。

## 当前环境阻塞

系统 Python 的 pandas 为 3.0.1，原框架要求 pandas>=2,<3。doctor 会拒绝该环境。已创建项目 .venv，但此前安装 requirements-dev.txt 失败：配置的 pip 代理连接被拒绝，本地 wheel 缓存也没有所需依赖。未修改系统全局依赖或放宽原要求。

恢复包下载通路后，在项目根目录运行：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m harnesssafe init --harness codex --model YOUR_MODEL_ID --name codex-smoke --smoke --output experiments/codex-smoke.json
.\.venv\Scripts\python.exe -m harnesssafe doctor --config experiments/codex-smoke.json
.\.venv\Scripts\python.exe -m harnesssafe plan --config experiments/codex-smoke.json --out artifacts/codex-smoke
```

run 才调用真实模型。其他 harness 的运行时要求、证明文件和评分限制见 adapters.md；不能仅因为离线测试通过就声称七种真实模型实验均可运行或均已正式评分。
