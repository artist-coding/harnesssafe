# HarnessSafe 论文与附录

**HarnessSafe: Evaluating Safety Across Persistent Carriers in Agent Harnesses**

本目录收录项目提供的匿名论文源码、与主稿对齐的附录及三张原始配图。主稿的 SHA-256 与原始代码与数据归档中的论文来源记录一致；复制时未改写稿件或配图。

| 文件 | 内容 |
| --- | --- |
| [harnesssafe_final.tex](harnesssafe_final.tex) | 主论文 LaTeX 源码 |
| [harnesssafe_appendix_restructured_paper_aligned.tex](harnesssafe_appendix_restructured_paper_aligned.tex) | 与主稿对齐的补充附录 |
| [Figures/benchmark.pdf](Figures/benchmark.pdf) | 基准设计图 |
| [Figures/background.pdf](Figures/background.pdf) | 背景与风险机制图 |
| [Figures/checkpoint_dist.pdf](Figures/checkpoint_dist.pdf) | 生命周期阶段分布图 |
| [CITATION.bib](CITATION.bib) | 当前匿名稿件的 BibTeX 引用 |

## 研究内容

论文围绕 agent harness 中的持久风险展开：攻击者影响的内容如何进入记忆、技能、工具或共享产物，跨越持久化边界，并在后续正常任务中被再次触发。

- **统一案例描述：** 以 Persistent-Risk Lifecycle 描述入口、载体、边界、触发条件和可观察违规，组织七类载体机制下的 328 个案例。
- **分阶段评估：** 根据执行证据判断攻击链推进至 N0–N5b 中的哪一阶段，并用 Chain-Stage Score（CSS）汇总。
- **配置与控制实验：** 分析 harness、模型后端和生命周期要素对风险遏制的影响。

论文中的历史实验结果对应原稿的实验配置；当前仓库中新运行的实验应单独报告，执行与正式评分边界见 [适配器状态](../docs/adapters.md)。

## 稿件与编译状态

当前提供的是 **LaTeX 源码稿件**，没有完整论文 PDF 或已确认的公开论文链接。源码仍保留原始匿名署名和编辑注释，不代表已正式发表。

主稿使用 `aaai2027` 模板并引用 `HarnessSafe.bib`。现有材料中未包含 `aaai2027.sty`、该模板所需的样式配套文件及 `HarnessSafe.bib`，因此本目录尚不是可独立编译的完整 LaTeX 工程。三张图的相对路径 `Figures/` 已保留。

这里的 [CITATION.bib](CITATION.bib) 是**引用这篇论文**的条目，不能替代论文自身的参考文献数据库 `HarnessSafe.bib`。

## 引用

作者字段沿用稿件的匿名信息；当前条目不包含未经确认的作者名单、会议收录信息、DOI 或 arXiv 编号。

```bibtex
@misc{harnesssafe2026,
  author = {{Anonymous Submission}},
  title = {{HarnessSafe}: Evaluating Safety Across Persistent Carriers in Agent Harnesses},
  year = {2026},
  howpublished = {Manuscript source},
  url = {https://github.com/artist-coding/harnesssafe/tree/main/paper},
  note = {Anonymous manuscript; publication metadata pending}
}
```

文件来源与完整性记录见 [provenance/paper_source.json](../provenance/paper_source.json)。论文材料的许可范围见 [LICENSES.md](../LICENSES.md)。
