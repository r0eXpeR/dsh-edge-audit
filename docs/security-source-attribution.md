# 来源与许可

本文记录 EdgeAudit 使用的上游项目、改编范围和许可。参考项目只作为只读资料，没有安装、执行或随包分发它们的运行时、Hook、CLI 或原生模块。

## 基础项目

| 项目 | 版本 | 许可 |
| --- | --- | --- |
| [Zenquiem/dsh-security-suite](https://github.com/Zenquiem/dsh-security-suite) | 0.54.28 | Apache-2.0 |

EdgeAudit 由 dsh-security-suite 0.54.28 的源码发展而来，曾用名 dsh-fonshang-audit。以下部分来自原项目，并已修改：

- DSH 插件结构、配置 Schema 和工具注册方式。
- Standard、Diff、Deep 扫描流程，Worker / Reducer 分工。
- 验证收据（claim token）和攻击路径收据的门禁。
- GitHub、Jira、Linear 跟踪，分诊，审批后的修复补丁，以及 Markdown / JSON / SARIF / CSV 导出。

原项目的部分提示词、扫描契约和严重度策略改编自 OpenAI Codex Security，这部分归属见下文。

本项目新增或重写的主要内容：确定性 AST / 数据流分析引擎、覆盖账本和覆盖 Critic、中断恢复与源码漂移检测、Docker 动态验证沙箱、修复回滚与独立复验、HTML 报告、随包 Skill，以及针对不可信仓库的 Git、符号链接、凭据和输出脱敏加固。

## 参考项目

| 项目 | 参考版本 | 许可 |
| --- | --- | --- |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | 提交 `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` | MIT，Copyright (c) 2025-2026 Cloudflare, Inc. |
| [openai/codex-security](https://github.com/openai/codex-security) | npm 0.8.0（gitHead `71bd7ae0e9bc859fb8fe9bc4b590b8f8998b19aa`），并对照阅读了 0.8.1 | Apache-2.0 |
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | 提交 `0c6a49f1fa56a1d472575da86a94dbc1edb78eda` | MIT，Copyright (c) 2025 Anthropic |

### 采用与未采用的内容

| 来源 | 采用 | 未采用 |
| --- | --- | --- |
| Cloudflare | 覆盖单元、独立覆盖 Critic、反证验证、Needs Validation 分级、按领域选择参考材料 | 原项目的输出目录与 Findings 格式、CJS 脚本、把“本地观测结果”作为唯一确认标准的定义 |
| Codex Security | Worker / Reducer / 证据包结构，威胁模型、验证与严重度规则，检查点和冻结范围 | Codex SDK、需要账号或托管服务的功能、托管修复、原生 MCP 二进制 |
| Anthropic | 增量审计的上下文分析、对候选的反证、常见误报先例 | 按关键词直接丢弃 DoS、资源耗尽等类别的过滤器；Claude API / CLI 调用；自动 PR 评论 |

### 具体文件

- `skills/dsh-edge-discovery/references/<领域>.md`：按 Cloudflare 上游的领域分类重写的检查点。
- `skills/dsh-edge-discovery/references/full/<领域>.md`：Cloudflare companion 文件的原文拷贝，首行注明来源，MIT 许可。
- `skills/dsh-edge-discovery/references/attack-classes.md`：由 Cloudflare 的 ATTACK-CLASSES.md 提炼。
- `skills/dsh-edge-discovery/references/threat-model.md`、`skills/dsh-edge-attack-path/references/severity-policy.md`：改编自 Codex Security 的 threat-model.md、severity-policy.md 和 default-severity-rubric，Apache-2.0。likelihood 各级的锚点为本项目补充。
- `skills/dsh-edge-validation/references/false-positive-precedents.md`：改编自 claude-code-security-review 的 findings_filter.py 和 prompts.py，改写为可以被证据推翻的默认假设，MIT 许可。各领域“常见误报”中的部分条目是据上游规则归纳，不是原文。
- `src/llm/prompts.ts`：保留 Codex Security 改编归属，DSH 目标约束和确认语义为本项目新增。
- `docs/prompts/` 下的提示词模板和 `src/prompt.ts` 中的 RCE / 业务不变量指导为本项目编写。

## 许可

- 本项目以 Apache-2.0 发布，`tests/golden/` 下的合成样本为本项目自建。
- 参考项目许可全文：[Cloudflare MIT](licenses/cloudflare-MIT.txt)、[Anthropic MIT](licenses/anthropic-MIT.txt)、[OpenAI Apache-2.0](licenses/openai-Apache-2.0.txt)。包内附 [NOTICE](../NOTICE)。
- 运行时只依赖 `@typescript-eslint/typescript-estree`；`@deepseek-ai/*` 由 DSH 宿主提供，作为可选 peer 依赖声明。
