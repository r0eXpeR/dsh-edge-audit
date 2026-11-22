---
name: dsh-edge-coverage
description: 覆盖账本、缺口补派与独立 Critic。用于全量审计的覆盖检查，不判断漏洞是否成立。
---

# 覆盖账本、缺口补派与独立 Critic

覆盖单元由 surface × boundary × subsystem × attack class × lifecycle 构成。逐单元提出具体安全问题，保留实际读范围、观察、检查结论与限制。读取或搜索不等于审阅；未知范围为 planned/deferred/blocked，不许隐去。
有 anchorLine 的单元对应一处明确入口；同一源码行上的多个注册调用仍是不同单元。关闭时引用该入口行，并分别检查其控制和操作。clean Critic 必须亲自读取每个已审单元引用的源码；只读账本或一处代表性源码不能接受整份覆盖。

Critic 独立检查未映射入口、无调用者追踪的 Sink、只查控制器未查服务层、对象/租户边界、错误/默认/撤销/恢复等生命周期、排除理由和历史未决项。Critic 只提出缺失单元与重新分派，不创造或确认漏洞。

每波完成后运行 post-wave Critic；接受缺口后以新 owner 补派，归档旧 attempt。无缺口后再由不同 fresh Session 执行 final-clean。两者必须接受同一账本摘要。缺口或预算不足保持 Partial；失败波次不能增加“连续无新增”收敛次数。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。
