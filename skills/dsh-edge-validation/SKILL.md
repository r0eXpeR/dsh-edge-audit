---
name: dsh-edge-validation
description: 对源码候选作独立反证、类别证明与最终记录复核。不将静态结论冒充已执行复现。
---

# 对源码候选作独立反证、类别证明与最终记录复核

你没有发现此候选。先尝试推翻：重建最强的有效认证、对象/租户授权、规范化、绑定、parser 安全选项、框架默认值、部署隔离与错误处理。安全 sibling 只是比较基线，不能证明候选路径安全；代码存在相同模式也不是撤销漏洞的理由。

按候选 rule/CWE 的 proof tuple 逐一证明攻击者输入、最近控制、实际消费点和具体影响。验证入口与 Sink 是同一条因果路径；受验证的值、身份、断言、路径、签名对象必须正是后续消费的那个。每个引用都要重读当前冻结源码，不复述发现者的文字。

常见误报见 [false-positive-precedents](references/false-positive-precedents.md)。其中条目是默认假设，须被具体源码证据推翻，不是关键词删除规则；命中条目不能代替读源码。候选所属领域的 `## 验证与反证` 段是该类别的证明要求，完整清单用 security_read_skill 读 dsh-edge-discovery 的 references/full/<id>.md。

每个候选必须得到处置：reportable、suppressed、not_applicable 或 deferred，并保留标识符、源码引用和受影响位置。一次代表性复现可支持相关实例，但每个实例的 source、control、sink、影响都要检查；安全 sibling 或更强的相邻发现不决定另一条记录。可独立触发的操作和被破坏的控制分开保留；wrapper 只证明可达，要保留实际实现或共享控制。

在使用点检查控制：追替代表示、分支转换、重定向、状态变更、对象选择是否改变了已验证内容。文档化的危险行为、可选限制、弃用只是上下文，要判断攻击者是否跨越预期边界。匹配 advisory、危险 API、helper 名、缺 guard 都只是线索。

抑制必须用能击败该确切主张的证据。缺调用方、部署或来源证据可作为聚焦跟进或 deferred 的理由，缺失本身不证明安全。环境搭建失败时把缺失服务、依赖、配置记为 proof gap，不当作安全证据；不用重新实现的替代品声称证明了原始行为。置信度评估完整发现：路径和影响已确立且无重大未决反证为 high；直接证据支持但实质前提不确定为 medium；间接或缺重要上下文为 low。Crash 只证明观察到的崩溃。

reportable 必须没有决定性缺口。继承的 discoveryProofGaps 逐项提供 resolved_proof_gaps 的解释与精确源码证据；外部部署事实无法由源码证明时保留 deferred 及安全验证计划。suppressed/not_applicable 需要真实反证。Needs Validation 也必须复核其前提与缺口，不能存放没有实际边界的猜想。

runtime/hybrid 需要候选绑定的隔离执行 receipt 和真实输出观察；命令 exit 0、规则消失或任意文本不证明漏洞。缺沙箱时使用静态验证并明确分级。声明已经复现必须对应实际保留的输入、结果和环境约束。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。

已有封存的 Needs Validation 可以由用户显式调用 security_start_candidate_followup，在当前工作树建立聚焦复核记录；保留原 seal，重新认领验证任务，再按已批准的隔离验证入口附加 receipt。复核记录不是一次新的全仓发现，也不继承旧确认。原始历史 Diff 必须明确使用其对应 checkout，不能偷换成当前工作树。
