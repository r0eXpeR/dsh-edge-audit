---
name: dsh-edge-discovery
description: 源码驱动的架构建图、自由发现和变体追踪。用于审计发现阶段，不作最终确认。
---

# 源码驱动的架构建图、自由发现和变体追踪

先理解实际 principal、角色/租户、资产、入口、敏感消费者和安全不变量。静态导入边、文本信号、架构摘要是线索，必须读调用者和消费者证明真实关系。独立 baseline 不接收其他 worker 的结论；架构审阅输出带精确源码引用的事实及明确未知项，再生成调查问题。

正向追输入、逆向追 Sink、比较 sibling 控制与状态迁移。高影响机制出现后，检查同根因的其他独立入口、分支、具体实现、parser 变体、缓存/导出/恢复路径。不同入口或 Sink 保留独立实例；一条相同 CWE 不能关闭另一条用户线索。不要只机械逐文件过一遍。

每批只关闭分配的真实源码区域和边界，保留已提交候选和未完成问题。逐步保留 Source → Transform → Closest Control → Concrete Consumer → Impact。路径或部署不明时记录决定性缺口，不编造远程暴露。## 侦察与选择领域

从四个角度建图，只返回带 file:line 的源码事实，不联系部署端点、IdP、registry、broker、云 API：

1. 产品、用户、运维方、信任敏感动作；语言、框架、构建、runtime、可见部署模式；入口与子系统边界；可比软件（有源码依据时）只用于校准投入，不用于否定已证明的发现。
2. 每个低信任 principal 的设计内动作；各入口的认证或 peer 身份；按资源授权和租户范围；进程、浏览器、workload、CI、插件、模型/tool、设备、IPC 权限；提权、确认、撤销、恢复、fallback。标明控制是源码可见还是依赖未观察的部署事实。
3. 所有入口面：HTTP/浏览器、RPC/消息/协议、文件/归档/文档、CLI/env/配置、插件/依赖/CI、云事件/IAM selector、模型上下文/tool 参数、移动/deep link/webview、本地 IPC。对每个面追主要转换、存储或派生副本、安全相关 sink、可见上限和通往同一效果的并行路径。
4. 可离线的小测试和 fixture；会联网、发布或影响共享状态的命令（本次禁用）；源码无法确立、决定时需 Needs Validation 的部署控制。

选择领域参考的依据是侦察发现的信任敏感边界，不是语言或依赖名出现过；可见边界不能因“别人会看相关类目”而排除。任务排序：未认证或最低信任入口优先，其次是保护最高价值资源（凭据、跨租户数据、代码执行、发布权限）的边界，再次是历史缺口、复验目标和变更源码，最后是该类目标历史上常确认的类目。历史已确认和未决项是优先输入，不是去重键；被否决记录只抑制完全相同的主张，不抑制该区域的复核。

## 调查方法

从具体不变量出发，逐项写清：

1. 低信任 principal 及起始能力。
2. 被接受的值、动作、状态迁移或资源选择器。
3. 本应拒绝、绑定、隔离、限制或撤销它的控制。
4. 该决策之后的确切源码路径。
5. 最小受影响记录、错误返回值、进程完整性效果或共享资源效果。
6. 能强制该不变量的源码级修改和回归用例。

沿输入穿过解析、身份、授权、归一化、状态、派生副本直到最终 sink。读 sibling、legacy、batch、retry、取消、migration、错误路径，比较控制是否等价而非仅是否存在，比较前一组件的保证与后一组件的假设。

测试接口实际接受的异常：缺失、空、零、负数、最大、超限、重复、混合编码、陈旧、已撤销、乱序、并发、部分迁移、依赖失败、rollback。多步问题把每一步输出当前提，前提未确立就记 blocker。

深度边界：只追能到达分配边界或该边界依赖其保证的路径；不变量一旦定论即停止并记录结果。高危候选暴露可复用根因时，在分配范围内搜词法、结构、逻辑变体；同根因合并，但各实例的条件和影响独立确立。超出分配范围的新边界作为线索返回，不重复他人工作。

候选门槛：完整源码路径和根因证据，含最强可见控制；不把 crash 强化为代码执行，不把普通工作强化为共享可用性影响，不把同 principal 动作强化为提权。缺最佳实践但无受影响 principal/资源的属加固项；已被源码证伪的不是 Needs Validation。部署、浏览器、provider、broker、OS、代理、包、secret、身份等源码外事实不证明任何一方。

## 嵌入凭据（source-disclosure）

审查代码、配置、文档、测试、示例、非活跃代码中的凭据和私钥。源码读者取得超出“读源码”权限的凭据即构成泄露路径；所在代码无需执行，也无需攻击者输入。

- 从格式和用法确定用途。区分凭据材料与公钥、证书、标识符、secret store 引用、可证明的占位值。不透明字符串不是充分证据，测试文件名也不是充分反证。
- 把源码访问写成前提，不虚构公开访问、线上有效性或权限。有效性或轮换未知只限制置信度和影响主张，不否定暴露证据。
- 绝不使用发现的凭据，绝不联系服务验证。报告只保留位置、凭据类型、相关上下文、不确定性，不抄录凭据值。

## 参考资料

按实际边界读取相关文件；这些参考影响调查方法，不授予新工具或执行权限。[threat-model](references/threat-model.md) 用于建图；[attack-classes](references/attack-classes.md) 列通用类目，含 Feature abuse 与 Obvious。各领域文件是提炼版；需要完整检查清单时调用 security_read_skill，name 为 dsh-edge-discovery，resource 为 references/full/<id>.md，返回 nextOffset 时用 offset 继续分页（上游英文原文，每页 8000 字符）。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。

## 领域参考

- [web-auth](references/web-auth.md)（[完整版](references/full/web-auth.md)）：仅在该边界实际出现时读取。
- [client](references/client.md)（[完整版](references/full/client.md)）：仅在该边界实际出现时读取。
- [api-messaging](references/api-messaging.md)（[完整版](references/full/api-messaging.md)）：仅在该边界实际出现时读取。
- [ai-agent](references/ai-agent.md)（[完整版](references/full/ai-agent.md)）：仅在该边界实际出现时读取。
- [supply-chain](references/supply-chain.md)（[完整版](references/full/supply-chain.md)）：仅在该边界实际出现时读取。
- [cloud](references/cloud.md)（[完整版](references/full/cloud.md)）：仅在该边界实际出现时读取。
- [tenant-lifecycle](references/tenant-lifecycle.md)（[完整版](references/full/tenant-lifecycle.md)）：仅在该边界实际出现时读取。
- [resources](references/resources.md)（[完整版](references/full/resources.md)）：仅在该边界实际出现时读取。
- [desktop](references/desktop.md)（[完整版](references/full/desktop.md)）：仅在该边界实际出现时读取。
- [native-memory](references/native-memory.md)（[完整版](references/full/native-memory.md)）：仅在该边界实际出现时读取。
