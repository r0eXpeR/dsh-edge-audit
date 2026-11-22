---
name: dsh-edge-attack-path
description: 独立复核攻击者到结果的路径与机械定级。仅用于已有独立验证的候选。
---

# 独立复核攻击者到结果的路径与机械定级

逐步检查攻击者、入口、身份、输入、控制、传播与最终结果；组合链每一跳必须有兼容的身份、权限、值流、配置和依赖。上传/写入/反序列化/模板/SSRF 等原语不自动等于 RCE，要证明执行触发器与目标进程执行终点。

先读 [severity-policy](references/severity-policy.md)，其中有 impact/likelihood 每级锚点、critical 判定和 DSH 代码的执行顺序。提交结构化 policy_facts，区分 impact、likelihood、vector、authScope、preconditions、attackerInputControl 和精确抑制事实。impact、preconditions、attackerInputControl 未知则维持候选严重度并标 deferred，deferred 不计入 confirmed；likelihood、vector、authScope 未知走矩阵 unknown 列；不要沿用候选严重度绕过策略。缺部署或 ingress 证据只影响 confidence 或让事实保持 unknown，不压低严重度；remote 只是默认，前提是攻击者位置现实且在范围内，代码不会自动抬到 high，likelihood 按证据填写；local_network、localhost 有证据支持更高级别时写 likelihoodOverrideReason。事实定下后机械走矩阵，不再重新争论。Critical 的 criticalCriteria 要有对应证据。管理员、同账号或本机操作只有真实跨越受保护边界才有可报告影响。

独立复核验证记录是否准确描述具体接口、条件、反证、静态/运行证据和影响上限。实质性改变根因、路径、影响或严重度后需要重新验证，不能静默加强发现者的结论。输出改变结论的具体条件。

方法改编自本地 Codex Security 0.8.0、Cloudflare security-audit-skill 与 Anthropic claude-code-security-review；宿主工具、状态和安全边界以 DSH 插件实现为准。许可见包内 NOTICE 与 docs/licenses。
