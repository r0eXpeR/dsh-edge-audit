<!-- 改编自 OpenAI Codex Security 0.8.0 skills/attack-path-analysis/references/severity-policy.md、attack-path-facts.md 与 dist/default-severity-rubric.js 的 defaultSeverityRubric，Apache-2.0；已按 DSH 实现修改。 -->

# 严重度与策略

在确立攻击路径、范围、反证之后应用。判断攻击者实际起始权限、被跨越的安全边界、新增的未授权危害。不在定级时重开发现，不虚构攻击路径。事实定下后机械走矩阵，不再从头争论严重度。

## 代码实现

`mechanicalPolicyPass` 按以下顺序执行，填写 policy_facts 时以此为准：

1. **硬抑制 → ignore**：selfOnly；unreachable 或 attackerInputControl=no；unrealisticPreconditions 或 preconditions=unachievable；privilegedOnly、operatorOnly、developerOnly、physicalAccessOnly（有 privilegeDelta 及具体证据时除外）。
2. **决定性事实 unknown → deferred**：impact、preconditions、attackerInputControl 任一为 unknown 时，维持候选严重度并标 deferred，不改写严重度。deferred 不计入 confirmed，不产生 priority，不得写成已确认。likelihood、vector、authScope 的 unknown 不阻断，继续走矩阵；部署或暴露未知只影响矩阵的 unknown 列。
3. **likelihood 加权**：local_network 把 high 收到 medium，localhost 收到 low；remote、none、unknown 不改写，直接取提交的 likelihood。`likelihoodOverrideReason` 不少于 40 字符时跳过加权。见下文“exposure 的前提”。
4. **权限上限**：无 privilegeDelta 时 admin-only 上限 low，internal-only 上限 medium；preconditions=unlikely 上限 low。
5. **impact×likelihood 矩阵**，再判 critical，再映射 priority。

policy_facts 只记录事实，严重度由代码得出，不要用候选严重度绕过策略。

## Impact 锚点

- **high**：越过重要边界带来重大后果：代码执行、账号接管、强认证绕过、大范围授权或租户失败、受保护数据或可重用凭据、签名/私钥、特权身份、生产工作负载或部署控制、沙箱/容器/VM/浏览器逃逸、跨租户删除、安全关键配置被改、关键共享服务重大且可重复的中断。
- **medium**：具体受限的影响：非秘密运维信息、窄范围未授权变更、非关键服务受控中断、隔离的开发或 staging 系统且无后续 pivot。完整演示的漏洞也可以是 medium。
- **low**：新增危害很小，且范围、敏感度、持续时间的限制已被核实：安全价值很低的少量信息、窄范围滋扰。不要用 low 代替对严重路径的不确定性。
- **ignore**：已证伪，或无有意义的安全影响。上游 Informational（加固机会或观察，证据确立没有新增未授权能力）落在此处，可在报告中作为加固项记录，但说明理由，不把缺利用证明当作安全证明。
- **unknown**：影响面的决定性事实未确定，走 deferred，维持候选严重度。

## Likelihood 锚点

- **high**：现实且在范围内的攻击者位置，低摩擦可达；未认证或普通外部用户，无需特殊配置或受害者配合之外的条件。
- **medium**：需要内部网络位置、特定配置、合理的受害者交互、已有的普通账号或若干可信前提。
- **low**：需要本机可达、多个不太可能同时成立的前提、窄时间窗或高摩擦交互。
- **ignore**：不可达、前提不可实现或极不现实。
- **unknown**：攻击者位置或暴露未确定。不走 deferred，走矩阵 unknown 列；此时结论不能到 critical。

## Exposure 的前提

- `remote` 只是默认而非强制：**前提是攻击者位置现实且在范围内**，才通常支持 high；代码不会把 remote 自动抬到 high，likelihood 要按证据自己填写。`local_network` 通常 medium，除非证据支持其他级别；`localhost` 通常 low，除非低权限攻击者能现实到达 listener；`none` 不因暴露提高 likelihood。
- 代码只对 local_network、localhost 加权。证据支持更高级别时（例如 localhost listener 但网页可经 DNS rebinding 到达），提交不少于 40 字符、引用具体证据的 `likelihoodOverrideReason`，此时不加权。remote 但需罕见受害者动作时，直接把 likelihood 填低，不需要 override。
- **缺部署或 ingress 证据只影响 confidence，或让事实保持 unknown，不压低严重度**。缺运行复现同理。不要假设 remote，也不要因“没看到公网入口”降级。暴露未知时 vector 填 unknown，likelihood 按已知证据填写，确实无法判断才填 unknown。
- 内部或私有暴露本身不抑制真实产品或生产流程中有支撑的授权、身份、信任边界、安全控制失效。
- 降级必须基于已核实的约束，不基于“缺证据即排除更大危害”的假设。

## Critical 判定

矩阵中 impact=high 且加权后 likelihood=high 时，`criticalCriteria` 至少一项有证据才为 critical，否则 high：codeExecution、accountTakeover、authBypass、privilegeGain、sensitiveDataExposure、sandboxEscape、memorySafetyExploitation。每个标志须有对应证据。

提交这些标志前，按上游 rubric 自查三个条件都满足：

- **Access**：未认证互联网攻击者、普通外部用户或公开准入的不可信 workload 可利用，不需要员工身份、邀请、已批准业务关系或可信供应商被攻破。
- **Impact**：越过重要边界，取得受保护数据、特权动作、实质代码执行、workload 逃逸或同等后果。
- **Evidence**：演示利用或强源码验证确立完整路径。

二阶攻击可符合：外部攻击者植入数据，可信用户或系统稍后处理，造成未授权访问或特权动作。

可支持 critical 的证据：任意代码执行或易利用内存破坏；账号接管、强认证绕过、可致账号沦陷或特权动作的 XSS；大范围授权或租户失败；高敏感数据、签名密钥、私钥、凭据库；暴露敏感数据或写入危险记录的查询注入；沙箱/容器/VM/浏览器/解释器逃逸；能执行代码或取 secret 的 SSTI；有现实持久化或执行路径的任意文件写；不可逆或大范围完整性破坏。这些都要求攻击者控制、范围内可达路径、所称影响的证据。未认证可达、低摩擦、跨租户、身份或签名沦陷、持久化、大规模利用可把可信的 high 提升为 critical。

## High 证据

现实路径让低信任攻击者获得其原本没有的实质未授权能力。内部用户、合作方、受邀协作者、准入的不可信 workload 都可算，不要求未认证互联网。例如：SSRF 可控目标且有实质内部、metadata、文件或副作用访问；重大影响的可利用内存破坏；未授权读取实质用户数据或源码；有现实执行/持久化路径的文件写；现实受害者交互下改变敏感状态的 CSRF；有效可达的硬编码或默认凭据；可致伪造、绕过安全信道、解密敏感数据的密码学失败；投递恶意代码或可信制品的更新/供应链沦陷；影响较窄但实质的对象级或同租户授权失败；可利用 XXE；可致存储型活动内容或可信 origin 脚本执行的上传；有实际影响但证据未到 critical 的反序列化、模板、插件、宏、解释器原语。

危险函数、生产标签、内部访问、特权凭据的存在本身都不够：要写明低信任 actor、边界跨越、新增能力。

- SSRF：文档化的出站功能或可选运维过滤不抵消已证明的目标控制绕过。
- CSRF：评估凭据附带、cookie 策略、preflight、请求解析、有效控制；method 或 JSON content type 不是绝对防御。
- XSS：区分 self-only 与受害者影响；`alert` 证明脚本执行，不决定严重度。

## 其他校准

受限、同租户、内部、localhost、self-only、已特权路径通常降低严重度，除非威胁模型或权限增量支持更高。普通正确性缺陷、低影响信息泄露、投机性注入或内存破坏、安全 header 或 crypto hygiene 观察、瞬时或自伤 DoS，无演示严重后果时不到 high/critical。评估实际权限增量和边界跨越。

不要仅因影响或可能性低就丢弃真实可报告发现，用较低严重度。源码证明不存在现实的低权限在范围内攻击路径时判 ignore；只是尚未确立时走 deferred。

## 矩阵

- `impact=high`：likelihood high→high（满足 critical 条件→critical）；medium→medium；low→low
- `impact=medium`：high→medium；medium→low；low→low
- `impact=low`：high/medium/low→low
- `likelihood=unknown`：impact high→medium；impact medium→low；impact low→low
- `impact` 或 `likelihood`=ignore：→ignore
- `impact=unknown` 不进矩阵，走 deferred

Priority：critical→P0，high→P1，medium→P2，low→P3；ignore 与 deferred 无 priority。

## 路径事实清单

范围与上下文（self-only 或跨越实质边界）、攻击路径（可控输入、步骤、敏感操作）、exposure 与 vector、身份与前提、影响（类别、受影响 runtime/data/identity/build/network 面、目标范围、涉及的 secret 类型）、控制与反证（最强反证及其为何成立或不成立）、不确定性（置信度、缺失事实、改变结论的条件）、决策（impact 与 likelihood 理由、最终策略）。事实与严重度、抑制决定分开记录。
