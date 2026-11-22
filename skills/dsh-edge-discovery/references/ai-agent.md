<!-- 改编自 Cloudflare security-audit-skill AI-AND-LLM.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/ai-agent.md -->

# AI、LLM 与 Agent

## 核心方法

适用：模型参与信任敏感决策的场景，包括聊天助手、RAG、持久 agent memory、tool-calling loop、MCP server/client、用不可信输入构造 prompt 的代码、消费模型输出并据此行动的代码。关键数据流是“不可信内容 → 模型或 memory → 能力、权限或 sink”。传输、访问控制、查询构造、文件系统、输出渲染仍是普通信任边界；本领域只覆盖模型特有的委托层。大型目标拆为 retrieval、memory、tool dispatch、MCP、输出处理。

- Prompt injection 本身不是发现。要有代码层边界失效：内容进入其他 principal 的上下文、调用请求者没有的权限、泄露其不可读数据、驱动其无法直达的 sink。
- 模型输出、memory、tool description、MCP 响应都是不可信输入。指出授予权限、信任输出、写持久状态或喂给 sink 的代码。
- Guardrail prompt 不是安全边界。只有确定性检查、按资源授权、隔离、绑定、受限凭据才算。
- 写明攻击者、受影响 principal、实际执行身份、资源、确切动作、所用权限、可观察影响。用户有意请求动用自身既有权限，不因模型执行而成为委托缺陷。
- 授权和动作绑定是两个控制。攻击者内容在受影响 principal 的有效权限下触发动作，若其未有意请求或批准该确切动作，即动作绑定失败。
- 先画四张图：执行身份、能力、可写上下文/memory 来源、输出目的地；再把起点 principal 连到终点权限。
- 从有副作用的 tool 反向走 dispatcher、schema、确认、模型上下文、retrieval、ingestion；从 durable memory 读取点追所有写入者。
- 比较同一动作的 direct、queued、retry、resume、batch、delegated 路径。最强闸门必须在参数定稿后、每次副作用前生效。

## 类目检查点

### 上下文、检索与 memory
- **间接注入**：攻击者可写的 RAG 文档、索引页面、文件、邮件、issue、tool 响应、元数据进入他人模型上下文。追谁能写每个来源、检索如何限定范围、谁的 session 消费、启用了什么能力；分别检查隔离、资源授权、与消费方意图的绑定。缺陷是缺确定性控制，不是文字有说服力。
- **跨 session/租户上下文串扰**：会话历史、embedding、检索结果、prompt cache 的 key 过宽。核实查询本身和每个 cache key 含 tenant 与 ACL 过滤；对象带 tenant 字段不等于强制，alternate query、共享缓存、batch 路径可能漏掉。
- **持久 memory 投毒**：攻击者内容或模型摘要写入 memory，影响后续任务、用户或特权 session。查谁能创建/更新/合并/删除，provenance 与租户范围，低信任观察是否变成持久指令或事实，检索是否区分用户偏好与 tool 策略。用户有意保存且只用于本人允许请求的 memory 不跨边界。
- **Prompt 角色/来源混淆**：不可信文本冒充 system、历史 turn、tool 结果、策略或 memory。找字符串拼接、无类型 history、调用方可控 role 字段、丢失来源标签的序列化往返；确认伪造来源改变了确定性信任决策或触达有意义能力。

### Tool 与动作
- **Tool 参数注入下游 sink**：模型参数未经 handler 侧校验到达 SQL、shell、文件、URL fetch、特权 API。把 tool schema 视为输入解析，逐字段追到 sink。结构化输出只收窄形状，不能确立授权、安全路径、安全 URL、查询语义。
- **过度代理/confused deputy**：agent 用服务身份或宽凭据，handler 不复查请求 principal 对具名资源的权限。核实实际身份，以及调用方能否经正常产品界面做同样操作。共享凭据但强制按用户限定查询不是缺陷。
- **动作确认与批准绑定**：用户批准一个描述，执行却可用变更后的参数、资源、principal 或后续模型 turn。确认须绑定归一化 tool 名、完整参数对象、请求者、目标、金额、expiry、batch 成员。查 retry 和 resumed session：批准不能授权变异或重复副作用。
- **Tool schema 与 dispatcher 分歧**：schema 接受 alias、多余字段、重复 key、类型强转、嵌套自由对象、越界值，dispatcher/handler 解释不同。比较校验、canonicalization、生成 binding、handler 默认值；值成为资源选择器或安全选项处再校验。
- **无界委托循环**：有界请求可排入重复的花费、发送、变更或外部 API 工作，缺单请求预算、逐动作授权、取消、幂等。确认对共享成本、配额、其他用户或持久状态的影响；用代码层计量和本地有界循环验证，不实际耗尽服务。

### MCP 与 sub-agent
- **信任继承**：委托任务获得完整 session、凭据、memory、能力而非最小权限。查每次调用携带的 principal 与 tenant、能力收窄、凭据 audience，返回结果是否被当不可信。
- **MCP server/tool 身份混淆**：调用或结果按攻击者可影响的 server 名、tool 名、request ID、resource URI、模型选择的 alias 路由，而非已认证连接与未完成请求。查两个 server 能否声称同一 tool/resource，重连是否改变绑定，一个 server 的响应能否满足另一 server 的 pending 调用。
- **MCP 元数据/schema 当策略**：peer 提供的 tool description、resource metadata、prompt、completion hint、schema 被当策略或授权。它们可引导模型但不能授予能力；找元数据冲突时仍权威的确定性 allowlist、server 身份检查、handler 授权。

### 输出与泄露
- **不安全输出渲染**：模型输出未按 sink 要求编码就进入可执行的 HTML、Markdown、模板、URL、命令 sink。浏览器渲染需核实自动加载资源、CSP、sanitization（见 client）。
- **敏感上下文提取**：组装的上下文含凭据、他人数据、私有源码或本身可授权的策略值，且用户可影响的输出会暴露。读 prompt 组装和取数代码。

## 验证与反证

1. 写出被跨越的边界和可观察结果：攻击者、受影响 principal 或共享资源、执行身份、目标、越权或未请求的动作或泄露。
2. Confused deputy：证明 tool 缺“请求者 + 资源”授权，且攻击者无法经正常途径做同样操作。动作绑定：改为证明攻击者内容在 principal 权限下触发了其未有意请求或批准的动作；有效的通用授权不等于有此意图。
3. Memory/retrieval：同时引用攻击者可控写入，和后续跨 principal 读取或特权决策。没有可达消费者的共享记录不够。
4. 动作绑定要确定有意请求或归一化批准对象（如有），与 handler 实际使用的对象比较，确认本地可观察的未请求动作、变更、重复或权限变化，不延伸到有害执行。Schema 分歧比较校验后对象与 handler 对象。
5. MCP 身份要核实已认证连接、请求关联、tool namespace、实际凭据。依赖外部 server 身份或部署路由记 Needs Validation。
6. **常见误报**：只有 prompt injection 文本；用户输入进入 prompt；泄露通用 system prompt 或行为说明而未跨数据边界；guardrail 被绕过却没有后续权限或数据影响；用户让模型用自己已有权限做事；同一用户自己的 memory。
7. 确认需完整源码路径和有意义结果；provider、模型、渲染器、身份行为无法本地观察时记 Needs Validation，并写明解决该事实的有界检查。
