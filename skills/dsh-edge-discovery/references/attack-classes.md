<!-- 改编自 Cloudflare security-audit-skill ATTACK-CLASSES.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。 -->

# 通用攻击类目

按侦察结果选择相关类目并按子系统拆分；不是每类都适用，可追加应用特有类目。工作定位是发现、验证、修复和排序漏洞；验证限于源码审阅和有界本地 fixture，不开发 payload 链，不在线上测试可用性，不在共享环境采取动作。领域边界实际出现时再读对应 reference：web-auth、client、api-messaging、ai-agent、supply-chain、cloud、tenant-lifecycle、resources、desktop、native-memory。

## Injection

把不可信输入追到危险 sink，sink 取决于应用类型：

- Web 应用：SQL、HTML 输出、shell、模板引擎、文件路径、HTTP 重定向、反序列化。
- 库：处理调用方数据却不校验的函数，如 buffer 操作、parser、format string。
- CLI：shell 命令构造、文件路径处理、环境变量插值。
- 服务：查询构造、消息序列化、日志注入、LDAP/XPath。
- 浏览器：DOM XSS、prototype pollution、`postMessage` 等，见 client。

不止看直接路径：安全存储后被另一段代码在危险上下文取出的间接注入；经字段名、key、header、元数据的注入；注入二级系统（日志、缓存、搜索索引、分析）。

## Access control

验证调用方不能越权。不只看检查是否存在，要看是否用**正确机制**对**正确资源**检查**正确权限**：

- 同一状态变更是否有检查较弱权限的另一路径？
- 请求体字段能否覆盖权限系统本要限制的内容？
- 哪些端点只认证未授权？
- 同一资源的多条访问路径检查是否一致？
- bulk/batch/export/import 是否逐项授权？

复杂访问模型把 auth bypass 与授权逻辑拆开调查。

## Resource and file handling

- Path traversal，含 symlink、编码序列、null byte。
- SSRF，含重定向、DNS rebinding、URL parser 差异。
- 不安全反序列化、归档解压（zip slip）、临时文件处理。
- 内存安全（如适用）：缓冲区溢出、UAF、整数溢出。
- 文件操作竞态（check 与 use 之间的 TOCTOU）。

## Cryptography and secrets

- 安全关键值（token、key、nonce）用弱随机。
- 硬编码 secret；secret 进入日志、错误信息、URL、客户端可见响应。
- 错误的 key derivation、缺 HMAC 校验、nonce 重用。
- secret 比较的 timing 侧信道。
- 加密原语误用：ECB、无认证加密、静态 IV 等。
- 加密操作失败时错误路径是否回退到不加密？

## Business logic

扫描器找不到、影响又高，需人工逐工作流推敲：

- **状态机违规**：能否跳步、回退、到达非法状态？重放已完成流程会怎样？三步中第二步失败时第一步是否回滚？
- **有业务影响的竞态**：并发造成 double-spend、double-approve、lost update，重点看非原子 check-then-act。
- **数值/数量操纵**：负值、零、溢出、精度损失、字符串与数字强转。
- **访问边界违规**：不是“检查存在吗”，而是“这是否符合业务规则的检查”；一个操作的输入能否绕过另一操作上针对同一效果的限制。
- **隐式信任假设**：来自存储、配置、其他组件、插件的数据因“入口校验过”被视为安全；若是另一条路径写入的呢？
- **时间逻辑**：expiry、调度、速率窗口、时钟偏差、边界时刻、组件间时区差异。
- **默认与回退**：配置缺失、feature flag 关闭、依赖不可用、迁移中途的安全姿态是什么？

## Feature abuse and data leakage

合法功能被用于非预期目的，缺陷常在设计而非代码：

- **导出/备份作外泄**：低权限用户能否触发含超权限数据的 export、snapshot、backup？能否导出他人数据？是否含已删除、草稿、私有内容或本应裁剪的修订历史？
- **导入/恢复作注入**：import 能否覆盖现有数据、绕过常规校验建记录、向无写权限的集合注入？是否遵守与 UI 相同的权限模型？
- **搜索/过滤/排序作 oracle**：查询能否揭示不可访问内容的存在？filter 参数能否探测不应知道的状态、角色、字段？按隐藏字段排序能否从顺序推断其值？
- **经副作用枚举**：“不存在”与“无权限”的错误、响应时间、响应大小、HTTP 状态是否不同？能否经密码重置、邀请、注册枚举用户？
- **预览/草稿/staging 泄露**：preview token 限于单项还是解锁更广？草稿能否经搜索、RSS、sitemap、列表 API 发现？cache header 能否让 CDN 公开提供私有内容？
- **通知/webhook 作 SSRF**：用户能否设置服务端会 fetch 的 notification、webhook、callback URL？是否校验内网地址？重定向之后呢？

## Chained vulnerabilities and trust boundaries

单独允许或受控的行为，在其他组件或生命周期步骤依赖更强保证时会成为漏洞：

- **多步边界失败**：列出低权限 principal 可读、可写、可调用、可保留的内容，只把具体输出连接到后续信任决策；确认每个前提，不假设下游效果。
- **跨组件信任缺口**：A 校验后传给 B，比较 A 的确切保证与 B 的假设，含截断、类型强转、归一化、租户范围、插件/扩展访问。
- **二阶使用**：存储时安全的数据在后续上下文变危险：字段名变 JSON path，slug 变文件路径，转义文本进入 raw 渲染，字符串变 URL、regex、模板或策略表达式。
- **范围与能力增长**：token、API key、插件、OAuth、MCP、AI 能力在委托、refresh、缓存、角色变更、组合后变宽；写出结果 principal 不应拥有的具体操作。
- **时序**：setup、migration、soft-delete、revoke/cache 过期、check/use、validate/consume 窗口；确认陈旧状态确被接受。
- **回滚与恢复**：undelete、restore、revision rollback、cancellation 须应用当前归属、校验、授权；确认恢复了哪个非法状态。

## Wildcard

不给类目，找标准类目之外的漏洞。读看似无聊或与安全无关的代码；跟进未完成、实验性、兼容、fallback 功能，但边界与验证要求不变。起点：

- 代码库里最奇怪的代码是什么？为何存在？被滥用会怎样？
- 哪些功能半成品、实验性或硬加上去？它们审查最少。
- 前端绝不会发、API 却接受的调用有哪些？
- 路由注册、middleware、配置里有哪些未文档化的端点、参数、header、功能？
- 混用未设计协作的功能：本地化 + 预览 + 缓存；导入 + 插件 + webhook；OAuth + impersonation + API key。
- git 历史：被 revert 的安全修复、注释掉的 auth、提交后删除的 secret（仍在历史中）。
- 哪些有效账号动作影响他人、共享完整性、可用性或运营方成本？核实隔离、配额、授权、恢复。
- 哪些操作不可逆或需提升确认？授权与批准要绑定最终 principal、动作、资源。
- 代码对环境有何假设：数据库在本地、时钟准确、DNS 可信、文件系统区分大小写？
- 测试**没有**测什么？比较开发者想到的边界与没想到的。

在分配范围内追异常直到不变量定论。注释解释“为何安全”时要验证解释；名为 `temp`、`hack`、`legacy` 的变量要细读。

## Obvious things

其他 worker 找隐蔽问题，这里检查人人以为别人查过的基础暴露。不需要创意，要彻底、逐字，每项都报告结果：

- 源码中的硬编码密码、API key、token、secret（搜 `password`、`secret`、`apikey`、`token`、`Bearer`、`-----BEGIN`、常见默认口令）。
- 涉及安全的待办注释（`FIXME`、`HACK`、`XXX` 及 to-do 标记，如“add auth”“validate input”“skip permission check”）。
- debug/dev 模式是否受控？能否经环境变量、query 参数、header 在生产开启？
- test/example/seed 凭据在生产是否可用？
- `/debug`、`/admin`、`/test`、`/status`、`/health`、`/metrics`、`/env`、`/.env`、`/config` 是否无保护？
- 仓库中是否有 `.env`、`.env.local`、`credentials.json`、`*.pem`、`*.key`？
- `.gitignore` 是否真正覆盖 secret、上传目录、本地配置？
- 依赖是否 pin？lockfile 中有无已知 CVE？
- 动态输入进入 `eval()`、`exec()`、`child_process`、`Function()`、`vm.runInContext`、`import()`？
- CORS 是否 `*` 或过宽？`Access-Control-Allow-Credentials` 是否配合通配 origin？
- cookie 是否缺 `HttpOnly`、`Secure`、`SameSite`？
- open redirect：`redirect`、`return`、`next`、`url`、`goto`、`continue` 参数是否未校验进入重定向？
- TLS 是否强制？有无仅 HTTP 的端点？
- 生产错误响应是否返回 stack trace、内部路径、SQL 错误？

**重要**：任何发现都要核实完整代码路径。缺 `HttpOnly` 要查 cookie 是否含安全敏感数据、JS 是否按设计需读取；错误信息含字段名要查该字段是否真会填入敏感数据。标志不是发现，先追影响。
