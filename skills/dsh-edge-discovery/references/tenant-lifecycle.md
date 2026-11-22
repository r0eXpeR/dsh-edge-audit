<!-- 改编自 Cloudflare security-audit-skill DATA-ISOLATION-AND-LIFECYCLE.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/tenant-lifecycle.md -->

# 数据隔离与生命周期

## 核心方法

适用：存储多租户或受访问控制数据，派生 search/index/cache/analytics 副本，签发对象链接，导出或恢复记录，迁移 schema，或承诺删除、撤销、保留行为。本领域跟随一条数据穿过每份副本和每次状态迁移。端点级访问控制见 attack-classes，provider 级存储策略见 cloud。大型目标拆为主存储、cache/search、object/blob、analytics/logging、export/backup、deletion/revocation、migration。

- 记录上的 tenant 或 owner 字段不是隔离。为每条读写路径找到强制它的 query、key、path、policy 或 row-level 控制。
- 追踪派生副本。已净化的主数据在 search、cache、analytics、export、preview、日志、replica、backup 中可能变得不安全，它们的 ACL 和保留规则不同。
- 删除和撤销是生命周期契约。在产品声明的边界内检查当前、历史、缓存、索引、导出、恢复、排队中的副本。
- 隐私或保留偏好不自动等于漏洞。需要明确的数据访问边界或删除/撤销保证，以及未授权读者或后续操作。
- 选一条受保护记录，画出主写入、query、cache、index、event、export、backup、deletion、restore 路径，每条边标 principal 和 tenant。
- 用两个假租户走同一本地 service 方法，再在 ACL 变更、删除、账号切换、restore 后重复。不用真实用户数据。
- 优先看 bypass client、后台 job、migration、全局唯一约束、cache key。这些路径常漏掉交互端点携带的请求级身份。

## 类目检查点

### 租户与对象隔离
- **缺租户/owner 强制**：read、update、delete、list、count、bulk query 定位对象却未绑定已认证 tenant/owner，或信任 body 字段提供身份。比较直接查询、嵌套关系、后台、admin、import、legacy 路径。
- **复合 key 与 namespace 碰撞**：cache key、object path、数据库唯一约束、search 文档 ID、临时文件、dedup key 漏掉 tenant 或环境，两个 principal 可覆盖或取得同一逻辑 key，即使应用记录各有 owner。
- **策略与查询不一致**：row-level policy、ORM default scope、授权过滤、raw/bypass client 的 predicate 不同。查 join、aggregate、alias、view、事务、`unscoped` 或 service client，以及上下文缺失的错误路径。
- **Blob 与签名引用越权**：object key、attachment ID、version ID、分享链接、signed URL 允许超出签发者权限的操作或 namespace，或在底层 ACL 变更后仍有效。绑定操作、确切对象/版本、audience、expiry、tenant。

### 派生数据与泄露
- **Search、cache、index ACL 漂移**：主记录 ACL 或生命周期变化，却未失效 searchable、cached、embedded、thumbnail、RSS、preview、index 副本。检索时过滤、文档摄入、失效逻辑都要验证。
- **分析、日志、trace、诊断作为替代读者**：私有内容或凭据流入访问更宽、保留更长或租户混合的系统。确认数据类别和现实读者；字段名、公开标识符、预期策略下仅运维可见的内容不够。
- **枚举与聚合 oracle**：count、filter、排序、错误、唯一约束、timing、通知行为、存在性检查泄露受保护的对象或账号状态。需要具体机密 predicate 和可观察差异，不是泛化响应差异。

### 导出、备份、恢复与迁移
- **导出/备份范围扩张**：export、snapshot、portability 包、report、backup 含其他租户、不可访问对象字段、软删除数据、secret 值或超出请求者权限的历史。查选择后的逐项授权，以及下载最终产物的授权。
- **导入/恢复权限扩张**：restore/import 绕过 owner、schema、ACL、唯一性、校验规则，覆盖已有资源，或在请求者不可写的租户重建记录。把归档内容当不可信验证，授权结果操作，不信任先前来源。
- **迁移默认值与归属混淆**：旧记录缺 tenant/ACL/生命周期字段，不兼容 ID 碰撞，或灰度让新旧读者使用不同默认值。查 backfill、dual-read/write、兼容、rollback、resumed migration。
- **备份与复制边界漂移**：加密 key、存储账号、跨区域 replica、恢复环境、支持快照的身份或租户范围比主数据更宽。源码只能确认仓库内策略；托管访问和保留需 Needs Validation。

### 删除、撤销与生命周期
- **软删除/tombstone 绕过**：直接查询、search、关系遍历、对象链接、后台处理、restore 忽略生命周期 predicate，返回或作用于已删除/撤销记录。查软删除标识符能否在所有引用消失前被重新注册。
- **陈旧授权与派生副本使用**：移除成员、ACL 更新、撤回同意、撤销 secret、降角色后，session、cache、subscription、job、物化数据仍授权后续操作。
- **保留期与排队工作超限**：主存储删除完成，但排队处理、retry、export、analytics、生成产物重建或保留数据，超出承诺边界。寻找幂等删除和 tombstone 传播。
- **恢复重新引入非法状态**：backup、undo、undelete、replica 恢复带回当前策略已不允许的数据、凭据、成员关系或权限。重新授权恢复状态，并重放快照后的生命周期变更。

## 验证与反证

1. 写出攻击者或低信任 principal、受保护数据/状态、受影响 owner/tenant、替代副本或操作、越权泄露或变更。
2. 同时引用预期的 source-of-truth 策略和遗漏或不一致的路径，并确认没有另一层强制相同的租户/生命周期条件。
3. 用本地假租户和非敏感 fixture 证明跨范围访问或陈旧生命周期行为，停在最小可观察记录或操作。
4. 依赖外部 cache、对象存储、replica、analytics、backup、保留策略时记 Needs Validation，写明所有者检查项。
5. **常见误报**：只有 tenant 字段缺失而 RLS 或默认 scope 已强制；响应差异未对应机密 predicate；字段名含 sensitive 但从不填充敏感值；运维按策略可读的日志；单纯保留偏好无删除保证；UUID 对象 ID 须另行证明可获取或仍缺授权，不可因其难猜就直接判安全（见 false-positive-precedents 的 ID 条目）。
6. 确认需完整 lineage 和具体边界影响；否则保留确切未解决的存储、ACL、失效、保留或恢复事实。
