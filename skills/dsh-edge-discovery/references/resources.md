<!-- 改编自 Cloudflare security-audit-skill RESOURCE-EXHAUSTION-AND-AVAILABILITY.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/resources.md -->

# 资源耗尽与可用性

## 核心方法

适用：不可信请求、消息、文件、租户状态或 agent 工作可消耗 CPU、内存、磁盘、连接、worker slot、付费 API、queue 容量，或可让共享服务死锁/崩溃。本领域区分可由源码审查的可用性漏洞与普通性能问题。绝不通过压测共享或线上服务验证。内存完整性缺陷见 native-memory，broker 投递逻辑见 api-messaging；可达的致命错误因共享影响归入本领域，即使底层 parser 属于其他领域。

- 需要“输入到成本”路径、缺失的有效上限，以及对其他用户、共享服务、安全功能或运营方花费的影响。请求者自身进程内自限的工作不是服务漏洞。
- 缺 rate limit 不够。定性为无界前，检查 body/message/file cap、并发、queue、deadline、数据库约束、上游 gateway、按租户配额。
- 不做压测、饱和或生产测试。用渐近分析、小型边界 fixture、mock 付费调用、严格本地资源上限、确定性取消测试。
- 写明攻击者成本、服务工作量、持久性、范围、恢复。单个有界输入造成超线性或持久共享影响，与持续大流量有本质区别。
- 建 input-to-resource 表：最早接受的大小/基数、认证前工作、下游 fan-out、持久性、共享池、上限与清理 owner、恢复。
- 比较聚合上限与单对象上限。一万个合法的单字节项可避开单消息 cap，却耗尽租户级或进程级状态。
- 只在有严格 CPU/内存/时间上限的隔离 fixture 内用小增长点验证，mock 外部与付费调用，观察到缺失上限或取消失败即停。

## 类目检查点

### 计算放大
- **超线性解析/匹配/求值**：小输入驱动灾难性 regex 回溯（ReDoS）、嵌套解析、递归校验、符号求值、图遍历、模板展开、对抗性排序/哈希行为。推导接受的深度/基数和复杂度，再本地展示有界增长曲线。
- **解压与表示放大**：压缩、稀疏、嵌套、alias、编码输入展开远超检查时的传输或文件大小。核实每次展开后、跨 parser 阶段的限制，含归档、图片、字体、结构化文档、协议压缩表。
- **数据库与下游查询放大**：小请求造成宽扫描、病态 join、fan-out、无界排序/聚合或大量下游调用，因查询深度、filter 基数、分页、expansion 字段无上限。确认授权并非有意允许相同资源范围。

### 资源累积
- **无界缓冲与基数**：body、乱序 stream、上传、session、唯一 cache key、metrics label、日志字段、subscription、pending job 累积，缺单项和聚合上限。查 disconnect、timeout、取消、部分解析时的清理和过期。
- **FD、句柄、临时资源泄漏**：畸形或取消的工作跳过清理，保留 socket、文件、数据库 cursor、timer、子进程、临时文件、对象引用。确认泄漏在有界本地迭代中重复出现，且影响共享池。
- **取消后的分离工作**：客户端 timeout、断连、job 取消、授权失败后控制已返回，但数据库、模型、网络、worker 工作仍在运行。追 cancellation 和 deadline 穿过每一层。

### 配额与调度
- **认证前工作失衡**：昂贵的解析、key lookup、加密、解压、外部请求发生在认证和最早大小/速率闸门之前。比较最小请求成本与共享服务成本，检查上游限制。
- **配额计量范围与重置缺口**：计量维度由攻击者影响（IP、路由、tenant、key prefix、task ID），一个 principal 的工作可逃出预算或消耗他人额度。查整数溢出、分布式竞态、retry、重连、账号切换。
- **Worker、池、优先级饥饿**：低优先级或攻击者控制的 job 占住无关用户所需的共享锁、worker、数据库连接池、event loop turn、调度优先级。需要绕过 queue/并发公平性或超 deadline 保留 slot 的路径。

### 失败与恢复
- **可达致命错误或死锁**：不可信输入到达 `panic`、abort、致命 assertion、未处理异常、进程退出、锁环、无限循环。确认 supervisor 范围，是一个 worker 还是整个服务不可用。隔离 worker 重启可降低影响，但不抹除缺陷。
- **Retry storm 与 fail-open 放大**：timeout、依赖错误、部分处理消息、health check 失败触发同步或无界 retry，缺 jitter、上限、circuit breaker、dedup。核实一个有界失败源能产生持续聚合工作。
- **毒记录与队头阻塞**：一条畸形记录在共享 queue、partition、启动扫描、migration、恢复循环前端反复失败。查 skip/quarantine 策略、offset、其他租户是否共享被阻塞单元。
- **不安全恢复与容量回滚**：重启、restore、fallback、清理路径重建无界状态、忽略当前配额，或恢复立即再次失败的输入。恢复正确性是可用性的一部分。

## 验证与反证

项目有意保留本类别，不按上游 claude-code-security-review 的做法直接排除 DoS；门槛是证明攻击者成本被放大。

1. 写出不可信输入、请求者工作量、服务放大或被保留资源、共享影响范围、恢复。缺限制但无具体共享影响属加固项。
2. 确认没有源码可见的上游、parser、queue、租户或框架上限阻断路径。未知的部署控制记 Needs Validation。
3. 超线性：确定接受的复杂度和有界本地增长。泄漏：展示本应清理后仍可重复保留。致命路径：确定进程/supervisor 隔离。
4. 优先级看低请求成本、未认证可达、跨租户范围、持久性、恢复能力差；验证过程不得造成可用性影响。
5. **常见误报**：只缺 rate limit；只有“大请求慢”而攻防成本线性；请求者只耗尽自己进程；纯崩溃而无共享影响；上游 gateway 已有 body cap；授权本就允许同样范围的重查询。
6. 确认需安全的本地证明和有意义的共享影响。上游限制、部署拓扑、autoscaling、付费配额、恢复行为在仓库外时记 Needs Validation，写明所有者需检查的确切事实。
